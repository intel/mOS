/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <getopt.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "lwksched.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static unsigned int n_threads, n_lwkcpus, n_util_threads;
static int max_util_cpus = -1; /* default mOS behavior */
static int  max_utils_per_cpu = 1; /* default mOS behavior */
static int  one_cpu_per_util_thread;
static unsigned long long spin_amount = 1ull << 30;
static size_t setsize;
static cpu_set_t *lwkcpus, *lwkcpus_reserved, *linuxcpus;
static cpu_set_t *lwkcpus_util_combined, *lwkcpus_util_shared;
static cpu_set_t *compute_threads, *util_threads, *temp_cpumask;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t count_cv = PTHREAD_COND_INITIALIZER;
static unsigned int threads_finished;
static pthread_mutex_t utils_registered_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t utils_registered_cv = PTHREAD_COND_INITIALIZER;
static unsigned int utils_registered;
static unsigned int registered;
static int pushed_utilities;

static void usage(void);
static int register_pthread(unsigned int tid, int cpu);
static void *worker(void *);

struct {
	volatile unsigned long long data  __attribute__ ((aligned (4096)));
	int my_cpu;
} work_area[MAX_THREADS];

static int get_scheduler_policy(void)
{
	int tid = syscall(SYS_gettid);

	return syscall(SYS_sched_getscheduler, tid);
}

/**
 * The worker function for each spawned pthread.  It does the following:
 *
 *   - ensure that the thread lands on an appropriate CPU.
 *   - ensure that the thread stays on the same CPU for the duration of
 *     the run unless it is a utility thread being pushed to a
 *     utility CPU.
 *   - ensure that utility threads are pushed off lwkcpus when expected.
 *   - ensure that worker threads are not overcommitted on lwkcpus.
 *
 * @param[in] arg specifies the thread number ([1,...,N]).
 * @return The overall status of this thread.
 */

static void *worker(void *arg)
{
	unsigned long long i, tid, check_cpu;
	char buffer[4096];
	long int rc = 0;

	tid = (unsigned long)arg;
	work_area[tid].my_cpu = sched_getcpu();

	log_msg(LOG_DEBUG,
		CPUFMT
		" Worker thread spawned. Spin=%llX wrk=%p cpu=%d affinity=%s",
		tid, spin_amount, &work_area[tid].data, work_area[tid].my_cpu,
		get_affinity(buffer, sizeof(buffer)));

	rc = register_pthread(tid, work_area[tid].my_cpu);

	if (tid <= n_util_threads) {
		pthread_mutex_lock(&utils_registered_lock);
		if (++utils_registered == n_util_threads)
			pthread_cond_broadcast(&utils_registered_cv);
		pthread_mutex_unlock(&utils_registered_lock);
	}

	if (rc) {
		log_msg(LOG_ERR, "Thread registration failed.");
		rc = -1;
		goto out;
	}
	check_cpu = spin_amount >> 8;
	for (i = 0; (i < spin_amount) || (registered < n_threads); i++) {

		work_area[tid].data = i;
		if (--check_cpu == 0) {

			int cpu_now = sched_getcpu();

			check_cpu = spin_amount >> 8;
			/*
			 * If a thread has unexpectedly moved to a new CPU
			 * log the error. A non-utility thread on an LWK CPU
			 * should never move. A utility thread should not move
			 * if there are enough lwkcpus to host all of the
			 * threads. We could also validate utility thread
			 * movement however this test is not necessary because
			 * if it did not move, the registration test to detect
			 * an overcommitted LWKCPU will fire and log the error.
			 */
			if (cpu_now != work_area[tid].my_cpu) {
				int cpu_old;
				int policy;

				if ((tid > n_util_threads) ||
				    ((tid <= n_util_threads) &&
				     (n_threads < n_lwkcpus))) {
					if ((one_cpu_per_util_thread) ||
					    (!CPU_ISSET_S(work_area[tid].my_cpu,
							setsize,
							lwkcpus_util_shared) ||
					    !CPU_ISSET_S(cpu_now, setsize,
							lwkcpus_util_shared))) {
						log_msg(LOG_ERR,
						    CPUFMT
						    " CPU violation: was %d but expected %d.",
						    tid, cpu_now,
						    work_area[tid].my_cpu);
						rc--;
						goto out;
					}
				}
				/* Test we moved to a utility CPU */
				if (!CPU_ISSET_S(cpu_now, setsize,
						 lwkcpus_util_shared)) {
					log_msg(LOG_ERR, CPUFMT
						" CPU migration violation: target %d (PID=%d) is not a utility CPU.",
						tid, syscall(SYS_gettid),
						cpu_now);
					rc--;
					goto out;
				}
				/*
				 * If we are a utility thread, test that we are
				 * now using the Linux scheduling policy
				 */
				if (tid <= n_util_threads) {
					policy = get_scheduler_policy();

					if (policy != SCHED_OTHER) {
						log_msg(LOG_ERR,
							"Utility thread (PID=%d) on utility CPU %d and not Linux policy (%d)\n",
							syscall(SYS_gettid), cpu_now, policy);
						rc--;
						goto out;
					}
				}
				/* CPU changed. Update registry and data */
				cpu_old = work_area[tid].my_cpu;
				pthread_mutex_lock(&lock);
				CPU_CLR_S(work_area[tid].my_cpu,
						setsize, util_threads);
				CPU_SET_S(cpu_now, setsize, util_threads);
				work_area[tid].my_cpu = cpu_now;
				if (CPU_ISSET_S(cpu_old, setsize, lwkcpus)) {
					++pushed_utilities;
				} else if (!one_cpu_per_util_thread) {
					log_msg(LOG_INFO, CPUFMT
						" Linux scheduler moved thread from CPU %d to %d (allowed)",
						tid, cpu_old, cpu_now);

				}  else {
					log_msg(LOG_ERR, CPUFMT
					    " Linux scheduler moved thread from CPU %d to %d",
					    tid, cpu_old, cpu_now);
					rc--;
					pthread_mutex_unlock(&lock);
					goto out;
				}
				pthread_mutex_unlock(&lock);
				log_msg(LOG_INFO, CPUFMT
					" Allowed thread move from CPU %d to %d",
					tid, cpu_old, cpu_now);
			}
			sched_yield();
		}
	}
 out:
	log_msg(LOG_DEBUG,
		CPUFMT " Worker thread complete. cpu=%d rc=%ld finished=%d",
		tid, sched_getcpu(), rc, threads_finished+1);

	pthread_mutex_lock(&count_lock);
	threads_finished++;
	if (threads_finished == n_threads) {
		log_msg(LOG_DEBUG, CPUFMT " All threads finished.", tid);
		pthread_cond_broadcast(&count_cv);
	}
	pthread_mutex_unlock(&count_lock);

	pthread_mutex_lock(&count_lock);
	while (threads_finished < n_threads) {
		log_msg(LOG_DEBUG, CPUFMT " Waiting.", tid);
		pthread_cond_wait(&count_cv, &count_lock);
	}
	pthread_mutex_unlock(&count_lock);

	return (void *)rc;
}

int main(int argc, char **argv)
{
	int rc = 0;
	unsigned int i = 0;
	int expected_pushes = 0;
	pthread_t threads[MAX_THREADS];

	struct option options[] = {
		/* Total number of pthreads to be created */
		{ "threads", required_argument, 0, 't' },
		/* Number of lwkcpus available to this process */
		{ "lwkcpus", required_argument, 0, 'c' },
		/* spin amount for worker threads */
		{ "spin", required_argument, 0, 's' },
		/* Number of utility threads. Same value provided to YOD */
		{ "uthreads", required_argument, 0, 'u' },
		/* Max LWK CPUs for utility threads. Same provided to YOD */
		{ "maxutilcpus", required_argument, 0, 'x' },
		/* Max util threads per LWK CPUs. Same value provided to YOD */
		{ "maxutilspercpu", required_argument, 0, 'y' },
		/* Enable additional debug output */
		{ "one_cpu_per_util", no_argument, 0, 'm' },
		/* Enable additional debug output */
		{ "debug", no_argument, 0, 'd' },
		{ "help", no_argument, 0, 'h' },
	};

	struct {
		cpu_set_t **set;
		const char *path;
	} sets[] = {
		{ .set = &lwkcpus,
		  .path = "/sys/kernel/mOS/lwkcpus_mask" },
		{ .set = &lwkcpus_util_combined,
		  .path = "/sys/kernel/mOS/utility_cpus_mask" },
		{ .set = &lwkcpus_reserved,
		  .path = "/sys/kernel/mOS/lwkcpus_reserved_mask" },
		{ .set = &lwkcpus_util_shared,
		  .path = "/sys/kernel/mOS/utility_cpus_mask" },
		{ .set = &compute_threads,
		  .path = 0 },
		{ .set = &linuxcpus,
		  .path = 0 },
		{ .set = &util_threads,
		  .path = 0 },
		{ .set = &temp_cpumask,
		  .path = 0 },
	};

	setlocale(LC_ALL, "");

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "t:c:s:u:x:y:mdh", options,
				&opt_index);

		if (c == -1)
			break;

		switch (c) {
		case 't':
			n_threads = atoi(optarg);
			break;
		case 's':
			spin_amount = 1ull << atoi(optarg);
			break;
		case 'c':
			n_lwkcpus = atoi(optarg);
			break;
		case 'u':
			n_util_threads = atoi(optarg);
			break;
		case 'x':
			max_util_cpus = atoi(optarg);
			break;
		case 'y':
			max_utils_per_cpu = atoi(optarg);
			break;
		case 'm':
			one_cpu_per_util_thread = 1;
			break;
		case 'd':
			logging_level++;
			break;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return -1;
		}
	}

	if (optind != argc) {
		usage();
		return -1;
	}

	assert(n_threads <= MAX_THREADS);

	/*
	 * Establish the CPU sets.
	 */
	setsize = CPU_ALLOC_SIZE(MAX_CPUS);

	for (i = 0; i < ARRAY_SIZE(sets); i++) {

		*sets[i].set = CPU_ALLOC(MAX_CPUS);
		assert(*sets[i].set);
		CPU_ZERO_S(setsize, *sets[i].set);

		if (sets[i].path) {
			if (parse_mos_mask(*sets[i].set,
					   setsize,
					   sets[i].path)) {
				log_msg(LOG_ERR, "Error parsing CPU set.");
				rc = -1;
				goto out;
			}
		}
	}
	for (i = 0; i < MAX_CPUS; i++) {
		if (!CPU_ISSET_S(i, setsize, lwkcpus))
			CPU_SET_S(i, setsize, linuxcpus);
		else
			CPU_SET_S(i, setsize, lwkcpus_util_combined);
	}

	/*
	 * Spawn the pthreads and then wait for them to finish.
	 * Accumulate overall status.
	 */

	log_msg(LOG_INFO, CPUFMT " Spawning %d worker threads", 0, n_threads);

	for (i = 0; i < n_threads; i++) {
		if (pthread_create(threads + i, 0, worker,
				   (void *)((unsigned long)(i + 1))))
			log_msg(LOG_FATAL,
				"Could not spawn: %s", strerror(errno));
		if (n_util_threads == (i + 1))
			/*
			 * Wait for all utility threads to register before
			 * proceeding since we want to register them on
			 * their initial CPUs before they are potentially
			 * pushed by worker threads.
			 */
			pthread_cond_wait(&utils_registered_cv,
					&utils_registered_lock);
	}

	for (i = 0; i < n_threads; i++) {
		void *retval = 0;

		pthread_join(threads[i], &retval);
		if (retval != 0) {
			log_msg(LOG_WARN,
				CPUFMT " Non-zero return (%p) from thread %d",
				0, retval, i);
			rc--;
		}
	}
	/* Did the expected number of utility threads get pushed */
	if ((n_threads + 1 < n_lwkcpus) || (n_util_threads == 0) ||
	    (max_util_cpus == 0) || !CPU_COUNT_S(setsize, lwkcpus_util_shared))
		expected_pushes = 0;
	else
		expected_pushes = MIN((n_threads + 1 - n_lwkcpus),
				      n_util_threads);


	if (expected_pushes != pushed_utilities) {
		log_msg(LOG_ERR,
			"Expected pushed threads=%d Actual pushed threads=%d",
			expected_pushes, pushed_utilities);
		rc--;
	}
 out:
	 log_msg(LOG_DEBUG,
		 "Expected pushed threads=%d Actual pushed threads=%d",
		 expected_pushes, pushed_utilities);

	if (rc)
		log_msg(LOG_ERR, "Test failed.");

	return rc;
}


static void usage(void)
{
	printf(
	"thread_placement [--lwkcpus <N>] [--threads <N>] [--uthreads <N>] "
	"[--spin <N>] [--maxutilcpus <N> [--maxutilspercpu <N>] [--debug].. "
	"[--help]\n"
	);
}


static int register_pthread(unsigned int tid, int cpu)
{
	int rc = 0;
	cpu_set_t *mos_set, *registry;
	const char *pthread_type;

	log_msg(LOG_GORY_DETAIL, "(>) %s tid=%d cpu=%d",
		__func__, tid, cpu);

	if (pthread_mutex_lock(&lock)) {
		log_msg(LOG_ERR, "Lock acquisition failed.");
		rc = -1;
		goto out;
	}

	if (tid <= n_util_threads) {
		mos_set = lwkcpus_util_combined;
		registry = util_threads;
		pthread_type = "utility";
	} else {
		mos_set = lwkcpus_reserved;
		registry = compute_threads;
		pthread_type = "compute";
	}

	log_msg(LOG_DEBUG, "(*) %s Thread %d is a %s thread.",
		__func__, tid, pthread_type);


	if (!CPU_ISSET_S(cpu, setsize, mos_set)) {
		log_msg(LOG_ERR, "CPU %d is not an mOS %s CPU.",
			cpu, pthread_type);
		rc--;
	}

	/*
	 * Determine if overcommitment is not expected.
	 * Any threads considered utility threads should be
	 * pushed to the utility CPUs before overcommitment
	 * occurs. The only allowed condition for overcommmitment
	 * of two compute threads is when the number of compute
	 * threads exceeds the number of LWK CPUs.
	 */
	if ((CPU_ISSET_S(cpu, setsize, lwkcpus)) &&
	    (CPU_ISSET_S(cpu, setsize, util_threads)) &&
	    (max_utils_per_cpu == 1) &&
	    (CPU_COUNT_S(setsize, lwkcpus_util_shared))) {
		log_msg(LOG_ERR,
			"Utility thread (PID=%d) on CPU %d is being over-committed with a %s thread.",
			syscall(SYS_gettid), cpu, pthread_type);
		rc--;
	}

	if ((CPU_ISSET_S(cpu, setsize, compute_threads)) &&
	    ((n_threads - n_util_threads) <= n_lwkcpus) &&
	    (CPU_COUNT_S(setsize, lwkcpus_util_shared))) {
		log_msg(LOG_ERR,
			"Compute thread (PID=%d) on CPU %d is being over-committed with a %s thread.",
			syscall(SYS_gettid), cpu, pthread_type);
		rc--;
	}

	/*
	 * Determine if expected overcommitment has occurred. If the max number
	 * of util cpus is set and more utility threads are created than that
	 * max number, then utility threads should be overcommitted on these
	 * utility CPUs.
	 */
	if ((max_util_cpus > 0) && /* fixed max number of lwk utility cPUs */
	    (max_utils_per_cpu > 1) && /* allowing overcommit of utils */
	    (CPU_ISSET_S(cpu, setsize, util_threads)) && /* this is a utility thread*/
	    ((int)tid > max_util_cpus) && /* more util threads than util CPUs */
	    !(CPU_ISSET_S(cpu, setsize, lwkcpus))) { /* Not being overcommitted on an LWK CPU*/
		log_msg(LOG_ERR,
			"Expected utility thread overcommitment on CPU %d with a %s thread did not occur.",
			cpu, pthread_type);
		rc--;
	}


	/*
	 * Verify that the utility registry does not have any more LWK CPUs registered
	 * than the maximum allowed number of utility CPUs.
	 */
	CPU_AND_S(setsize, temp_cpumask, lwkcpus, util_threads);
	if ((max_util_cpus >= 0) &&
	    (CPU_COUNT_S(setsize, temp_cpumask) > max_util_cpus) &&
	    (CPU_COUNT_S(setsize, lwkcpus_util_shared))) {
		log_msg(LOG_ERR,
			"Utility threads occupying=%d CPUs. Max number of Utility CPUs allowed=%d.",
			CPU_COUNT_S(setsize, temp_cpumask), max_util_cpus);
			rc--;
	}
	/*
	 * Verify that a utility thread running on an LWK CPU has
	 * the LWK scheduling policy and a utility thread running on a
	 * Syscall target CPU has the Linux Fair scheduling policy.
	 */

	if (tid <= n_util_threads) {
		int policy = get_scheduler_policy();

		if (CPU_ISSET_S(cpu, setsize, lwkcpus) &&
		    (policy != SCHED_FIFO) &&
		    (policy != SCHED_RR)) {
			log_msg(LOG_ERR,
				"Utility (PID=%d) on an LWK CPU not using mOS Scheduling.  Policy=%d\n",
				syscall(SYS_gettid), policy);
			rc--;
		} else if (CPU_ISSET_S(cpu, setsize, lwkcpus_util_shared) &&
			  (policy != SCHED_OTHER)) {
			log_msg(LOG_ERR,
				"Utility (PID=%d) on Syscall CPU not using Linux scheduling.  Policy=%d\n",
				syscall(SYS_gettid), policy);
			rc--;
		} else if (!CPU_ISSET_S(cpu, setsize, lwkcpus) &&
			  !CPU_ISSET_S(cpu, setsize, lwkcpus_util_shared)) {
			log_msg(LOG_ERR,
			       "Utility thread (PID=%d) not on an LWK or a utility CPU (%d).\n",
			       syscall(SYS_gettid), cpu);
			rc--;
		}
	}
	CPU_SET_S(cpu, setsize, registry);
	++registered;

	if (pthread_mutex_unlock(&lock))
		log_msg(LOG_ERR, "Could not unlock mutex from tid=%d", tid);
 out:
	log_msg(LOG_GORY_DETAIL, "(<) %s tid=%d cpu=%d rc=%d",
		__func__, tid, cpu, rc);

	return rc;
}
