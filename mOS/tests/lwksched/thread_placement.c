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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <getopt.h>
#include <locale.h>
#include "lwksched.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static unsigned int n_threads, n_lwkcpus, n_util_threads;
static unsigned long long spin_amount = 1ull << 30;
static size_t setsize;
static cpu_set_t *lwkcpus, *lwkcpus_reserved, *linuxcpus;
static cpu_set_t *lwkcpus_util_combined, *lwkcpus_util_shared;
static cpu_set_t *compute_threads, *util_threads;
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

/**
 * The worker function for each spawned pthread.  It does the following:
 *
 *   - ensure that the thread lands on an appropriate CPU.
 *   - ensure that the thread stays on the same CPU for the duration of
 *     the run unless it is a utility thread being pushed to a shared CPU.
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

	log_msg(LOG_INFO,
		CPUFMT
		" Worker thread spawned. Spin=%llX wrk=%p cpu=%d affinity=%s",
		tid, spin_amount, &work_area[tid].data, work_area[tid].my_cpu,
		get_affinity(buffer, sizeof(buffer)));

	if (register_pthread(tid, work_area[tid].my_cpu)) {
		log_msg(LOG_ERR, "Thread registration failed.");
		rc = -1;
		goto out;
	}
	if (tid <= n_util_threads) {
		pthread_mutex_lock(&utils_registered_lock);
		if (++utils_registered == n_util_threads)
			pthread_cond_broadcast(&utils_registered_cv);
		pthread_mutex_unlock(&utils_registered_lock);
	}
	check_cpu = spin_amount >> 8;
	for (i = 0; (i < spin_amount) || (registered < n_threads); i++) {

		work_area[tid].data = i;
		if (--check_cpu == 0) {

			int cpu_now = sched_getcpu();

			check_cpu = spin_amount >> 8;
			/*
			 * If a thread has unexpectedly moved to a new CPU
			 * log the error. A non-utility thread should never
			 * move. A utility thread should not move if there are
			 * enough lwkcpus to host all of the threads.
			 * We could also validate utility thread movement
			 * however this test is not necessary because
			 * if it did not move, the registration test to detect
			 * an overcommitted LWKCPU will fire and log the error.
			 */
			if (cpu_now != work_area[tid].my_cpu) {
				int cpu_old;

				if ((tid > n_util_threads) ||
				    ((tid <= n_util_threads) &&
				     (n_threads < n_lwkcpus))) {
					log_msg(LOG_ERR,
						CPUFMT
						" CPU violation: was %d but expected %d.",
						tid, cpu_now,
						work_area[tid].my_cpu);
					rc--;
					goto out;
				}
				/* Test we moved to a shared utility CPU */
				if (!CPU_ISSET_S(cpu_now, setsize,
						 lwkcpus_util_shared)) {
					log_msg(LOG_ERR, CPUFMT
						" CPU migration violation: target %d is not a shared utility CPU.",
						tid, cpu_now);
					rc--;
					goto out;
				}
				/* CPU changed. Update registry and data */
				cpu_old = work_area[tid].my_cpu;
				pthread_mutex_lock(&lock);
				CPU_CLR_S(work_area[tid].my_cpu,
						setsize, util_threads);
				CPU_SET_S(cpu_now, setsize, util_threads);
				work_area[tid].my_cpu = cpu_now;
				++pushed_utilities;
				pthread_mutex_unlock(&lock);
				log_msg(LOG_INFO, CPUFMT
					" Allowed thread move from CPU %d to %d",
					tid, cpu_old, cpu_now);
			}
			sched_yield();
		}
	}
 out:
	log_msg(LOG_INFO,
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
	int expected_pushes;
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
		  .path = "/sys/kernel/mOS/lwkcpus_syscall_mask" },
		{ .set = &lwkcpus_reserved,
		  .path = "/sys/kernel/mOS/lwkcpus_reserved_mask" },
		{ .set = &lwkcpus_util_shared,
		  .path = "/sys/kernel/mOS/lwkcpus_syscall_mask" },
		{ .set = &compute_threads,
		  .path = 0 },
		{ .set = &linuxcpus,
		  .path = 0 },
		{ .set = &util_threads,
		  .path = 0 },
	};

	setlocale(LC_ALL, "");

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "t:c:s:u:dh", options, &opt_index);

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
			 * their initial CPUs before the are potentially
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
	if ((n_threads + 1 < n_lwkcpus) || (n_util_threads == 0))
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
	if (rc)
		log_msg(LOG_ERR, "Test failed.");

	return rc;
}


static void usage(void)
{
	printf(
	"thread_placement [--lwkcpus <N>] [--threads <N>] [--uthreads <N>] [--spin <N>] [--debug].. [--help]\n"
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

	/* Determine if overcommitment is expected.
	 * Any threads considered utility threads should be
	 * pushed to the shared Linux CPUs before overcommitment
	 * occurs. The only allowed condition for overcommmitment
	 * of two compute threads is when the number of compute
	 * threads exceeds the number of LWK CPUs.
	 */
	if ((CPU_ISSET_S(cpu, setsize, lwkcpus)) &&
	    (CPU_ISSET_S(cpu, setsize, util_threads))) {
		log_msg(LOG_ERR,
			"Utility thread on CPU %d is being over-committed with a %s thread.",
			cpu, pthread_type);
		rc--;
	}

	if ((CPU_ISSET_S(cpu, setsize, compute_threads)) &&
	    ((n_threads - n_util_threads) <= n_lwkcpus)) {
		log_msg(LOG_ERR,
			"Compute thread on CPU %d is being over-committed with a %s thread.",
			cpu, pthread_type);
		rc--;
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
