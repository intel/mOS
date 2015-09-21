/*
 * Multi Operating System (mOS)
 * Copyright (c) 2017, Intel Corporation.
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
#include <stdio.h>
#include <sched.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <getopt.h>
#include <locale.h>
#include <pthread.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include "lwksched.h"

#define MAXCOMPUTES MAX_CPUS
#define CPUTYPE_LWK 1
#define CPUTYPE_FWK 2
#define NOT_ENABLED (-1)
#define CPUSHARE_TEST_ENABLE 1

struct thread_parms {
	int cindex;
	int index_start;
	int index_end;
};

static void usage(void);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t workload_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t workload_cv = PTHREAD_COND_INITIALIZER;
static int workload_start;
static pthread_mutex_t workload_done_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t workload_done_cv = PTHREAD_COND_INITIALIZER;
static int workload_done;
static pthread_mutex_t finished_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t finished_cv = PTHREAD_COND_INITIALIZER;
static int cthreads_workload_start;
static int cthreads_workload_done;
static int cthreads_finished;
static pthread_mutex_t driver_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t drivers_ready_cv = PTHREAD_COND_INITIALIZER;
static int drivers_ready;
static int numtests;
static int numcomputes_created;
static int numfails;
static int num_initial_overcommits;
static int thread_balance_moves;
static int numsuccess;
static int num_cthreads;
static size_t setsize;
static cpu_set_t *lwkcpus;

static struct {
	pthread_t pthread;
	pthread_attr_t pthread_attr;
	struct thread_parms pthread_arg;
	int api_retval_expected;
	int api_retval_actual;
	long int cputype_expected;
	long int cputype_actual;
	int created;
	int enable_compute_cpu_share_test;
	int share_level_computes;
	int my_initial_cpu;
	int my_pre_workload_cpu;
	int my_final_cpu;
	int workload_result;
} cthread[MAXCOMPUTES];

static int num_lwkcpus;
static int initial_compute_thread_count[MAX_CPUS];
static int pre_workload_compute_thread_count[MAX_CPUS];
static int final_compute_thread_count[MAX_CPUS];

long var1;
long var2;

/* Return nanosecond difference in two timespecs */
static long timespec_diff(struct timespec *start, struct timespec *end)
{
	long start_nanosecs = start->tv_sec * 1000000000 + start->tv_nsec;
	long end_nanosecs = end->tv_sec * 1000000000 + end->tv_nsec;

	return (end_nanosecs - start_nanosecs);
}

static int workload(int usecs)
{
	int i;
	struct timespec start;
	struct timespec current;

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start))
		return errno;
	current = start;
	while (timespec_diff(&start, &current) < (usecs * 1000)) {
		for (i = 0; i < 10000; i++)
			var1 = var1 * var2 + var2;
		if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &current))
			return errno;
	}
	return 0;
}

static void init_cthreads(void)
{
	int i;

	numcomputes_created = 0;
	cthreads_workload_start = 0;
	cthreads_workload_done = 0;
	cthreads_finished = 0;
	drivers_ready = 0;
	thread_balance_moves = 0;
	for (i = 0; i < MAXCOMPUTES; i++) {
		pthread_attr_init(&(cthread[i].pthread_attr));
		cthread[i].pthread_arg.cindex = 0;
		cthread[i].pthread_arg.index_start = 0;
		cthread[i].pthread_arg.index_end = 0;
		cthread[i].api_retval_expected = 0;
		cthread[i].api_retval_actual = 0;
		cthread[i].cputype_expected = 0;
		cthread[i].cputype_actual = 0;
		cthread[i].created = 0;
		cthread[i].enable_compute_cpu_share_test = 0;
		cthread[i].share_level_computes = 0;
		cthread[i].my_initial_cpu = 0;
		cthread[i].my_final_cpu = 0;
		cthread[i].workload_result = 0;
	}
	for (i = 0; i < MAX_CPUS; i++) {
		initial_compute_thread_count[i] = 0;
		final_compute_thread_count[i] = 0;
	}
}

static int api_failure(void)
{
	int i;
	int numfails = 0;

	for (i = 0; i < num_cthreads; i++) {
		if (cthread[i].api_retval_actual !=
				cthread[i].api_retval_expected) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d cthread=%d detected api return code failure. Actual/Expected=%d/%d",
				numtests, i, cthread[i].api_retval_actual,
				cthread[i].api_retval_expected);
		}
	}
	return numfails;
}

static int cputype_failure(void)
{
	int i;
	int numfails = 0;

	for (i = 0; i < num_cthreads; i++) {
		if (cthread[i].cputype_actual !=
				cthread[i].cputype_expected) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d cthread=%d detected cpu type failure. Actual/Expected=%d/%d",
				numtests, i, cthread[i].cputype_actual,
				cthread[i].cputype_expected);
		}
	}
	return numfails;
}

static int cpushare_pre_workload_failure(void)
{
	int i;
	int numfails = 0;

	for (i = 0; i < num_cthreads; i++) {
		int cpu;

		if (!cthread[i].enable_compute_cpu_share_test)
			return 0;
		cpu = cthread[i].my_pre_workload_cpu;
		if (pre_workload_compute_thread_count[cpu] !=
		    cthread[i].share_level_computes) {
			numfails++;
			log_msg(LOG_ERR,
			  "Test=%d cthread=%d detected pre-workload cpu=%d share failure with a compute thread. Actual=%d Expected=%d",
			  numtests, i, cpu,
			  pre_workload_compute_thread_count[cpu],
			  cthread[i].share_level_computes);
		}
	}
	return numfails;
}

static int cpushare_post_workload_failure(void)
{
	int i;
	int numfails = 0;

	for (i = 0; i < num_cthreads; i++) {
		int final_cpu;
		int pre_cpu;

		if (!cthread[i].enable_compute_cpu_share_test)
			return 0;
		final_cpu = cthread[i].my_final_cpu;
		pre_cpu = cthread[i].my_pre_workload_cpu;
		if (final_compute_thread_count[final_cpu] !=
		    cthread[i].share_level_computes) {
			numfails++;
			log_msg(LOG_ERR,
			  "Test=%d cthread=%d detected final cpu=%d share failure with a compute thread. Actual=%d Expected=%d",
			  numtests, i, final_cpu,
			  final_compute_thread_count[final_cpu],
			  cthread[i].share_level_computes);
		} else if (final_cpu != pre_cpu) {
			log_msg(LOG_ERR,
			  "Test=%d cthread=%d moved from CPU=%d to CPU=%d during workload",
			  numtests, i, pre_cpu,
			  final_cpu);
		}
	}
	return numfails;
}

static int cpushare_initial_overcommits(void)
{
	int i;
	int initial_overcommits = 0;

	for (i = 0; i < num_cthreads; i++) {
		int initial_cpu;

		if (!cthread[i].enable_compute_cpu_share_test)
			return 0;
		initial_cpu = cthread[i].my_initial_cpu;
		if (initial_compute_thread_count[initial_cpu] !=
		    cthread[i].share_level_computes) {
			initial_overcommits++;
			log_msg(LOG_DEBUG,
			"Test=%d cthread=%d detected initial cpu=%d share with a compute thread. Actual=%d Desired=%d",
			numtests, i, initial_cpu,
			initial_compute_thread_count[initial_cpu],
			cthread[i].share_level_computes);
		}
	}
	return initial_overcommits;
}

static int workload_failure(void)
{
	int i;
	int numfails = 0;

	for (i = 0; i < num_cthreads; i++) {
		if (cthread[i].workload_result) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d cthread=%d detected workload failure. errno=%d",
				numtests, i, cthread[i].workload_result);
		}
	}
	return numfails;
}

static void end_test(int expected_computes)
{
	int num_thread_fails;
	int cindex;
	void *retval;

	log_msg(LOG_DEBUG, "max cpus=%d", MAX_CPUS);

	for (cindex = 0; cindex < num_cthreads; cindex++) {
		if (cthread[cindex].created) {
			/* Created threads should reach pthread_join */
			pthread_join(cthread[cindex].pthread, &retval);
			cthread[cindex].cputype_actual = (long int)retval;
		}
	}

	num_initial_overcommits = cpushare_initial_overcommits();
	if (num_initial_overcommits) {
		log_msg(LOG_INFO,
			"Test=%d  Due to concurrent clone syscalls within one process,",
			numtests, num_initial_overcommits);
		log_msg(LOG_INFO,
			"        %d threads were not initially assigned to their own CPU.",
			num_initial_overcommits);
		log_msg(LOG_INFO,
			"        The kernel moved %d threads to fix the imbalance.",
			thread_balance_moves);
	}
	if (numcomputes_created != expected_computes) {
		log_msg(LOG_ERR,
		    "Test=%d failed. Expected/actual cthreads=%d/%d",
		    numtests, expected_computes, numcomputes_created);
	  numfails += 1;

	} else if ((num_thread_fails = api_failure())) {
		log_msg(LOG_ERR,
			"Test=%d API return code for %d threads.",
			numtests, num_thread_fails);
	} else if ((num_thread_fails = cputype_failure())) {
		log_msg(LOG_ERR,
			"Test=%d cpu type failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else if ((num_thread_fails = cpushare_pre_workload_failure())) {
		log_msg(LOG_ERR,
			"Test=%d pre-workload CPU sharing failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else if ((num_thread_fails = cpushare_post_workload_failure())) {
		log_msg(LOG_ERR,
			"Test=%d post-workload CPU sharing failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else if ((num_thread_fails = workload_failure())) {
		log_msg(LOG_ERR,
			"Test=%d executing the workload failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else {
		log_msg(LOG_INFO,
			"Test=%d passed.\n", numtests);
		numsuccess += 1;
	}
	/* Reset the state of the condition variables */
	pthread_cond_destroy(&drivers_ready_cv);
	pthread_cond_destroy(&workload_cv);
	pthread_cond_destroy(&workload_done_cv);
	pthread_cond_destroy(&finished_cv);
}

static int summarize(void)
{
	log_msg(LOG_INFO, "Tests run: %d Successes: %d Failures: %d",
		numtests, numsuccess, numfails);
	if (numfails || (numtests != (numsuccess + numfails)))
		return -1;
	return 0;
}

static void record_pthread_api_results(int cindex)
{
	if (!cthread[cindex].api_retval_actual)
		cthread[cindex].created = 1;
}

static void *compute_thread(void *arg)
{
	struct thread_parms *myparms = (struct thread_parms *)arg;
	long rc = 0;
	int my_initial_cpu = sched_getcpu();
	int threads_finished;
	int driver_threads_ready;
	long cindex;
	int my_cindex = myparms->cindex;
	int my_pre_workload_cpu;
	int my_final_cpu;

	/*
	 * Indicate that this thread has been created
	 */
	cthread[my_cindex].my_initial_cpu = my_initial_cpu;
	pthread_mutex_lock(&lock);
	numcomputes_created++;
	++initial_compute_thread_count[my_initial_cpu];
	pthread_mutex_unlock(&lock);

	/* Are we a driver thread */
	if (my_cindex < 2) {
		/*
		 * Wait until driver threads are ready to begin. We want
		 * the to start creating pthreads concurrently.
		 */
		pthread_mutex_lock(&driver_lock);
		driver_threads_ready = ++drivers_ready;
		if (driver_threads_ready == 2) {
			log_msg(LOG_DEBUG, "Driver pthreads ready to start.");
			pthread_cond_broadcast(&drivers_ready_cv);
		}
		pthread_mutex_unlock(&driver_lock);

		pthread_mutex_lock(&driver_lock);
		while (drivers_ready < 2)
			pthread_cond_wait(&drivers_ready_cv, &driver_lock);
		pthread_mutex_unlock(&driver_lock);

		/*
		 * Create additional compute threads
		 */
		log_msg(LOG_DEBUG,
		    "Driver index=%d preparing to create start_index=%d end_index=%d",
		    myparms->cindex, myparms->index_start, myparms->index_end);


		for (cindex = myparms->index_start;
		      cindex < myparms->index_end;
		      cindex++) {
			/* Set test expectations for each compute thread */
			cthread[cindex].enable_compute_cpu_share_test = 1;
			cthread[cindex].share_level_computes = 1;
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;
			cthread[cindex].pthread_arg.cindex = cindex;
			cthread[cindex].pthread_arg.index_start = 0;
			cthread[cindex].pthread_arg.index_end = 0;

			/* create a commpute thread */
			log_msg(LOG_DEBUG,
			    "pthread_create from cindex=%d to cindex=%d",
			    my_cindex, cindex);
			cthread[cindex].api_retval_actual = pthread_create(
			    &(cthread[cindex].pthread),
			    &(cthread[cindex].pthread_attr),
			    compute_thread,
			    (void *)&cthread[cindex].pthread_arg);
			/* Record the API result */
			record_pthread_api_results(cindex);
		}
	}
	/*
	 * Do not allow the thread  to enter its workload loop until
	 * all driver and compute threads are ready to start
	 */
	pthread_mutex_lock(&workload_lock);
	workload_start = ++cthreads_workload_start;
	if (workload_start == num_cthreads) {
		log_msg(LOG_DEBUG, "workloads can now start.");
		pthread_cond_broadcast(&workload_cv);
	}
	pthread_mutex_unlock(&workload_lock);

	pthread_mutex_lock(&workload_lock);
	while (cthreads_workload_start < num_cthreads)
		pthread_cond_wait(&workload_cv, &workload_lock);
	pthread_mutex_unlock(&workload_lock);

	my_pre_workload_cpu = sched_getcpu();
	cthread[my_cindex].my_pre_workload_cpu = my_pre_workload_cpu;
	pthread_mutex_lock(&lock);
	++pre_workload_compute_thread_count[my_pre_workload_cpu];
	if (my_pre_workload_cpu != my_initial_cpu)
		thread_balance_moves++;
	pthread_mutex_unlock(&lock);
	if (my_pre_workload_cpu != my_initial_cpu) {
		log_msg(LOG_DEBUG,
		    "Balancing occurred... cindex=%ld moved from cpu=%d to cpu=%d",
		    my_cindex, my_initial_cpu, my_pre_workload_cpu);
	}
	/* Burn cycles running a simulated workload */
	cthread[my_cindex].workload_result = workload(1000); /* 1000 usecs */

	/* Wait until all workloads are completed */
	pthread_mutex_lock(&workload_done_lock);
	workload_done = ++cthreads_workload_done;
	if (workload_done ==  num_cthreads) {
		log_msg(LOG_DEBUG, "All threads completed the workload.");
		pthread_cond_broadcast(&workload_done_cv);
	}
	pthread_mutex_unlock(&workload_done_lock);

	pthread_mutex_lock(&workload_done_lock);
	while (cthreads_workload_done < num_cthreads)
		pthread_cond_wait(&workload_done_cv, &workload_done_lock);
	pthread_mutex_unlock(&workload_done_lock);

	/* See if we are still balanced across all the CPUs */
	my_final_cpu = sched_getcpu();
	cthread[my_cindex].my_final_cpu = my_final_cpu;
	pthread_mutex_lock(&lock);
	++final_compute_thread_count[my_final_cpu];
	pthread_mutex_unlock(&lock);

	/*
	 * Do not allow this thread to exit until all
	 * driver and compute threads are done
	 */
	pthread_mutex_lock(&finished_lock);
	threads_finished = ++cthreads_finished;
	if (threads_finished == num_cthreads) {
		log_msg(LOG_DEBUG, "All threads finished.");
		pthread_cond_broadcast(&finished_cv);
	}
	pthread_mutex_unlock(&finished_lock);

	pthread_mutex_lock(&finished_lock);
	while (cthreads_finished < num_cthreads)
		pthread_cond_wait(&finished_cv, &finished_lock);
	pthread_mutex_unlock(&finished_lock);

	if (CPU_ISSET_S(my_initial_cpu, setsize, lwkcpus))
		rc = CPUTYPE_LWK;
	else
		rc = CPUTYPE_FWK;

	return (void *)rc;
}

/*****************************************************************************
 * In many threaded HPC applications, pthread creations do not
 * occur concurrently within a process. It is likely that multiple
 * threads are concurrently being created across the node in multiple
 * processes/ranks however since YOD assigns CPUs to individual
 * processes, the mOS kernel does not need to worry about CPU
 * assignment collisions across processes. The mOS kernel is optimized for
 * the HPC environment and the CPU-to-process isolation and therefore does
 * not impose locking overhead when selecting a CPU to use. Also due to
 * the integration with the Linux scheduler, the necessary locking would
 * likely introduce a degradation in overall performance, effecting not
 * just clone flows but also general wakeup and dispatch flows. This means
 * that optimal CPU assignment may not initially occur if multiple threads
 * within a process are creating threads at the same time. The mOS kernel
 * has mechanisms to recover from imbalances if they should occur. At
 * thread wake-up, the kernel will re-evaluate the current CPU assignment
 * and may assign the thread to a new CPU home if it is currently
 * overcommitted and a free uncommitted CPU is available.
 *
 * This test has two threads creating pthreads concurrently within one
 * process to fill up all available CPUs in the node. It will stress the
 * intra-process CPU assignment code within the mOS kernel. It will detect
 * if it has caused the expected sub-optimal initial CPU assignment and
 * then it will verify that the mOS kernel re-balance actions occur to
 * cause the threads to be each running on its own CPU prior to the
 * threads entering their workload phase.
 ******************************************************************************
 */
int main(int argc, char **argv)
{
	long int rc;
	int i;
	cpu_set_t *cpuset_temp;
	int my_initial_cpu = sched_getcpu();
	int my_final_cpu;

	struct option options[] = {
		{ "debug", no_argument, 0, 'd' },
		{ "help", no_argument, 0, 'h' },
	};

	struct {
		cpu_set_t **set;
		const char *path;
		int required;
	} sets[] = {
		{ .set = &lwkcpus,
		  .path = "/sys/kernel/mOS/lwkcpus_mask",
		  .required = 1 },
		{ .set = &cpuset_temp,
		  .path = 0,
		  .required = 1	},
	};

	setlocale(LC_ALL, "");

	while (1) {
		int c;
		int opt_index;

		c = getopt_long(argc, argv, "dh", options, &opt_index);

		if (c == -1)
			break;

		switch (c) {
		case 'd':
			logging_level++;
			break;
		case 'h':
			usage();
			return 0;
		}
	}
	if (optind != argc) {
		usage();
		return -1;
	}
	/*
	 * Establish the CPU sets.
	 */
	setsize = CPU_ALLOC_SIZE(MAX_CPUS);

	for (i = 0; i < (int)ARRAY_SIZE(sets); i++) {

		*sets[i].set = CPU_ALLOC(MAX_CPUS);
		assert(*sets[i].set);
		CPU_ZERO_S(setsize, *sets[i].set);

		if (sets[i].path) {
			if (parse_mos_mask(*sets[i].set,
					   setsize,
					   sets[i].path)) {
				if (sets[i].required) {
					log_msg(LOG_ERR,
						"Error parsing CPU set.");
					rc = -1;
					goto out;
				}
			}
		}
	}
	/* Initialize */
	numtests++;
	init_cthreads();
	initial_compute_thread_count[my_initial_cpu] = 1;
	pthread_cond_init(&drivers_ready_cv, NULL);
	pthread_cond_init(&workload_cv, NULL);
	pthread_cond_init(&workload_done_cv, NULL);
	pthread_cond_init(&finished_cv, NULL);
	pthread_mutex_init(&driver_lock, NULL);
	pthread_mutex_init(&workload_lock, NULL);
	pthread_mutex_init(&workload_done_lock, NULL);
	pthread_mutex_init(&finished_lock, NULL);
	pthread_mutex_init(&lock, NULL);
	num_lwkcpus = CPU_COUNT_S(setsize, lwkcpus);
	num_cthreads = num_lwkcpus - 1;
	initial_compute_thread_count[my_initial_cpu] = 1;
	cthread[0].pthread_arg.index_start = 2;
	cthread[0].pthread_arg.index_end  = 2 + (num_cthreads - 2)/2;
	cthread[1].pthread_arg.index_start = 2 + (num_cthreads - 2)/2;
	cthread[1].pthread_arg.index_end = num_cthreads;

	/* Create the driver threads */
	for (i = 0; i < 2; i++) {
		cthread[i].pthread_arg.cindex = i;
		cthread[i].enable_compute_cpu_share_test = 1;
		cthread[i].share_level_computes = 1;
		cthread[i].api_retval_expected = 0;
		cthread[i].cputype_expected = CPUTYPE_LWK;
		cthread[i].api_retval_actual = pthread_create(
		    &(cthread[i].pthread),
		    &(cthread[i].pthread_attr),
		    compute_thread,
		    (void *)&cthread[i].pthread_arg);
		/* Record the API result */
		record_pthread_api_results(i);
	}
	pthread_mutex_lock(&lock);
	my_final_cpu = sched_getcpu();
	++final_compute_thread_count[my_final_cpu];
	pthread_mutex_unlock(&lock);
	if (my_final_cpu != my_initial_cpu) {
		log_msg(LOG_DEBUG,
		    "Balancing occurred... main thread moved from cpu=%d to cpu=%d",
		    my_initial_cpu, my_final_cpu);
	}
	end_test(num_cthreads);

	/************************************************
	 * Test completed. Now summarize the results
	 ************************************************/
	rc = summarize();
out:
	return rc;
}

static void usage(void)
{
	printf("concurrent_placement [--debug].. [--help]\n");
}
