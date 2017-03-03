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
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include "lwksched.h"

#define MIN(a, b) (((a) < (b))?(a):(b))
#define LWKSCHED_MAX_PTHREADS 8
#define TS_ENTRIES 256

volatile int n_threads, time_quantum, window, thread_request_exit, test_enable,
	register_count;
static int yield_control;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *);
static void initialize_workarea(void);
static void usage(void);
static int validate_results(void);


struct thread_work {
	struct timeval tv;
	volatile int cpu;
	volatile long long int progress_indicator;
	int total_count;
	long long int ts[TS_ENTRIES];
} work_area[LWKSCHED_MAX_PTHREADS];

static void *worker(void *arg)
{
	unsigned long long tid;
	int i;
	long int rc = 0;
	struct timeval tv_current;
	unsigned long long t1, t2;
	long long int yield_count = 0;

	tid = (unsigned long)arg;
	pthread_mutex_lock(&mutex);
	register_count++;
	pthread_mutex_unlock(&mutex);
	work_area[tid].cpu = sched_getcpu();
	work_area[tid].tv = tv_current;
	gettimeofday(&tv_current, NULL);
	while (!thread_request_exit) {
		if (test_enable) {
			work_area[tid].progress_indicator++;
			if (yield_control &&
			    (work_area[tid].progress_indicator /
			     yield_control) > yield_count) {
				yield_count++;
				pthread_yield();
			}
		}
		work_area[tid].cpu = sched_getcpu();
		for (i = 0; i < n_threads; i++) {
			if (test_enable && (work_area[i].cpu >= 0) &&
			    work_area[tid].cpu != work_area[i].cpu) {
				log_msg(LOG_FATAL,
				    "Unexpected CPU mis-match: %d, %d",
				    work_area[i].cpu, sched_getcpu());
			}
		}
		gettimeofday(&tv_current, NULL);
		/* Assume a gap of > 1ms is a preemption */
		t1 = tv_current.tv_sec * 1000000 + tv_current.tv_usec;
		t2 = work_area[tid].tv.tv_sec * 1000000 + work_area[tid].tv.tv_usec;

		if (test_enable && (t1 - t2) > 1000) {
			/* We lost the processor and now we are back. */
			work_area[tid].ts[
				((work_area[tid].total_count++)%TS_ENTRIES)] =
				t1 - t2;
		}
		work_area[tid].tv = tv_current;
	}
	log_msg(LOG_DEBUG,
		CPUFMT "Worker thread=%d completed with rc=%ld ",
		 sched_getcpu(), tid, rc);

	return (void *)rc;
}

static void initialize_workarea(void)
{
	int i, j;

	for (i = 0; i < LWKSCHED_MAX_PTHREADS; i++) {
		work_area[i].cpu = -1;
		work_area[i].tv.tv_usec = 0;
		work_area[i].total_count = 0;
		for (j = 0; j < TS_ENTRIES; j++)
			work_area[i].ts[j] = 0;
		work_area[i].progress_indicator = 0;
	}
}
static int validate_results(void)
{
	int i;
	int rc = 0;
	int zero_progress = 0;
	int zero_preempts = 0;
	long long int max_progress = 0;
	long long int min_progress = LLONG_MAX;

	for (i = 0; i < n_threads; i++) {
		if (!work_area[i].total_count)
			zero_preempts++;
		if (!work_area[i].progress_indicator)
			zero_progress++;
		log_msg(LOG_DEBUG, "tid=%d, cpu=%d, progress=%lld, preempts=%d",
			i, work_area[i].cpu, work_area[i].progress_indicator,
			work_area[i].total_count);
	}
	if (time_quantum >= (window * 1000) && yield_control == 0) {
		/*
		* quantum >= window, only one thread should have
		* progress and * all threads should have no preempts
		*/
		if (!zero_preempts) {
			log_msg(LOG_ERR,
			   "More than one thread with non-zero preempts=%d",
			   n_threads - zero_preempts);
			rc = -1;
		}
		if (n_threads-1 != zero_progress) {
			log_msg(LOG_ERR,
			   "More than one thread with non-zero progress=%d",
			   n_threads - zero_progress);
			rc = -1;
		}
	} else {
		/*
		* quantum < window, each thread should have preempts and should
		* have made similar progress
		*/
		if (zero_preempts) {
			log_msg(LOG_ERR,
			   "Threads with zero preempts detected=%d",
			   zero_preempts);
			rc = -1;
		}
		if (zero_progress) {
			log_msg(LOG_ERR,
			   "Threads with zero progress detected=%d",
			   zero_progress);
			rc = -1;
		}
		/*
		 * Test to see that balanced progress was made across the
		 * threads. This will verify that each thread has been given
		 * approximately equal execution time and equal number of
		 * preemptions.
		*/
		for (i = 0; i < n_threads; i++) {
			if (work_area[i].progress_indicator > max_progress)
				max_progress = work_area[i].progress_indicator;
			if (work_area[i].progress_indicator < min_progress)
				min_progress = work_area[i].progress_indicator;
		}
		if ((max_progress - min_progress) > max_progress/10) {
			log_msg(LOG_ERR,
			   "Progress delta exceeds limit. max=%d min=%d",
			   max_progress, min_progress);
			rc = -1;
		}
	}
	return rc;
}

int main(int argc, char **argv)
{
	int i;
	int setsize;
	int cpu, mycpu;
	int register_expect;
	int rc = 0;
	pthread_t threads[LWKSCHED_MAX_PTHREADS];
	cpu_set_t *affinity;
	pthread_attr_t attr;

	struct option options[] = {
		{ "threads", required_argument, 0, 't' },
		{ "quantum", required_argument, 0, 'q'},
		{ "window", required_argument, 0, 'w'},
		{ "yield", required_argument, 0, 'y'},
		{ "debug", no_argument, 0, 'd' },
		{ "help", no_argument, 0, 'h' },
	};

	time_quantum = INT_MAX;
	yield_control = 0;

	setlocale(LC_ALL, "");

	while (1) {
		int c;
		int opt_index;

		c = getopt_long(argc, argv, "t:q:w:y:dh", options, &opt_index);

		if (c == -1)
			break;

		switch (c) {
		case 't':
			n_threads = atoi(optarg);
			break;
		case 'q':
			time_quantum = atoi(optarg); /* ms */
			break;
		case 'w':
			window = atoi(optarg); /* seconds */
			break;
		case 'y':
			yield_control = atoi(optarg); /* loop count */
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

	if (n_threads < 2 || n_threads > LWKSCHED_MAX_PTHREADS)
		log_msg(LOG_FATAL, "Incorrect number of threads specified: %d",
		    n_threads);

	if (window < 2)
		log_msg(LOG_FATAL,
		    "Incorrect window: %d. Must be at least 2 seconds.",
		    window);

	if (time_quantum < 10)
		log_msg(LOG_FATAL,
		    "Incorrect time quantum: %d. Must be at least 10 ms.",
		    window);

	if (yield_control < 0)
		log_msg(LOG_FATAL,
		    "Incorrect yield: %d. Must be zero or greater.",
		    window);

	/* Initialize the work areas for the threads */
	initialize_workarea();

	register_count = 0;
	test_enable = 0;
	thread_request_exit = 0;

	log_msg(LOG_INFO, "Timer preemption test begin...");
	log_msg(LOG_DEBUG, "Spawning %d worker threads", n_threads);

	/*
	 *  Get the current Affinity mask and select one CPU to use for test.
	 *  Only stipulation is to use the CPU that main is using
	 */
	affinity = CPU_ALLOC(MAX_CPUS);
	setsize = CPU_ALLOC_SIZE(MAX_CPUS);
	CPU_XOR_S(setsize, affinity, affinity, affinity);

	if (sched_getaffinity(0, setsize, affinity))
		log_msg(LOG_FATAL, "Could not obtain affinity: %s",
		    strerror(errno));

	mycpu = sched_getcpu();
	CPU_CLR_S(mycpu, setsize, affinity);
	cpu = -1;
	if (CPU_COUNT_S(setsize, affinity)) {
		int found_target = 0;

		for (cpu = 0; cpu < MAX_CPUS; cpu++) {
			if (CPU_ISSET_S(cpu, setsize, affinity)) {
				if (!found_target)
					found_target = 1;
				else
					CPU_CLR_S(cpu, setsize, affinity);
			}
		}
	}
	if (cpu < 0)
		log_msg(LOG_FATAL,
		    "Required CPUs not available. Two CPUs required.");

	pthread_attr_init(&attr);
	pthread_attr_setaffinity_np(&attr, setsize, affinity);

	for (i = 0; i < n_threads; i++) {
		if (pthread_create(threads + i, &attr, worker,
				   (void *)((unsigned long)(i))))
			log_msg(LOG_FATAL,
				"Could not spawn: %s", strerror(errno));
	}

	register_expect = (time_quantum >= (window * 1000)) ? 1 : n_threads;
	for (i = 0; i < 5; i++) {
		sleep(1);
		if (register_expect == register_count)
			break;
	}
	if (register_expect != register_count) {
		log_msg(LOG_ERR,
		   "Timeout for expected number of registered threads. Expected=%d Registered=%d",
		   register_expect, register_count);
		rc = -1;
	}

	test_enable = 1;

	/*
	 * Sleep while the threads take turns on the test cpu, after the sleep
	 * time expires, tell the threads to exit
	 */
	sleep(window);

	thread_request_exit = 1;

	for (i = 0; i < n_threads; i++) {
		void *retval = 0;

		pthread_join(threads[i], &retval);
		if (retval != 0) {
			log_msg(LOG_FATAL,
			    "Non-zero return (%p) from thread %d",
			    0, retval, i);
		}
	}
	/* Now it is time to see what our test threads did while we slept */
	rc = (validate_results() || rc) ? -1 : 0;

	if (rc)
		log_msg(LOG_ERR, "Test failed!");

	log_msg(LOG_INFO, "Test completed with rc=%d", rc);

	return rc;
}

static void usage(void)
{
	printf("timer_preemption --threads <N> --quantum <N> --window <N> --yield <N> [--debug].. [--help]\n");
	printf("examples: yod -C 2 -u 0 -o lwksched-enable-rr=100 ./timer_preemption -t 4 -q 100 -w 6\n");
	printf("          yod -C 2 -u 0  ./timer_preemption -t 4 -w 6\n");
	printf("          yod -C 2 -u 0  ./timer_preemption -t 4 -w 6 -y 10000\n");
	printf("note on units: --quantum milliseconds, --window seconds --yield iterations\n");
}
