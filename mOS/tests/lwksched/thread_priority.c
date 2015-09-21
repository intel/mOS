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
#define N_SAMPLES 256
#define N_THREADS 3
#define N_TESTS 3
#define N_CMDS 20

volatile int thread_request_exit;
pthread_t threads[N_THREADS];
pthread_attr_t attr;

enum Cmds {
	End,
	StartThreadHigh,
	StartThreadMedium,
	StartThreadLow,
	ExitThreadHigh,
	ExitThreadMedium,
	ExitThreadLow,
	ExitAll,
	ExpectNoProgressHigh,
	ExpectNoProgressMedium,
	ExpectNoProgressLow,
	ExpectProgressHigh,
	ExpectProgressMedium,
	ExpectProgressLow,
	ExpectNoPreemptsHigh,
	ExpectNoPreemptsMedium,
	ExpectNoPreemptsLow,
	ExpectPreemptsHigh,
	ExpectPreemptsMedium,
	ExpectPreemptsLow,
	Wait,
};

enum ThreadType {
	ThreadHigh = 0,
	ThreadMedium,
	ThreadLow,
};

enum ThreadExitMask {
	ThreadHighExit = 0x1 << ThreadHigh,
	ThreadMediumExit = 0x1 << ThreadMedium,
	ThreadLowExit = 0x1 << ThreadLow,
	ThreadAllExit = ThreadHighExit | ThreadMediumExit | ThreadLowExit,
};

enum Cmds cmd[N_TESTS][N_CMDS] = {
	/*
	 *  Test 1:
	 *  Start high, medium, and low priority thread on one CPU in
	 *  the indicated order. Exit these threads at the same time. Verify
	 *  that the firstly started high priority thread obtained all of the
	 *  cycles and was not preempted during its executing. Also verify
	 *  that the other lower priority threads did not progress at all and
	 *  did not experience any preemptions
	 */
	{StartThreadHigh, StartThreadMedium, StartThreadLow, Wait, ExitAll,
	 Wait, ExpectProgressHigh, ExpectNoProgressMedium, ExpectNoProgressLow,
	 ExpectNoPreemptsHigh, ExpectNoPreemptsMedium, ExpectNoPreemptsLow,
	 End},
	/*
	 * Test 2:
	 * Start high, medium, low priority threads in the indicated order.
	 * Exit the high priority thread, let existing threads run, exit the
	 * medium priority thread, let the remaining thread run, exit the last
	 * thread. Verify that all threads have made progress. Also verify that
	 * No thread preemptions occurred within the threads.
	 */
	{StartThreadHigh, Wait, StartThreadMedium, Wait, StartThreadLow, Wait,
	 ExitThreadHigh, Wait, ExitThreadMedium, Wait, ExitThreadLow, Wait,
	 ExpectProgressHigh, ExpectProgressMedium, ExpectProgressLow,
	 ExpectNoPreemptsHigh, ExpectNoPreemptsMedium, End},
	/*
	 * Test 3:
	 * Start a low priority thread, let run, start a medium priority
	 * thread, let run, start a high priority thread and let run. Exit the
	 * high priority thread, medium priority thread, and then the low
	 * priority thread. Verify that all threads made progress. Also verify
	 * that the medium and low priority threads were preempted and that the
	 * high priority thread was not preempted.
	 */
	{StartThreadLow, Wait, StartThreadMedium, Wait, StartThreadHigh, Wait,
	 ExitThreadHigh, Wait, ExitThreadMedium, Wait, ExitThreadLow, Wait,
	 ExpectProgressHigh, ExpectProgressMedium, ExpectProgressLow,
	 ExpectPreemptsMedium, ExpectPreemptsLow, ExpectNoPreemptsHigh, End},
};

struct thread_work {
	struct timeval tv;
	volatile int cpu;
	volatile long long int progress;
	int total_count;
	long long int lost[N_SAMPLES];
	long long int regain[N_SAMPLES];
	long long int delta[N_SAMPLES];
} work_area[N_THREADS];

char thread_name[N_THREADS][16] = {
			{"ThreadHigh"},
			{"ThreadMedium"},
			{"ThreadLow"}
				  };

static void *worker(void *);
static void initialize_workarea(void);
static void usage(void);
static void create_pthread(enum ThreadType thread_type);
static int test_progress(enum ThreadType, int expected, int test_num);
static int test_preemption(enum ThreadType, int expected, int test_num);

static void *worker(void *arg)
{
	unsigned long long tid;
	int i;
	long int rc = 0;
	struct timeval tv_current;
	unsigned long long t1, t2;

	tid = (unsigned long)arg;

	work_area[tid].cpu = sched_getcpu();
	gettimeofday(&tv_current, NULL);
	work_area[tid].tv = tv_current;
	while (!(thread_request_exit & (1<<tid))) {
		work_area[tid].progress++;
		work_area[tid].cpu = sched_getcpu();
		for (i = 0; i < N_THREADS; i++) {
			if ((work_area[i].cpu >= 0) &&
			    work_area[tid].cpu != work_area[i].cpu) {
				log_msg(LOG_FATAL,
				    "Unexpected CPU mis-match: %d, %d",
				    work_area[i].cpu, sched_getcpu());
			}
		}
		gettimeofday(&tv_current, NULL);
		/* Assume a gap of > 1ms is a preemption */
		t1 = tv_current.tv_sec * 1000000 + tv_current.tv_usec;
		t2 = work_area[tid].tv.tv_sec * 1000000 +
			work_area[tid].tv.tv_usec;

		if ((t1 - t2) > 1000) {
			/* We lost the processor and now we are back. */
			work_area[tid].delta[
				((work_area[tid].total_count)%N_SAMPLES)] =
				t1 - t2;
			work_area[tid].lost[
				((work_area[tid].total_count)%N_SAMPLES)] =
				t2;
			work_area[tid].regain[
				((work_area[tid].total_count++)%N_SAMPLES)] =
				t1;
		}
		work_area[tid].tv = tv_current;
	}
	log_msg(LOG_DEBUG,
		CPUFMT "Worker thread=%s completed with rc=%ld ",
		 sched_getcpu(), thread_name[tid], rc);

	return (void *)rc;
}

static void initialize_workarea(void)
{
	int i;

	memset(work_area, 0, sizeof(work_area));
	for (i = 0; i < N_THREADS; i++)
		work_area[i].cpu = -1;
}

static void create_pthread(enum ThreadType thread_type)
{
	struct sched_param param;
	int rc;

	param.sched_priority = 50 - 2 * thread_type;
	pthread_attr_setschedparam(&attr, &param);
	if ((rc = pthread_create(threads + thread_type, &attr, worker,
	    (void *)((unsigned long)(thread_type))))) {
		log_msg(LOG_FATAL,
		   "Could not spawn: %s", strerror(errno));
	}
}

static int test_progress(enum ThreadType ttype, int expected, int test_num)
{
	int rc = 0;

	if (work_area[ttype].progress) {
		if (!expected) {
			log_msg(LOG_ERR,
			    "Test %d: Progress (%d) detected in %s\n",
			    test_num, work_area[ttype].progress,
			    thread_name[ttype]);
			rc = -1;
		}
	} else {

		if (expected) {
			log_msg(LOG_ERR,
			    "Test %d: No progress detected in %s\n",
			    test_num, thread_name[ttype]);

			rc = -1;
		}
	}
	return rc;
}

static int test_preemption(enum ThreadType ttype, int expected, int test_num)
{
	int rc = 0;

	if (work_area[ttype].total_count) {
		if (!expected) {
			log_msg(LOG_ERR,
			    "Test %d: Preemptions (%d) detected in %s\n",
			    test_num, work_area[ttype].total_count,
			    thread_name[ttype]);
			rc = -1;
		}
	} else {

		if (expected) {
			log_msg(LOG_ERR,
			    "Test %d: No preemptions detected in %s\n",
			    test_num, thread_name[ttype]);

			rc = -1;
		}
	}
	return rc;
}

int main(int argc, char **argv)
{
	int i, j;
	int setsize;
	int cpu, mycpu;
	int rc = 0;
	cpu_set_t *affinity;


	struct option options[] = {
		{ "debug", no_argument, 0, 'd' },
		{ "help", no_argument, 0, 'h' },
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
		default:
			usage();
			return -1;
		}
	}

	if (optind != argc) {
		usage();
		return -1;
	}


	log_msg(LOG_INFO, "Priority test begin...");
	log_msg(LOG_DEBUG, "Spawning %d worker threads", N_THREADS);

	/*
	 *  Get the current Affinity mask and select one CPU to use for test.
	 *  Only stipulation is to not use the CPU that main is using
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
	pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	pthread_attr_setschedpolicy(&attr, SCHED_FIFO);

	/* Loop through each test scenario */
	for (i = 0; i < N_TESTS; i++) {
		int end_cmds = 0;

		/* Initialize the work areas for the threads */
		initialize_workarea();
		thread_request_exit = 0;
		for (j = 0; j < N_CMDS; j++) {
			switch (cmd[i][j]) {

			case StartThreadHigh:
				create_pthread(ThreadHigh);
				break;
			case StartThreadMedium:
				create_pthread(ThreadMedium);
				break;
			case StartThreadLow:
				create_pthread(ThreadLow);
				break;
			case ExitThreadHigh:
				thread_request_exit |= ThreadHighExit;
				break;
			case ExitThreadMedium:
				thread_request_exit |= ThreadMediumExit;
				break;
			case ExitThreadLow:
				thread_request_exit |= ThreadLowExit;
				break;
			case ExitAll:
				thread_request_exit |= ThreadAllExit;
				break;
			case ExpectNoProgressHigh:
				if (test_progress(ThreadHigh, 0, i+1))
					rc = -1;
				break;
			case ExpectNoProgressMedium:
				if (test_progress(ThreadMedium, 0, i+1))
					rc = -1;
				break;
			case ExpectNoProgressLow:
				if (test_progress(ThreadLow, 0, i+1))
					rc = -1;
				   break;
			case ExpectProgressHigh:
				if (test_progress(ThreadHigh, 1, i+1))
					rc = -1;
				break;
			case ExpectProgressMedium:
				if (test_progress(ThreadMedium, 1, i+1))
					rc = -1;
				break;
			case ExpectProgressLow:
				if (test_progress(ThreadLow, 1, i+1))
					rc = -1;
				break;
			case ExpectNoPreemptsHigh:
				if (test_preemption(ThreadHigh, 0, i+1))
					rc = -1;
				break;
			case ExpectNoPreemptsMedium:
				if (test_preemption(ThreadMedium, 0, i+1))
					rc = -1;
				break;
			case ExpectNoPreemptsLow:
				if (test_preemption(ThreadLow, 0, i+1))
					rc = -1;
				break;
			case ExpectPreemptsHigh:
				if (test_preemption(ThreadHigh, 1, i+1))
					rc = -1;
				break;
			case ExpectPreemptsMedium:
				if (test_preemption(ThreadMedium, 1, i+1))
					rc = -1;
				break;
			case ExpectPreemptsLow:
				if (test_preemption(ThreadLow, 1, i+1))
					rc = -1;
				break;
			case Wait:
				sleep(1);
				break;
			case End:
				end_cmds = 1;
				break;
			default:
				{
				}
			};
			if (end_cmds)
				break;
		}

		for (j = 0; j < N_THREADS; j++) {
			void *retval = 0;

			pthread_join(threads[j], &retval);
			if (retval != 0) {
				log_msg(LOG_FATAL,
				    "Non-zero return (%p) from %s",
				    0, retval, thread_name[j]);
			}
		}
	}

	if (rc)
		log_msg(LOG_ERR, "Test failed!");

	log_msg(LOG_INFO, "Test completed with rc=%d", rc);

	return rc;
}

static void usage(void)
{
	printf("thread_priority [--debug].. [--help]\n");
	printf("example: yod -C 2 -u 0 ./thread_priority\n");
}
