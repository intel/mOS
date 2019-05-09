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
#include <uti.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "lwksched.h"

#define NDSZ  4

#define BITS_IN_LONG (sizeof(unsigned long) * 8)
#define MAX_NUMNODES (NDSZ * BITS_IN_LONG)
#define NUMNODES 8
#define MAXUTILS (MAX_CPUS * 2)
#define MAXCOMPUTES MAX_CPUS
#define CPUTYPE_LWK 1
#define CPUTYPE_FWK 2
#define NOT_ENABLED (-1)
#define ALL_UTILS_SAME (-2)
#define ALL_UTILS_DIFF (-3)
#define CPUSHARE_TEST_ENABLE 1

static unsigned long nodes[NDSZ];
static pthread_mutex_t lock;
static unsigned long nodes[NDSZ];
static void usage(void);
static pthread_mutex_t count_lock;
static pthread_cond_t count_cv;
static int uthreads_finished;
static int cthreads_finished;
static int numtests;
static int numskipped;
static int numutils_created;
static int numcomputes_created;
static int numfails;
static int numsuccess;
static int num_uthreads;
static int num_cthreads;
static size_t setsize;
static cpu_set_t *lwkcpus;
static cpu_set_t *linuxutilcpus;
static cpu_set_t *nodecpus[NUMNODES];
static unsigned long location_key;
static int subtest;
static int subtest_loop_count;

enum OverrideBehavior {
	AllCommits = 0,
	OnlyComputeCommits,
	OnlyUtilityCommits,
};

static struct {
	pthread_t pthread;
	uti_attr_t attr;
	pthread_attr_t pthread_attr;
	void *pthread_arg;
	int api_retval_expected;
	int api_retval_actual;
	long int cputype_expected;
	long int cputype_actual;
	int placement_expected;
	int placement_failed;
	int behavior_expected;
	int behavior_failed;
	int numa_id_expected;
	int numa_id_not_expected;
	int numa_id_actual;
	int created;
	int enable_compute_cpu_share_test;
	int enable_util_cpu_share_test;
	int share_level_computes;
	int share_level_utils;
	int mycpu;
} uthread[MAXUTILS];

static struct {
	pthread_t pthread;
	pthread_attr_t pthread_attr;
	void *pthread_arg;
	int api_retval_expected;
	int api_retval_actual;
	long int cputype_expected;
	long int cputype_actual;
	int created;
	int enable_compute_cpu_share_test;
	int enable_util_cpu_share_test;
	int share_level_computes;
	int share_level_utils;
	int mycpu;
} cthread[MAXCOMPUTES];

static int num_lwkcpus;
static int lwkcpus_in_node[NUMNODES];
static int utilitycpus_in_node[NUMNODES];
static int util_thread_count[MAX_CPUS];
static int compute_thread_count[MAX_CPUS];
static int num_nodes_containing_lwkcpus;
static int num_nodes_containing_utilitycpus;
static int overcommit_behavior = OnlyUtilityCommits;

static void *myuthread(void *arg)
{
	int i;
	long int uindex = (long int)arg;
	long int rc = 0;
	int mycpu = sched_getcpu();
	int threads_finished;

	log_msg(LOG_DEBUG, "Util thread created. uindex=%d cpu=%d", uindex,
		mycpu);
	/* Indicate that a utility thread has been created */

	if (pthread_mutex_lock(&lock)) {
		log_msg(LOG_ERR, "Mutex acquisition failed for uthread=%d.",
				uindex);
		rc = -1;
		goto out;
	}
	numutils_created++;
	uthread[uindex].mycpu = mycpu;
	/* Bump count of compute threads on a given CPU */
	++util_thread_count[mycpu];

	if (pthread_mutex_unlock(&lock)) {
		log_msg(LOG_ERR, "Could not unlock mutex for uthread index=%d",
				uindex);
		rc = -1;
		goto out;
	}
	/* Record the numa domain this thread is currently running in */
	for (i = 0; i < NUMNODES; i++) {
		if (CPU_ISSET_S(mycpu, setsize, nodecpus[i])) {
			log_msg(LOG_DEBUG,
				"cpu=%d found in node=%d for uthread=%d",
				mycpu, i, uindex);
			uthread[uindex].numa_id_actual = i;
			break;
		}
	}
	if (uthread[uindex].numa_id_actual == -1) {
		log_msg(LOG_ERR, "Could not get numa id for uthread index=%d",
				uindex);
		rc = -1;
		goto out;
	}
	/* Do not allow a util thread  to exit until all util
	 * and compute threads are created
	 */
	pthread_mutex_lock(&count_lock);
	threads_finished = ++uthreads_finished + cthreads_finished;
	if (threads_finished == (num_uthreads + num_cthreads)) {
		log_msg(LOG_DEBUG, "All threads finished.");
		pthread_cond_broadcast(&count_cv);
	}
	pthread_mutex_unlock(&count_lock);

	pthread_mutex_lock(&count_lock);
	while ((uthreads_finished + cthreads_finished) <
	       (num_uthreads + num_cthreads)) {
		pthread_cond_wait(&count_cv, &count_lock);
	}
	pthread_mutex_unlock(&count_lock);

	if (CPU_ISSET_S(mycpu, setsize, lwkcpus))
		rc = CPUTYPE_LWK;
	else
		rc = CPUTYPE_FWK;
out:

	return (void *)rc;
}

static void *mycthread(void *arg)
{
	long int cindex = (long int)arg;
	long int rc = 0;
	int mycpu = sched_getcpu();
	int threads_finished;

	if (pthread_mutex_lock(&lock)) {
		log_msg(LOG_ERR, "Mutex acquisition failed for cthread=%d.",
				cindex);
		rc = -1;
		goto out;
	}
	/* Indicate that a compute thread has been created */
	numcomputes_created++;
	/* Bump count of compute threads on a given CPU */
	++compute_thread_count[mycpu];
	cthread[cindex].mycpu = mycpu;

	if (pthread_mutex_unlock(&lock)) {
		log_msg(LOG_ERR, "Could not unlock mutex for cthread index=%d",
				cindex);
		rc = -1;
		goto out;
	}
	/* Do not allow a compute thread  to exit until all utility
	 * and compute threads are created
	 */
	pthread_mutex_lock(&count_lock);
	threads_finished = ++cthreads_finished + uthreads_finished;
	if (threads_finished == (num_uthreads + num_cthreads)) {
		log_msg(LOG_DEBUG, "All threads finished.");
		pthread_cond_broadcast(&count_cv);
	}
	pthread_mutex_unlock(&count_lock);

	pthread_mutex_lock(&count_lock);
	while ((uthreads_finished + cthreads_finished) <
	       (num_uthreads + num_cthreads)) {
		pthread_cond_wait(&count_cv, &count_lock);
	}
	pthread_mutex_unlock(&count_lock);

	if (CPU_ISSET_S(mycpu, setsize, lwkcpus))
		rc = CPUTYPE_LWK;
	else
		rc = CPUTYPE_FWK;
out:

	return (void *)rc;
}

static void init_nodes(void)
{
       int i;

	for (i = 0; i < NDSZ; i++)
		nodes[i] = 0;
}

static void init_uthreads(void)
{
	int i;

	numutils_created = 0;
	uthreads_finished = 0;
	for (i = 0; i < MAXUTILS; i++) {
		uti_attr_init(&(uthread[i].attr));
		pthread_attr_init(&(uthread[i].pthread_attr));
		uthread[i].pthread_arg = NULL;
		uthread[i].api_retval_expected = 0;
		uthread[i].api_retval_actual = 0;
		uthread[i].cputype_expected = 0;
		uthread[i].cputype_actual = 0;
		uthread[i].placement_expected = 0;
		uthread[i].placement_failed = 0;
		uthread[i].behavior_expected = 0;
		uthread[i].behavior_failed = 0;
		uthread[i].created = 0;
		uthread[i].numa_id_expected = NOT_ENABLED;
		uthread[i].numa_id_not_expected = NOT_ENABLED;
		uthread[i].numa_id_actual = NOT_ENABLED;
		uthread[i].enable_util_cpu_share_test = 0;
		uthread[i].enable_compute_cpu_share_test = 0;
		uthread[i].share_level_computes = 0;
		uthread[i].share_level_utils = 0;
	}
	for (i = 0; i < MAX_CPUS; i++)
		util_thread_count[i] = 0;
}

static void init_cthreads(void)
{
	int i;

	numcomputes_created = 0;
	cthreads_finished = 0;
	for (i = 0; i < MAXCOMPUTES; i++) {
		pthread_attr_init(&(cthread[i].pthread_attr));
		cthread[i].pthread_arg = NULL;
		cthread[i].api_retval_expected = 0;
		cthread[i].api_retval_actual = 0;
		cthread[i].cputype_expected = 0;
		cthread[i].cputype_actual = 0;
		cthread[i].created = 0;
		cthread[i].enable_util_cpu_share_test = 0;
		cthread[i].enable_compute_cpu_share_test = 0;
		cthread[i].share_level_utils = 0;
		cthread[i].share_level_computes = 0;
	}
	for (i = 0; i < MAX_CPUS; i++)
		compute_thread_count[i] = 0;
	compute_thread_count[sched_getcpu()] = 1;

}

static int begintest(int testnum)
{
	if (subtest && (testnum != subtest))
		/* Subtesting active, but not this test */
		return 0;
	if ((subtest == testnum) && (subtest_loop_count-- < 0))
		/* Subtesting active. completed iterating over loop count */
		return 0;
	if (!subtest && (numtests == testnum))
		/* Subtesting not active. Already ran our test once */
		return 0;
	numtests = testnum;
	if (!num_uthreads) {
		numskipped++;
		return 0;
	}
	init_nodes();
	init_uthreads();
	init_cthreads();
	pthread_cond_init(&count_cv, NULL);
	pthread_mutex_init(&count_lock, NULL);
	pthread_mutex_init(&lock, NULL);
	if (num_uthreads)
		log_msg(LOG_INFO, "Beginning test=%d...", numtests);
	return 1;
}

static void behavior_results(int uindex)
{
	if ((uthread[uindex].behavior_expected) &&
	    (!uti_result_behavior(&(uthread[uindex].attr)))) {
		uthread[uindex].behavior_failed = 1;
	}
}

static void placement_results(int uindex)
{
	if ((uthread[uindex].placement_expected) &&
	    (!uti_result_location(&(uthread[uindex].attr)))) {
		uthread[uindex].placement_failed = 1;
	}
}

static int placement_failure(void)
{
	int i;
	int numfails;

	for (i = 0, numfails = 0; i < num_uthreads; i++) {
		if (uthread[i].placement_failed) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d uthread=%d detected placement failure.",
				numtests, i);
		}
	}
	return numfails;
}

static int behavior_failure(void)
{
	int i;
	int numfails;

	for (i = 0, numfails = 0; i < num_uthreads; i++) {
		if (uthread[i].behavior_failed) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d uthread=%d detected behavior failure.",
				numtests, i);
		}
	}
	return numfails;
}

static int api_failure(void)
{
	int i;
	int numfails;

	for (i = 0, numfails = 0; i < num_uthreads; i++) {
		if (uthread[i].api_retval_actual !=
				uthread[i].api_retval_expected) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d uthread=%d detected api return code failure. Actual/Expected=%d/%d",
				numtests, i, uthread[i].api_retval_actual,
				uthread[i].api_retval_expected);
		}
	}
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
	int numfails;

	for (i = 0, numfails = 0; i < num_uthreads; i++) {
		if (uthread[i].cputype_actual !=
				uthread[i].cputype_expected) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d uthread=%d detected cpu type failure. Actual/Expected=%d/%d",
				numtests, i, uthread[i].cputype_actual,
				uthread[i].cputype_expected);
		}
	}
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

static int numa_id_failure(void)
{
	int i, j;
	int numfails;
	int node_count[NUMNODES];

	for (i = 0; i < NUMNODES; i++)
		node_count[i] = 0;

	for (i = 0, numfails = 0; i < num_uthreads; i++) {
		if ((uthread[i].numa_id_expected >= 0) &&
		   (uthread[i].numa_id_actual != uthread[i].numa_id_expected)) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d uthread=%d detected numa id failure. Actual/Expected=%d/%d",
				numtests, i, uthread[i].numa_id_actual,
				uthread[i].numa_id_expected);
		} else if ((uthread[i].numa_id_not_expected >= 0) &&
				(uthread[i].numa_id_actual ==
				 uthread[i].numa_id_not_expected)) {
			numfails++;
			log_msg(LOG_ERR,
				"Test=%d uthread=%d detected numa id failure. Not expected id=%d",
				numtests, i, uthread[i].numa_id_not_expected);
		}
		if (uthread[i].numa_id_actual >= 0 &&
		    uthread[i].numa_id_actual < NUMNODES)
			node_count[uthread[i].numa_id_actual]++;
	}
	for (i = 0; i < num_uthreads; i++) {
		if (uthread[i].numa_id_expected == ALL_UTILS_DIFF) {
			/* Verify that no counts are greater than one */
			for (j = 0; j < NUMNODES; j++) {
				if (node_count[j] > 1) {
					numfails++;
					log_msg(LOG_ERR,
					"TEST=%d uthread=%d expected all util threads in different domains. Domain=%d",
					numtests, i, uthread[i].numa_id_actual);
				}
			}
		} else if (uthread[i].numa_id_expected == ALL_UTILS_SAME) {
			int non_zero_counts = 0;

			/* Verify only one node id with non-zero count */
			for (j = 0; j < NUMNODES; j++) {
				if (node_count[j])
					non_zero_counts++;
			}
			if (non_zero_counts > 1) {
				numfails++;
				log_msg(LOG_ERR,
				"TEST=%d uthread=%d expected all util threads in same domain. Domain=%d",
				numtests, i, uthread[i].numa_id_actual);
			}
		}
	}
	return numfails;
}

static int cpushare_failure(void)
{
	int i;
	int numfails;

	for (i = 0, numfails = 0; i < num_uthreads; i++) {
		if (uthread[i].enable_compute_cpu_share_test) {
			if (compute_thread_count[uthread[i].mycpu] !=
			    uthread[i].share_level_computes) {
				numfails++;
				log_msg(LOG_ERR,
				    "Test=%d uthread=%d detected cpu=%d share failure with a compute thread. Actual=%d Expected=%d",
				    numtests, i, uthread[i].mycpu,
				    compute_thread_count[uthread[i].mycpu],
				    uthread[i].share_level_computes);
			}
		}
		if (uthread[i].enable_util_cpu_share_test) {
			if (util_thread_count[uthread[i].mycpu] !=
			    uthread[i].share_level_utils) {
				numfails++;
				log_msg(LOG_ERR,
				    "Test=%d uthread=%d detected cpu=%d share failure with a util thread. Actual=%d Expected=%d",
				    numtests, i, uthread[i].mycpu,
				    util_thread_count[uthread[i].mycpu],
				    uthread[i].share_level_utils);
			}
		}
	}
	for (i = 0; i < num_cthreads; i++) {
		if (cthread[i].enable_compute_cpu_share_test) {
			if (compute_thread_count[cthread[i].mycpu] !=
			    cthread[i].share_level_computes) {
				numfails++;
				log_msg(LOG_ERR,
				    "Test=%d cthread=%d detected cpu=%d share failure with a compute thread. Actual=%d Expected=%d",
				    numtests, i, cthread[i].mycpu,
				    compute_thread_count[cthread[i].mycpu],
				    cthread[i].share_level_computes);
			}
		}
		if (cthread[i].enable_util_cpu_share_test) {
			if (util_thread_count[cthread[i].mycpu] !=
			    cthread[i].share_level_utils) {
				numfails++;
				log_msg(LOG_ERR,
				    "Test=%d cthread=%d detected cpu=%d share failure with a util thread. Actual=%d Expected=%d",
				    numtests, i, cthread[i].mycpu,
				    util_thread_count[cthread[i].mycpu],
				    cthread[i].share_level_utils);
			}
		}
	}

	return numfails;
}

static void end_test(int expected_utils, int expected_computes)
{
	int num_thread_fails;
	int uindex;
	int cindex;
	void *retval;

	log_msg(LOG_DEBUG, "max cpus=%d", MAX_CPUS);
	for (uindex = 0; uindex < num_uthreads; uindex++) {
		if (uthread[uindex].created) {
			/* Created utility threads should reach pthread_join */
			pthread_join(uthread[uindex].pthread, &retval);
			uthread[uindex].cputype_actual = (long int)retval;
		}
	}


	for (cindex = 0; cindex < num_cthreads; cindex++) {
		if (cthread[cindex].created) {
			/* Created utility threads should reach pthread_join */
			pthread_join(cthread[cindex].pthread, &retval);
			cthread[cindex].cputype_actual = (long int)retval;
		}
	}

	if (numutils_created != expected_utils) {
		log_msg(LOG_ERR,
			"Test=%d failed. Expected/actual uthreads=%d/%d",
			numtests, expected_utils, numutils_created);
		numfails += 1;
	}
	if (numcomputes_created != expected_computes) {
		log_msg(LOG_ERR,
		    "Test=%d failed. Expected/actual cthreads=%d/%d",
		    numtests, expected_computes, numcomputes_created);
	  numfails += 1;

	} else if ((num_thread_fails = api_failure())) {
		log_msg(LOG_ERR,
			"Test=%d UTI API return code(s) for %d utility threads.",
			numtests, num_thread_fails);
	} else if ((num_thread_fails = placement_failure())) {
		log_msg(LOG_ERR,
			"Test=%d placement failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else if ((num_thread_fails = behavior_failure())) {
		log_msg(LOG_ERR,
			"Test=%d behavior failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else if ((num_thread_fails = cputype_failure())) {
		log_msg(LOG_ERR,
			"Test=%d cpu type failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else if ((num_thread_fails = numa_id_failure())) {
		log_msg(LOG_ERR,
			"Test=%d unexpected numa id for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;
	} else if ((num_thread_fails = cpushare_failure())) {
		log_msg(LOG_ERR,
			"Test=%d cpu sharing failed for %d threads.",
			numtests, num_thread_fails);
		numfails += 1;

	} else {
		log_msg(LOG_INFO,
			"Test=%d passed.\n", numtests);
		numsuccess += 1;
	}
	/* Reset the state of the condition variable */
	pthread_cond_destroy(&count_cv);
}

static int summarize(void)
{
	log_msg(LOG_INFO,
	    "Tests run: %d Successes: %d Failures: %d Skipped: %d",
		numtests, numsuccess, numfails, numskipped);
	if (numfails || (numtests != (numsuccess + numskipped)))
		return -1;
	return 0;
}

static void record_uti_api_results(int uindex)
{
	if (!uthread[uindex].api_retval_actual) {
		uthread[uindex].created = 1;
		/* Record location and behavior results */
		behavior_results(uindex);
		placement_results(uindex);
	}
}

static void record_pthread_api_results(int cindex)
{
	if (!cthread[cindex].api_retval_actual) {
		cthread[cindex].created = 1;
	}
}

int main(int argc, char **argv)
{
	long int rc;
	long int uindex;
	long int cindex;
	int testnum = 0;
	int i, j;
	int valid_environment;
	unsigned long node_mask;
	int mycpu, my_nodeid;
	int numa_list[NUMNODES];
	cpu_set_t *cpuset_temp;

	struct option options[] = {
		{ "debug", no_argument, 0, 'd' },
		{ "behavior", required_argument, 0, 'b' },
		{ "subtest", required_argument, 0, 's' },
		{ "loopcount", required_argument, 0, 'l' },
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
		{ .set = &linuxutilcpus,
		  .path = "/sys/kernel/mOS/utility_cpus_mask",
		  .required = 1 },
		{ .set = &nodecpus[0],
		  .path = "/sys/devices/system/node/node0/cpumap",
		  .required = 1 },
		{ .set = &nodecpus[1],
		  .path = "/sys/devices/system/node/node1/cpumap",
		  .required = 0	},
		{ .set = &nodecpus[2],
		  .path = "/sys/devices/system/node/node2/cpumap",
		  .required = 0 },
		{ .set = &nodecpus[3],
		  .path = "/sys/devices/system/node/node3/cpumap",
		  .required = 0	},
		{ .set = &nodecpus[4],
		  .path = "/sys/devices/system/node/node4/cpumap",
		  .required = 0	},
		{ .set = &nodecpus[5],
		  .path = "/sys/devices/system/node/node5/cpumap",
		  .required = 0	},
		{ .set = &nodecpus[6],
		  .path = "/sys/devices/system/node/node6/cpumap",
		  .required = 0	},
		{ .set = &nodecpus[7],
		  .path = "/sys/devices/system/node/node7/cpumap",
		  .required = 0	},
		{ .set = &cpuset_temp,
		  .path = 0,
		  .required = 1	},
	};

	setlocale(LC_ALL, "");

	while (1) {
		int c;
		int opt_index;

		c = getopt_long(argc, argv, "db:s:l:h", options, &opt_index);

		if (c == -1)
			break;

		switch (c) {
		case 'd':
			logging_level++;
			break;
		case 'h':
			usage();
			return 0;
		case 'b':
			overcommit_behavior = atoi(optarg);
			break;
		case 's':
			subtest = atoi(optarg);
			break;
		case 'l':
			subtest_loop_count = atoi(optarg);
			break;
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
	/* Find the numa domain id of the CPU that we are
	 * currently running on
	 */
	mycpu = sched_getcpu();
	/* Record the numa domain this CPU is in */
	for (i = 0, my_nodeid = -1; i < NUMNODES; i++) {
		if (CPU_ISSET_S(mycpu, setsize, nodecpus[i])) {
			my_nodeid = i;
			break;
		}
	}
	if (my_nodeid == -1) {
		rc = -1;
		log_msg(LOG_ERR,
			"Error obtaining current numa domain id");
		goto out;
	}
	/* Determine the number of LWK and Linux CPUs in each numa domain */
	for (i = 0; i < NUMNODES; i++) {
		CPU_AND_S(setsize, cpuset_temp, lwkcpus, nodecpus[i]);
		lwkcpus_in_node[i] = CPU_COUNT_S(setsize, cpuset_temp);
		if (lwkcpus_in_node[i])
			num_nodes_containing_lwkcpus++;
		CPU_AND_S(setsize, cpuset_temp, linuxutilcpus, nodecpus[i]);
		utilitycpus_in_node[i] = CPU_COUNT_S(setsize, cpuset_temp);
		if (utilitycpus_in_node[i])
			num_nodes_containing_utilitycpus++;
	}
	/* Seed the random number generator */
	srandom(time(NULL));

	num_lwkcpus = CPU_COUNT_S(setsize, lwkcpus);
	/*
	 *****************************************************
	 * Test 1: Create two util threads on same numa domain
	 ****************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 2;
	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].numa_id_expected = my_nodeid;

			/* Setup and call the uti api */
			uti_attr_same_numa_domain(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 2: Create two util threads on different numa domain
	 *********************************************************
	 */
	testnum++;

	/* Determine if the environment supports this test */
	if (num_nodes_containing_lwkcpus < 2) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires more than one domain.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 2;

	/* Prep environment for starting testcase */
	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].numa_id_not_expected = my_nodeid;

			/* Setup and call the uti api */
			uti_attr_different_numa_domain(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *****************************************************
	 * Test 3: Create a util thread in same L2 cache
	 ****************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 1;
	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_LWK;

			/* Setup and call the uti api */
			uti_attr_same_l2(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 4: Create two util threads on different L2 caches
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 2;
	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_LWK;

			/* Setup and call the uti api */
			uti_attr_different_l2(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 5: Create two util threads explicitly on LWK CPUs
	 *         and two util threads explicitly on FWK CPUs
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	if (!num_nodes_containing_utilitycpus) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires at least one utility CPU.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 4;
	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;

			/* Setup and call the uti api */
			if (uindex < 2) {
				uthread[uindex].cputype_expected = CPUTYPE_FWK;
				uti_attr_prefer_fwk(&(uthread[uindex].attr));
			} else {
				uthread[uindex].cputype_expected = CPUTYPE_LWK;
				uti_attr_prefer_lwk(&(uthread[uindex].attr));
			}
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 6: Create four util threads explicitly on Utility CPUs
	 *         and in a different numa domain as the caller
	 *********************************************************
	 */
	testnum++;

	/* Determine if the environment supports this test */
	valid_environment = 0;
	for (i = 0; i < NUMNODES; i++) {
		if (i == my_nodeid)
			continue;
		if (utilitycpus_in_node[i]) {
			valid_environment = 1;
			break;
		}
	}
	if (valid_environment)
		num_uthreads = 4;
	else {
		num_uthreads = 0; /* Skip test */
		log_msg(LOG_INFO,
			"Skipping test=%d. Requires Utility CPU in a different numa domain.",
			testnum);
	}
	/* Prep environment for starting testcase */
	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_FWK;
			uthread[uindex].numa_id_not_expected = my_nodeid;

			/* Setup and call the uti api */
			uti_attr_prefer_fwk(&(uthread[uindex].attr));
			uti_attr_different_numa_domain(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 7: Create util threads explicitly on LWK CPUs
	 *         and explicity on all available numa domains
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = num_nodes_containing_lwkcpus;
	for (i = 0, j = 0; i < NUMNODES; i++) {
		if (lwkcpus_in_node[i])
			numa_list[j++] = i;
	}
	node_mask = 1;
	while (begintest(testnum)) {
		log_msg(LOG_DEBUG,
		    "Explicitly setting threads on %d numa domains.",
				num_uthreads);

		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].numa_id_expected = uindex;

			/* Setup and call the uti api */
			nodes[0] = (node_mask << numa_list[uindex]);
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uti_attr_numa_set(&(uthread[uindex].attr), nodes,
			    NUMNODES);
			log_msg(LOG_DEBUG, "Node mask=%lx\n", nodes[0]);
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 8: Create two util threads explicitly on LWK CPUs
	 *         and explicity specify invalid domains
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 2;
	node_mask = 0x10;
	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 0;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_LWK;

			/* Setup and call the uti api */
			nodes[0] = node_mask;
			node_mask *=  2; /* adjust to next node in bit map */
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uti_attr_numa_set(&(uthread[uindex].attr), nodes,
								NUMNODES);
			log_msg(LOG_DEBUG, "Node mask=%lx\n", nodes[0]);
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 9: Create two util threads explicitly on FWK
	 *         and explicity in a valid domain
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	if (!num_nodes_containing_utilitycpus) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires at least one utility CPU.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 2;

	/* Find the first domain that contains a Linux utility CPU */
	node_mask = 1;
	for (i = 0; i < NUMNODES; i++) {
		if (utilitycpus_in_node[i])
			break;
	}
	/* Set the node mask to this domain */
	node_mask <<= i;

	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_FWK;
			uthread[uindex].numa_id_expected = i;

			/* Setup and call the uti api */
			nodes[0] = node_mask;
			uti_attr_prefer_fwk(&(uthread[uindex].attr));
			uti_attr_numa_set(&(uthread[uindex].attr), nodes,
								NUMNODES);
			log_msg(LOG_DEBUG, "Node mask=%lx\n", nodes[0]);
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 ***************************************************************
	 * Test 10:  Testing conflicting domain placement requests
	 ***************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 1;
	while (begintest(testnum)) {
		/* Set test expectations */
		uthread[0].api_retval_expected = EINVAL;

		/* Setup and call the uti api */
		uti_attr_same_numa_domain(&(uthread[0].attr));
		uti_attr_different_numa_domain(&(uthread[0].attr));
		log_msg(LOG_DEBUG, "Node mask=%lx\n", nodes[0]);
		uthread[0].api_retval_actual = uti_pthread_create(
			&(uthread[0].pthread),
			&(uthread[0].pthread_attr),
			myuthread,
			(void *)0,
			&(uthread[0].attr));
		/* Record the API result */
		record_uti_api_results(0);
		end_test(0, 0);
	}
	/*
	 ***************************************************************
	 * Test 11:  Testing conflicting cache placement requests
	 ***************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 1;
	while (begintest(testnum)) {
		/* Set test expectations */
		uthread[0].api_retval_expected = EINVAL;

		/* Setup and call the uti api */
		uti_attr_same_l1(&(uthread[0].attr));
		uti_attr_different_l1(&(uthread[0].attr));
		log_msg(LOG_DEBUG, "Node mask=%lx\n", nodes[0]);
		uthread[0].api_retval_actual = uti_pthread_create(
			&(uthread[0].pthread),
			&(uthread[0].pthread_attr),
			myuthread,
			(void *)0,
			&(uthread[0].attr));
		/* Record the API result */
		record_uti_api_results(0);
		end_test(0, 0);
	}
	/*
	 ***************************************************************
	 * Test 12:  Testing conflicting cache placement requests
	 ***************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 1;
	while (begintest(testnum)) {
		/* Set test expectations */
		uthread[0].api_retval_expected = EINVAL;

		/* Setup and call the uti api */
		uti_attr_same_l2(&(uthread[0].attr));
		uti_attr_different_l2(&(uthread[0].attr));
		log_msg(LOG_DEBUG, "Node mask=%lx\n", nodes[0]);
		uthread[0].api_retval_actual = uti_pthread_create(
			&(uthread[0].pthread),
			&(uthread[0].pthread_attr),
			myuthread,
			(void *)0,
			&(uthread[0].attr));
		/* Record the API result */
		record_uti_api_results(0);
		end_test(0, 0);
	}
	/*
	 ***************************************************************
	 * Test 13:  Testing conflicting cache placement requests
	 ***************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 1;
	while (begintest(testnum)) {
		/* Set test expectations */
		uthread[0].api_retval_expected = EINVAL;

		/* Setup and call the uti api */
		uti_attr_same_l1(&(uthread[0].attr));
		uti_attr_different_l2(&(uthread[0].attr));
		log_msg(LOG_DEBUG, "Node mask=%lx\n", nodes[0]);
		uthread[0].api_retval_actual = uti_pthread_create(
			&(uthread[0].pthread),
			&(uthread[0].pthread_attr),
			myuthread,
			(void *)0,
			&(uthread[0].attr));
		/* Record the API result */
		record_uti_api_results(0);
		end_test(0, 0);
	}
	/*
	 *********************************************************
	 * Test 14: Location KEY test.
	 *          Create four util threads explicitly on FWK CPUs
	 *          with a key specifying that they should all be
	 *          in the same domain
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	if (!num_nodes_containing_utilitycpus) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires at least one utility CPU.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 4;

	while (begintest(testnum)) {
		/* Generate a new location key */
		location_key  = random();

		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_FWK;
			uthread[uindex].numa_id_expected = ALL_UTILS_SAME;

			/* Setup and call the uti api */
			uti_attr_prefer_fwk(&(uthread[uindex].attr));
			uti_attr_location_key(&(uthread[uindex].attr),
						location_key);
			uti_attr_same_numa_domain(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 15: Location KEY test.
	 *          Create four util threads explicitly on FWK CPUs
	 *          with a key specifying that they should all be
	 *          in the same L2
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	if (!num_nodes_containing_utilitycpus) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires at least one utility CPU.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 4;

	while (begintest(testnum)) {
		/* Generate a new location key */
		location_key  = random();

		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_FWK;
			uthread[uindex].numa_id_expected = ALL_UTILS_SAME;

			/* Setup and call the uti api */
			uti_attr_prefer_fwk(&(uthread[uindex].attr));
			uti_attr_location_key(&(uthread[uindex].attr),
						location_key);
			uti_attr_same_l2(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 16: Location KEY test.
	 *          Create two util threads explicitly on FWK CPUs
	 *          with a key specifying that they should be
	 *          in different domains
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	if (num_nodes_containing_utilitycpus < 2) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires utility CPUs in two domains.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 2;

	while (begintest(testnum)) {
		location_key = random();

		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_FWK;
			uthread[uindex].numa_id_expected = ALL_UTILS_DIFF;

			/* Setup and call the uti api */
			uti_attr_prefer_fwk(&(uthread[uindex].attr));
			uti_attr_location_key(&(uthread[uindex].attr),
						location_key);
			uti_attr_different_numa_domain(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 17: Create two util threads to be placed on CPUs
	 *          handling fabric interrupts. This test relies
	 *          on the mOS behavior that IRQs are redirected
	 *          to the non-LWK CPUs at LWK Partition creation.
	 *          The test does not explicitly test the CPU mask
	 *          of the fabric IRQs to see if the utility thread
	 *          is running on one of these CPUs. This could be
	 *          a future testcase enhancement.
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	if (!num_nodes_containing_utilitycpus) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires at least one utility CPU.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 2;

	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;
			uthread[uindex].behavior_expected = 1;
			uthread[uindex].cputype_expected = CPUTYPE_FWK;

			/* Setup and call the uti api */
			uti_attr_fabric_intr_affinity(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(num_uthreads, 0);
	}
	/*
	 *********************************************************
	 * Test 18: Create a util thread to be placed on a CPU
	 *          handling fabric interrupts. Also set a request
	 *          to place on a LWK CPU. Verify that this conflict
	 *          is surfaced as an invalid specification.
	 *********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	if (!num_nodes_containing_utilitycpus) {
		log_msg(LOG_INFO,
		    "Skipping test=%d. Requires at least one utility CPU.",
		    testnum);
		num_uthreads = 0; /* Skip test */
	} else
		num_uthreads = 1;

	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {

			/* Set test expectations for each utility thread */
			uthread[uindex].api_retval_expected = EINVAL;

			/* Setup and call the uti api */
			uti_attr_fabric_intr_affinity(&(uthread[uindex].attr));
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
				&(uthread[uindex].pthread),
				&(uthread[uindex].pthread_attr),
				myuthread,
				(void *)uindex,
				&(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		end_test(0, 0);
	}
	/*
	 **********************************************************
	 * Test 19: Validate that a process enivronment can be created
	 *          in which each CPU is hosting a compute thread and
	 *          a utility thread, and no CPU contains more than one
	 *          compute thread. We will alternately create compute threads
	 *          and utility threads until we have created 2 times the
	 *          number of CPUs available with threads. Verify that the
	 *          scheduler has placed the threads appropriately
	 **********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = num_lwkcpus; /* 1 on each CPU */
	num_cthreads = num_lwkcpus - 1; /* 1 on each CPU */

	while (begintest(testnum)) {
		uindex = 0;
		cindex = 0;
		while (uindex < num_uthreads || cindex < num_cthreads) {

			if (uindex < num_uthreads) {
				/* Set test expectations for utility thread */
				uthread[uindex].cputype_expected = CPUTYPE_LWK;
				uthread[uindex].enable_compute_cpu_share_test = 1;
				uthread[uindex].share_level_computes = 1;
				uthread[uindex].enable_util_cpu_share_test = 1;
				switch (overcommit_behavior) {
				case AllCommits:
					if (((uindex >= num_uthreads/2) &&
					  (uindex < num_uthreads - num_uthreads/4)) ||
					  (uindex < num_uthreads/4))
					uthread[uindex].share_level_utils = 2;
					else
					uthread[uindex].share_level_utils = 1;
					break;
				case OnlyComputeCommits:
					uthread[uindex].share_level_utils = num_uthreads;
					break;
				case OnlyUtilityCommits:
					uthread[uindex].share_level_utils = 1;
					break;
				}
				uthread[uindex].api_retval_expected = 0;
				uthread[uindex].placement_expected = 1;

				/* Setup and call the uti api */
				uti_attr_prefer_lwk(&(uthread[uindex].attr));
				uthread[uindex].api_retval_actual =
					uti_pthread_create(
					    &(uthread[uindex].pthread),
					    &(uthread[uindex].pthread_attr),
					    myuthread,
					    (void *)uindex,
					    &(uthread[uindex].attr));
				/* Record the API result */
				record_uti_api_results(uindex);
				uindex++;
			}
			if (cindex >= num_cthreads)
				continue;
			/* Set test expectations for each compute thread */
			cthread[cindex].enable_compute_cpu_share_test =
								      1;
			cthread[cindex].share_level_computes = 1;
			cthread[cindex].enable_util_cpu_share_test = 1;
			switch (overcommit_behavior) {
			case AllCommits:
				if (cindex < (num_uthreads/4 - 1))
					cthread[cindex].share_level_utils = 0;
				else if (cindex >=
					 (num_uthreads -
					  num_uthreads/4 - 1))
					cthread[cindex].share_level_utils = 2;
				else
					cthread[cindex].share_level_utils = 1;
				break;
			case OnlyUtilityCommits:
				cthread[cindex].share_level_utils = 1;
				break;
			case OnlyComputeCommits:
				if (cindex == num_cthreads - 1)
					cthread[cindex].share_level_utils = num_uthreads;
				else
					cthread[cindex].share_level_utils = 0;
				break;
			}
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;

			/* create a commpute thread */
			cthread[cindex].api_retval_actual =
				pthread_create(
				    &(cthread[cindex].pthread),
				    &(cthread[cindex].pthread_attr),
				    mycthread,
				    (void *)cindex);
			/* Record the API result */
			record_pthread_api_results(cindex);
			cindex++;
		}
		end_test(num_uthreads, num_cthreads);
	}
	/*
	 **********************************************************
	 * Test 20: Validate that a process enivronment can be created
	 *          in which each CPU is hosting a compute thread and
	 *          a utility thread, and no CPU contains more than one
	 *          compute thread. We will first create compute threads
	 *          to fill up all CPUs. We will then create utility
	 *          threads. Verify that the scheduler has placed
	 *          threads appropriately.
	 **********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = num_lwkcpus; /* 1 on each CPU */
	num_cthreads = num_lwkcpus - 1; /* 1 on each CPU */

	while (begintest(testnum)) {
		for (cindex = 0; cindex < num_cthreads; cindex++) {
			/* Set test expectations for each compute thread */
			cthread[cindex].enable_compute_cpu_share_test = 1;
			cthread[cindex].share_level_computes = 1;
			cthread[cindex].enable_util_cpu_share_test = 1;
			switch (overcommit_behavior) {
			case AllCommits:
			case OnlyUtilityCommits:
				cthread[cindex].share_level_utils = 1;
				break;
			case OnlyComputeCommits:
				if (cindex == num_cthreads - 1)
					cthread[cindex].share_level_utils = num_uthreads;
				else
					cthread[cindex].share_level_utils = 0;
			}
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;

			/* create a commpute thread */
			cthread[cindex].api_retval_actual = pthread_create(
			    &(cthread[cindex].pthread),
			    &(cthread[cindex].pthread_attr),
			    mycthread,
			    (void *)cindex);
			/* Record the API result */
			record_pthread_api_results(cindex);
		}
		for (uindex = 0; uindex < num_uthreads; uindex++) {
			/* Set test expectations for each utility thread */
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].enable_compute_cpu_share_test = 1;
			uthread[uindex].share_level_computes = 1;
			uthread[uindex].enable_util_cpu_share_test = 1;

			switch (overcommit_behavior) {
			case AllCommits:
			case OnlyUtilityCommits:
				uthread[uindex].share_level_utils = 1;
				break;
			case OnlyComputeCommits:
				uthread[uindex].share_level_utils = num_uthreads;
				break;
			}
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;

			/* Setup and call the uti api */
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
			    &(uthread[uindex].pthread),
			    &(uthread[uindex].pthread_attr),
			    myuthread,
			    (void *)uindex,
			    &(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}

		end_test(num_uthreads, num_cthreads);
	}
	/*
	 **********************************************************
	 * Test 21: Validate that a process enivronment can be created
	 *          in which each CPU is hosting a compute thread and
	 *          a utility thread, and no CPU contains more than one
	 *          compute thread. We will first create utility threads
	 *          to fill up all CPUs. Then we will create compute
	 *          threads until we have put a compute thread on
	 *          each CPU . Verify that the default layout of the
	 *          scheduler has placed one compute on each CPU.
	 **********************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = num_lwkcpus; /* 1 on each CPU */
	num_cthreads = num_lwkcpus - 1; /* 1 on each CPU */

	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {
			/* Set test expectations for each utility thread */
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].enable_compute_cpu_share_test = 1;
			uthread[uindex].share_level_computes = 1;
			uthread[uindex].enable_util_cpu_share_test = 1;
			switch (overcommit_behavior) {
			case AllCommits:
				if ((uindex == 0) ||
				    (uindex == num_uthreads - 1))
					uthread[uindex].share_level_utils = 2;
				else
					uthread[uindex].share_level_utils = 1;
				break;
			case OnlyComputeCommits:
				uthread[uindex].share_level_utils = num_uthreads;
				break;
			case OnlyUtilityCommits:
				uthread[uindex].share_level_utils = 1;
				break;
			}
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;

			/* Setup and call the uti api */
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
			    &(uthread[uindex].pthread),
			    &(uthread[uindex].pthread_attr),
			    myuthread,
			    (void *)uindex,
			    &(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		for (cindex = 0; cindex < num_cthreads; cindex++) {
			/* Set test expectations for each compute thread */
			cthread[cindex].enable_compute_cpu_share_test = 1;
			cthread[cindex].share_level_computes = 1;
			cthread[cindex].enable_util_cpu_share_test = 1;
			switch (overcommit_behavior) {
			case AllCommits:
				if (cindex == num_cthreads - 1)
					cthread[cindex].share_level_utils = 2;
				else
					cthread[cindex].share_level_utils = 1;
				break;
			case OnlyComputeCommits:
				if (cindex == num_cthreads - 1)
					cthread[cindex].share_level_utils = num_uthreads;
				else
					cthread[cindex].share_level_utils = 0;
				break;
			case OnlyUtilityCommits:
				cthread[cindex].share_level_utils = 1;
				break;
			}
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;

			/* create a commpute thread */
			cthread[cindex].api_retval_actual = pthread_create(
			    &(cthread[cindex].pthread),
			    &(cthread[cindex].pthread_attr),
			    mycthread,
			    (void *)cindex);
			/* Record the API result */
			record_pthread_api_results(cindex);
		}

		end_test(num_uthreads, num_cthreads);
	}
	/*
	 **********************************************************************
	 * Test 22: Validate that a process enivronment can be created
	 *          in which each CPU is hosting a compute thread and multiple
	 *          utility threads, and no CPU contains more than one
	 *          compute thread. We will first create a total number of
	 *          utility threads equal to 2 times the number of available
	 *          CPUs. Then we will create compute threads until we have one
	 *          compute thread on each CPU.
	 **********************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = num_lwkcpus * 2; /* 2  on each CPU */
	num_cthreads = num_lwkcpus - 1; /* 1 on each CPU */

	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {
			/* Set test expectations for each utility thread */
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].enable_compute_cpu_share_test = 1;
			uthread[uindex].share_level_computes = 1;
			uthread[uindex].enable_util_cpu_share_test = 1;
			switch (overcommit_behavior) {
			case AllCommits:
				if ((uindex == 0) ||
				    (uindex == num_uthreads/2 - 1) ||
				    (uindex == num_uthreads - 1))
					uthread[uindex].share_level_utils = 3;
				else if (uindex == num_uthreads - 2)
					uthread[uindex].share_level_utils = 1;
				else
					uthread[uindex].share_level_utils = 2;
				break;
			case OnlyComputeCommits:
				uthread[uindex].share_level_utils = num_uthreads;
				break;
			case OnlyUtilityCommits:
				uthread[uindex].share_level_utils = 2;
				break;
			}
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;

			/* Setup and call the uti api */
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
			    &(uthread[uindex].pthread),
			    &(uthread[uindex].pthread_attr),
			    myuthread,
			    (void *)uindex,
			    &(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		for (cindex = 0; cindex < num_cthreads; cindex++) {
			/* Set test expectations for each compute thread */
			cthread[cindex].enable_compute_cpu_share_test = 1;
			cthread[cindex].share_level_computes = 1;
			cthread[cindex].enable_util_cpu_share_test = 1;
			switch (overcommit_behavior) {
			case AllCommits:
				if (cindex == num_cthreads - 1)
					cthread[cindex].share_level_utils = 3;
				else
					cthread[cindex].share_level_utils = 2;
				break;
			case OnlyComputeCommits:
				if (cindex == num_cthreads - 1)
					cthread[cindex].share_level_utils = num_uthreads;
				else
					cthread[cindex].share_level_utils = 0;
				break;
			case OnlyUtilityCommits:
				cthread[cindex].share_level_utils = 2;
				break;
			}
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;

			/* create a commpute thread */
			cthread[cindex].api_retval_actual = pthread_create(
			    &(cthread[cindex].pthread),
			    &(cthread[cindex].pthread_attr),
			    mycthread,
			    (void *)cindex);
			/* Record the API result */
			record_pthread_api_results(cindex);
		}

		end_test(num_uthreads, num_cthreads);
	}
	/*
	 **********************************************************************
	 * Test 23: Validate that a process enivronment can be created
	 *          in which a utility thread can be located at some location
	 *          other than the end of the sequence list for the compute
	 *          threads and fill up all of the CPUs with compute threads
	 *          with no overcommitting of any CPUs. The CPU assignment for
	 *          the compute thread should skip the CPU occupied by the
	 *          utility thread and be committed to the remaining available
	 *          CPUs.
	 **********************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 1;
	/* Set number of cthreads equal to the number of CPUs minus the CPU
	 * that the main thread occupies, minus the CPU(s) that the unthread(s)
	 * will occupy.
	 */
	num_cthreads = num_lwkcpus - 1 - num_uthreads;

	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {
			/* Set test expectations for each utility thread */
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			if (overcommit_behavior == AllCommits)
				uthread[uindex].enable_compute_cpu_share_test = 1;
			uthread[uindex].share_level_computes = 0;
			uthread[uindex].enable_util_cpu_share_test = 1;
			uthread[uindex].share_level_utils = 1;
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;

			/* Setup and call the uti api */
			uti_attr_same_l2(&(uthread[uindex].attr));
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
			    &(uthread[uindex].pthread),
			    &(uthread[uindex].pthread_attr),
			    myuthread,
			    (void *)uindex,
			    &(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		for (cindex = 0; cindex < num_cthreads; cindex++) {
			/* Set test expectations for each compute thread */
			if (overcommit_behavior == AllCommits)
				cthread[cindex].enable_util_cpu_share_test = 1;
			cthread[cindex].share_level_utils = 0;
			cthread[cindex].enable_compute_cpu_share_test = 1;
			cthread[cindex].share_level_computes = 1;
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;

			/* create a commpute thread */
			cthread[cindex].api_retval_actual = pthread_create(
			    &(cthread[cindex].pthread),
			    &(cthread[cindex].pthread_attr),
			    mycthread,
			    (void *)cindex);
			/* Record the API result */
			record_pthread_api_results(cindex);
		}

		end_test(num_uthreads, num_cthreads);
	}
	/*
	 **********************************************************************
	 * Test 24: Validate that a process enivronment can be created
	 *          in which an utility thread is created to run
	 *          exclusively on an LWK CPU. Compute threads and
	 *          additional utility threads are also created, overcommitting
	 *          the available CPU resources. Verify that no other threads
	 *          are placed on the utility thread that is designated as
	 *          needing exclusive use of a CPU.
	 **********************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 3;
	num_cthreads = num_lwkcpus;

	while (begintest(testnum)) {
		for (uindex = 0; uindex < num_uthreads; uindex++) {
			/* Set test expectations for each utility thread */
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;

			/* Setup and call the uti api */
			if (uindex == 1) {
				uti_attr_exclusive_cpu(&(uthread[uindex].attr));
				uthread[uindex].behavior_expected = 1;
				uthread[uindex].enable_util_cpu_share_test = 1;
				uthread[uindex].share_level_utils = 1;
				uthread[uindex].enable_compute_cpu_share_test = 1;
				uthread[uindex].share_level_computes = 0;
			}
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
			    &(uthread[uindex].pthread),
			    &(uthread[uindex].pthread_attr),
			    myuthread,
			    (void *)uindex,
			    &(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}
		for (cindex = 0; cindex < num_cthreads; cindex++) {
			/* Set test expectations for each compute thread */
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;

			/* create a commpute thread */
			cthread[cindex].api_retval_actual = pthread_create(
			    &(cthread[cindex].pthread),
			    &(cthread[cindex].pthread_attr),
			    mycthread,
			    (void *)cindex);
			/* Record the API result */
			record_pthread_api_results(cindex);
		}

		end_test(num_uthreads, num_cthreads);
	}
	/*
	 **********************************************************************
	 * Test 25: Create an environment where all CPUs are occuppied by
	 *          compute threads and utility threads and then attempt to
	 *          create a utility thread that requires an exclusive CPU.
	 *          Verify that the the API returns an indication that the
	 *          requested exclusive behavior was not honored.
	 **********************************************************************
	 */
	testnum++;

	/* Prep environment for starting testcase */
	num_uthreads = 3;
	num_cthreads = num_lwkcpus - num_uthreads;

	while (begintest(testnum)) {
		for (cindex = 0; cindex < num_cthreads; cindex++) {
			/* Set test expectations for each compute thread */
			cthread[cindex].api_retval_expected = 0;
			cthread[cindex].cputype_expected = CPUTYPE_LWK;

			/* create a commpute thread */
			cthread[cindex].api_retval_actual = pthread_create(
			    &(cthread[cindex].pthread),
			    &(cthread[cindex].pthread_attr),
			    mycthread,
			    (void *)cindex);
			/* Record the API result */
			record_pthread_api_results(cindex);
		}

		for (uindex = 0; uindex < num_uthreads; uindex++) {
			/* Set test expectations for each utility thread */
			uthread[uindex].cputype_expected = CPUTYPE_LWK;
			uthread[uindex].api_retval_expected = 0;
			uthread[uindex].placement_expected = 1;

			/* Setup and call the uti api */
			if (uindex == num_uthreads - 1) {
				uti_attr_exclusive_cpu(&(uthread[uindex].attr));
				/* No free CPU, expect behavior fail reported */
				uthread[uindex].behavior_expected = 0;
				uthread[uindex].enable_util_cpu_share_test = 1;
				uthread[uindex].share_level_utils = 1;
				uthread[uindex].enable_compute_cpu_share_test = 1;
				uthread[uindex].share_level_computes = 0;
			}
			uti_attr_prefer_lwk(&(uthread[uindex].attr));
			uthread[uindex].api_retval_actual = uti_pthread_create(
			    &(uthread[uindex].pthread),
			    &(uthread[uindex].pthread_attr),
			    myuthread,
			    (void *)uindex,
			    &(uthread[uindex].attr));
			/* Record the API result */
			record_uti_api_results(uindex);
		}

		end_test(num_uthreads, num_cthreads);
	}
	/************************************************
	 * All tests completed. Now summarize the results
	 ************************************************/
	rc = summarize();
out:
	return rc;
}

static void usage(void)
{
	printf(
	    "uti_placement [--behavior <N>] [--subtest <N>] [--debug].. [--help]\n");
}
