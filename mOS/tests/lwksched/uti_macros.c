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
#include <uti.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "lwksched.h"

#define BITS_IN_LONG (sizeof(unsigned long) * 8)
#define NUMNODES 8

static int testnum;
static int testfail;
static uti_attr_t attr;

static void usage(void);

static void begin_test(void)
{
	testnum++;
	uti_attr_init(&attr);
}

static void end_test(long int rc)
{
	if (rc) {
		log_msg(LOG_ERR, "Test=%d failed with rc=%d", testnum, rc);
		testfail++;
	}
	uti_attr_destroy(&attr);
}

static int summarize_results(void)
{
	log_msg(LOG_INFO,
		"Tests run: %d Successes: %d Failures: %d",
		testnum, testnum - testfail, testfail);
	return testfail ? -1 : 0;
}

/* Verify that the macro interfaces properly invoke the library
 * function interfaces.
 */
int main(int argc, char **argv)
{
	long int rc;
	unsigned long nodemask = 0;
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
		}
	}

	if (optind != argc) {
		usage();
		return -1;
	}

	log_msg(LOG_INFO, "Begin UTI macro tests...");

	/* Test 1 */
	begin_test();
	rc = UTI_ATTR_SAME_L1(&attr);
	end_test(rc);

	/* Test 2 */
	begin_test();
	rc = UTI_ATTR_SAME_L2(&attr);
	end_test(rc);

	/* Test 3 */
	begin_test();
	rc = UTI_ATTR_SAME_L3(&attr);
	end_test(rc);

	/* Test 4 */
	begin_test();
	rc = UTI_ATTR_DIFFERENT_L1(&attr);
	end_test(rc);

	/* Test 5 */
	begin_test();
	rc = UTI_ATTR_DIFFERENT_L2(&attr);
	end_test(rc);

	/* Test 6 */
	begin_test();
	rc = UTI_ATTR_DIFFERENT_L3(&attr);
	end_test(rc);

	/* Test 7 */
	begin_test();
	rc = UTI_ATTR_PREFER_LWK(&attr);
	end_test(rc);

	/* Test 8 */
	begin_test();
	rc = UTI_ATTR_PREFER_FWK(&attr);
	end_test(rc);

	/* Test 9 */
	begin_test();
	rc = UTI_ATTR_FABRIC_INTR_AFFINITY(&attr);
	end_test(rc);

	/* Test 10 */
	begin_test();
	rc = UTI_ATTR_HIGH_PRIORITY(&attr);
	end_test(rc);

	/* Test 11 */
	begin_test();
	rc = UTI_ATTR_LOW_PRIORITY(&attr);
	end_test(rc);

	/* Test 12 */
	begin_test();
	rc = UTI_ATTR_NON_COOPERATIVE(&attr);
	end_test(rc);

	/* Test 13 */
	begin_test();
	rc = UTI_ATTR_CPU_INTENSIVE(&attr);
	end_test(rc);

	/* Test 14 */
	begin_test();
	rc = UTI_ATTR_LOCATION_KEY(&attr, 0x1234567);
	end_test(rc);

	/* Test 15 */
	begin_test();
	rc = UTI_ATTR_SAME_NUMA_DOMAIN(&attr);
	end_test(rc);

	/* Test 16 */
	begin_test();
	rc = UTI_ATTR_DIFFERENT_NUMA_DOMAIN(&attr);
	end_test(rc);

	/* Test 17 */
	begin_test();
	rc = UTI_ATTR_NUMA_SET(&attr, &nodemask, NUMNODES);
	end_test(rc);

	/* Test 18 */
	begin_test();
	rc = UTI_RESULT_NUMA_SET(&attr);
	end_test(rc);

	/* Test 19 */
	begin_test();
	rc = UTI_RESULT_DIFFERENT_NUMA_DOMAIN(&attr);
	end_test(rc);

	/* Test 20 */
	begin_test();
	rc = UTI_RESULT_SAME_L1(&attr);
	end_test(rc);

	/* Test 21 */
	begin_test();
	rc = UTI_RESULT_SAME_L2(&attr);
	end_test(rc);

	/* Test 22 */
	begin_test();
	rc = UTI_RESULT_SAME_L3(&attr);
	end_test(rc);

	/* Test 23 */
	begin_test();
	rc = UTI_RESULT_DIFFERENT_L1(&attr);
	end_test(rc);

	/* Test 24 */
	begin_test();
	rc = UTI_RESULT_DIFFERENT_L2(&attr);
	end_test(rc);

	/* Test 25 */
	begin_test();
	rc = UTI_RESULT_DIFFERENT_L3(&attr);
	end_test(rc);

	/* Test 26 */
	begin_test();
	rc = UTI_RESULT_PREFER_LWK(&attr);
	end_test(rc);

	/* Test 27 */
	begin_test();
	rc = UTI_RESULT_PREFER_FWK(&attr);
	end_test(rc);

	/* Test 28 */
	begin_test();
	rc = UTI_RESULT_FABRIC_INTR_AFFINITY(&attr);
	end_test(rc);

	/* Test 29 */
	begin_test();
	rc = UTI_RESULT_HIGH_PRIORITY(&attr);
	end_test(rc);

	/* Test 30 */
	begin_test();
	rc = UTI_RESULT_LOW_PRIORITY(&attr);
	end_test(rc);

	/* Test 31 */
	begin_test();
	rc = UTI_RESULT_NON_COOPERATIVE(&attr);
	end_test(rc);

	/* Test 32 */
	begin_test();
	rc = UTI_RESULT_CPU_INTENSIVE(&attr);
	end_test(rc);

	return summarize_results();
}

static void usage(void)
{
	printf("uti_macros [--debug].. [--help]\n");
}
