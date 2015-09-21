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

#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <mos.h>
#include <stdarg.h>
#include <getopt.h>
#include <locale.h>
#include "lwksched.h"

#define NDSZ  4

#define BITS_IN_LONG (sizeof(unsigned long) * 8)
#define MAX_NUMNODES (NDSZ * BITS_IN_LONG)
#define NUMNODES 8

static unsigned long nodes[NDSZ];
static void usage(void);

static int ret;

static int numtests;
static int numfails;
static int numsuccess;

struct mos_clone_attr attr;
struct mos_clone_result result;

static void initnodes(void)
{
       int i;

	for (i = 0; i < NDSZ; i++)
		nodes[i] = 0;
}

static void initattr(void)
{
	attr.size = sizeof(struct mos_clone_attr);
	attr.flags = 0;
	attr.behavior = 0;
	attr.placement = 0;
}

static void initresult(void)
{
	result.behavior = 0;
	result.placement = 0;
}

static void begintest(void)
{
	initnodes();
	initattr();
	initresult();
	numtests++;
	errno = 0;
	log_msg(LOG_DEBUG, "Beginning test=%d...\n", numtests);
}

static void expect(int expectrc, long int expectval,
		   unsigned int result_behavior,
		   unsigned int result_placement)
{
	if (errno != expectval || ret != expectrc) {
		log_msg(LOG_ERR,
			"Test=%d failed. rc/errno expected=%d/%d actual=%d/%d\n",
			numtests, expectrc, expectval, ret, errno);
		numfails += 1;
	} else if (result.behavior != result_behavior) {
		log_msg(LOG_ERR,
			"Test=%d failed. behavior result expected=%u actual=%u\n",
			numtests, result_behavior, result.behavior);
		numfails += 1;
	} else if (result.placement != result_placement) {
		log_msg(LOG_ERR,
			"Test=%d failed. placement result expected=%u actual=%u\n",
			numtests, result_placement, result.placement);
		numfails += 1;
	} else {
		log_msg(LOG_DEBUG,
			"Test=%d passed. rc/errno: %d/%d\n",
			numtests, ret, errno);
		numsuccess += 1;
	}
}

static int summarize(void)
{
	log_msg(LOG_INFO, "Tests run: %d Successes: %d Failures: %d\n",
		numtests, numsuccess, numfails);
	if (numfails || (numtests != (numsuccess + numfails)))
		return -1;
	return 0;
}

/* Basic test of parameter validity */
int main(int argc, char **argv)
{
	int rc, i;

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
	/*
	 * Size of attribute structure mismatch
	 * expect errno = EINVAL
	 */
	begintest();
	attr.size = sizeof(struct mos_clone_attr) - 1;
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	ret = mos_set_clone_attr(&attr, NUMNODES, nodes, &result, 0);
	expect(-1, EINVAL, 0, 0);

	/*
	 * Invalid pointer to attributes
	 * expect errno = EFAULT
	 */
	begintest();
	ret = mos_set_clone_attr((void *)0x10, NUMNODES, nodes, &result, 0);
	expect(-1, EFAULT, 0, 0);

	/*
	 * Invalid pointer to node mask
	 * expect errno = EFAULT
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	ret = mos_set_clone_attr(&attr, NUMNODES, (unsigned long *)0x10,
				&result, 0);
	expect(-1, EFAULT, 0, 0);

	/*
	 * Request for same and different domain
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	attr.placement |= MOS_CLONE_ATTR_SAME_DOMAIN;
	attr.placement |= MOS_CLONE_ATTR_DIFF_DOMAIN;
	ret = mos_set_clone_attr(&attr, NUMNODES, nodes, &result, 0);
	expect(-1, EINVAL, 0, 0);

	/*
	 * Request for same cache for two levels
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	attr.placement |= MOS_CLONE_ATTR_SAME_L1CACHE;
	attr.placement |= MOS_CLONE_ATTR_SAME_L2CACHE;
	ret = mos_set_clone_attr(&attr, NUMNODES, nodes, &result, 0);
	expect(-1, EINVAL, 0, 0);

	/*
	 * Request with no node mask provided requesting domain placement
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	attr.placement |= MOS_CLONE_ATTR_USE_NODE_SET;
	ret = mos_set_clone_attr(&attr, 0, NULL, &result, 0);
	expect(-1, EINVAL, 0, 0);

	/*
	 * Request with no node set in mask, requesting domain placement
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	attr.placement |= MOS_CLONE_ATTR_USE_NODE_SET;
	ret = mos_set_clone_attr(&attr, 0, nodes, &result, 0);
	expect(-1, EINVAL, 0, 0);

	/*
	 * Request with no node mask provided not requesting domain placement
	 * Not requesting behavior modification
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	attr.placement |= MOS_CLONE_ATTR_SAME_L1CACHE;
	ret = mos_set_clone_attr(&attr, 0, NULL, &result, 0);
	expect(0, 0, 0,	MOS_CLONE_PLACEMENT_REQUESTED);

	/*
	 * Request with no node mask provided not requesting any placement
	 * Requesting behavior
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	attr.behavior |= MOS_CLONE_ATTR_NON_COOP;
	ret = mos_set_clone_attr(&attr, 0, NULL, &result, 0);
	expect(0, 0, MOS_CLONE_BEHAVIOR_REQUESTED, 0);

	/*
	 * Valid domain placement request using num nodes = 8, contained
	 * in a mask of size unsigned long.
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	nodes[0] = 0x10;
	attr.placement |= MOS_CLONE_ATTR_USE_NODE_SET;
	attr.behavior |= MOS_CLONE_ATTR_NON_COOP;
	ret = mos_set_clone_attr(&attr, NUMNODES, nodes, &result, 0);
	expect(0, 0, MOS_CLONE_BEHAVIOR_REQUESTED,
		MOS_CLONE_PLACEMENT_REQUESTED);

	/*
	 * Domain placement request using max num nodes > 64.
	 * As long as no node is set within the bitmask area that exceeds
	 * the size of the kernel bitmask, this should succeed.
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	nodes[0] = 1;
	attr.placement |= MOS_CLONE_ATTR_USE_NODE_SET;
	attr.behavior |= MOS_CLONE_ATTR_NON_COOP;
	ret = mos_set_clone_attr(&attr, MAX_NUMNODES, nodes, &result, 0);
	expect(0, 0, MOS_CLONE_BEHAVIOR_REQUESTED,
		MOS_CLONE_PLACEMENT_REQUESTED);

	/*
	 * Domain placement request using max num nodes > 64.
	 * Set a node outside of the nodes that are supported
	 * by a 64 bit mask. This should fail since the kernel
	 * can only deal with a node that can be contained in its
	 * bitmask within the nodemask_t structure.
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	nodes[NDSZ - 1] = 1;
	attr.placement |= MOS_CLONE_ATTR_USE_NODE_SET;
	attr.behavior |= MOS_CLONE_ATTR_NON_COOP;
	ret = mos_set_clone_attr(&attr, MAX_NUMNODES, nodes, &result, 0);
	expect(-1, EINVAL, 0, 0);

	/*
	 * Provide a location key. Loop to wrap within the kernel key table.
	 */
	for (i = 0; i < 10; i++) {
		begintest();
		attr.flags |= MOS_CLONE_ATTR_UTIL;
		attr.placement |= MOS_CLONE_ATTR_SAME_DOMAIN;
		attr.behavior |= MOS_CLONE_ATTR_NON_COOP;
		ret = mos_set_clone_attr(&attr, NUMNODES, nodes, &result, i+1);
		expect(0, 0, MOS_CLONE_BEHAVIOR_REQUESTED,
			MOS_CLONE_PLACEMENT_REQUESTED);
	}

	/*
	 * Typical request
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_UTIL;
	attr.placement |= MOS_CLONE_ATTR_SAME_DOMAIN;
	attr.behavior |= MOS_CLONE_ATTR_NON_COOP;
	ret = mos_set_clone_attr(&attr, NUMNODES, nodes, &result, 0);
	expect(0, 0, MOS_CLONE_BEHAVIOR_REQUESTED,
		MOS_CLONE_PLACEMENT_REQUESTED);

	/*
	 * Typical clear request
	 */
	begintest();
	attr.flags |= MOS_CLONE_ATTR_CLEAR;
	ret = mos_set_clone_attr(&attr, 0, NULL, NULL, 0);
	expect(0, 0, 0, 0);

	rc = summarize();

	return rc;
}

static void usage(void)
{
	printf("set_clone_attr [--debug].. [--help]\n");
}
