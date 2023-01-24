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

#include <unistd.h>
#include "../../../include/uapi/asm-generic/unistd.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "../../../include/uapi/linux/mos.h"
#include "../../../include/uapi/linux/uti.h"
#include <pthread.h>
#include <stdio.h>

#define UTI_ATTR ((struct _uti_attr *)attr)
/*
 * This is the opaque attribute object used to hold the behavior and
 * placement hints and to hold the results of the uti_pthread_create
 * request.
 */
struct _uti_attr {
	struct {
		unsigned long behavior;
		unsigned long location;
		unsigned long *nodes;
		unsigned long maxnodes;
		unsigned long key;
	} request;
	struct {
		unsigned long behavior;
		unsigned long location;
	} result;
};

/*
 * Initialize the attribute structure
 */
int uti_attr_init(uti_attr_t *attr)
{
	if (sizeof(struct _uti_attr) > __SIZEOF_UTI_ATTR)
		return EINVAL;
	if (!attr)
		return EINVAL;
	memset(attr, 0, sizeof(struct _uti_attr));
	return 0;
}

/*
 * Destroy the object of utility thread attributes pointed
 * to by uti_attr.
 */
int uti_attr_destroy(uti_attr_t *attr)
{
	/*
	 * destroy an initialized attribute object
	 */
	free(UTI_ATTR->request.nodes);
	return 0;
}

/*
 * Set numa_set attribute of uti_attr to the set specified by
 * nodemask and maxnode and make the attribute valid. nodemask
 * points to a bit vector whose length is maxnode.
 */
int uti_attr_numa_set(uti_attr_t *attr, unsigned long *nodemask,
		unsigned long maxnodes)
{
	int sz = sizeof(unsigned long);
	size_t nodemask_size = ((maxnodes + sz - 1)/sz) * sz;

	UTI_ATTR->request.nodes = malloc(nodemask_size);
	UTI_ATTR->request.maxnodes = maxnodes;
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_USE_NODE_SET;
	memcpy(UTI_ATTR->request.nodes, nodemask, nodemask_size);

	return 0;
}

/*
 * Indicate that the utility thread should run in
 * the same NUMA domain as the caller
 */
int uti_attr_same_numa_domain(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_SAME_DOMAIN;
	return 0;
}

/*
 * Indicate that the utility thread should run in
 * a different NUMA domain as the caller
 */
int uti_attr_different_numa_domain(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_DIFF_DOMAIN;
	return 0;
}

/*
 * Indicate that the utility thread should run in
 * the same L1 as the caller
 */
int uti_attr_same_l1(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_SAME_L1CACHE;
	return 0;
}

/*
 * Indicate that the utility thread should run in
 * a different L1 as the caller
 */
int uti_attr_different_l1(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_DIFF_L1CACHE;
	return 0;
}

/*
 * Indicate that the utility thread should run in
 * the same L2 as the caller
 */
int uti_attr_same_l2(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_SAME_L2CACHE;
	return 0;
}

/*
 * Indicate that the utility thread should run in
 * a different L2 as the caller
 */
int uti_attr_different_l2(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_DIFF_L2CACHE;
	return 0;
}

/*
 * Indicate that the utility thread should run in
 * the same L3 as the caller
 */
int uti_attr_same_l3(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_SAME_L3CACHE;
	return 0;
}

/*
 * Indicate that the utility thread should run in
 * a different L3 as the caller
 */
int uti_attr_different_l3(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_DIFF_L3CACHE;
	return 0;
}

/*
 * Indicate a preference to run on an LWK CPU
 */
int uti_attr_prefer_lwk(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_LWK_CPU;
	return 0;
}

/*
 * Indicate a preference to run on a Linux CPU
 */
int uti_attr_prefer_fwk(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_FWK_CPU;
	return 0;
}

/*
 * Indicate a preference to run on a Linux CPU
 */
int uti_attr_fabric_intr_affinity(uti_attr_t *attr)
{
	UTI_ATTR->request.location |= MOS_CLONE_ATTR_FABRIC_INT;
	return 0;
}

/*
 * Indicate that this utility thread requests exclusive use
 * of a CPU
 */
int uti_attr_exclusive_cpu(uti_attr_t *attr)
{
	UTI_ATTR->request.behavior |= MOS_CLONE_ATTR_EXCL;
	return 0;
}

/*
 * Indicate that this utility thread is CPU Intensive
 */
int uti_attr_cpu_intensive(uti_attr_t *attr)
{
	UTI_ATTR->request.behavior |= MOS_CLONE_ATTR_HCPU;
	return 0;
}

/*
 * Indicate that this utility thread requests to be treated
 * with high scheduling priority
 */
int uti_attr_high_priority(uti_attr_t *attr)
{
	UTI_ATTR->request.behavior |= MOS_CLONE_ATTR_HPRIO;
	return 0;
}

/*
 * Indicate that this utility thread requests to be treated
 * with low scheduling priority
 */
int uti_attr_low_priority(uti_attr_t *attr)
{
	UTI_ATTR->request.behavior |= MOS_CLONE_ATTR_LPRIO;
	return 0;
}

/*
 * Indicate that this utility thread is non cooperative,
 * i.e. does not yield or block often.
 */
int uti_attr_non_cooperative(uti_attr_t *attr)
{
	UTI_ATTR->request.behavior |= MOS_CLONE_ATTR_NON_COOP;
	return 0;
}

/*
 * Set a key to be used to match same/different location requests
 * with other utility threads having the same key. This changes the
 * behavior of these same/different location requests to not use the
 * caller location information for comparisons.
 */
int uti_attr_location_key(uti_attr_t *attr, unsigned long key)
{
	UTI_ATTR->request.key = key;
	return 0;
}

/*
 * Was a request to place on a specific domain honored
 */
int uti_result_numa_set(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_USE_NODE_SET) ?
		1 : 0;
}

/*
 * Was a request to place on the same domain honored
 */
int uti_result_same_numa_domain(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_SAME_DOMAIN) ? 1 : 0;
}

/*
 * Was a request to place on a different domain honored
 */
int uti_result_different_numa_domain(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_DIFF_DOMAIN) ? 1 : 0;
}

/*
 * Was a request to place on the same L1 honored
 */
int uti_result_same_l1(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_SAME_L1CACHE) ?
		1 : 0;
}

/*
 * Was a request to place on a different L1 honored
 */
int uti_result_different_l1(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_DIFF_L1CACHE) ?
		1 : 0;
}

/*
 * Was a request to place on the same L2 honored
 */
int uti_result_same_l2(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_SAME_L2CACHE) ?
		1 : 0;
}

/*
 * Was a request to place on a different L2 honored
 */
int uti_result_different_l2(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_DIFF_L2CACHE) ?
		1 : 0;
}

/*
 * Was a request to place on the same L3 honored
 */
int uti_result_same_l3(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_SAME_L3CACHE) ?
		1 : 0;
}

/*
 * Was a request to place on a different L3 honored
 */
int uti_result_different_l3(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_DIFF_L3CACHE) ?
		1 : 0;
}

/*
 * Was preference to run on an LWK CPU honored
 */
int uti_result_prefer_lwk(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_LWK_CPU) ? 1 : 0;
}

/*
 * Was preference to run on a Linux CPU honored
 */
int uti_result_prefer_fwk(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_FWK_CPU) ? 1 : 0;
}

/*
 * Was preference to run on a Linux CPU honored
 */
int uti_result_fabric_intr_affinity(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location & MOS_CLONE_ATTR_FABRIC_INT) ? 1 : 0;
}

/*
 * Was a request to run exclusively on a cpu honored
 */
int uti_result_exclusive_cpu(uti_attr_t *attr)
{
	return (UTI_ATTR->result.behavior & MOS_CLONE_ATTR_EXCL) ? 1 : 0;
}

/*
 * Was a request to recognize a cpu intensive thread honored
 */
int uti_result_cpu_intensive(uti_attr_t *attr)
{
	return (UTI_ATTR->result.behavior & MOS_CLONE_ATTR_HCPU) ? 1 : 0;
}

/*
 * Was a request to treat as a high priority thread honored
 */
int uti_result_high_priority(uti_attr_t *attr)
{
	return (UTI_ATTR->result.behavior & MOS_CLONE_ATTR_HPRIO) ? 1 : 0;
}

/*
 * Was a request to treat as a low priority thread  honored
 */
int uti_result_low_priority(uti_attr_t *attr)
{
	return (UTI_ATTR->result.behavior & MOS_CLONE_ATTR_LPRIO) ? 1 : 0;
}

/*
 * Was a request to treat thread as non-cooperative honored
 */
int uti_result_non_cooperative(uti_attr_t *attr)
{
	return (UTI_ATTR->result.behavior & MOS_CLONE_ATTR_NON_COOP) ? 1 : 0;
}

/*
 * Was the behavior request satisfied
 */
int uti_result_behavior(uti_attr_t *attr)
{
	return (UTI_ATTR->result.behavior == UTI_ATTR->request.behavior);
}

/*
 * Was the location request satisfied
 */
int uti_result_location(uti_attr_t *attr)
{
	return (UTI_ATTR->result.location == UTI_ATTR->request.location);
}

/*
 * Was the uti request satisfied
 */
int uti_result(uti_attr_t *attr)
{
	int location =
		(UTI_ATTR->result.location == UTI_ATTR->request.location);
	int behavior =
		(UTI_ATTR->result.behavior == UTI_ATTR->request.behavior);

	return (location && behavior);
}

/*
 * Create a pthread-compatible non-computational thread and denote the
 * utility thread attributes specified by uti_attr.
 */
int uti_pthread_create(pthread_t *thread,
			const pthread_attr_t *pthread_attr,
			void *(*start_routine)(void *), void *arg,
			uti_attr_t *attr)
{
	struct mos_clone_attr clone_attr;
	struct mos_clone_result clone_result;
	int rc;

	memset(&clone_attr, 0, sizeof(clone_attr));
	memset(&clone_result, 0, sizeof(clone_result));

	clone_attr.flags = MOS_CLONE_ATTR_UTIL;
	clone_attr.size = sizeof(clone_attr);
	clone_attr.behavior = UTI_ATTR->request.behavior;
	clone_attr.placement = UTI_ATTR->request.location;

	rc = syscall(511, &clone_attr, UTI_ATTR->request.maxnodes,
			UTI_ATTR->request.nodes, &clone_result,
			UTI_ATTR->request.key);
	if (rc)
		return errno;
	rc = pthread_create(thread, pthread_attr, start_routine, arg);
	if (rc) {
		memset(&clone_attr, 0, sizeof(clone_attr));
		clone_attr.flags = MOS_CLONE_ATTR_CLEAR;
		syscall(511, &clone_attr, 0, NULL, NULL);
		return rc;
	}
	if (clone_result.behavior == MOS_CLONE_BEHAVIOR_ACCEPTED)
		UTI_ATTR->result.behavior =
			UTI_ATTR->request.behavior;
	if (clone_result.placement == MOS_CLONE_PLACEMENT_ACCEPTED)
		UTI_ATTR->result.location =
			UTI_ATTR->request.location;
	return 0;
}
