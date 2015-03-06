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

#ifndef _LIB_MOS_H
#define _LIB_MOS_H

/* mOS memory system calls */

long mos_get_addr_info(unsigned long addr, unsigned long *phys_addr,
	int *numa_domain, int *page_size);

/* mOS scheduler system calls */

enum mos_mwait_sleep {
	mos_mwait_sleep_normal,
	mos_mwait_sleep_deep,
};

struct mos_clone_attr {
	unsigned int size;
	unsigned int flags;
	unsigned int behavior;
	unsigned int placement;
};

struct mos_clone_result {
	unsigned int behavior;
	unsigned int placement;
};

/* mos_set_clone_attr flags */
#define MOS_CLONE_ATTR_CLEAR	0x00000001 /* Clear pending attributes */
#define MOS_CLONE_ATTR_UTIL	0x00000002 /* Utility thread */

/* mos_set_clone_attr behaviors */
#define MOS_CLONE_ATTR_EXCL	0x00000001	/* Needs an exclusive CPU */
#define MOS_CLONE_ATTR_HCPU	0x00000002	/* High CPU use, i.e. polling */
#define MOS_CLONE_ATTR_HPRIO	0x00000004	/* High priority scheduling */
#define MOS_CLONE_ATTR_LPRIO	0x00000008	/* Low priority scheduling */
#define MOS_CLONE_ATTR_NON_COOP	0x00000010	/* Doesn't yld/blk often */

/* mos_set_clone_attr placement */
#define MOS_CLONE_ATTR_SAME_L1CACHE 0x00000001	/* Same cache as caller */
#define MOS_CLONE_ATTR_SAME_L2CACHE 0x00000002	/* Same cache as caller */
#define MOS_CLONE_ATTR_SAME_L3CACHE 0x00000004	/* Same cache as caller */
#define MOS_CLONE_ATTR_DIFF_L1CACHE 0x00000008	/* Different cache as caller */
#define MOS_CLONE_ATTR_DIFF_L2CACHE 0x00000010	/* Different cache as caller */
#define MOS_CLONE_ATTR_DIFF_L3CACHE 0x00000020	/* Different cache as caller */
#define MOS_CLONE_ATTR_SAME_DOMAIN  0x00000040	/* Same NUMA domain as caller */
#define MOS_CLONE_ATTR_DIFF_DOMAIN  0x00000080	/* Different domain as caller */
#define MOS_CLONE_ATTR_USE_NODE_SET 0x00000100	/* Use specified node mask */
#define MOS_CLONE_ATTR_LWK_CPU	    0x00000200	/* Use an LWK CPU */
#define MOS_CLONE_ATTR_FWK_CPU	    0x00000400	/* Use an FWK CPU */
#define MOS_CLONE_ATTR_FABRIC_INT   0x00000800	/* Fabric intrpt handling CPU */

/* result of mos_set_clone_attr and clone syscall sequence */
#define MOS_CLONE_BEHAVIOR_REQUESTED  1
#define MOS_CLONE_BEHAVIOR_ACCEPTED   2
#define MOS_CLONE_BEHAVIOR_REJECTED   3
#define MOS_CLONE_PLACEMENT_REQUESTED 1
#define MOS_CLONE_PLACEMENT_ACCEPTED  2
#define MOS_CLONE_PLACEMENT_REJECTED  3


long mos_set_clone_attr(struct mos_clone_attr *attr,
			unsigned long max_nodes,
			unsigned long *nodes,
			struct mos_clone_result *rslt,
			unsigned long location_key);

long mos_mwait(unsigned int sleep,
		unsigned long *location,
		unsigned long previous_value,
		unsigned int msec_timeout);

/* other mOS system calls */

#endif

