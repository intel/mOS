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

#ifndef _LIB_UTI_H
#define _LIB_UTI_H

#include <bits/pthreadtypes.h>

#define __SIZEOF_UTI_ATTR 64

#define UTI_ATTR_NUMA_SET(attr, nm, mn) uti_attr_numa_set(attr, nm, mn)
#define UTI_ATTR_SAME_NUMA_DOMAIN(attr) uti_attr_same_numa_domain(attr)
#define UTI_ATTR_DIFFERENT_NUMA_DOMAIN(attr) \
					uti_attr_different_numa_domain(attr)
#define UTI_ATTR_SAME_L1(attr) uti_attr_same_l1(attr)
#define UTI_ATTR_SAME_L2(attr) uti_attr_same_l2(attr)
#define UTI_ATTR_SAME_L3(attr) uti_attr_same_l3(attr)
#define UTI_ATTR_DIFFERENT_L1(attr) uti_attr_different_l1(attr)
#define UTI_ATTR_DIFFERENT_L2(attr) uti_attr_different_l2(attr)
#define UTI_ATTR_DIFFERENT_L3(attr) uti_attr_different_l3(attr)
#define UTI_ATTR_PREFER_LWK(attr) uti_attr_prefer_lwk(attr)
#define UTI_ATTR_PREFER_FWK(attr) uti_attr_prefer_fwk(attr)
#define UTI_ATTR_FABRIC_INTR_AFFINITY(attr) uti_attr_fabric_intr_affinity(attr)
#define UTI_ATTR_HIGH_PRIORITY(attr) uti_attr_high_priority(attr)
#define UTI_ATTR_LOW_PRIORITY(attr) uti_attr_low_priority(attr)
#define UTI_ATTR_NON_COOPERATIVE(attr) uti_attr_non_cooperative(attr)
#define UTI_ATTR_CPU_INTENSIVE(attr) uti_attr_cpu_intensive(attr)
#define UTI_ATTR_LOCATION_KEY(attr, key) uti_attr_location_key(attr, key)
#define UTI_RESULT_NUMA_SET(attr) uti_result_numa_set(attr)
#define UTI_RESULT_SAME_NUMA_DOMAIN(attr) uti_result_same_numa_domain(attr)
#define UTI_RESULT_DIFFERENT_NUMA_DOMAIN(attr) \
					uti_result_different_numa_domain(attr)
#define UTI_RESULT_SAME_L1(attr) uti_result_same_l1(attr)
#define UTI_RESULT_SAME_L2(attr) uti_result_same_l2(attr)
#define UTI_RESULT_SAME_L3(attr) uti_result_same_l3(attr)
#define UTI_RESULT_DIFFERENT_L1(attr) uti_result_different_l1(attr)
#define UTI_RESULT_DIFFERENT_L2(attr) uti_result_different_l2(attr)
#define UTI_RESULT_DIFFERENT_L3(attr) uti_result_different_l3(attr)
#define UTI_RESULT_PREFER_LWK(attr) uti_result_prefer_lwk(attr)
#define UTI_RESULT_PREFER_FWK(attr) uti_result_prefer_fwk(attr)
#define UTI_RESULT_FABRIC_INTR_AFFINITY(attr) \
					uti_result_fabric_intr_affinity(attr)
#define UTI_RESULT_HIGH_PRIORITY(attr) uti_result_high_priority(attr)
#define UTI_RESULT_LOW_PRIORITY(attr) uti_result_low_priority(attr)
#define UTI_RESULT_NON_COOPERATIVE(attr) uti_result_non_cooperative(attr)
#define UTI_RESULT_CPU_INTENSIVE(attr) uti_result_cpu_intensive(attr)
#define UTI_RESULT_LOCATION(attr) uti_result_location(attr)
#define UTI_RESULT_BEHAVIOR(attr) uti_result_behavior(attr)
#define UTI_RESULT(attr) uti_result(attr)

/* The structure of the attribute type is not exposed on purpose */
struct uti_attr {
	union {
		char __size[__SIZEOF_UTI_ATTR];
		long int __align;
	};
};
typedef struct uti_attr uti_attr_t;

__BEGIN_DECLS

extern int uti_attr_init(uti_attr_t *attr);
extern int uti_attr_destroy(uti_attr_t *attr);
extern int uti_attr_numa_set(uti_attr_t *attr, unsigned long *nodemask,
			unsigned long maxnodes);
extern int uti_attr_same_numa_domain(uti_attr_t *attr);
extern int uti_attr_different_numa_domain(uti_attr_t *attr);
extern int uti_attr_same_l1(uti_attr_t *attr);
extern int uti_attr_different_l1(uti_attr_t *attr);
extern int uti_attr_same_l2(uti_attr_t *attr);
extern int uti_attr_different_l2(uti_attr_t *attr);
extern int uti_attr_same_l3(uti_attr_t *attr);
extern int uti_attr_different_l3(uti_attr_t *attr);
extern int uti_attr_prefer_lwk(uti_attr_t *attr);
extern int uti_attr_prefer_fwk(uti_attr_t *attr);
extern int uti_attr_fabric_intr_affinity(uti_attr_t *attr);
extern int uti_attr_exclusive_cpu(uti_attr_t *attr);
extern int uti_attr_cpu_intensive(uti_attr_t *attr);
extern int uti_attr_high_priority(uti_attr_t *attr);
extern int uti_attr_low_priority(uti_attr_t *attr);
extern int uti_attr_non_cooperative(uti_attr_t *attr);
extern int uti_attr_location_key(uti_attr_t *attr, unsigned long key);
extern int uti_result_numa_set(uti_attr_t *attr);
extern int uti_result_same_numa_domain(uti_attr_t *attr);
extern int uti_result_different_numa_domain(uti_attr_t *attr);
extern int uti_result_same_l1(uti_attr_t *attr);
extern int uti_result_different_l1(uti_attr_t *attr);
extern int uti_result_same_l2(uti_attr_t *attr);
extern int uti_result_different_l2(uti_attr_t *attr);
extern int uti_result_same_l3(uti_attr_t *attr);
extern int uti_result_different_l3(uti_attr_t *attr);
extern int uti_result_prefer_lwk(uti_attr_t *attr);
extern int uti_result_prefer_fwk(uti_attr_t *attr);
extern int uti_result_fabric_intr_affinity(uti_attr_t *attr);
extern int uti_result_exclusive_cpu(uti_attr_t *attr);
extern int uti_result_cpu_intensive(uti_attr_t *attr);
extern int uti_result_high_priority(uti_attr_t *attr);
extern int uti_result_low_priority(uti_attr_t *attr);
extern int uti_result_non_cooperative(uti_attr_t *attr);
extern int uti_result_location(uti_attr_t *attr);
extern int uti_result_behavior(uti_attr_t *attr);
extern int uti_result(uti_attr_t *attr);
extern int uti_pthread_create(pthread_t *thread,
			const pthread_attr_t *pthread_attr,
			void *(*start_routine)(void *),
			void *arg, uti_attr_t *attr);

__END_DECLS

#endif

