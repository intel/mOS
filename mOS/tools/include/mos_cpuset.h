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

#ifndef __MOS_CPUSET__
#define __MOS_CPUSET__

#define _GNU_SOURCE
#include <sched.h>

/**
 * Use dynamic sized cpusets and wrap cpu_set_t in
 * a structure. This simplifies some of the gory details
 * of dealing with cpu_set_t.  This should typically be
 * treated as an opaque type.
 */

typedef struct mos_cpuset {
	cpu_set_t *cpuset;
	char _buffer[512+1];
} mos_cpuset_t;

extern int mos_max_cpus(void);

/**
 * Allocates a cpuset.
 * @return A dynamically allocated cpu set.  Any memory allocation
 *   failure is assumed to be fatal.  Thus, callers need
 *   not check the pointer for null.
 */

extern mos_cpuset_t *mos_cpuset_alloc(void);

/**
 * Frees a mos_cpuset_t
 */
extern void mos_cpuset_free(mos_cpuset_t *);

/**
 * Formats a mos_cpuset_t into list (string) format.
 */

extern char *mos_cpuset_to_list(mos_cpuset_t *);

/**
 * Formats a mos_cpuset_t into mask (string) format.
 */
extern char *mos_cpuset_to_mask(mos_cpuset_t *);

/**
 * Converts the string in list format to a mos_cpuset_t.
 * @param[in] lst The list string to be parsed.
 * @param[out] set The corresponding CPU set.
 * @pre Set is assumed to be non-null.
 * @return 0 if lst was a legal cpu list format.
 */
extern int mos_parse_cpulist(const char *lst, mos_cpuset_t *set);

/**
 * Converts the string in mask format to a mos_cpuset_t.
 * @param[in] msk The mask string to be parsed.
 * @param[out] set The corresponding CPU set.
 * @pre Set is assumed to be non-null.
 * @return 0 if msk was a legal cpu mask.
 */
extern int mos_parse_cpumask(const char *msk, mos_cpuset_t *set);

/**
 * Sets the bit on for the given CPU number.
 * @param[in] cpu The CPU number.
 * @param[in] set The CPU set being altered.
 * @pre set is assumed to be non-null.
 */
extern void mos_cpuset_set(int cpu, mos_cpuset_t *);

/**
 * Clears the bit for the given CPU number.
 * @param[in] cpu The CPU number.
 * @param[in] set The CPU set being altered.
 * @pre set is assumed to be non-null.
 */
extern void mos_cpuset_clr(int cpu, mos_cpuset_t *set);

extern size_t mos_setsize(void);

/**
 * The following logical operations are pretty much self-explanatory.
 */

extern void mos_cpuset_xor(mos_cpuset_t *, mos_cpuset_t *, mos_cpuset_t *);
extern void mos_cpuset_or(mos_cpuset_t *, mos_cpuset_t *, mos_cpuset_t *);
extern void mos_cpuset_and(mos_cpuset_t *, mos_cpuset_t *, mos_cpuset_t *);
extern int mos_cpuset_equal(mos_cpuset_t *, mos_cpuset_t *);
extern int mos_cpuset_is_empty(mos_cpuset_t *);
extern int mos_cpuset_biggest(mos_cpuset_t *);
extern int mos_cpuset_cardinality(mos_cpuset_t *);
extern int mos_cpuset_is_subset(mos_cpuset_t *sub, mos_cpuset_t *super);
extern void mos_cpuset_not(mos_cpuset_t *, mos_cpuset_t *);
extern int mos_cpuset_is_set(int cpu, mos_cpuset_t *);
extern mos_cpuset_t *mos_cpuset_clone(mos_cpuset_t *s);
extern int mos_cpuset_nth_cpu(int n, mos_cpuset_t *);

#endif
