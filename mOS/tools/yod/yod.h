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

#ifndef __YOD_H
#define __YOD_H

#include <sched.h>
#include <stdbool.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif
#ifndef ARRAY_COPY
#define ARRAY_COPY(dst, src) memcpy(dst, src, sizeof(src))
#endif

#define STARTS_WITH(s, prefix) (strncmp(s, prefix, strlen(prefix)) == 0)

#define ARRAY_ENT(arr, idx, fld, dflt)	\
	(idx < ARRAY_SIZE(arr) ? arr[idx].fld : dflt)

#define STR_APPEND(s, size, ...) snprintf(s + strlen(s), (size) - strlen(s), ##__VA_ARGS__)

#define YOD_MAX_NIDS 64
#define YOD_MAX_GROUPS YOD_MAX_NIDS


/**
 * yod uses dynamic sized cpusets and wraps cpu_set_t in
 * a structure. This simplifies some of the gory details
 * of dealing with cpu_set_t.  This should typically be
 * treated as an opaque type.
 */

typedef struct yod_cpuset {
	cpu_set_t *cpuset;
	char _buffer[512+1];
} yod_cpuset_t;


extern int yodopt_parse_integer(const char *opt, long int *val, long int lower,
				long int upper);

extern int yod_max_cpus(void);

/**
 * Allocates a cpuset.
 * @return A dynamically allocated cpu set.  Any memory allocation
 *   failure is assumed to be fatal in yod.  Thus, callers need
 *   not check the pointer for null.
 */

extern yod_cpuset_t *yod_cpuset_alloc(void);

/**
 * Frees a yod_cpuset_t
 */
extern void yod_cpuset_free(yod_cpuset_t *);

/**
 * Formats a yod_cpuset_t into list (string) format.
 */

extern char *yod_cpuset_to_list(yod_cpuset_t *);

/**
 * Formats a yod_cpuset_t into mask (string) format.
 */
extern char *yod_cpuset_to_mask(yod_cpuset_t *);

/**
 * Converts the string in list format to a yod_cpuset_t.
 * @param[in] lst The list string to be parsed.
 * @param[out] set The corresponding CPU set.
 * @pre Set is assumed to be non-null.
 * @return 0 if lst was a legal cpu list format.
 */
extern int yod_parse_cpulist(const char *lst, yod_cpuset_t *set);

/**
 * Converts the string in mask format to a yod_cpuset_t.
 * @param[in] msk The mask string to be parsed.
 * @param[out] set The corresponding CPU set.
 * @pre Set is assumed to be non-null.
 * @return 0 if msk was a legal cpu mask.
 */
extern int yod_parse_cpumask(const char *msk, yod_cpuset_t *set);

/**
 * Sets the bit on for the given CPU number.
 * @param[in] cpu The CPU number.
 * @param[in] set The CPU set being altered.
 * @pre set is assumed to be non-null.
 * @pre cpu is assumed to be a valid CPU number.
 */

extern void yod_cpuset_set(int cpu, yod_cpuset_t *);

extern size_t yod_setsize(void);

/**
 * The following logical operations are pretty much self-explanatory.
 */

extern void yod_cpuset_xor(yod_cpuset_t *, yod_cpuset_t *, yod_cpuset_t *);
extern void yod_cpuset_or(yod_cpuset_t *, yod_cpuset_t *, yod_cpuset_t *);
extern void yod_cpuset_and(yod_cpuset_t *, yod_cpuset_t *, yod_cpuset_t *);
extern int yod_cpuset_equal(yod_cpuset_t *, yod_cpuset_t *);
extern int yod_cpuset_is_empty(yod_cpuset_t *);
extern int yod_cpuset_biggest(yod_cpuset_t *);
extern int yod_cpuset_cardinality(yod_cpuset_t *);
extern int yod_cpuset_is_subset(yod_cpuset_t *sub, yod_cpuset_t *super);
extern void yod_cpuset_not(yod_cpuset_t *, yod_cpuset_t *);
extern int yod_cpuset_is_set(int cpu, yod_cpuset_t *);
extern yod_cpuset_t *yod_cpuset_clone(yod_cpuset_t *s);
extern int yod_cpuset_nth_cpu(int n, yod_cpuset_t *);

enum map_elem_t {
	YOD_CORE = 0,
	YOD_TILE = 1,
	YOD_NODE = 2,
	YOD_MEM_GROUP = 3,
	YOD_NUM_MAP_ELEMS
};

struct map_type_t {
	int size;
	int capacity;
	yod_cpuset_t **map;
};

extern struct map_type_t *yod_get_map(enum map_elem_t typ);
extern int yod_count_by(yod_cpuset_t *set, enum map_elem_t typ);
extern int yod_select_by(int n, enum map_elem_t typ, bool ascending, bool partial, yod_cpuset_t *from, yod_cpuset_t *selected);

enum mem_group_t {
	YOD_DRAM = 0,
	YOD_MCDRAM = 1,
	YOD_NUM_MEM_GROUPS
};

/**
 * Define the plugin for yod.  This abstracts the interface to 
 * the back-end to the system.
 */
struct yod_plugin {

	/**
	 * Fetch the set of CPUs designated for light-weight kernel (LWK)
	 * use.
	 * @param[out] set The set of designated LWK CPUs.
	 * @return 0 if the set was fetched successfully; non-zero if it
	 *   could not be obtained.
	 */ 
	int (*get_designated_lwkcpus)(yod_cpuset_t *set);

	/**
	 * Fetch the set of in-use light-weight kernel (LWK) CPUs.
	 * @param[out] set The set of busy LWK CPUs.
	 */
	int (*get_reserved_lwk_cpus)(yod_cpuset_t *);

	/**
	 * Allocate a set of CPUs to be used for this instance of yod.  
	 * @param[in] set  The set of LWK CPUs being requested.
	 * @pre set should be a subset of the set difference
	 *   get_lwk_cpus() \ get_reserved_lwk_cpus().
	 * @return 0 if the request was successful; yod now has accepted
	 *   ownership of these CPUs.  Non-zero if the request could not
	 *   be fulfilled.
	 */
	int (*request_lwk_cpus)(yod_cpuset_t *);

	/**
	 * Set the number of utility threads for this job launch.
	 * @param[in] int  The number of utility threads to be set.
	 * @return 0 if the request was successful; yod now has informed
	 *   the kernel of the number of utility threads.  Non-zero if
	 *   the action could not be fulfilled.
	 */
	int (*set_util_threads)(int num_util_threads);

	/**
	 * Fetch the amount of memory (in bytes) designated for use
	 * by LWKs.
	 * @param[out] lwkmem The amount of memory designated for
	 *   LWK usage by NID.
	 * @param[in/out] n As input, this describes the array size of
	 *   lwkmem.  As output, it describes the actual size of the
	 *   results (i.e., the number of NIDs in the lwkmem array).
	 */

	void (*get_designated_lwkmem)(size_t *lwkmem, int *n);

	/**
	 * Fetch the amount of LWK memory that is already reserved.
	 * @param[out] lwkmem_reserved The amount of memory reserved for
	 *   LWK usage by NID.
	 * @param[in/out] n As input, this describes the array size of
	 *   lwkmem_reserved.  As output, it describes the actual size of the
	 *   results (i.e., the number of NIDs in the lwkmem_reserved array).

	 */
	void (*get_reserved_lwkmem)(size_t *lwkmem_reserved, int *n);

	/**
	 * Request the specified amount of LWK memory.
	 * @param[in] lwkmem_request The number of bytes of memory being
	 *   requested, indexed by nid.
	 * @param[in] n The number of elements in the lwkmem array.
	 * @return 0 if the request was successful; yod has now accepted
	 *   ownerhips of this amount of memory.  Non-zero if the request
	 *   could not be fulfilled.
	 */
	int (*request_lwk_memory)(size_t *lwkmem_request, int n);

	/**
	 * Request the specified ordering of CPU usage within the selected
	 * (requested) LWK CPUs.
	 * @param[in] order The list of CPUs, in order of preferred thread
	 *   layout.
	 * @return 0 if the request was succeessful.
	 */
	int (*lwkcpus_sequence_request)(char *order);

	/**
	 * Returns the element of specified type associated with the given CPU.
	 * @param[in] cpu The CPU number.
	 @ @param[in] typ The requested element type.
	 * @return The element number (>=0) associated with the given CPU
	 *   or -1 if the CPU is not known to the plugin or otherwise cannot
	 *   be mapped to the specified type.
	 */
	int (*map_cpu)(int cpu, enum map_elem_t typ);

	/**
	 * Requests that a lock be acquired to perform LWK resource
	 * request operations.
	 * @param[in] timeout_millis specifies the approximate amount of
	 *   time that the plugin should wait before giving up on
	 *   acquiring the lock.
	 * @return 0 if the lock was acquired; -1 if the lock was not
	 *   acquired.
	 */
	int (*lock)(unsigned long timeout_millis);

	/**
	 * Release the request operations lock.
	 * @param[in] the opaque token established during the last lock
	 *   request.
	 * @return 0 if the lock was freed; -1 if the lock was not freed.
	 */
	int (*unlock)(void);

	/**
	 * Get the memory distance map for the specified NUMA domain.
	 * @param[in] nid The NUMA domain being queried.
	 * @param[out] dist The list of distances (indexed by nid)
	 * @param[in/out] n As input, describes the capacity of the
	 *   dist array.  As output, describes the actual number of
	 *   valid entries in dist array.  If zero, the nid was
	 *   not recognized.
	 */
	void (*get_distance_map)(int nid, size_t *dist, int *n);

	/**
	 * Passes user-specified options along to the kernel.
	 */
	int (*set_options)(char *options);

	/**
	 * Writes memory domain information to the LWK.
	 * @param[in] order The information to be written.
	 * @return 0 if the request was succeessful.
	 */
	int (*set_lwkmem_domain_info)(char *order);

};

void yod_abort(int rc, const char *fmt, ...) __attribute__ ((noreturn));

typedef struct lwk_request_t {
	size_t lwkmem_size;
	size_t lwkmem_size_by_group[YOD_MAX_GROUPS];
	size_t lwkmem_designated[YOD_MAX_NIDS];
	size_t lwkmem_reserved[YOD_MAX_NIDS];
	size_t lwkmem_request[YOD_MAX_NIDS];
	double fit[YOD_MAX_GROUPS+1];
	int n_nids;
	int n_groups;
	yod_cpuset_t *lwkcpus_request;
	char layout_descriptor[128];
	char layout_request[4096];
	char options[4096];
	int lwkmem_domain_info[YOD_NUM_MEM_GROUPS][YOD_MAX_NIDS];
	int lwkmem_domain_info_len[YOD_NUM_MEM_GROUPS];
	char lwkmem_domain_info_str[4096];
	void (*memsize_resolver)(struct lwk_request_t *this);
	void (*lwkcpus_resolver)(struct lwk_request_t *this);
	double (*fitness)(struct lwk_request_t *this);

	/**
	 * The interface for allocating computational cores.
	 * @param[in/out] this The request object.
	 * @param[in] num_cores The number of cores to allocate.
	 * @param[in] available The list of available LWK CPUs.
	 * @return 0 if the specified number of cores is available; -1 if there
	 *   were not sufficient cores to fulfill the request.
	 * @post this->lwkcpus_request describes the cores to be reserved
	 *   for this process.
	 * @post this->lwkcpus_request is a subset of available.
	 */
	int (*compute_core_algorithm)(struct lwk_request_t *this,
				      int num_cores, yod_cpuset_t *available);

	/**
	 * The interface for resolving the general memory size state into
	 * a specific LWK memory request.
	 * @param[in/out] this The request object.
	 * @pre this->lwkmem_size has been set to establish the overall amount
	 *   of LWK memory remaining to be assigned (reserved).
	 * @post this->lwkmem_size is zeroed.
	 * @post this->lwkmem_request is populated.
	 * @return 0 if the memory was selected; non-zero if something went
	 *   wrong.
	 */
	int (*memory_selection_algorithm)(struct lwk_request_t *this);

	/**
	 * TBD
	 */
	int (*layout_algorithm)(struct lwk_request_t *this);
} lwk_request_t;

int yod_general_layout_algorithm(struct lwk_request_t *);

extern struct yod_plugin *init_tst_plugin(const char *);

#endif
