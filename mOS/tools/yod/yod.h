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

#include <stdbool.h>
#include "mos_cpuset.h"

#define _unused_ __attribute__((unused))

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
#define MAX_DISTANCES_PER_GROUP 32
#define MAX_PARTITIONS 32


extern int yodopt_parse_integer(const char *opt, long int *val, long int lower,
				long int upper);

enum map_elem_t {
	YOD_CORE = 0,
	YOD_TILE = 1,
	YOD_NODE = 2,
	YOD_MEM_GROUP = 3,
	YOD_NUM_MAP_ELEMS
};

struct map_type_t {
	size_t size;
	size_t capacity;
	mos_cpuset_t **map;
};

extern struct map_type_t *yod_get_map(enum map_elem_t typ);
extern ssize_t yod_count_by(mos_cpuset_t *set, enum map_elem_t typ);
extern ssize_t yod_select_by(int n, enum map_elem_t typ, bool ascending,
			 bool partial, mos_cpuset_t *from,
			 mos_cpuset_t *selected);
extern bool yod_null_map(struct map_type_t *map, int index);

enum mem_group_t {
	YOD_HBM = 0,
	YOD_DRAM = 1,
	YOD_NVRAM = 2,
	YOD_NUM_MEM_GROUPS,
	YOD_MEM_GROUP_UNKNOWN = -1
};

extern const char * const MEM_GROUPS[];

enum mem_scopes_t {
	YOD_SCOPE_MMAP = 0,
	YOD_SCOPE_STACK = 1,
	YOD_SCOPE_STATIC = 2,
	YOD_SCOPE_BRK = 3,
	YOD_NUM_MEM_SCOPES = 4,
	YOD_SCOPE_ALL = 4,
	YOD_SCOPE_UNKNOWN = -1
};

enum rank_layout_t {
	YOD_RANK_COMPACT = 0,
	YOD_RANK_SCATTER = 1,
	YOD_RANK_DISABLE = 2
};

struct lock_options_t {
	/**
	 * The amount of time to wait to acquire the lock before giving up.
	 */
	unsigned long timeout_millis;

	/**
	 * The rank layout type and stride.
	 */
	enum rank_layout_t layout;
	int stride;
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
	int (*get_designated_lwkcpus)(mos_cpuset_t *set);

	/**
	 * Fetch the set of in-use light-weight kernel (LWK) CPUs.
	 * @param[out] set The set of busy LWK CPUs.
	 * @return 0 if the set was fetched successfully; non-zero if it
	 *   could not be obtained.
	 */
	int (*get_reserved_lwk_cpus)(mos_cpuset_t *);

	/**
	 * Allocate a set of CPUs to be used for this instance of yod.  
	 * @param[in] set  The set of LWK CPUs being requested.
	 * @pre set should be a subset of the set difference
	 *   get_lwk_cpus() \ get_reserved_lwk_cpus().
	 * @return 0 if the request was successful; yod now has accepted
	 *   ownership of these CPUs.  Non-zero if the request could not
	 *   be fulfilled.
	 */
	int (*request_lwk_cpus)(mos_cpuset_t *);

	/**
	 * Set the number of utility threads for this job launch.
	 * @param[in] int  The number of utility threads to be set.
	 * @return 0 if the request was successful; yod now has informed
	 *   the kernel of the number of utility threads.  Non-zero if
	 *   the action could not be fulfilled.
	 */
	int (*set_util_threads)(size_t num_util_threads);

	/**
	 * Fetch the amount of memory (in bytes) designated for use
	 * by LWKs.
	 * @param[out] lwkmem The amount of memory designated for
	 *   LWK usage by NID.
	 * @param[in/out] n As input, this describes the array size of
	 *   lwkmem.  As output, it describes the actual size of the
	 *   results (i.e., the number of NIDs in the lwkmem array).
	 */

	void (*get_designated_lwkmem)(size_t *lwkmem, size_t *n);

	/**
	 * Fetch the amount of LWK memory that is already reserved.
	 * @param[out] lwkmem_reserved The amount of memory reserved for
	 *   LWK usage by NID.
	 * @param[in/out] n As input, this describes the array size of
	 *   lwkmem_reserved.  As output, it describes the actual size of the
	 *   results (i.e., the number of NIDs in the lwkmem_reserved array).

	 */
	void (*get_reserved_lwkmem)(size_t *lwkmem_reserved, size_t *n);

	/**
	 * Request the specified amount of LWK memory.
	 * @param[in] lwkmem_request The number of bytes of memory being
	 *   requested, indexed by nid.
	 * @param[in] n The number of elements in the lwkmem array.
	 * @return 0 if the request was successful; yod has now accepted
	 *   ownerhips of this amount of memory.  Non-zero if the request
	 *   could not be fulfilled.
	 */
	int (*request_lwk_memory)(size_t *lwkmem_request, size_t n);

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
	ssize_t (*map_cpu)(size_t cpu, enum map_elem_t typ);

	/**
	 * Requests that a lock be acquired to perform LWK resource
	 * request operations.
	 * @param[in] options provides various parameters to the
	 *   locking algorithm, including timeout.
	 * @return 0 if the lock was acquired; -1 if the lock was not
	 *   acquired.
	 */
	int (*lock)(struct lock_options_t *);

	/**
	 * Release the request operations lock.
	 * @param[in] the opaque token established during the last lock
	 *   request.
	 * @return 0 if the lock was freed; -1 if the lock was not freed.
	 */
	int (*unlock)(struct lock_options_t *);

	/**
	 * Get the memory distance map for the specified NUMA domain.
	 * @param[in] nid The NUMA domain being queried.
	 * @param[out] dist The list of distances (indexed by nid)
	 * @param[in/out] n As input, describes the capacity of the
	 *   dist array.  As output, describes the actual number of
	 *   valid entries in dist array.  If zero, the nid was
	 *   not recognized.
	 */
	void (*get_distance_map)(size_t nid, size_t *dist, size_t *n);

	/**
	 * Passes user-specified options along to the kernel.
	 */
	int (*set_options)(char *options, size_t length);

	/**
	 * Writes memory domain information to the LWK.
	 * @param[in] order The information to be written.
	 * @return 0 if the request was succeessful.
	 */
	int (*set_lwkmem_domain_info)(char *order);

	/**
	 * Get mOS view of current process
	 */
	bool (*get_mos_view)(char *mos_view, size_t len);
	/**
	 * Set mOS view of current process
	 */
	bool (*set_mos_view)(char *mos_view);
};

void yod_abort(int rc, const char *fmt, ...) __attribute__ ((noreturn));

typedef struct envelope_t {
	mos_cpuset_t *cpus;
	size_t nids[YOD_MAX_NIDS];
	size_t n_nids;
	struct envelope_t *next;
} envelope_t;

typedef struct lwk_request_t {
	size_t lwkmem_size;
	size_t lwkmem_size_by_group[YOD_MAX_GROUPS];
	size_t lwkmem_designated[YOD_MAX_NIDS];
	size_t lwkmem_reserved[YOD_MAX_NIDS];
	size_t lwkmem_request[YOD_MAX_NIDS];
	double fit[YOD_MAX_GROUPS+1];
	size_t n_nids;
	size_t n_groups;
	mos_cpuset_t *lwkcpus_request;
	char layout_descriptor[128];
	char layout_request[4096];
	char options[4096];
	size_t options_idx;
	size_t lwkmem_domain_info[YOD_NUM_MEM_GROUPS][YOD_MAX_NIDS];
	size_t lwkmem_domain_info_len[YOD_NUM_MEM_GROUPS];
	char lwkmem_domain_info_str[4096];
	struct memory_preferences_t {
		enum mem_group_t lower_order[YOD_NUM_MEM_GROUPS];
		enum mem_group_t upper_order[YOD_NUM_MEM_GROUPS];
		unsigned long threshold;
	} memory_preferences[YOD_NUM_MEM_SCOPES];
	bool memory_preferences_present;

	void (*memsize_resolver)(struct lwk_request_t *this);
	void (*lwkcpus_resolver)(struct lwk_request_t *this);

	size_t dist_by_type[YOD_NUM_MEM_GROUPS][MAX_DISTANCES_PER_GROUP];
	size_t dist_by_type_len[YOD_NUM_MEM_GROUPS];
	size_t n_partitions;
	envelope_t *partition[MAX_PARTITIONS];
	envelope_t *selected_envelope;
	struct yod_plugin *plugin;

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
			      size_t num_cores, mos_cpuset_t *available);

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

extern mos_cpuset_t *mos_cpuset_alloc_validate(void);
extern char *mos_cpuset_to_list_validate(mos_cpuset_t *s);

extern enum mem_group_t yod_nid_to_mem_group(int nid);
extern void yod_append_memory_nid(int grp, size_t nid, lwk_request_t *req);
extern int yod_numa_memory_selection_algorithm(lwk_request_t *this);
extern int yod_numa_compute_core_algorithm(struct lwk_request_t *this,
				   size_t n_cores, mos_cpuset_t *available);
extern int yod_ordered_set_insert(size_t *set, size_t value, size_t *length,
				  size_t capacity);

#endif
