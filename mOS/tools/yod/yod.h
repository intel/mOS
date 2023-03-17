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
#include <linux/types.h>
#include "mos_cpuset.h"
#include "mos_gpuset.h"

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
	YOD_CORE = 0,	   /* indexed by cpu id in cpu_map */
	YOD_TILE = 1,	   /* indexed by cpu id in cpu_map */
	YOD_NODE = 2,	   /* indexed by cpu id in cpu_map */
	YOD_MEM_GROUP = 3, /* indexed by nid in cpu_map*/
	YOD_NODE_GPU = 4,  /* indexed by gpu index in cpu_map */
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

/*
 * Need to keep this in the same order as that of LWK_VMR_*
 * in include/linux/moslwkmem.h
 */
enum mem_scopes_t {
	YOD_SCOPE_DBSS = 0,
	YOD_SCOPE_HEAP = 1,
	YOD_SCOPE_MMAP = 2,
	YOD_SCOPE_TSTACK = 3,
	YOD_SCOPE_STACK = 4,
	YOD_NUM_MEM_SCOPES = 5,
	YOD_SCOPE_ALL = 5,
	YOD_SCOPE_UNKNOWN = -1
};

enum rank_layout_t {
	YOD_RANK_COMPACT = 0,
	YOD_RANK_SCATTER = 1,
	YOD_RANK_DISABLE = 2
};

enum page_types_t {
	PG_TYPE_4K = 0,
	PG_TYPE_2M = 1,
	PG_TYPE_4M = 2,
	PG_TYPE_1G = 3,
	PG_TYPE_UNKNOWN = -1
};

/*
 * Need to keep this in the same order as that of LWK_PF_*
 * in include/linux/moslwkmem.h
 */
enum page_fault_levels_t {
	PF_LEVEL_NOFAULT = 0,
	PF_LEVEL_ONEFAULT = 1,
	PF_LEVEL_UNKNOWN = -1
};

enum policy_types_t {
	MEMPOLICY_NORMAL = 0,
	MEMPOLICY_RANDOM,
	MEMPOLICY_INTERLEAVE,
	MEMPOLICY_INTERLEAVE_RANDOM,
	MEMPOLICY_UNKNOWN
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
	 * Fetch the set of GPUs designated for light-weight kernel
	 * (LWK) use.
	 * @param[out] set The set of designated LWK GPUs.
	 * @return 0 if the set was fetched successfully; non-zero if it
	 *   could not be obtained.
	 */
	int (*get_designated_lwkgpus)(mos_cpuset_t *set);

	/**
	 * Fetch the set of in-use light-weight kernel (LWK) GPUs.
	 * @param[out] set The set of busy LWK GPUs.
	 * @return 0 if the set was fetched successfully; non-zero if it
	 *   could not be obtained.
	 */
	int (*get_reserved_lwk_gpus)(mos_cpuset_t *);

	/**
	 * Fetch a list of usage counts for the designated GPU devices.
	 * @param[out] set The integer list of usage counts.
	 * @return 0 if the list was fetched successfully; non-zero
	 *   if it could not be obtained.
	 */
	int (*get_gpu_usage_counts)(int *array_of_counts, int num_counts);

	/**
	 * Fetch a list of numa ids for the designated GPU devices.
	 * @param[out] set The integer list of numa ids.
	 * @return 0 if the list was fetched successfully; non-zero
	 *   if it could not be obtained.
	 */
	int (*get_gpu_numa)(int *array_of_nids, int num_counts);

	/**
	 * Allocate a set of GPUs to be used for this instance of yod.
	 * @param[in] gpuset  The set of LWK GPUs being requested.
	 * @param[in] char*   The string for the ZE_AFFINITY_MASK envar.
	 * @pre set should be a subset of get_lwk_gpus()
	 * @return 0 if the request was successful; yod now has accepted
	 *   ownership of these GPUs.  Non-zero if the request could not
	 *   be fulfilled.
	 */
	int (*request_lwk_gpus)(mos_cpuset_t *, char *ze_affinity_mask);


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
	 * Read bitmask that indicates NUMA nodes that are online.
	 *   @param[out] bitmask of NUMA nodes that are online.
	 */
	int (*get_numa_nodes_online)(mos_cpuset_t *set);

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
	 * Writes memory policy information to the LWK.
	 * @param[in] mempolicy_info, the information to be written.
	 * @param[in] len size of information to be written in bytes.
	 * @return 0 if the request was succeessful.
	 */
	int (*set_lwkmem_mempolicy_info)(char *mempolicy_info, size_t len);

	/**
	 * Get mOS view of current process
	 */
	bool (*get_mos_view)(char *mos_view, size_t len);

	/**
	 * Set mOS view of current process
	 */
	bool (*set_mos_view)(char *mos_view);

	/**
	 * Fetch the existing list of LWK processes.
	 * @param[out] lwkprocs The LWK processes (PIDs).
	 * @param[in/out] n As input, this describes the array size of
	 *   lwkprocs.  As output, it describes the actual size of the
	 *   results (i.e., the number of PIDs in the lwkprocs array).
	 */

	void (*get_lwk_processes)(pid_t *lwkprocs, size_t *n);

};

void yod_abort(int rc, const char *fmt, ...) __attribute__ ((noreturn));

typedef struct envelope_t {
	mos_cpuset_t *cpus;
	mos_cpuset_t *gpus; /* using the mos_cpuset interfaces for gpu mask */
	size_t nids[YOD_MAX_NIDS];
	size_t n_nids;
	struct envelope_t *next;
} envelope_t;

/*
 * Mempory policy info buffer passed to LWK
 *
 * +------------------------+
 * | Common header          |
 * +------------------------+
 * | Mempolicy-dbss         |
 * +------------------------+
 * | Mempolicy-heap         |
 * +------------------------+
 * | Mempolicy-anon_private |
 * +------------------------+
 * | Mempolicy-tstack       |
 * +------------------------+
 * | Mempolicy-stack        |
 * +------------------------+
 */

#define LWKMEM_MEMPOL_LIST_MAX			16 /* Max number of lists */
#define LWKMEM_MEMPOL_MAX_NODES_PER_LIST	16 /* Max nodes per list  */
#define LWKMEM_MEMPOL_LONGS_PER_LIST		((LWKMEM_MEMPOL_MAX_NODES_PER_LIST + 7) / 8)
#define LWKMEM_MEMPOL_EOL			((unsigned char) 0xff)

/*
 * CAUTION: Any changes to structures lwkmem_mempolicy_info_header_t and
 *          lwkmem_mempolicy_info_t structure needs to update the LWK memory
 *          policy info store method lwk_mm_set_mempolicy_info() that interprets
 *          the user buffer as per below format. Failing to do so may result in
 *          LWK seeing inconsistent memory policy info for the process and
 *          reject such format.
 */
typedef struct lwkmem_mempolicy_info_header_t {
	__u64 header_size;	  /* Size of this structure               */
	__u64 info_size;	  /* Size of lwkmem_mempolicy_info_t      */
	__u64 nvmrs;		  /* Number of VMRs mempolicy info is for */
	__u64 nlists_max;	  /* Max number of lists per set          */
	__u64 nlists_valid;	  /* Actual number of lists valid         */
	__u64 max_longs_per_list; /* Max number of 64 bit fields per list */
} lwkmem_mempolicy_info_header_t;

typedef struct lwkmem_mempolicy_info_t {
	/*
	 * Each 64 bit entry has 8 elements of the list each 8 bit in size.
	 * First element starting at byte 0, second byte 1, so on. An entry
	 * of 0xFF indicates the end of the list.
	 */
	__u64 above_threshold[LWKMEM_MEMPOL_LIST_MAX][LWKMEM_MEMPOL_LONGS_PER_LIST];
	/*
	 * Each 64 bit entry has 8 elements of the list each 8 bit in size.
	 * First element starting at byte 0, second byte 1, so on. An entry
	 * of 0xFF indicates the end of the list.
	 */
	__u64 below_threshold[LWKMEM_MEMPOL_LIST_MAX][LWKMEM_MEMPOL_LONGS_PER_LIST];
	__u64 threshold;
	__u64 max_page_size;
	__u64 pagefault_level;
	__u64 policy_type;
	__u64 nodelist_ratio;
} lwkmem_mempolicy_info_t;

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
	mos_cpuset_t *lwkgpus_request;
	char ze_affinity_request[MOS_MAX_GPU_TILES * 6];
	char *ze_affinity_on_entry;
	bool explicit_gpus_request;
	char layout_descriptor[128];
	char layout_request[4096];
	char options[4096];
	size_t options_idx;
	size_t lwkmem_domain_info[YOD_NUM_MEM_GROUPS][YOD_MAX_NIDS];
	size_t lwkmem_domain_info_len[YOD_NUM_MEM_GROUPS];
	struct memory_preferences_t {
		enum mem_group_t lower_order[YOD_NUM_MEM_GROUPS];
		enum mem_group_t upper_order[YOD_NUM_MEM_GROUPS];
		unsigned long threshold;
		unsigned long max_page_size;
		unsigned long pagefault_level;
		unsigned long policy_type;
		unsigned long nodelist_ratio;
	} memory_preferences[YOD_NUM_MEM_SCOPES];

	void (*memsize_resolver)(struct lwk_request_t *this);
	void (*lwkcpus_resolver)(struct lwk_request_t *this);
	void (*lwkgpus_resolver)(struct lwk_request_t *this);

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
	/**
	 * The interface for allocating GPU resources.
	 */
	int (*gpu_selection_algorithm)(struct lwk_request_t *this,
				       size_t num_gpus, bool device,
				       mos_cpuset_t *availgpus);
} lwk_request_t;

int yod_general_layout_algorithm(struct lwk_request_t *);

extern struct yod_plugin *init_tst_plugin(const char *);

extern mos_cpuset_t *mos_cpuset_alloc_validate(void);
extern char *mos_cpuset_to_list_validate(mos_cpuset_t *s);

extern enum mem_group_t yod_nid_to_mem_group(int nid);
extern void yod_append_memory_nid(int grp, size_t nid, lwk_request_t *req);
extern int yod_numa_memory_selection_algorithm(lwk_request_t *this);
extern int yod_numa_gpu_selection_algorithm(lwk_request_t *this,
				   size_t n_gpu, bool device, mos_cpuset_t *avail_gpus);
extern int yod_numa_compute_core_algorithm(struct lwk_request_t *this,
				   size_t n_cores, mos_cpuset_t *available);
extern int yod_ordered_set_insert(size_t *set, size_t value, size_t *length,
				 size_t capacity);
extern void show_state(int level);
extern void yod_get_gpu_usage_counts(int *counts, int num);
extern void yod_balanced_gpu_select(int num_gpus, bool device, mos_cpuset_t *candidates, mos_cpuset_t *gpus);
extern void yod_get_designated_lwkgpus(mos_cpuset_t *gpus);
extern int yod_get_num_tiles_per_gpu(void);
extern int yod_strtol(char *in_str, long int *out_int);
extern void yod_ze_mask_to_mos_gpuset(char *ze_mask, mos_cpuset_t *gpuset);
#endif
