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

#define HAVE_DECL_CPU_ALLOC 1
#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <math.h>
#include <stdint.h>
#include <sys/user.h>

#include "yod.h"
#include "yod_debug.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))


#define YOD_MEM_ALGORITHM_4KB 0
#define YOD_MEM_ALGORITHM_LARGE 1

#define YOD_MOS_VIEW_LEN 	20

static const char * const YOD_MEM_ALGORITHMS[] = {
	"4kb",
	"large"
};

static const enum mem_group_t DEFAULT_MEMORY_ORDER[] = {
	YOD_HBM,
	YOD_DRAM,
	YOD_NVRAM
};

static const char * const SCOPES[] = {
	"dbss",
	"heap",
	"anon_private",
	"tstack",
	"stack",
	"all"
};

const char * const MEM_GROUPS[] = {
	"hbm",
	"dram",
	"nvram",
};

static const char * const MAP_TYPES[] = {
	"core",
	"tile",
	"node",
	"mem_group",
};

const char * const PAGE_TYPES[] = {
	"4k",
	"2m",
	"4m",
	"1g"
};

const char * const PAGE_FAULT_LEVELS[] = {
	"nofault",
	"onefault"
};

static const __u64 PAGE_SIZES[] = {
	1UL << 12,
	1UL << 21,
	1UL << 22,
	1UL << 30
};

const char * const MEMPOLICY_TYPES[] = {
	"normal",
	"random",
	"interleave",
	"interleave_random"
};

/*
 * Values for command line options that do not have short
 * versions (used by getopt_long, below)
 */

#define YOD_OPT_BASE 0x1000
#define YOD_OPT_DRYRUN  (YOD_OPT_BASE | 0x0002)
#define YOD_OPT_RESOURCE_ALGORITHM (YOD_OPT_BASE | 0x0004)
#define YOD_OPT_MEM_ALGORITHM (YOD_OPT_BASE | 0x0005)
#define YOD_OPT_RANK_LAYOUT (YOD_OPT_BASE | 0x0006)
#define YOD_OPT_ALIGNED_MMAP (YOD_OPT_BASE | 0x0007)
#define YOD_OPT_BRK_CLEAR_LEN (YOD_OPT_BASE | 0x0008)
#define YOD_OPT_MOSVIEW (YOD_OPT_BASE | 0x0009)
#define YOD_OPT_LWKMEM_DISABLE (YOD_OPT_BASE | 0x000A)
#define YOD_OPT_MAXPAGE (YOD_OPT_BASE | 0x000B)
#define YOD_OPT_PAGEFAULT (YOD_OPT_BASE | 0x000C)
#define YOD_OPT_MEMPOLICY (YOD_OPT_BASE | 0x000D)

/*
 * yod state.
 */

static struct map_type_t *yod_maps[YOD_NUM_MAP_ELEMS];

static bool explicit_maxpage[YOD_NUM_MEM_SCOPES];

int yod_verbosity = YOD_CRIT;
int mpi_localnranks = 0;

extern struct yod_plugin mos_plugin;
static struct yod_plugin *plugin = &mos_plugin;
static int dry_run = 0;
static int num_util_threads;
static unsigned long requested_lwk_mem = -1;
static double requested_lwk_mem_fraction = 0.0;
static mos_cpuset_t *requested_lwk_cpus;
static int all_lwk_cpus_specified = 0;
static int requested_lwk_cores = -1;
static int requested_lwk_gpus = 0;
static int requested_lwk_gpu_devices = 0;
static unsigned int mem_algorithm = YOD_MEM_ALGORITHM_LARGE;
static mos_cpuset_t *designated_lwkcpus;
static mos_cpuset_t *reserved_lwkcpus;
static char extra_help[4096];
static unsigned int resource_algorithm_index;
static bool lwkmem_disabled;
static bool gpu_sharing;

static struct lock_options_t lock_options = {
	.timeout_millis = 60 * 1000, /* one minute */
	.layout = YOD_RANK_COMPACT,
	.stride = -1, /* To be filled in later */
};

static lwk_request_t lwk_req = {
	.layout_algorithm = yod_general_layout_algorithm,
	.options = {'\0', '\0', }, /* two nulls indicates end of list */
	.options_idx = 0,
};

static char view[YOD_MOS_VIEW_LEN] = { "all" };

struct help_text {
	const char *option;
	const char *argument;
	const char *description;
} HELP[] = {
	{"Option", "Argument", "Description",},
	{"----------------", "----------------",
		    "--------------------------------"},
	{"--resources, -R", "<fraction|all|MPI|file:>", "Reserves a portion of LWK"},
	{0, 0, "resources.  If MPI is specified then MPI environment"},
	{0, 0, "variables are used to determine the fractional amount."},
	{"--cpus, -c", "<list>|all", "Reserves the LWK CPUs."},
	{"--cores, -C", "<num|fraction>|all", "Reserves the LWK cores."},
	{"--gpus, -G", "<num|fraction>|all", "Reserves the GPU devices."},
	{"--gpu-tiles, -g", "<num|fraction>|all", "Reserves the GPU tiles."},
	{"--util_threads, -u", "<num>", "Specifies the number of utility"},
	{0, 0, "threads to be heuristically identified"},
	{"--mem, -M", "<size>|<fraction>|all", "Reserves the specified amount"},
	{0, 0, "of LWK memory for this job."},
	{"--mem_algorithm", "<mem-alg>", "Selects the memory algorithm to"},
	{0, 0, "be used for this job."},
	{"--resource_algorithm", "<alg>", "Selects the resource algorithm to"},
	{0, 0, "be used for this job."},
	{"--layout", "<descr>", "Specifies CPU scheduling layout"},
	{0, 0, "within the reserved CPUs.  <descr>"},
	{0, 0, "can be \"scatter\", \"compact\" or"},
	{0, 0, "a permutation of the strings \"node\","},
	{0, 0, "\"tile\", \"core\" and \"cpu\"."},
	{"--rank-layout", "<descr>", "Suggest a layout pattern for MPI ranks"},
	{0, 0, "on the compute node."},
	{"--aligned-mmap", "<threshold>[:<alignment>]", "Private, anonymous"},
	{0, 0, "mmaps of size >= <threshold> will be aligned in virtual"},
	{0, 0, "address space per the given alignment."},
	{"--brk-clear-length", "<size>", "Specifies the amount of memory to"},
	{0, 0, "clear (zero) at the beginning of the expansion area when the"},
	{0, 0, "data segment is expanded via brk."},
	{"--mosview", "<view>", "Specifies the mOS view to be set for the"},
	{0, 0, "LWK process - lwk or all (default)"},
	{"--lwkmem-disable", 0, "Do not use LWK memory for this process."},
	{"--maxpage", "<scope:maxpage>", "Set the upper limit on page size for virtual memory regions."},
	{0, 0, "Settings for multiple regions can be specified using"},
	{0, 0, "separator '/' between them."},
	{0, 0, "scope    - dbss, heap, anon_private, tstack, stack, or all"},
	{0, 0, "maxpage  - 4k, 2m, 1g"},
	{"--pagefault", "<scope:pf_level>", "Set pagefault level for virtual memory regions."},
	{0, 0, "Settings for multiple regions can be specified using"},
	{0, 0, "separator '/' between them."},
	{0, 0, "scope    - dbss, heap, anon_private, tstack, stack, or all"},
	{0, 0, "pf_level - nofault, onefault"},
	{"--mempolicy", "<scope:type>", "Set memory policy type for virtual memory regions."},
	{0, 0, "Settings for multiple regions can be specified using"},
	{0, 0, "separator '/' between them."},
	{0, 0, "scope    - dbss, heap, anon_private, tstack, stack, or all"},
	{0, 0, "type - normal, random, interleave, interleave_random"},
	{"--verbose, -v", "<level>", "Sets verbosity of yod."},
	{0, 0, "be used for this job."}
};

void yod_abort(int rc, const char* format, ...)
{
	char buffer[4096];
	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	YOD_ERR("%s (rc=%d)\n", buffer, rc);
	va_end(args);

	plugin->unlock(&lock_options);
	exit(rc);
}

/**
 * Fetch the list of designated LWK CPUs.
 * @todo make this mos_cpuset_t const *
 */

static mos_cpuset_t *get_designated_lwkcpus(void)
{
	if (designated_lwkcpus == 0) {

		designated_lwkcpus = mos_cpuset_alloc_validate();

		if (plugin->get_designated_lwkcpus(designated_lwkcpus))
			yod_abort(-1, "Could not read lwkcpus");
	}

	return designated_lwkcpus;
}

/**
 * Fetch the list of available LWK cpus.
 * @param[out] set is an allocated yod_cpuse_t
 * @return void - This is a fundamental query in yod.  If it cannot
 *   be completed, yod is in serious trouble.  Thus the caller may
 *   assume that it was successful; yod will abort if something goes
 *   wrong.
 */
static void yod_get_available_lwkcpus(mos_cpuset_t *set)
{
	reserved_lwkcpus = mos_cpuset_alloc_validate();

	if (plugin->get_designated_lwkcpus(set))
		yod_abort(-1, "Could not obtain designated LWK CPU list from plugin.");

	if (plugin->get_reserved_lwk_cpus(reserved_lwkcpus)) {
		yod_abort(-1,
		  "Could not obtain reserved LWK CPU list from plugin.");
	}

	mos_cpuset_xor(set, set, reserved_lwkcpus);
}

int yod_strtol(char *in_str, long int *out_int)
{
	char *remainder;

	errno = 0;
	*out_int = strtol(in_str, &remainder, 0);
	if (errno == ERANGE)
		return -1;
	if (remainder == in_str)
		/* Nothing found */
		return -1;
	if ((errno != 0) && (*out_int == 0))
		return -1;
	return 0;
}

/**
 * Fetch the list of designated LWK gpus.
 * @param[out] set is an allocated yod_cpuset
 * @return void - This is a fundamental query in yod.  If it cannot
 *   be completed, yod is in serious trouble.  Thus the caller may
 *   assume that it was successful; yod will abort if something goes
 *   wrong.
 */
void yod_get_designated_lwkgpus(mos_cpuset_t *gpus)
{
	if (plugin->get_designated_lwkgpus(gpus))
		yod_abort(-1, "Could not obtain designated LWK GPU list from plugin.");
}

int yod_get_num_tiles_per_gpu()
{
	int i;
	int tile_count = 0;
	mos_cpuset_t *temp = mos_cpuset_alloc_validate();

	yod_get_designated_lwkgpus(temp);
	for (i = 0; i < MOS_MAX_TILES_PER_GPU; i++) {
		if (mos_cpuset_is_set(i, temp))
			tile_count++;
	}
	mos_cpuset_free(temp);

	YOD_LOG(YOD_WARN, "(<) %s", __func__);
	return tile_count;
}

static int yod_get_num_designated_lwkgpus(void)
{
	int num;
	mos_cpuset_t *temp = mos_cpuset_alloc_validate();

	yod_get_designated_lwkgpus(temp);
	num = mos_cpuset_cardinality(temp);
	mos_cpuset_free(temp);

	return num;
}


/**
 * Fetch the list of available LWK cpus.
 * @param[out] set is an allocated yod_cpuse_t
 * @return void - This is a fundamental query in yod.  If it cannot
 *   be completed, yod is in serious trouble.  Thus the caller may
 *   assume that it was successful; yod will abort if something goes
 *   wrong.
 */
static void yod_get_available_lwkgpus(mos_cpuset_t *gpus)
{
	/* Current design is that all designated gpus are available to be requested */
	yod_get_designated_lwkgpus(gpus);
}

/**
 * Fetch the list of available LWK cpus.
 * @param[out] set is an allocated yod_cpuse_t
 * @return void - This is a fundamental query in yod.  If it cannot
 *   be completed, yod is in serious trouble.  Thus the caller may
 *   assume that it was successful; yod will abort if something goes
 *   wrong.
 */
void yod_get_gpu_usage_counts(int *counts, int num)
{
	/* Current design is that all designated gpus are available to be requested */
	if (plugin->get_gpu_usage_counts(counts, num)) {
		yod_abort(-1, "Could not obtain gpu usage counts from plugin.");
	}
}

/**
 * Acquires a reference to the specified CPU mapping. This also acts as a lazy
 * initializer of the map (no need to construct it unless it is actually
 * requested).
 * @return a pointer to the CPU-to-xxx map.  If the map cannot be constructed,
 *   the routine will abort yod.  So callers can assume that the return value
 *   is non-null and valid.
 */
struct map_type_t *yod_get_map(enum map_elem_t typ)
{
	/* NOTE: this is not thread safe.  But yod is single-threaded. */

	if (!yod_maps[typ]) {

		size_t i, N;

		yod_maps[typ] = malloc(sizeof(struct map_type_t));

		if (!yod_maps[typ]) {
			yod_abort(-1,
				  "Could not malloc memory for map [%s:%d]",
				  __func__, __LINE__);
		}

		yod_maps[typ]->capacity = 64;
		yod_maps[typ]->size = 0;

		yod_maps[typ]->map = calloc(yod_maps[typ]->capacity,
					    sizeof(mos_cpuset_t *));
		if (!yod_maps[typ]->map) {
			yod_abort(-1,
				  "Could not malloc memory for map [%s:%d]",
				  __func__, __LINE__);
		}
		for (i = 0, N = mos_max_cpus(); i < N; i++) {
			ssize_t elem = plugin->map_cpu(i, typ);

			if (elem < 0)
				continue;

			if ((size_t)elem >= yod_maps[typ]->capacity) {

				/* Double the size, ensuring that the newly
				 * allocated area is cleared out (realloc does
				 * not guarantee this).
				 */

				yod_maps[typ]->capacity <<= 1;
				yod_maps[typ]->map =
					realloc(yod_maps[typ]->map,
						sizeof(mos_cpuset_t *) *
						yod_maps[typ]->capacity);

				if (!yod_maps[typ]->map)
					yod_abort(-1, "Could not malloc memory for map [%s:%d]", __func__, __LINE__);

				memset(yod_maps[typ]->map +
				       (yod_maps[typ]->capacity >> 1),
					0,
					(yod_maps[typ]->capacity >> 1) *
					sizeof(mos_cpuset_t *));
			}

			if (!yod_maps[typ]->map[elem]) {
				yod_maps[typ]->map[elem] =
					mos_cpuset_alloc_validate();
			}

			mos_cpuset_set(i, yod_maps[typ]->map[elem]);

			if (yod_maps[typ]->size <= (size_t)elem)
				yod_maps[typ]->size = elem + 1;

			YOD_LOG(YOD_GORY,
				"mapping type %s : %zd -> %zd  list: %s",
				MAP_TYPES[typ], i, elem,
				mos_cpuset_to_list_validate(yod_maps[typ]->map[elem]));
		}
	}

	return yod_maps[typ];
}

bool yod_null_map(struct map_type_t *m, int i)
{
	return !m->map[i] ||  !mos_cpuset_cardinality(m->map[i]);
}

/**
 * Counts the number of (entire) elements in the given set.
 * For example, yod_count_by(s, YOD_CORE) counts the number
 * of complete cores in the set s.
 */

ssize_t yod_count_by(mos_cpuset_t *set, enum map_elem_t typ)
{
	size_t i, count = 0;
	mos_cpuset_t *tmp;
	struct map_type_t *m;

	m = yod_get_map(typ);
	tmp = mos_cpuset_alloc_validate();

	for (i = 0; i < m->size; i++) {

		if (!m->map[i])
			continue;

		mos_cpuset_and(tmp, set, m->map[i]);

		if (mos_cpuset_equal(tmp, m->map[i]))
			count++;
	}

	mos_cpuset_free(tmp);
	return count;
}




/**
 * Reduces the given set so that it contains entire elements
 * of the specified type.  Returns the number of entire
 * elements in the reduced set.
 * For example, yod_filter_by(t, s, YOD_CORE) eliminates any
 * "loose" CPUs from s.
 */

static int yod_filter_by(mos_cpuset_t *out, mos_cpuset_t *in,
			 enum map_elem_t typ)
{
	size_t i, count = 0;
	mos_cpuset_t *tmp, *tmpin = NULL;
	struct map_type_t *m;

	m = yod_get_map(typ);
	tmp = mos_cpuset_alloc_validate();

	/* If the same set is used for both input and output, we
	 * need to create a temporary copy.
	 */
	if (in == out) {
		tmpin = mos_cpuset_alloc_validate();
		mos_cpuset_or(tmpin, in, in);
		in = tmpin;
	}

	mos_cpuset_xor(out, out, out);

	for (i = 0; i < m->size; i++) {

		if (!m->map[i])
			continue;

		mos_cpuset_and(tmp, in, m->map[i]);

		if (mos_cpuset_equal(tmp, m->map[i])) {
			mos_cpuset_or(out, out, tmp);
			count++;
		}
	}

	mos_cpuset_free(tmp);
	if (tmpin)
		mos_cpuset_free(tmpin);
	return count;
}

/**
 * Searches the set and selects n elements of the specified type.

 * @param[in] n The number of elements to select.
 * @param[in] typ The type of element being searched for.
 * @param[in] ascending If true, selects elements in ascending order; else selects
 *   elements in descending order.
 * @param[in] partial If true, select an element if any CPU in the element of
 *   specified type is found; else select an element only if the entire element
 *   of specified type is found.
 * @param[in] from The set being searched.
 * @param[out] selected The selected elements.
 * @return The number of selected elements (n) if succesfull; otherwise -m where
 *   m is the number of elements that could be selected.
 */

ssize_t yod_select_by(int n, enum map_elem_t typ, bool ascending, bool partial,
		  mos_cpuset_t *from, mos_cpuset_t *selected)
{
	ssize_t i;
	int rc = 0;

	mos_cpuset_t *tmp, *tmpin = NULL;
	struct map_type_t *map;

	map = yod_get_map(typ);
	tmp = mos_cpuset_alloc_validate();

	/* If the same set is used for both input and output, we
	 * need to create a temporary copy.
	 */

	if (from == selected) {
		tmpin = mos_cpuset_clone(from);
		from = tmpin;
	}

	mos_cpuset_xor(selected, selected, selected);

	for (i = ascending ? 0 : map->size - 1; i >= 0 && i < (ssize_t)map->size && n > 0; ascending ? i++ : i--) {

		if (!map->map[i])
			continue;

		mos_cpuset_and(tmp, from, map->map[i]);

		if ((partial && !mos_cpuset_is_empty(tmp)) |
		    mos_cpuset_equal(tmp, map->map[i])) {
			mos_cpuset_or(selected, selected, map->map[i]);
			n--;
			rc++;
		}
	}

	if (n > 0)
		rc = -rc;

	mos_cpuset_free(tmp);
	if (tmpin)
		mos_cpuset_free(tmpin);

	return rc;
}

/**
 * Inserts a value into an ordered set of elements.
 *
 * @param[in/out] set The ordered set of elements.
 * @param[in] value The value to be inserted.
 * @param[in/out] length The number of elements in the set.
 * @param[in] capacity The maximum number of elements (array length) of the set.
 * @return One (1) if the value was added to the set.  Zero (0) if the value
 *   was already present.  Negative one (-1) if an error occurred (typically
 *   out of space in the array).
 */
int yod_ordered_set_insert(size_t *set, size_t value, size_t *length,
			   size_t capacity)
{
	ssize_t i, j;

	for (i = 0; i < (ssize_t)*length; i++) {

		if (set[i] == value)
			return 0;

		if (set[i] > value)
			goto insert;
	}

 insert:
	if ((*length + 1) > capacity)
		return -1;

	for (j = *length - 1; j >= i; j--)
		set[j+1] = set[j];

	(*length)++;
	set[i] = value;

	return 1;
}

enum mem_group_t yod_nid_to_mem_group(int nid)
{
	size_t g;
	struct map_type_t *map = yod_get_map(YOD_MEM_GROUP);

	for (g = 0; g < map->size; g++) {
		if (!map->map[g])
			continue;
		if (mos_cpuset_is_set(nid, map->map[g]))
			return g;
	}
	return YOD_MEM_GROUP_UNKNOWN;
}

void yod_append_memory_nid(int grp, size_t nid, lwk_request_t *req)
{
	size_t i;

	if (grp < 0)
		return;

	for (i = 0; i < req->lwkmem_domain_info_len[grp]; i++)
		if (req->lwkmem_domain_info[grp][i] == nid)
			return;

	req->lwkmem_domain_info[grp][req->lwkmem_domain_info_len[grp]++] = nid;
}

/**
 * The simple core allocation algorithm.  As defined by the mOS Software
 * Requirements Specification, this algorithm allocates compute cores in
 * ascending order.  Note that this routine does not actually allocate the
 * cores, but rather only identifies the set of cores to be allocated.
 */
static int yod_simple_compute_core_algorithm(struct lwk_request_t *this,
					     size_t num_cores,
					     mos_cpuset_t *available)
{
	return yod_select_by(num_cores, YOD_CORE, true, false, available,
		     this->lwkcpus_request) == (ssize_t)num_cores ? 0 : -1;
}

static int yod_simple_memory_selection_algorithm(lwk_request_t *this)
{
	size_t i, remainder;
	enum mem_group_t g;

	/* First fit grouped memory into specific NIDs:
	 */

	for (i = 0; i < this->n_nids; i++) {

		g = yod_nid_to_mem_group(i);

		if (g == YOD_MEM_GROUP_UNKNOWN)
			yod_abort(-EINVAL, "Uncategorized NID %d", i);

		if (this->lwkmem_size_by_group[g]) {
			remainder = this->lwkmem_designated[i] - this->lwkmem_reserved[i] - this->lwkmem_request[i];
			remainder = MIN(remainder, this->lwkmem_size_by_group[g]);
			this->lwkmem_request[i] += remainder;
			this->lwkmem_size_by_group[g] -= remainder;
			if (remainder)
				yod_append_memory_nid(g, i, this);
			YOD_LOG(YOD_DEBUG,
				"Selecting %'zd bytes from nid %zd / group %s ; remaining: %'zd",
				remainder, i, MEM_GROUPS[g], this->lwkmem_size_by_group[g]);
		}
		YOD_LOG(YOD_DEBUG, "lwkmem_request[%zd] = %'zd (group:%s)",
			i, this->lwkmem_request[i], MEM_GROUPS[g]);
	}

	for (g = 0; g < (int)this->n_groups; g++)
		if (this->lwkmem_size_by_group[g]) {
			YOD_ERR("Unfulfilled %'ld bytes from group %s",
				this->lwkmem_size_by_group[g], MEM_GROUPS[g]);
			show_state(YOD_CRIT);
			return -EBUSY;
		}

	for (i = 0; i < this->n_nids && this->lwkmem_size; i++) {
		remainder = this->lwkmem_designated[i] - this->lwkmem_reserved[i] - this->lwkmem_request[i];
		remainder = MIN(remainder, this->lwkmem_size);
		this->lwkmem_request[i] += remainder;
		this->lwkmem_size -= remainder;
		if (remainder)
			yod_append_memory_nid(yod_nid_to_mem_group(i), i, this);
	}

	return this->lwkmem_size ? -EBUSY : 0;
}

void yod_balanced_gpu_select(int num_gpus, bool device, mos_cpuset_t *candidate_gpus,
				mos_cpuset_t *gpus)
{
	int level, gpu, gpus_selected;
	int max_overcommit = 256;
	int counts[MOS_MAX_GPU_TILES];

	yod_get_gpu_usage_counts(counts, MOS_MAX_GPU_TILES);

	/* If we are doing device allocation, use the first tile's usage count
	 * during the search. If we assume the other YOD invocations are also
	 * using device granularity, the usage counts for the other tiles
	 * in the device will be consistent
	 */
	if (device) {
		/* Device granularity */
		for (level = 0, gpus_selected = 0;
		     (gpus_selected < num_gpus) && (level < max_overcommit);
		     level++) {
			for (gpu = 0;
			     gpu < MOS_MAX_GPU_TILES;
			     gpu += MOS_MAX_TILES_PER_GPU) {
				if (!mos_cpuset_is_set(gpu, candidate_gpus))
					continue;
				if (level == counts[gpu]) {
					/* Set all tiles in this device */
					int sub;

					for (sub = gpu;
					      sub < gpu + MOS_MAX_TILES_PER_GPU;
					      sub++) {
						if (mos_cpuset_is_set(sub, candidate_gpus))
							mos_cpuset_set(sub, gpus);
					}
					if (++gpus_selected >= num_gpus)
						break;
				}
			}
			if (level == 1)
				gpu_sharing = true;
		}
	} else {
		/* Tile granularity */
		for (level = 0, gpus_selected = 0;
		     (gpus_selected < num_gpus) && (level < max_overcommit);
		     level++) {
			for (gpu = 0; gpu < MOS_MAX_GPU_TILES; gpu++) {
				if (!mos_cpuset_is_set(gpu, candidate_gpus))
					continue;
				if (level == counts[gpu]) {
					mos_cpuset_set(gpu, gpus);
					if (++gpus_selected >= num_gpus)
						break;
				}
			}
			if (level == 1)
				gpu_sharing = true;
		}
	}
	if (level == max_overcommit)
		YOD_LOG(YOD_WARN, "GPU overcommit threshold of %d reached. No GPUs reserved.", max_overcommit);
}

static int yod_simple_gpu_selection_algorithm(lwk_request_t *req,
						int num_gpus,
						bool device,
						mos_cpuset_t *avail_gpus)
{
	yod_balanced_gpu_select(num_gpus, device, avail_gpus, req->lwkgpus_request);

	return 0;
}

static int yod_select_cores_randomly(int num_cores,
				     mos_cpuset_t *from,
				     mos_cpuset_t *selected)
{
	struct map_type_t *cmap;
	int *core_available;
	mos_cpuset_t *tmp;
	size_t i;

	YOD_LOG(YOD_GORY, "(>) %s num_cores=%d from=%s",
		__func__, num_cores, mos_cpuset_to_list_validate(from));

	if (yod_count_by(from, YOD_CORE) < num_cores)
		return -EINVAL;

	cmap = yod_get_map(YOD_CORE);
	core_available = malloc(cmap->size * sizeof(int));
	tmp = mos_cpuset_alloc_validate();

	for (i = 0; i < cmap->size; i++) {
		core_available[i] = 0;
		if (cmap->map[i]) {
			mos_cpuset_and(tmp, cmap->map[i], from);
			core_available[i] = mos_cpuset_equal(tmp, cmap->map[i]);
		}
	}

	while (num_cores > 0) {

		do {
			i = rand() % cmap->size;
		} while (!core_available[i]);

		mos_cpuset_or(selected, selected, cmap->map[i]);
		core_available[i] = 0;
		num_cores--;
		YOD_LOG(YOD_GORY, "(*) %s num_cores=%d selected=%s", __func__,
			num_cores, mos_cpuset_to_list_validate(selected));
	}

	free(core_available);
	mos_cpuset_free(tmp);

	YOD_LOG(YOD_GORY, "(<) %s num_cores=%d selected=%s", __func__,
		num_cores, mos_cpuset_to_list_validate(selected));
	return 0;
}

static int yod_random_compute_core_algorithm(lwk_request_t *this,
				     size_t num_cores, mos_cpuset_t *available)
{
	return yod_select_cores_randomly(num_cores, available, this->lwkcpus_request);
}

enum resource_type_t {
	YOD_DESIGNATED,
	YOD_RESERVED
};

static size_t yod_get_lwkmem(enum resource_type_t typ)
{
	size_t mem[YOD_MAX_NIDS], result, i, n = ARRAY_SIZE(mem);

	switch (typ) {
	case YOD_DESIGNATED:
		plugin->get_designated_lwkmem(mem, &n);
		break;
	case YOD_RESERVED:
		plugin->get_reserved_lwkmem(mem, &n);
		break;
	default:
		yod_abort(-1, "Internal error: unknown resource type [%s:%d]", __func__, __LINE__);
	}

	for (i = 0, result = 0; i < n; i++)
		result += mem[i];

	return result;
}

struct resource_algorithm_entry {
	const char *name;
	void *compute_core_algorithm;
	void *memory_selection_algorithm;
	void *gpu_selection_algorithm;
} RESOURCE_ALGORITHMS[] = {
	{.name = "simple",
	 .compute_core_algorithm = yod_simple_compute_core_algorithm,
	 .memory_selection_algorithm = yod_simple_memory_selection_algorithm,
	 .gpu_selection_algorithm = yod_simple_gpu_selection_algorithm,
	},
	{.name = "random",
	 .compute_core_algorithm = yod_random_compute_core_algorithm,
	 .memory_selection_algorithm = yod_simple_memory_selection_algorithm,
	 .gpu_selection_algorithm = yod_simple_gpu_selection_algorithm,
	},
	{.name = "numa",
	 .compute_core_algorithm = yod_numa_compute_core_algorithm,
	 .memory_selection_algorithm = yod_numa_memory_selection_algorithm,
	 .gpu_selection_algorithm = yod_numa_gpu_selection_algorithm,
	},
};

#define HELPSTR(s) (s ? s : "")

static void usage(void)
{
	unsigned int i;

	printf("Usage: yod [options] target\n");
	printf("Options:\n");
	for (i = 0; i < sizeof(HELP) / sizeof(HELP[0]); i++) {
		printf(" %-16s  %-16s  %s\n", HELPSTR(HELP[i].option),
		       HELPSTR(HELP[i].argument), HELPSTR(HELP[i].description));
	}
}

/*
 * Convert a label (string) to its corresponding index
 * in a list of labels.
 */

static int label_to_int(const char *lbl, const char * const list[], const int length)
{
	int i;

	for (i = 0; i < length; i++) {
		if (strcmp(lbl, list[i]) == 0)
			return i;
	}
	return -1;
}

/* Return the first index of the specified value within the array or
 * -1 if it is not present.
 */

static int yod_index_of(const int value, const int *array, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (array[i] == value)
			return i;

	return -1;
}

static int null_memory_selection_algorithm(_unused_ lwk_request_t *req)
{
	return 0;
}

static void all_available_memsize_resolver(lwk_request_t *this)
{
	size_t i;

	for (i = 0; i < this->n_nids; i++) {
		this->lwkmem_request[i] = this->lwkmem_designated[i] - this->lwkmem_reserved[i];
		if (this->lwkmem_request[i])
			yod_append_memory_nid(yod_nid_to_mem_group(i), i, this);
	}

	this->lwkmem_size = 0; /* resolved */
	memset(this->lwkmem_size_by_group, 0, sizeof(this->lwkmem_size_by_group));

	this->memory_selection_algorithm = null_memory_selection_algorithm;
}

static void resolve_by_ratio(lwk_request_t *this, double ratio)
{
	size_t i;
	enum mem_group_t g;

	memset(this->lwkmem_size_by_group, 0, sizeof(this->lwkmem_size_by_group));

	for (i = 0; i < YOD_MAX_NIDS; i++) {
		g = yod_nid_to_mem_group(i);
		if (g == YOD_MEM_GROUP_UNKNOWN)
			break;
		this->lwkmem_size_by_group[g] += this->lwkmem_designated[i];
	}

	for (i = 0; i < this->n_groups; i++) {
		this->lwkmem_size_by_group[i] *= ratio;
		this->lwkmem_size_by_group[i] &= PAGE_MASK;
	}
}

static void memsize_by_ratio_resolver(lwk_request_t *this)
{
	resolve_by_ratio(this, requested_lwk_mem_fraction);
}

static void explicit_memsize_resolver(lwk_request_t *this)
{
	int i;
	enum mem_group_t g;
	double total = 0.0, per_group[YOD_MAX_GROUPS] = {0.0, };
	size_t delta, available[YOD_MAX_GROUPS] = {0, };

	if (requested_lwk_mem > yod_get_lwkmem(YOD_DESIGNATED))
		yod_abort(-EINVAL,
			  "Requested memory exceeds memory designated for LWK usage.");

	/* lwkmem_size represents the total amount of memory remaining to be
	 * reserved for this process.  This quantity needs to be dispersed
	 * into the various groups (lwkmem_size_by_group).
	 */

	this->lwkmem_size = requested_lwk_mem;

	/* Pass 1: attempt to disperse the remaining amount in proportion to the
	 * designated sizes of the groups:
	 */

	for (i = 0; i < YOD_MAX_NIDS; i++) {
		g = yod_nid_to_mem_group(i);
		if (g == YOD_MEM_GROUP_UNKNOWN)
			break;
		per_group[g] += this->lwkmem_designated[i];
		available[g] += this->lwkmem_designated[i] -
			this->lwkmem_reserved[i];
		total += this->lwkmem_designated[i];
	}

	for (g = 0; g < (int)this->n_groups; g++) {
		delta = requested_lwk_mem * (per_group[g] / total);
		delta = MIN(delta, available[g]);
		this->lwkmem_size_by_group[g] += delta;
		this->lwkmem_size -= delta;
		available[g] -= delta;
	}

	/* Pass 2: If there is still some memory that has not yet been dispersed
	 * to a group, borrow from whatever is available:
	 */

	for (g = 0; g < (int)this->n_groups && this->lwkmem_size > 0; g++) {
		delta = MIN(this->lwkmem_size, available[g]);
		if (delta > 0) {
			this->lwkmem_size_by_group[g] += delta;
			this->lwkmem_size -= delta;
			YOD_LOG(YOD_WARN,
				"Borrowing %'ld bytes from %s to fullfil this request.",
				delta, MEM_GROUPS[g]);
		}
	}

	if (this->lwkmem_size) {
		show_state(YOD_CRIT);
		yod_abort(-EBUSY, "Not enough memory is available.");
	}
}

/** Checks to see if any CPUs in set are non-LWK CPUs.  If so,
 * returns the set of non-LWK CPUs; otherwise returns NULL.
 * Note that we leak a cpuset in the non-empty case.  So be it.
 */
static mos_cpuset_t *check_for_non_lwk_cpus(mos_cpuset_t *set)
{
	mos_cpuset_t *all_lwkcpus, *non_lwkcpus;

	non_lwkcpus = mos_cpuset_alloc_validate();
	all_lwkcpus = mos_cpuset_alloc_validate();

	if (plugin->get_designated_lwkcpus(all_lwkcpus))
		yod_abort(-1, "Could not obtain LWK CPU list from plugin.");

	mos_cpuset_not(non_lwkcpus, all_lwkcpus);
	mos_cpuset_and(non_lwkcpus, non_lwkcpus, set);

	if (!mos_cpuset_is_empty(non_lwkcpus)) {
		YOD_LOG(YOD_GORY, "Non-LWK CPUs detected - 0x%s",
			mos_cpuset_to_mask(non_lwkcpus));
	} else {
		mos_cpuset_free(non_lwkcpus);
		non_lwkcpus = 0;
	}

	mos_cpuset_free(all_lwkcpus);

	return non_lwkcpus;
}

static void all_available_lwkcpus_resolver(lwk_request_t *this)
{
	/* Resolver for "--cpus all" option */
	yod_get_available_lwkcpus(this->lwkcpus_request);

	if (mos_cpuset_is_empty(this->lwkcpus_request)) {
		show_state(YOD_CRIT);
		yod_abort(-EBUSY, "No LWK CPUs are available.");
	}
}

static void all_available_lwk_cores_resolver(lwk_request_t *this)
{
	/* Resolver for "--cores all" option */
	yod_get_available_lwkcpus(this->lwkcpus_request);

	if (yod_filter_by(this->lwkcpus_request, this->lwkcpus_request, YOD_CORE) <= 0) {

		int n;

		n = yod_count_by(get_designated_lwkcpus(), YOD_CORE);
		show_state(YOD_CRIT);
		yod_abort(n > 0 ? -EBUSY : -EINVAL, "There are no complete cores available.");
	}
}

static void lwkcpus_by_list_resolver(lwk_request_t *this)
{
	mos_cpuset_t *non_lwkcpus;

	/* Resolver for "--cpus <list>" option. It is possible in this path
	 * to ask for some CPU(s) that are not LWK CPUs.  Or that no CPUs
	 * were actually requested.
	 */

	if (mos_cpuset_is_empty(requested_lwk_cpus)) {
		if (all_lwk_cpus_specified) {
			show_state(YOD_CRIT);
			yod_abort(-EBUSY, "No LWK CPUs are available.");
		} else
			yod_abort(-EINVAL, "No LWK CPUs were requested.");
	}

	non_lwkcpus = check_for_non_lwk_cpus(requested_lwk_cpus);

	if (non_lwkcpus)
		yod_abort(-EINVAL,
			  "One or more requested CPUs (%s) is not an LWK CPU.\n\t%s",
			  mos_cpuset_to_list_validate(non_lwkcpus),
			  extra_help);

	mos_cpuset_or(this->lwkcpus_request, requested_lwk_cpus,
		      requested_lwk_cpus);
}

static void n_cores_lwkcpu_resolver(lwk_request_t *this)
{
	/* Resolver for the --cores <N|FRAC> options. */

	mos_cpuset_t *available_cpus;
	int n_desig;

	n_desig = yod_count_by(get_designated_lwkcpus(), YOD_CORE);

	if (requested_lwk_cores > n_desig)
		yod_abort(-EINVAL, "Your configuration has %d designated LWK cores, but you are asking for %d.",
			  n_desig, requested_lwk_cores);

	available_cpus = mos_cpuset_alloc_validate();
	yod_get_available_lwkcpus(available_cpus);

	if (this->compute_core_algorithm(this, requested_lwk_cores, available_cpus)) {
		show_state(YOD_CRIT);
		yod_abort(-EBUSY, "There are not enough cores available.");
	}

	assert(mos_cpuset_is_subset(this->lwkcpus_request, available_cpus));
	mos_cpuset_free(available_cpus);
}

void yod_ze_mask_to_mos_gpuset(char *ze_mask, mos_cpuset_t *gpuset)
{
	char *device_s, *tile_s;
	char *p, *dup;
	long device, tile;
	int i, tiles_per_gpu;

	/* Extract the devices from the string and set the lwk gpu
	 * request bitmap. We need this to bump usage counts to
	 * accurately track LWK users of the GPU devicies so that proper
	 * balancing can be done for other lwk processes. The string is
	 * in the form: device.tile,device.tile,... with ".tile"
	 * being optional. Operate on a copy since the string will be
	 * modified.
	*/
	p = dup = strdup(ze_mask);
	if (!p)
		yod_abort(-ENOMEM, "Call to strdup failed allocating memory.");

	tiles_per_gpu = yod_get_num_tiles_per_gpu();
	while ((tile_s = strsep(&p, ","))) {
		if (strlen(tile_s) == 0)
			break;
		device_s = strsep(&tile_s, ".");
		if (strlen(device_s) == 0)
			break;
		if (yod_strtol(device_s, &device))
			yod_abort(-EINVAL, "Error converting device string(%s) to integer.", device_s);
		if (!tile_s || strlen(tile_s) == 0) {
			/* No tile specifed. Need to set all available tiles */
			for (i = 0; i < tiles_per_gpu; i++) {
				mos_cpuset_set(device * MOS_MAX_TILES_PER_GPU + i,
					gpuset);
			}
		} else {
			if (yod_strtol(tile_s, &tile))
				yod_abort(-EINVAL, "Error converting device string(%s) to integer.", tile_s);
			mos_cpuset_set(device * MOS_MAX_TILES_PER_GPU + tile, gpuset);
		}
	}
	free(dup);
}


static void use_original_gpu_affinity(lwk_request_t *request)
{

	/* Setup to restore the original ze_affinity_mask. */
	assert(sizeof(request->ze_affinity_request) > strlen(request->ze_affinity_on_entry));
	strncpy(request->ze_affinity_request, request->ze_affinity_on_entry,
		sizeof(request->ze_affinity_request));

	yod_ze_mask_to_mos_gpuset(request->ze_affinity_request, request->lwkgpus_request);
}

static void n_gpus_resolver(lwk_request_t *request)
{
	/* Resolver for the --gpus <N|FRAC> options. */
	mos_cpuset_t *gpu_set;
	int n_desig, size, length;
	long g_index;
	int t_num, d_num;
	char *p;


	if (request->ze_affinity_on_entry && !request->explicit_gpus_request) {
		use_original_gpu_affinity(request);
	} else {
		gpu_set = mos_cpuset_alloc_validate();
		yod_get_designated_lwkgpus(gpu_set);
		n_desig = mos_cpuset_cardinality(gpu_set);
		if (!n_desig)
			return; /* The --resource option may have gotten us here */
		if (requested_lwk_gpus > n_desig)
			yod_abort(-EINVAL, "Your configuration has %d designated GPU tiles, but you are asking for %d.",
			    n_desig, requested_lwk_gpus);
		if (requested_lwk_gpu_devices > (n_desig / yod_get_num_tiles_per_gpu()))
			yod_abort(-EINVAL, "Your configuration has %d designated GPU devices, but you are asking for %d.",
			    n_desig, requested_lwk_gpu_devices);

		yod_get_available_lwkgpus(gpu_set);

		if (request->gpu_selection_algorithm(request,
				requested_lwk_gpus ? requested_lwk_gpus : requested_lwk_gpu_devices,
				requested_lwk_gpus ? 0 : 1, gpu_set)) {
			show_state(YOD_CRIT);
			yod_abort(-EBUSY, "There are not enough gpus available.");
		}

		assert(mos_cpuset_is_subset(request->lwkgpus_request, gpu_set));
		mos_cpuset_free(gpu_set);

		/* Generate the affinity environment variable string */

		request->ze_affinity_request[0] = 0;
		p = request->ze_affinity_request;
		for (g_index = 0, size = sizeof(request->ze_affinity_request);
		    g_index < MOS_MAX_GPU_TILES; g_index++) {
			if (!mos_cpuset_is_set(g_index, request->lwkgpus_request))
				continue;
			d_num = g_index / MOS_MAX_TILES_PER_GPU;
			t_num = d_num ? g_index % (d_num * MOS_MAX_TILES_PER_GPU) : g_index;
			length = snprintf(p, size, "%d.%d,", d_num, t_num);
			size -= length;
			p += length;
		}
		/* remove the trailing comma */
		*(--p) = '\0';
	}
}

static void all_available_gpus_resolver(lwk_request_t *request)
{
	int length, size;
	long g_index;
	int t_num, d_num;
	char *p;

	/* Test to see if we entered due to no --gpus keyword and caller has
	 * set the ZE_AFFINITY_MASK environment variable
	 */
	if (request->ze_affinity_on_entry && !request->explicit_gpus_request) {
		use_original_gpu_affinity(request);
	} else {


		p = request->ze_affinity_request;

		yod_get_available_lwkgpus(request->lwkgpus_request);
		/* Construct the ZE_AFFINITY_MASK string */
		request->ze_affinity_request[0] = '\0';
		for (g_index = 0, size = sizeof(request->ze_affinity_request);
		     g_index < MOS_MAX_GPU_TILES;
		     g_index++) {
			if (!mos_cpuset_is_set(g_index, request->lwkgpus_request))
				continue;
			d_num = g_index / MOS_MAX_TILES_PER_GPU;
			t_num = d_num ? g_index % (d_num * MOS_MAX_TILES_PER_GPU) : g_index;
			length = snprintf(p, size, "%d.%d,", d_num, t_num);
			size -= length;
			p += length;
		}
		/* remove the trailing comma */
		 *(--p) = '\0';
	}
}

/*
 * The yodopt_* routines are handlers for the various command line options.
 */

static inline bool no_lwkmem_requested(void)
{
	return requested_lwk_mem == (unsigned long)-1;
}

static void yodopt_check_for_cpus_already_specified(void)
{
	if (requested_lwk_cpus || (requested_lwk_cores != -1))
		yod_abort(-EINVAL,
			  "Specify only one of --cpus/-c, --cores/-C, --resources/-R."
			  );
}

static void yodopt_check_for_gpus_already_specified(void)
{
	if (requested_lwk_gpus)
		yod_abort(-EINVAL,
			  "Specify only one of --gpus/-G, --resources/-R."
			  );
}

static void yodopt_check_for_mem_already_specified(void)
{
	if (!lwkmem_disabled && !no_lwkmem_requested())
		yod_abort(-EINVAL,
			  "Specify only one of --mem/-M, --resources/-R."
			  );
}

static void assert_lwkmem_enabled(void)
{
	if (lwkmem_disabled)
		yod_abort(-EINVAL,
			  "Conflicting memory option with --lwkmem-disable");
}

/** Converts opt to a long int value.  Expects opt to look exactly like
 * an integer.  The integer value must be in the range [lower,upper).
 */
int yodopt_parse_integer(const char *opt, long int *val, long int lower,
			 long int upper)
{

	char *remainder;

	errno = 0;
	*val = strtol(opt, &remainder, 0);

	if (errno == ERANGE)
		return -1;

	if (remainder == opt)
		/* Nothing found */
		return -1;

	if (*remainder != '\0')
		/* Extraneous characters */
		return -1;

	if ((errno != 0) && (*val == 0))
		/* Other cases (see strtol man page) */
		return -1;

	if ((*val < lower) || (*val > upper))
		return -1;

	return 0;
}

/** Converts opt to a floating point value.  The value must be
 *  in the range [lower,upper] where both lower and upper are
 *  floating point numbers (excluding infinities and NaNs). */

static int yodopt_parse_floating_point(const char *opt, double *val,
				       double lower, double upper)
{
	char *remainder;

	errno = 0;
	*val = strtod(opt, &remainder);

	if (errno == ERANGE)
		/* Over or underflow */
		return -1;

	if (remainder == opt)
		/* nothing found */
		return -1;

	if (*remainder != '\0')
		/* Extraneous characters */
		return -1;

	if ((fpclassify(*val) == FP_NAN) ||
	    (fpclassify(*val) == FP_INFINITE))
		return -1;

	if ((*val < lower) || (*val > upper))
		return -1;

	return 0;
}

/** Converts opt to a fractional value when opt is of the form
 * "M/N", M and N integers, N != 0
 */

static int yodopt_parse_rational(const char *opt, double *val,
				 double lower, double upper)
{
	char *copy = 0,  *arg, *numerstr;
	long int numerator, denominator;

	if (!strchr(opt, '/'))
		goto err;

	copy = strdup(opt);

	if (!copy)
		goto err;

	arg = copy;
	numerstr = strsep(&arg, "/");

	if (yodopt_parse_integer(numerstr, &numerator, 0, LONG_MAX) ||
	    yodopt_parse_integer(arg, &denominator, 1, LONG_MAX))
		goto err;

	*val = (double)numerator / (double)denominator;

	if ((*val < lower) || (*val > upper))
		goto err;

	free(copy);
	return 0;

 err:
	free(copy);
	return -1;
}

static int yodopt_parse_memsize(const char *opt, long *size)
{
	char *nxt;
	double frac;
	bool symbolic;

	*size = 1;
	symbolic = false;
	frac = strtod(opt, &nxt);

	if (!isfinite(frac))
		goto illegal;

	switch (*nxt) {

	case 'P':
	case 'p':
		*size <<= 10;
		symbolic = true;
		/* fallthrough */
	case 'G':
	case 'g':
		*size <<= 10;
		symbolic = true;
		/* fallthrough */
	case 'm':
	case 'M':
		*size <<= 10;
		symbolic = true;
		/* fallthrough */
	case 'k':
	case 'K':
		*size <<= 10;
		symbolic = true;
		break;
	}

	if (symbolic ? nxt[1] != '\0' : nxt[0] != '\0')
		goto illegal;

	*size *= frac;

	return 0;

 illegal:
	return -1;
}

static int yodopt_is_mask(const char *opt)
{
	return
		(strlen(opt) > 1) &&
		(opt[0] == '0') &&
		(opt[1] == 'x' || opt[1] == 'X');
}

static int yodopt_lwk_cpus(const char *opt)
{

	yodopt_check_for_cpus_already_specified();

	requested_lwk_cpus = mos_cpuset_alloc_validate();

	if (strcmp("all", opt) == 0) {
		yod_get_available_lwkcpus(requested_lwk_cpus);
		lwk_req.lwkcpus_resolver = all_available_lwkcpus_resolver;
		all_lwk_cpus_specified = 1;
	} else {
		if (yodopt_is_mask(opt)) {
			if (mos_parse_cpumask(opt, requested_lwk_cpus))
				yod_abort(-EINVAL,
					  "Could not parse CPU mask \"%s\".",
					  opt);
		} else if (mos_parse_cpulist(opt, requested_lwk_cpus)) {
			yod_abort(-EINVAL, "Could not parse CPU list \"%s\".",
				  opt);
		}


		lwk_req.lwkcpus_resolver = lwkcpus_by_list_resolver;

		/* A common error is to specify "--cpu N" thinking that one
		 * is requesting N CPUs rather than CPU #N.  If a single CPU
		 * is being requested, we'll squirrel away a message that
		 * might be useful later.
		 */
		if (mos_cpuset_cardinality(requested_lwk_cpus) == 1) {
			snprintf(extra_help, sizeof(extra_help),
				 "You specified \"--cpus %s\".  Do you realize that the argument is a list?",
				 mos_cpuset_to_list_validate(requested_lwk_cpus));
			YOD_LOG(YOD_WARN, "%s", extra_help);
		}
	}

	return 0;
}


static int yodopt_lwk_cores(const char *opt)
{
	long int ncores;
	double fraction;

	yodopt_check_for_cpus_already_specified();

	lwk_req.lwkcpus_resolver = n_cores_lwkcpu_resolver;

	if (strcmp("all", opt) == 0) {
		requested_lwk_cores = INT_MAX;
		lwk_req.lwkcpus_resolver = all_available_lwk_cores_resolver;
	} else if (strcmp("MPI", opt) == 0) {
		if (!mpi_localnranks)
			yod_abort(-EINVAL, "Invalid MPI_LOCALNRANKS value %u.", mpi_localnranks);
		fraction = 1.0 / (double)mpi_localnranks;

		requested_lwk_cores = fraction *
			yod_count_by(get_designated_lwkcpus(), YOD_CORE);
	} else if (yodopt_parse_integer(opt, &ncores, 1, INT_MAX) == 0) {
		requested_lwk_cores = ncores;
	} else if (yodopt_parse_floating_point(opt, &fraction, 0.0, 1.0) == 0 ||
		   yodopt_parse_rational(opt, &fraction, 0.0, 1.0) == 0) {
		requested_lwk_cores = fraction *
			yod_count_by(get_designated_lwkcpus(), YOD_CORE);
	} else {
		yod_abort(-EINVAL, "Bad argument for --cores.");
	}

	if (requested_lwk_cores == 0)
		yod_abort(-EINVAL, "No compute cores requested.");

	return 0;
}

static int _yodopt_lwk_gpus(const char *opt, bool device)
{
	long int ngpus;
	double fraction;
	int tiles_per_gpu_device = yod_get_num_tiles_per_gpu();
	int designated_gpus = yod_get_num_designated_lwkgpus();

	if (!designated_gpus)
		yod_abort(-EINVAL, "Requesting GPUs but non available.");

	yodopt_check_for_gpus_already_specified();

	lwk_req.explicit_gpus_request = true;

	lwk_req.lwkgpus_resolver = n_gpus_resolver;

	if (strcmp("all", opt) == 0) {
		requested_lwk_gpus = designated_gpus;
		lwk_req.lwkgpus_resolver = all_available_gpus_resolver;
	} else if (strcmp("MPI", opt) == 0) {

		if (!mpi_localnranks)
			yod_abort(-EINVAL, "Invalid MPI_LOCALNRANKS value %u.", mpi_localnranks);
		fraction = 1.0 / (double)mpi_localnranks;
		if (device) {
			requested_lwk_gpu_devices = fraction * (designated_gpus / tiles_per_gpu_device);
			if (!requested_lwk_gpu_devices)
				requested_lwk_gpu_devices = 1;
		} else {
			requested_lwk_gpus = fraction * designated_gpus;
			if (!requested_lwk_gpus)
				requested_lwk_gpus = 1;
		}
	} else if (yodopt_parse_integer(opt, &ngpus, 1, INT_MAX) == 0) {
		if (device)
			requested_lwk_gpu_devices = ngpus;
		else
			requested_lwk_gpus = ngpus;
	} else if (yodopt_parse_floating_point(opt, &fraction, 0.0, 1.0) == 0 ||
		   yodopt_parse_rational(opt, &fraction, 0.0, 1.0) == 0) {

		if (device) {
			requested_lwk_gpu_devices = fraction * (designated_gpus / tiles_per_gpu_device);
			if (!requested_lwk_gpu_devices)
				requested_lwk_gpu_devices = 1;
		} else {
			requested_lwk_gpus = fraction * designated_gpus;
			if (!requested_lwk_gpus)
				requested_lwk_gpus = 1;
		}
	} else {
		yod_abort(-EINVAL, "Bad argument for --gpus.");
	}
	if (requested_lwk_gpus == 0 && requested_lwk_gpu_devices == 0)
		yod_abort(-EINVAL, "No gpus requested.");

	return 0;
}

static int yodopt_lwk_gpus(const char *opt)
{
	return _yodopt_lwk_gpus(opt, 1);
}
static int yodopt_lwk_gpu_tiles(const char *opt)
{
	return _yodopt_lwk_gpus(opt, 0);
}

static int yodopt_util_threads(const char *opt)
{
	long int nthreads;

	if (yodopt_parse_integer(opt, &nthreads, 0, INT_MAX))
		yod_abort(-EINVAL, "Bad argument for --util-threads.");

	num_util_threads = nthreads;

	return 0;
}

static int yodopt_mem(const char *opt)
{
	assert_lwkmem_enabled();
	yodopt_check_for_mem_already_specified();

	if (strcmp("all", opt) == 0) {
		lwk_req.memsize_resolver = all_available_memsize_resolver;
		requested_lwk_mem = LONG_MAX;
	} else if (strcmp("MPI", opt) == 0) {
		double fraction;
		unsigned long size;

		if (!mpi_localnranks)
			yod_abort(-EINVAL, "Invalid MPI_LOCALNRANKS value %u.", mpi_localnranks);
		fraction = 1.0 / (double)mpi_localnranks;
		size = yod_get_lwkmem(YOD_DESIGNATED);
		requested_lwk_mem = (unsigned long)(fraction * size);
		lwk_req.memsize_resolver = explicit_memsize_resolver;
	} else {
		char *nxt;
		double frac;
		unsigned long size = 1;

		if (yodopt_parse_rational(opt, &frac, -HUGE_VAL, HUGE_VAL)) {
			frac = strtod(opt, &nxt);

			if (frac <= 0.0 || !isfinite(frac))
				goto illegal;

			switch (*nxt) {
			case '\0':
				/* A fractional specifier with no additional
				 * memory size decoration is a fractional amount
				 * of designated memory.
				 */
				if (frac < 1.0)
					size = yod_get_lwkmem(YOD_DESIGNATED);
				break;
			case 'P':
			case 'p':
				size <<= 10; /* fallthrough */
			case 'G':
			case 'g':
				size <<= 10; /* fallthrough */
			case 'm':
			case 'M':
				size <<= 10; /* fallthrough */
			case 'k':
			case 'K':
				size <<= 10;
				break;
			default:
				goto illegal;
			}

			if (nxt[0] != '\0' && nxt[1] != '\0')
				goto illegal;
		} else {
			if (frac <= 0.0 || frac > 1.0)
				goto illegal;
			size = yod_get_lwkmem(YOD_DESIGNATED);
		}

		requested_lwk_mem = (unsigned long)(frac * size);
		lwk_req.memsize_resolver = explicit_memsize_resolver;
	}

	YOD_LOG(YOD_GORY, "LWK memory requested : %s -> %lX", opt,
		requested_lwk_mem);
	return 0;

 illegal:
	yod_abort(-EINVAL, "Illegal argument for --mem.");
}

static void yodopt_process_resource_file(const char *);

static int yodopt_lwk_resources(const char *opt)
{
	double fraction = 0.0;
	int designated_gpus;

	yodopt_check_for_cpus_already_specified();
	yodopt_check_for_gpus_already_specified();
	yodopt_check_for_mem_already_specified();

	lwk_req.lwkcpus_resolver = n_cores_lwkcpu_resolver;

	if (strcmp("all", opt) == 0) {
		requested_lwk_cores = INT_MAX;
		requested_lwk_gpus = yod_get_num_designated_lwkgpus();
		lwk_req.lwkcpus_resolver = all_available_lwk_cores_resolver;
		lwk_req.lwkgpus_resolver = all_available_gpus_resolver;
		if (!lwkmem_disabled) {
			requested_lwk_mem = LONG_MAX;
			lwk_req.memsize_resolver = all_available_memsize_resolver;
		}
		fraction = 1.0;
	} else if (strncmp("file:", opt, strlen("file:")) == 0) {
		yodopt_process_resource_file(opt + strlen("file:"));
	} else if (strcmp("MPI", opt) == 0 ||
		   (yodopt_parse_floating_point(opt, &fraction, 0.0, 1.0) == 0 ||
		    yodopt_parse_rational(opt, &fraction, 0.0, 1.0) == 0)) {
		if (fraction == 0.0) {
			if (!mpi_localnranks)
				yod_abort(-EINVAL, "Invalid MPI_LOCALNRANKS value %u.", mpi_localnranks);
			fraction = 1.0 / (double)mpi_localnranks;
		}
		requested_lwk_cores = fraction *
			yod_count_by(get_designated_lwkcpus(), YOD_CORE);
		lwk_req.lwkcpus_resolver = n_cores_lwkcpu_resolver;
		designated_gpus = yod_get_num_designated_lwkgpus();
		requested_lwk_gpus = fraction * designated_gpus;
		if (!requested_lwk_gpus && designated_gpus && fraction > 0.0)
			requested_lwk_gpus = 1;
		lwk_req.lwkgpus_resolver = n_gpus_resolver;

		if (!lwkmem_disabled) {
			requested_lwk_mem = (unsigned long)(fraction *
						yod_get_lwkmem(YOD_DESIGNATED));
			requested_lwk_mem_fraction = fraction;
			lwk_req.memsize_resolver = memsize_by_ratio_resolver;
		}
	} else {
		yod_abort(-EINVAL, "Bad argument for --resources/-R.");
	}

	if (requested_lwk_cores == 0)
		yod_abort(-EINVAL,
			  "Requested fractional number of compute cores is zero (%f x %d < 1)",
			  fraction,
			  yod_count_by(get_designated_lwkcpus(), YOD_CORE));

	return 0;
}

static int yodopt_resource_algorithm(const char *opt)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(RESOURCE_ALGORITHMS); i++) {
		if (strcmp(RESOURCE_ALGORITHMS[i].name, opt) == 0) {
			lwk_req.compute_core_algorithm =
				RESOURCE_ALGORITHMS[i].compute_core_algorithm;
			lwk_req.memory_selection_algorithm =
				RESOURCE_ALGORITHMS[i].memory_selection_algorithm;
			lwk_req.gpu_selection_algorithm =
				RESOURCE_ALGORITHMS[i].gpu_selection_algorithm;

			resource_algorithm_index = i;

			if (strcmp(opt, "random") == 0) {
				srand(time(0));
			}
			return 0;
		}
	}

	yod_abort(-EINVAL, "Invalid resource_algorithm: \"%s\".", opt);
}

static int yodopt_mem_algorithm(const char *opt)
{
	assert_lwkmem_enabled();
	mem_algorithm =
	    label_to_int(opt, YOD_MEM_ALGORITHMS,
			 ARRAY_SIZE(YOD_MEM_ALGORITHMS));
	if (mem_algorithm == (unsigned int)-1) {
		YOD_ERR("Invalid mem_algorithm: %s", opt);
		return -1;
	}
	return 0;
}

static void yodopt_layout(const char *descr)
{
	strncpy(lwk_req.layout_descriptor, descr, sizeof(lwk_req.layout_descriptor) - 1);

	if (strlen(descr) != strlen(lwk_req.layout_descriptor))
	    yod_abort(-EINVAL, "Overrun of layout buffer in %s", __func__);
}

static void yodopt_rank_layout(const char *descr)
{
	static const char * const RANK_LAYOUTS[] = {
		"compact",
		"scatter",
		"disable"
	};

	unsigned int i;
	char *opt = (char *)descr;

	for (i = 0; i < ARRAY_SIZE(RANK_LAYOUTS); i++) {
		if (!strncmp(RANK_LAYOUTS[i], opt, strlen(RANK_LAYOUTS[i]))) {
			lock_options.layout = i;
			opt += strlen(RANK_LAYOUTS[i]);
			break;
		}
	}

	if (lock_options.layout == YOD_RANK_SCATTER) {
		long int stride;

		if (*opt == ':') {
			opt++;
			if (yodopt_parse_integer(opt, &stride, 1, LONG_MAX))
				yod_abort(-EINVAL,
					  "Bad stride for --rank-layout");
			lock_options.stride = stride;
			*opt = '\0';
		}
	}

	if (*opt != '\0')
		yod_abort(-EINVAL, "Illegal argument for --rank-layout: %s",
			  descr);
}

static void yodopt_option(const char *opt)
{
	size_t offset, this_opt_len;

	/* options_idx is the offset of the last option string contained in the
	 * options buffer.  So the current offset into the buffer is this
	 * options_idx plus the length of the string at that offset:
	 */

	offset = strlen(lwk_req.options + lwk_req.options_idx) +
		lwk_req.options_idx;
	this_opt_len = strlen(opt);

	YOD_LOG(YOD_DEBUG, "(>) %s opt=%s offs=%zd first=%s idx=%zd last=%s",
		__func__, opt, offset, lwk_req.options+1, lwk_req.options_idx,
		lwk_req.options + lwk_req.options_idx);

	/* We need room for the null terminator of the old string plus the new
	 * string plus two null characters to demarcate the end of the buffer.
	 */

	if (offset + this_opt_len + 3 > sizeof(lwk_req.options))
		yod_abort(-EINVAL, "Overflow in options buffer.");

	/* Insert the string into the buffer, leaving the string termination
	 * character from the old string, and inserting an extra null
	 * character at the end of the new string.
	 */

	lwk_req.options_idx +=
		strlen(lwk_req.options + lwk_req.options_idx) + 1;
	strcat(lwk_req.options + lwk_req.options_idx, opt);
	lwk_req.options[lwk_req.options_idx + this_opt_len + 1] = '\0';
}

static void yodopt_aligned_mmap(const char *opt)
{
	char *copy = 0, *remainder, *arg;
	char buffer[256];
	long threshold = -1, alignment = -1;
	int rc;

	assert_lwkmem_enabled();
	copy = strdup(opt);
	if (!copy)
		yod_abort(-ENOMEM, "Out of memory");

	remainder = copy;
	arg = strsep(&remainder, ":");

	if (yodopt_parse_memsize(arg, &threshold) || (threshold < 0))
		goto illegal;

	arg = strsep(&remainder, ":");

	if (arg) {

		if (yodopt_parse_memsize(arg, &alignment) || (alignment <= 0))
			goto illegal;

		if ((alignment < (long)(PAGE_SIZE << 1) ||
		     (alignment & (PAGE_SIZE - 1)))) {
			yod_abort(-EINVAL,
				"Alignment must be at least %ld and multiple of %ld.",
				  2 * PAGE_SIZE, PAGE_SIZE);
		}

		rc = snprintf(buffer, sizeof(buffer),
			 "lwkmem-aligned-mmap=%ld:%ld", threshold, alignment);
	} else {
		rc = snprintf(buffer, sizeof(buffer), "lwkmem-aligned-mmap=%ld",
			      threshold);
	}

	if (rc >= (int)sizeof(buffer))
		yod_abort(-EINVAL, "Buffer overflow");

	yodopt_option(buffer);

	free(copy);
	return;

 illegal:
	yod_abort(-EINVAL, "Illegal aligned-mmap argument: %s", opt);
}

static void yodopt_brk_clear_length(const char *opt)
{
	long length = -1;
	char buffer[256];
	int rc;

	assert_lwkmem_enabled();
	if (yodopt_parse_memsize(opt, &length))
		goto illegal;

	rc = snprintf(buffer, sizeof(buffer), "lwkmem-brk-clear-len=%ld",
		      length);

	if (rc >= (int)sizeof(buffer))
		yod_abort(-EINVAL, "Buffer overflow.");

	yodopt_option(buffer);
	return;

 illegal:
	yod_abort(-EINVAL, "Illegal brk-clear-length argument: %s", opt);
}

static void yodopt_maxpage(const char *opt)
{
	int s;
	char *arg, *arg_start;
	char *pref_s, *scope_s, *maxpg_s;
	enum mem_scopes_t scope;
	enum page_types_t maxpg;

	arg = strdup(opt);
	arg_start = arg;

	if (!arg)
		yod_abort(-ENOMEM, "Could not copy: %s", opt);

	while ((pref_s = strsep(&arg, "/"))) {
		if (strlen(pref_s) == 0)
			continue;

		scope_s = strsep(&pref_s, ":");
		maxpg_s = strsep(&pref_s, ":");

		if (pref_s)
			yod_abort(-EINVAL,
				  "Invalid maxpage: Extraneous characters afer %s:%s",
				  scope_s,
				  maxpg_s);

		if (!scope_s || !maxpg_s)
			yod_abort(-EINVAL,
				  "Invalid arguments to set maxpage");

		scope = label_to_int(scope_s, SCOPES, ARRAY_SIZE(SCOPES));
		if (scope == YOD_SCOPE_UNKNOWN)
			yod_abort(-EINVAL,
				  "Invalid scope to set maxpage: \"%s\"",
				  scope_s);

		maxpg = label_to_int(maxpg_s, PAGE_TYPES, ARRAY_SIZE(PAGE_TYPES));
		if (maxpg == PG_TYPE_UNKNOWN)
			yod_abort(-EINVAL,
				  "Invalid page type to set maxpage: \"%s\"",
				  maxpg_s);

		if (scope == YOD_SCOPE_ALL) {
			for (s = 0; s < YOD_NUM_MEM_SCOPES; s++) {
				lwk_req.memory_preferences[s].max_page_size = PAGE_SIZES[maxpg];
				explicit_maxpage[s] = true;
			}
		} else {
			lwk_req.memory_preferences[scope].max_page_size = PAGE_SIZES[maxpg];
			explicit_maxpage[scope] = true;
		}
	}
	free(arg_start);
}

static void yodopt_pagefault_level(const char *opt)
{
	int s;
	char *arg, *arg_start;
	char *pref_s, *scope_s, *pf_level_s;
	enum mem_scopes_t scope;
	enum page_fault_levels_t pf_level;

	assert_lwkmem_enabled();
	arg = strdup(opt);
	arg_start = arg;

	if (!arg)
		yod_abort(-ENOMEM, "Could not copy: %s", opt);

	while ((pref_s = strsep(&arg, "/"))) {
		if (strlen(pref_s) == 0)
			continue;

		scope_s = strsep(&pref_s, ":");
		pf_level_s = strsep(&pref_s, ":");

		if (pref_s)
			yod_abort(-EINVAL,
				  "Invalid pagefault level: Extraneous characters afer %s:%s",
				  scope_s,
				  pf_level_s);

		if (!scope_s || !pf_level_s)
			yod_abort(-EINVAL,
				  "Invalid arguments to set pagefault level");

		scope = label_to_int(scope_s, SCOPES, ARRAY_SIZE(SCOPES));
		if (scope == YOD_SCOPE_UNKNOWN)
			yod_abort(-EINVAL,
				  "Invalid scope to set pagefault level: \"%s\"",
				  scope_s);

		pf_level = label_to_int(pf_level_s, PAGE_FAULT_LEVELS, ARRAY_SIZE(PAGE_FAULT_LEVELS));
		if (pf_level == PF_LEVEL_UNKNOWN)
			yod_abort(-EINVAL,
				  "Invalid pagefault level: \"%s\"",
				  pf_level_s);

		if (scope == YOD_SCOPE_ALL) {
			for (s = 0; s < YOD_NUM_MEM_SCOPES; s++)
				lwk_req.memory_preferences[s].pagefault_level = pf_level;
		} else
			lwk_req.memory_preferences[scope].pagefault_level = pf_level;
	}
	free(arg_start);
}

static void yodopt_mempolicy_type(const char *opt)
{
	int s;
	char *arg, *arg_start;
	char *pref_s, *scope_s, *policy_type_s;
	enum mem_scopes_t scope;
	enum policy_types_t policy_type;

	assert_lwkmem_enabled();
	arg = strdup(opt);
	arg_start = arg;

	if (!arg)
		yod_abort(-ENOMEM, "Could not copy: %s", opt);

	while ((pref_s = strsep(&arg, "/"))) {
		if (strlen(pref_s) == 0)
			continue;

		scope_s = strsep(&pref_s, ":");
		policy_type_s = strsep(&pref_s, ":");

		if (pref_s)
			yod_abort(-EINVAL,
				  "Invalid memory policy type: Extraneous characters afer %s:%s",
				  scope_s,
				  policy_type_s);

		if (!scope_s || !policy_type_s)
			yod_abort(-EINVAL,
				  "Invalid arguments to set memory policy type");

		scope = label_to_int(scope_s, SCOPES, ARRAY_SIZE(SCOPES));
		if (scope == YOD_SCOPE_UNKNOWN)
			yod_abort(-EINVAL,
				  "Invalid scope to set memory policy type: \"%s\"",
				  scope_s);

		policy_type = label_to_int(policy_type_s, MEMPOLICY_TYPES, ARRAY_SIZE(MEMPOLICY_TYPES));
		if (policy_type == MEMPOLICY_UNKNOWN)
			yod_abort(-EINVAL,
				  "Invalid memory policy type: \"%s\"",
				  policy_type_s);

		if (scope == YOD_SCOPE_ALL) {
			for (s = 0; s < YOD_NUM_MEM_SCOPES; s++)
				lwk_req.memory_preferences[s].policy_type = policy_type;
		} else
			lwk_req.memory_preferences[scope].policy_type = policy_type;
	}
	free(arg_start);
}
static void yod_set_default_memory_preferences(void)
{
	struct memory_preferences_t *pref;
	int s;

	assert_lwkmem_enabled();

	for (s = 0; s < YOD_NUM_MEM_SCOPES; s++) {
		pref = &lwk_req.memory_preferences[s];
		pref->threshold = 1;
		pref->max_page_size = s != YOD_SCOPE_HEAP ? ((__u64)1) << 30 : ((__u64)1) << 21;
		pref->pagefault_level = PF_LEVEL_NOFAULT;
		pref->policy_type = MEMPOLICY_UNKNOWN;
		memcpy(pref->lower_order, DEFAULT_MEMORY_ORDER, sizeof(DEFAULT_MEMORY_ORDER));
		memcpy(pref->upper_order, DEFAULT_MEMORY_ORDER, sizeof(DEFAULT_MEMORY_ORDER));
	}
}

static void yodopt_memory_preference(const char *opt)
{
	char *arg, *arg_start, *pref_s;
	char *scope_s, *threshold_s, *order_s, *group_s;
	int g, s;
	enum mem_scopes_t scope;
	long int threshold;
	enum mem_group_t order[YOD_NUM_MEM_GROUPS];
	int order_i;
	struct memory_preferences_t *pref;

	assert_lwkmem_enabled();

	arg = strdup(opt);
	arg_start = arg;

	while ((pref_s = strsep(&arg, "/"))) {

		if (strlen(pref_s) == 0)
			continue;

		/* Format: scope[:threshold]:order */
		scope_s = strsep(&pref_s, ":");
		threshold_s = strsep(&pref_s, ":");
		order_s = strsep(&pref_s, ":");

		if (pref_s)
			yod_abort(-EINVAL,
				  "Invalid preference: Extraneous characters afer %s:%s:%s\n",
				  scope_s,
				  threshold_s,
				  order_s);

		if (!order_s) {
			order_s = threshold_s;
			threshold_s = "1";
		}

		if (!order_s)
			yod_abort(-EINVAL,
				"Invalid memory preference for scope: %s",
				scope_s);

		scope = label_to_int(scope_s, SCOPES, ARRAY_SIZE(SCOPES));
		if (scope == YOD_SCOPE_UNKNOWN)
			yod_abort(-EINVAL,
				  "Invalid memory preference scope: \"%s\"",
				  scope_s);

		if (yodopt_parse_integer(threshold_s, &threshold, 0, LONG_MAX))
			yod_abort(-EINVAL,
				  "Invalid threshold: \"%s\"",
				  threshold_s);

		/* Break apart the order string, which is a sequence of comma
		 * delimited memory types.  Append to the end of the list, but
		 * check for duplicates or invalid strings.
		 */

		order_i = 0;

		while ((group_s = strsep(&order_s, ","))) {

			order[order_i] = label_to_int(group_s, MEM_GROUPS, ARRAY_SIZE(MEM_GROUPS));

			if (order[order_i] == YOD_MEM_GROUP_UNKNOWN)
				yod_abort(-EINVAL,
					  "Invalid memory type: \"%s\"",
					  group_s);

			if (yod_index_of(order[order_i], order, order_i) >= 0)
				yod_abort(-EINVAL,
					  "Memory type \"%s\" specified more than once.",
					  group_s);

			order_i++;
		}

		/* Backfill the remainder of the list with missing elements
		 * using the default order:
		 */
		for (g = 0; g < YOD_NUM_MEM_GROUPS; g++) {
			if (yod_index_of(DEFAULT_MEMORY_ORDER[g], order, order_i) >= 0)
				continue;
			order[order_i++] = DEFAULT_MEMORY_ORDER[g];
		}

		/* Now all strings are all validated and converted -- insert
		 * the preference into the proper location(s) in the request
		 * structure:
		 */
		if (scope == YOD_SCOPE_ALL) {
			for (s = 0; s < YOD_NUM_MEM_SCOPES; s++) {
				pref = &(lwk_req.memory_preferences[s]);
				if (threshold == 1)
					memcpy(pref->lower_order, order, sizeof(order));
				memcpy(pref->upper_order, order, sizeof(order));
				pref->threshold = threshold;
			}
		} else {
			pref = &lwk_req.memory_preferences[scope];
			if (threshold == 1)
				memcpy(pref->lower_order, order, sizeof(order));
			memcpy(pref->upper_order, order, sizeof(order));
			pref->threshold = threshold;
		}
	}

	free(arg_start);
}

static void yodopt_mosview(const char *opt)
{
	if (strcmp(opt, "lwk") && strcmp(opt, "lwk-local") &&
	    strcmp(opt, "all"))
		yod_abort(-EINVAL, "Invalid mOS view specified: %s", opt);
	strncpy(view, opt, sizeof(view)-1);
	if (strlen(opt) != strlen(view))
		yod_abort(-EINVAL, "Overrun of \"view\" buffer in %s", __func__);
}

static void yodopt_process_resource_file(const char *opt)
{
	FILE *fptr;
	char *line = 0, *tline, *toks[64], *tok, *this_rank;
	ssize_t rc;
	size_t line_size = 0;
	size_t i, j, n_toks;
	bool rank_handled, arg_handled;

	struct {
		const char *short_arg;
		const char *long_arg;
		int (*handler)(const char *);
	} HANDLERS[] = {
		{ "-c", "--cpus", yodopt_lwk_cpus, },
		{ "-C", "--cores", yodopt_lwk_cores, },
		{ "-M", "--mem", yodopt_mem, },
		{ "-R", "--resources", yodopt_lwk_resources},
		{ "-u", "--util_threads", yodopt_util_threads},
		{ "-G", "--gpus", yodopt_lwk_gpus},
		{ "-g", "--gpu-tiles", yodopt_lwk_gpu_tiles},
	};

	this_rank = getenv("MPI_LOCALRANKID");

	if (!this_rank)
		yod_abort(-EINVAL, "The -R file: option requires that MPI_LOCALRANKID be set.");

	fptr = fopen(opt, "r");

	if (!fptr)
		yod_abort(-EINVAL, "Could not open \"%s\" for reading.", opt);

	YOD_LOG(YOD_DEBUG, "(>) %s file=%s this_rank=%s", __func__, opt, this_rank);

	rank_handled = false;

	while (((rc = getline(&line, &line_size, fptr)) != -1) && !rank_handled) {

		YOD_LOG(YOD_DEBUG, "file: %s", line);

		/* Ignore comment lines */

		if (line[0] == '#')
			continue;

		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = 0;

		/* Tokenize the line. */

		tline = line;
		n_toks = 0;
		while ((tok = strtok(tline, " "))) {
			toks[n_toks++] = tok;
			tline = 0;
		}

		/* Skip to the next line if our rank does not match the current
		 * line.
		 */
		if (strcmp(toks[0], this_rank) && strcmp(toks[0], "*"))
			goto next_line;


		/* Process the remainder of the line as arguments. */

		for (i = 1; i < n_toks; i++) {

			for (j = 0, arg_handled = false; j < ARRAY_SIZE(HANDLERS) && !arg_handled; j++) {
				if (strcmp(HANDLERS[j].short_arg, toks[i]) && strcmp(HANDLERS[j].long_arg, toks[i]))
					continue;
				HANDLERS[j].handler(toks[++i]);
				arg_handled = true;
			}

			if (!arg_handled)
				yod_abort(-EINVAL, "Invalid argument \"%s\"", toks[i]);
		}

		rank_handled = true;

next_line:
		free(line);
		line = 0;
	}

	if (!rank_handled)
		yod_abort(-EINVAL, "No matching line in %s for rank %s", opt, this_rank);

}

static char *mem_vec_to_str(size_t *vec, size_t len, char *buff, size_t bufflen, size_t *total)
{
	char elem[PATH_MAX];
	size_t i, remainder = bufflen;
	int rc;

	buff[0] = '\0';
	*total = 0;

	for (i = 0; i < len; i++) {
		rc = snprintf(elem, PATH_MAX, "nid[%zd] %zd MiB, ", i,
			      vec[i] >> 20);
		if (rc >= PATH_MAX)
			yod_abort(-EINVAL, "Overflow in memory vector buffer.");

		strncat(buff, elem, remainder);
		remainder -= strlen(elem);

		if (remainder <= 0)
			yod_abort(-EINVAL, "Overflow in memory vector buffer.");

		*total += vec[i];

	}

	return buff;
}

static char *cpuset_dump_str(mos_cpuset_t *cpuset, char *buff, size_t bufflen)
{
	if (!cpuset)
		return "<null>";

	snprintf(buff, bufflen, "%s [%d CPUs]",
		 mos_cpuset_to_list_validate(cpuset),
		 mos_cpuset_cardinality(cpuset));

	return buff;
}

/*
 * Dump the internal state of yod (useful in debugging)
 */

void show_state(int level)
{
	if (yod_verbosity >= level) {

		char buff[8192];
		size_t total = 0, i, remainder;
		pid_t lwkprocs[1024];

		struct {
			char *label;
			size_t *mvec;
		} lwkmem[] = {
			{ .label = "Designated", .mvec = lwk_req.lwkmem_designated, },
			{ .label = "Reserved  ", .mvec = lwk_req.lwkmem_reserved, },
			{ .label = "Requested ", .mvec = lwk_req.lwkmem_request, },
		};

		YOD_LOG(level, "Designated LWK CPUs : %s", cpuset_dump_str(get_designated_lwkcpus(), buff, sizeof(buff)));
		YOD_LOG(level, "Reserved   LWK CPUs : %s", cpuset_dump_str(reserved_lwkcpus, buff, sizeof(buff)));
		YOD_LOG(level, "Requested  LWK CPUs : %s", cpuset_dump_str(lwk_req.lwkcpus_request, buff, sizeof(buff)));
		YOD_LOG(level, "Requested LWK cores       : %d", requested_lwk_cores);
		YOD_LOG(level, "Requested utility threads : %d", num_util_threads);

		for (i = 0; i < ARRAY_SIZE(lwkmem); i++) {
			mem_vec_to_str(lwkmem[i].mvec, lwk_req.n_nids, buff, sizeof(buff) - 1, &total);
			YOD_LOG(level, "%s LWK memory : %s  total %zd MiB", lwkmem[i].label, buff, total >> 20);
		}

		total = ARRAY_SIZE(lwkprocs);
		plugin->get_lwk_processes(lwkprocs, &total);
		buff[0] = '\0';

		for (i = 0, remainder = sizeof(buff) - 1; i < total; i++) {
			char tmp[1024];

			snprintf(tmp, sizeof(tmp), "%s%d", i > 0 ? "," : "", lwkprocs[i]);
			strncat(buff, tmp, remainder);
			remainder = sizeof(buff) - strlen(buff) - 1;
		}

		YOD_LOG(level, "LWK processes %s", buff);
	}
}

static void show_target(int level, int start, int argc, char **argv)
{
	if (yod_verbosity >= level) {
		char target[0x4000];
		unsigned remaining = sizeof(target);
		int i;

		target[0] = 0;

		for (i = start; i < argc; i++) {
			strncat(target, argv[i], remaining-1);
			remaining -= strlen(argv[i]);
			strncat(target, " ", remaining-1);
			remaining--;
		}

		YOD_LOG(level, "target: \"%s\"", target);
	}
}

/**
 * Attempts to identify the compute CPUs, GPUs, and the memory
 * to be reserved for the LWK process being launched.
 * @param[in/out] req The request object.
 */
static void resolve_options(lwk_request_t *req)
{
	int rc;
	size_t i;
	enum mem_group_t g;
	mos_cpuset_t *numa_nodes_online = NULL;
	char *gpu_affinity_mask = NULL;

	/* --cores/-C requires that --mem/-M is also specified. */

	if ((requested_lwk_cores != -1 || requested_lwk_cpus != NULL) &&
	    !lwkmem_disabled && no_lwkmem_requested())
		yod_abort(-EINVAL,
			  "--cores/-C requires --mem/-M to also be specified.");

	/* --mem/-M requires that CPUs be specified in some form. */

	if (!no_lwkmem_requested() && requested_lwk_cores == -1 &&
	    requested_lwk_cpus == NULL)
		yod_abort(-EINVAL,
			  "--mem/-M requires either --cores/-C or --cpus/-c to also be specified.");

	/*
	 * Implicitly disable LWKMEM usage if there is no designated
	 * LWK memory. In this case yod just ignores all memory related
	 * arguments and kernel is expected to ignore LWK memory related
	 * yod options.
	 */
	if (yod_get_lwkmem(YOD_DESIGNATED) == 0) {
		lwkmem_disabled = true;
		YOD_LOG(YOD_DEBUG, "LWK memory not found. Disabling LWK memory usage.");
	}

	/* Fill in any missing resolvers and such. */

	if (!lwkmem_disabled && !req->memsize_resolver)
		req->memsize_resolver = all_available_memsize_resolver;

	if (!req->lwkcpus_resolver)
		req->lwkcpus_resolver = all_available_lwkcpus_resolver;

	if (!req->lwkgpus_resolver)
		req->lwkgpus_resolver = all_available_gpus_resolver;

	req->lwkcpus_request = mos_cpuset_alloc_validate();
	req->lwkgpus_request = mos_cpuset_alloc_validate();

	if ((gpu_affinity_mask = getenv("ZE_AFFINITY_MASK")))
		req->ze_affinity_on_entry = strdup(gpu_affinity_mask);

	req->plugin = plugin;


	/* -----------------------------------------------------------------
	 * Step 1: determine the overall amount of LWK memory to be
	 *         reserved for this launch.
	 * ----------------------------------------------------------------- */

	if (!lwkmem_disabled) {
		req->n_nids = ARRAY_SIZE(req->lwkmem_designated);
		plugin->get_designated_lwkmem(req->lwkmem_designated, &req->n_nids);
		plugin->get_reserved_lwkmem(req->lwkmem_reserved, &req->n_nids);

		for (i = 0; i < YOD_MAX_NIDS; i++) {
			g = yod_nid_to_mem_group(i);
			if (g == YOD_MEM_GROUP_UNKNOWN)
				break;
			req->n_groups = g < (int)req->n_groups ? req->n_groups : (size_t)g + 1;
		}

		req->memsize_resolver(req);

		if (req->lwkmem_size > yod_get_lwkmem(YOD_DESIGNATED))
			yod_abort(-EINVAL, "Requested memory exceeds memory designated for LWK usage.");
	} else {
		numa_nodes_online = mos_cpuset_alloc_validate();
		if (plugin->get_numa_nodes_online(numa_nodes_online))
			yod_abort(-EINVAL, "Failed to read the number of online NUMA nodes");
		req->n_nids = mos_cpuset_cardinality(numa_nodes_online);
		if (req->n_nids <= 0)
			yod_abort(-EINVAL, "Invalid number of online NUMA nodes detected");
	}

	/* -----------------------------------------------------------------
	 * Step 2: determine the overall set of LWK CPUs to be requested for
	 *         this launch.
	 * ----------------------------------------------------------------- */

	req->lwkcpus_resolver(req);

	/* -----------------------------------------------------------------
	 * Step 3: Resolve any lingering memory selections.
	 * ----------------------------------------------------------------- */

	if (!lwkmem_disabled) {
		rc = req->memory_selection_algorithm(req);
		if (rc)
			yod_abort(rc, "Could not construct LWK memory request.");
	}

	/* -----------------------------------------------------------------
	 * Step 4: determine the GPUs to used.
	 * ----------------------------------------------------------------- */

	req->lwkgpus_resolver(req);

	YOD_LOG(YOD_DEBUG, "Requesting LWK CPUs     : %s",
		 mos_cpuset_to_list_validate(req->lwkcpus_request));
	if (!lwkmem_disabled)
		YOD_LOG(YOD_DEBUG, "Requesting LWK memory   : %'ld / 0x%lX", req->lwkmem_size, req->lwkmem_size);

	rc = req->layout_algorithm(req);
	if (rc)
		yod_abort(rc, "Failed in layout algorithm.");
}

static void parse_options(int argc, char **argv)
{
	int c, opt_index;
	char opt_string[] = {"+c:C:G:g:M:p:R:U:u:x:y:o:v:h"};

	static struct option options[] = {
		{"cpus", required_argument, 0, 'c'},
		{"cores", required_argument, 0, 'C'},
		{"gpus", required_argument, 0, 'G'},
		{"gpu-tiles", required_argument, 0, 'g'},
		{"util_threads", required_argument, 0, 'u'},
		{"mem", required_argument, 0, 'M'},
		{"memory-preference", required_argument, 0, 'p'},
		{"maxpage", required_argument, 0, YOD_OPT_MAXPAGE},
		{"pagefault", required_argument, 0, YOD_OPT_PAGEFAULT},
		{"mempolicy", required_argument, 0, YOD_OPT_MEMPOLICY},
		{"resources", required_argument, 0, 'R'},
		{"resource_algorithm", required_argument, 0,
		 YOD_OPT_RESOURCE_ALGORITHM},
		{"mem_algorithm", required_argument, 0, YOD_OPT_MEM_ALGORITHM},
		{"layout", required_argument, 0, 'l'},
		{"rank-layout", required_argument, 0, YOD_OPT_RANK_LAYOUT},
		{"aligned-mmap", required_argument, 0, YOD_OPT_ALIGNED_MMAP},
		{"brk-clear-length", required_argument, 0,
		 YOD_OPT_BRK_CLEAR_LEN},
		{"mosview", required_argument, 0, YOD_OPT_MOSVIEW},
		{"opt", required_argument, 0, 'o'},
		{"lwkmem-disable", no_argument, 0, YOD_OPT_LWKMEM_DISABLE},
		{"help", no_argument, 0, 'h'},
		{"verbose", required_argument, 0, 'v'},
		{"dry-run", no_argument, 0, YOD_OPT_DRYRUN},
		{0, 0, 0, 0},
	};

	/* Parse options that are mutually exclusive to others options. */
	/* Disable printing error as we check only for few options here. */
	opterr = 0;
	while ((c = getopt_long(argc, argv, opt_string, options, NULL)) != -1) {
		if (c == YOD_OPT_LWKMEM_DISABLE) {
			lwkmem_disabled = true;
			break;
		}
	}

	/* Set default memory preferences in case if user doesn't specify one */
	if (!lwkmem_disabled)
		yod_set_default_memory_preferences();

	/* Reset scan in argv and enable printing error */
	optind = 0;
	opterr = 1;
	while (1) {

		c = getopt_long(argc, argv, opt_string, options,
				&opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 'R':
			yodopt_lwk_resources(optarg);
			break;

		case 'c':
			yodopt_lwk_cpus(optarg);
			break;

		case 'C':
			yodopt_lwk_cores(optarg);
			break;

		case 'G':
			yodopt_lwk_gpus(optarg);
			break;

		case 'g':
			yodopt_lwk_gpu_tiles(optarg);
			break;

		case 'u':
			/* If the no.of utility threads is already set by
			 * -R file:map_file then ignore -u option. The
			 * -R file:map_file settings override -u settings
			 * if -u is applied first.
			 */
			if (!num_util_threads)
				yodopt_util_threads(optarg);
			break;

		case 'M':
			yodopt_mem(optarg);
			break;

		case 'p':
			yodopt_memory_preference(optarg);
			break;

		case YOD_OPT_MAXPAGE:
			yodopt_maxpage(optarg);
			break;

		case YOD_OPT_PAGEFAULT:
			yodopt_pagefault_level(optarg);
			break;

		case YOD_OPT_MEMPOLICY:
			yodopt_mempolicy_type(optarg);
			break;

		case YOD_OPT_RESOURCE_ALGORITHM:
			yodopt_resource_algorithm(optarg);
			break;

		case YOD_OPT_MEM_ALGORITHM:
			yodopt_mem_algorithm(optarg);
			break;

		case YOD_OPT_RANK_LAYOUT:
			yodopt_rank_layout(optarg);
			break;

		case YOD_OPT_ALIGNED_MMAP:
			yodopt_aligned_mmap(optarg);
			break;

		case YOD_OPT_BRK_CLEAR_LEN:
			yodopt_brk_clear_length(optarg);
			break;

		case YOD_OPT_MOSVIEW:
			yodopt_mosview(optarg);
			break;

		case 'l':
			yodopt_layout(optarg);
			break;

		case 'o':
			yodopt_option(optarg);
			break;

		case YOD_OPT_LWKMEM_DISABLE:
			/* Noop here as it is already parsed once previously */
			break;

		case 'h':{
			usage();
			exit(0);
			break;
		}

		case 'v':{
			char *optp = optarg;
			yod_verbosity = strtol(optarg, &optp, 10);
			if (*optp) {
				yod_abort(-EINVAL, "You must specify a verbosity level.");
			}
			break;
		}

		case YOD_OPT_DRYRUN:{
			dry_run = 1;
			break;
		}

		case '?':
		default:
			{
				/* getopt has already emitted an error message */
				exit(-1);
				break;
			}
		}
	}
}

static void set_mos_view(char *view_requested)
{
	char curr_view[YOD_MOS_VIEW_LEN] = { 0 };

	if (view_requested && plugin->get_mos_view && plugin->set_mos_view) {
		if (plugin->set_mos_view(view_requested) &&
		    plugin->get_mos_view(curr_view, YOD_MOS_VIEW_LEN)) {
			if (strcmp(curr_view, view_requested)) {
				yod_abort(-EINVAL, "Invalid mOS view set [%s]",
					  curr_view);
			}
		} else {
			yod_abort(-1, "Failed to set yod's mOS view to [%s]",
				view_requested);
		}
	}
}

static void write_mempolicy_normal(unsigned char *buffer)
{
	lwkmem_mempolicy_info_t *mempolicy_info, *info;
	lwkmem_mempolicy_info_header_t *mempolicy_info_header;
	struct memory_preferences_t *pref;
	enum mem_group_t g, gvalid_above, gvalid_below;
	unsigned char *byte;
	char *line;
	unsigned long line_size = 4096;
	int s, n, rc, domain_len;

	YOD_LOG(YOD_DEBUG, "Setting memory policy: normal");

	/* Build common header */
	mempolicy_info_header = (lwkmem_mempolicy_info_header_t *) buffer;
	mempolicy_info_header->header_size = sizeof(lwkmem_mempolicy_info_header_t);
	mempolicy_info_header->info_size = sizeof(lwkmem_mempolicy_info_t);
	mempolicy_info_header->nvmrs = YOD_NUM_MEM_SCOPES;
	mempolicy_info_header->nlists_max = LWKMEM_MEMPOL_LIST_MAX;
	mempolicy_info_header->max_longs_per_list = LWKMEM_MEMPOL_LONGS_PER_LIST;
	mempolicy_info_header->nlists_valid = 0;

	for (g = 0; g < (int)lwk_req.n_groups; g++) {
		/* Skip a memory type not present */
		if (lwk_req.lwkmem_domain_info_len[g] <= 0)
			continue;
		mempolicy_info_header->nlists_valid++;
	}

	YOD_LOG(YOD_DEBUG, "header_size        : %llu", mempolicy_info_header->header_size);
	YOD_LOG(YOD_DEBUG, "info_size          : %llu", mempolicy_info_header->info_size);
	YOD_LOG(YOD_DEBUG, "nvmrs              : %llu", mempolicy_info_header->nvmrs);
	YOD_LOG(YOD_DEBUG, "nlists_max         : %llu", mempolicy_info_header->nlists_max);
	YOD_LOG(YOD_DEBUG, "nlists_valid       : %llu", mempolicy_info_header->nlists_valid);
	YOD_LOG(YOD_DEBUG, "max_longs_per_list : %llu", mempolicy_info_header->max_longs_per_list);

	/* Build mempolicy info per virtual memory regions  */
	mempolicy_info = (lwkmem_mempolicy_info_t *)(buffer + mempolicy_info_header->header_size);
	for (s = 0; s < YOD_NUM_MEM_SCOPES; s++) {
		pref = &(lwk_req.memory_preferences[s]);

		info = mempolicy_info + s;

		gvalid_above = 0;
		gvalid_below = 0;
		info->threshold = pref->threshold;
		info->pagefault_level = pref->pagefault_level;
		for (g = 0; g < (int) lwk_req.n_groups; g++) {
			domain_len = lwk_req.lwkmem_domain_info_len[pref->upper_order[g]];
			if (domain_len) {
				if (domain_len > LWKMEM_MEMPOL_MAX_NODES_PER_LIST) {
					yod_abort(-1, "NUMA domains of type [%s] [%d] > supported list length [%d]",
						MEM_GROUPS[pref->upper_order[g]], domain_len,
						LWKMEM_MEMPOL_MAX_NODES_PER_LIST);
				}

				if (domain_len > 1 && pref->policy_type == MEMPOLICY_UNKNOWN)
					pref->policy_type = MEMPOLICY_INTERLEAVE;

				byte = (unsigned char *)&info->above_threshold[gvalid_above++];
				for (n = 0; n < domain_len; n++)
					byte[n] = lwk_req.lwkmem_domain_info[pref->upper_order[g]][n];
				/* Mark end of list */
				if (n < LWKMEM_MEMPOL_MAX_NODES_PER_LIST)
					byte[n] = LWKMEM_MEMPOL_EOL;
			}

			domain_len = lwk_req.lwkmem_domain_info_len[pref->lower_order[g]];
			if (domain_len) {
				if (domain_len > LWKMEM_MEMPOL_MAX_NODES_PER_LIST) {
					yod_abort(-1, "NUMA domains of type [%s] [%d] > supported list length [%d]",
						MEM_GROUPS[pref->lower_order[g]], domain_len,
						LWKMEM_MEMPOL_MAX_NODES_PER_LIST);
				}

				byte = (unsigned char *)&info->below_threshold[gvalid_below++];
				for (n = 0; n < domain_len; n++)
					byte[n] = lwk_req.lwkmem_domain_info[pref->lower_order[g]][n];
				/* Mark end of list */
				if (n < LWKMEM_MEMPOL_MAX_NODES_PER_LIST)
					byte[n] = LWKMEM_MEMPOL_EOL;
			}
		}

		if (pref->policy_type == MEMPOLICY_UNKNOWN)
			pref->policy_type = MEMPOLICY_NORMAL;
		info->policy_type = pref->policy_type;
		if (pref->policy_type == MEMPOLICY_INTERLEAVE && !explicit_maxpage[s])
			pref->max_page_size = ((__u64)1) << 21;
		info->max_page_size = pref->max_page_size;
		/* Debug prints */
		YOD_LOG(YOD_DEBUG, "[%s] : threshold %llu maxpg %llu pflvl %llu policy %llu",
			SCOPES[s], info->threshold, info->max_page_size,
			info->pagefault_level, info->policy_type);

		if (yod_verbosity >= YOD_DEBUG) {
			line = (char *) malloc(line_size);
			if (line) {
				for (g = 0; g < (int) gvalid_above; g++) {
					byte = (unsigned char *)&info->above_threshold[g];
					rc = snprintf(line, line_size, "above_threshold[%d]: ", g);
					for (n = 0; n < LWKMEM_MEMPOL_MAX_NODES_PER_LIST; n++) {
						if (byte[n] == LWKMEM_MEMPOL_EOL)
							break;
						rc += snprintf(line+rc, line_size-rc, "%s%d",
							       n ? ", " : "", byte[n]);
					}
					YOD_LOG(YOD_DEBUG, "%s", line);
				}

				for (g = 0; g < (int) gvalid_below; g++) {
					byte = (unsigned char *)&info->below_threshold[g];
					rc = snprintf(line, line_size, "below_threshold[%d]: ", g);
					for (n = 0; n < LWKMEM_MEMPOL_MAX_NODES_PER_LIST; n++) {
						if (byte[n] == LWKMEM_MEMPOL_EOL)
							break;
						rc += snprintf(line+rc, line_size-rc, "%s%d",
							       n ? ", " : "", byte[n]);
					}
					YOD_LOG(YOD_DEBUG, "%s", line);
				}
				free(line);
			}
		}
	}
}

int main(int argc, char **argv)
{

	char *verbose_env, *tst_plugin, *options, *mpi_env;
	int rc;
	char *timeout_str;
	size_t total_mem;
	char mem_str[PATH_MAX];

	verbose_env = getenv("YOD_VERBOSE");
	if (verbose_env)
		yod_verbosity = atoi(verbose_env);

	mpi_env = getenv("MPI_LOCALNRANKS");
	if (mpi_env)
		mpi_localnranks = atoi(mpi_env);

	tst_plugin = getenv("YOD_TST_PLUGIN");
	if (tst_plugin)
		plugin = init_tst_plugin(tst_plugin);

	/*
	 * Until it becomes an LWK process yod needs to have full system
	 * view. i.e. its view need to be mOS view: all. Override the
	 * inherited mos_view from the parent and set it to 'all'
	 */
	set_mos_view("all");

	options = getenv("YOD_OPTIONS");
	if (options) {
		char *opt, *next = options;

		while ((opt = strsep(&next, " ")))
			yodopt_option(opt);
	}

	setlocale(LC_ALL, "");

	yodopt_resource_algorithm("numa");

	parse_options(argc, argv);

	show_state(YOD_DEBUG);

	if (argc - optind < 1) {
		yod_abort(-EINVAL, "No target specified.");
	}

	show_target(YOD_DEBUG, optind, argc, argv);

	timeout_str = getenv("YOD_TIMEOUT");
	if (timeout_str)
		lock_options.timeout_millis = strtoul(timeout_str, 0, 0);

	if (plugin->lock(&lock_options) != 0)
		yod_abort(-EBUSY, "Could not acquire lock for reserving resources.");

	resolve_options(&lwk_req);

	if (dry_run)
		return 0;

	show_state(YOD_DEBUG);

	rc = plugin->request_lwk_cpus(lwk_req.lwkcpus_request);
	/*
	** Careful!
	** We are now marked as an mOS process. System calls which the LWK
	** handles are now effective for this process. E.g., a large enough
	** malloc() or a brk() will from here on end up in the lwk_sys_*()
	** versions.
	*/

	if (rc != 0)
		yod_abort(rc, "Could not acquire LWK CPUs %s. (%s)",
			  mos_cpuset_to_list_validate(lwk_req.lwkcpus_request),
					     strerror(-rc));

	YOD_LOG(YOD_INFO, "LWK CPUs requested:  %s, total: %d",
		mos_cpuset_to_list_validate(lwk_req.lwkcpus_request),
		mos_cpuset_cardinality(lwk_req.lwkcpus_request));

	rc = plugin->lwkcpus_sequence_request(lwk_req.layout_request);
	if (rc)
		yod_abort(rc, "Could not write sequence request.");
	YOD_LOG(YOD_INFO, "LWK CPUs sequence: %s", lwk_req.layout_request);

	rc = plugin->set_util_threads(num_util_threads);

	if (rc != 0)
		yod_abort(rc, "Could not set number of utility threads. (%s)",
			  strerror(-rc));
	YOD_LOG(YOD_INFO, "Utility thread count: %d", num_util_threads);

	/*
	 * Even if lwkmem usage is disabled (implicitly or explicitly)
	 * we request zero LWK memory to kernel to indicate that we do
	 * not use LWK memory for this process.
	 */
	rc = plugin->request_lwk_memory(lwk_req.lwkmem_request, lwk_req.n_nids);

	if (rc != 0)
		yod_abort(rc, "Could not acquire %zd bytes of LWK memory. (%s)",
			  lwk_req.lwkmem_size, strerror(-rc));

	mem_vec_to_str(lwk_req.lwkmem_request, lwk_req.n_nids, mem_str, PATH_MAX - 1, &total_mem);
	YOD_LOG(YOD_INFO, "LWK memory requested: %s total %zd MiB",
		mem_str, total_mem >> 20);

	/* Set LWK memory policy information if LWK memory is enabled */
	if (!lwkmem_disabled) {
		unsigned char *buffer;
		size_t mempolicy_info_size;

		/* Allocate buffer to hold mempolicy info format, see yod.h  */
		mempolicy_info_size = sizeof(lwkmem_mempolicy_info_header_t);
		mempolicy_info_size += sizeof(lwkmem_mempolicy_info_t) * YOD_NUM_MEM_SCOPES;

		buffer = malloc(mempolicy_info_size);
		if (!buffer)
			yod_abort(-ENOMEM, "Could not allocate mempolicy info");
		memset(buffer, 0, mempolicy_info_size);

		write_mempolicy_normal(buffer);
		rc = plugin->set_lwkmem_mempolicy_info((char *)buffer, mempolicy_info_size);
		free(buffer);

		if (rc)
			yod_abort(-1, "Failed to write memory policy information");
	}

	/* Tell the kernel what GPUs we are allowing and setup the
	 * ZE_AFFINITY_MASK environment variable.
	 */
	rc = plugin->request_lwk_gpus(lwk_req.lwkgpus_request, lwk_req.ze_affinity_request);

	if (rc != 0)
		yod_abort(rc, "Could not acquire LWK GPUs %s. (%s)",
		    mos_cpuset_to_list_validate(lwk_req.lwkgpus_request),
		    strerror(-rc));

	rc = plugin->set_options(lwk_req.options, lwk_req.options_idx +
				 strlen(lwk_req.options + lwk_req.options_idx) +
				 2);
	if (rc != 0)
		yod_abort(rc, "Could not set job options \"%s\".",
			  lwk_req.options);

	if (lwk_req.options_idx) {
		char *opt = lwk_req.options;

		if (*opt == '\0')
			opt++;

		YOD_LOG(YOD_INFO, "Options:");

		while (strlen(opt)) {
			YOD_LOG(YOD_INFO, "    %s", opt);
			opt += strlen(opt) + 1;
		}
	}

	if (gpu_sharing)
		YOD_LOG(YOD_WARN, "GPU device(s) shared across processes.");

	YOD_LOG(YOD_DEBUG, "Setting affinity to %s",
		mos_cpuset_to_list_validate(lwk_req.lwkcpus_request));

	if (tst_plugin) {
		/* Many of the unit tests are designed to run outside of a
		 * complete mOS system and may also be running in environments
		 * that simulate other processor topologies.  Therefore we
		 * do not affinitize the launched process to the reserved
		 * LWK CPUs ... they might not exist.
		 */
		YOD_LOG(YOD_INFO, "sched_setaffinity inhibited.");
	} else if (sched_setaffinity(0, mos_setsize(),
				     lwk_req.lwkcpus_request->cpuset)) {
		yod_abort(-1, "Could not set affinity to %s: %s",
			mos_cpuset_to_list_validate(lwk_req.lwkcpus_request),
			strerror(errno));
	}

	/* Set mOS view of this process to user specified or default all view */
	set_mos_view(view);

	plugin->unlock(&lock_options);

	fflush(stdout);
	fflush(stderr);

	execvp(argv[optind], &argv[optind]);

	/* If we got here, something terribly wrong happened */
	yod_abort(-1, "exec failed: %s", strerror(errno));
}
