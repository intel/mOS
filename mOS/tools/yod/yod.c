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
	"mmap",
	"stack",
	"static",
	"brk",
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

/*
 * yod state.
 */

static struct map_type_t *yod_maps[YOD_NUM_MAP_ELEMS];

int yod_verbosity = YOD_QUIET;
int mpi_localnranks = 0;

extern struct yod_plugin mos_plugin;
static struct yod_plugin *plugin = &mos_plugin;
static int dry_run = 0;
static int num_util_threads;
static unsigned long requested_lwk_mem = -1;
static float requested_lwk_mem_fraction = 0.0;
static mos_cpuset_t *requested_lwk_cpus;
static int all_lwk_cpus_specified = 0;
static int requested_lwk_cores = -1;
static unsigned int mem_algorithm = YOD_MEM_ALGORITHM_LARGE;
static mos_cpuset_t *designated_lwkcpus;
static char extra_help[4096];
static unsigned int resource_algorithm_index;

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
	{"--resources, -R", "<fraction|all|MPI>", "Reserves a portion of LWK"},
	{0, 0, "resources.  If MPI is specified then MPI environment"},
	{0, 0, "variables are used to determine the fractional amount."},
	{"--cpus, -c", "<list>|all", "Reserves the LWK CPUs."},
	{"--cores, -C", "<num>|all", "Reserves the LWK cores."},
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
	mos_cpuset_t *reserved = mos_cpuset_alloc_validate();

	if (plugin->get_designated_lwkcpus(set))
		yod_abort(-1, "Could not obtain LWK CPU list from plugin.");

	if (plugin->get_reserved_lwk_cpus(reserved)) {
		yod_abort(-1,
		  "Could not obtain reserved LWK CPU list from plugin.");
	}

	mos_cpuset_xor(set, set, reserved);

	mos_cpuset_free(reserved);
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
} RESOURCE_ALGORITHMS[] = {
	{.name = "simple",
	 .compute_core_algorithm = yod_simple_compute_core_algorithm,
	 .memory_selection_algorithm = yod_simple_memory_selection_algorithm,
	},
	{.name = "random",
	 .compute_core_algorithm = yod_random_compute_core_algorithm,
	 .memory_selection_algorithm = yod_simple_memory_selection_algorithm,
	},
	{.name = "numa",
	 .compute_core_algorithm = yod_numa_compute_core_algorithm,
	 .memory_selection_algorithm = yod_numa_memory_selection_algorithm,
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

	if (this->lwkmem_size)
		yod_abort(-EBUSY, "Not enough memory is available.");
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

	if (mos_cpuset_is_empty(this->lwkcpus_request))
		yod_abort(-EBUSY, "No LWK CPUs are available.");
}

static void all_available_lwk_cores_resolver(lwk_request_t *this)
{
	/* Resolver for "--cores all" option */
	yod_get_available_lwkcpus(this->lwkcpus_request);

	if (yod_filter_by(this->lwkcpus_request, this->lwkcpus_request, YOD_CORE) <= 0) {

		int n;

		n = yod_count_by(get_designated_lwkcpus(), YOD_CORE);
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
		if (all_lwk_cpus_specified)
			yod_abort(-EBUSY, "No LWK CPUs are available.");
		else
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

	if (this->compute_core_algorithm(this, requested_lwk_cores, available_cpus))
		yod_abort(-EBUSY, "There are not enough cores available.");

	assert(mos_cpuset_is_subset(this->lwkcpus_request, available_cpus));
	mos_cpuset_free(available_cpus);
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

static void yodopt_check_for_mem_already_specified(void)
{
	if (!no_lwkmem_requested())
		yod_abort(-EINVAL,
			  "Specify only one of --mem/-M, --resources/-R."
			  );
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
	yodopt_check_for_mem_already_specified();

	if (strcmp("all", opt) == 0) {
		lwk_req.memsize_resolver = all_available_memsize_resolver;
		requested_lwk_mem = LONG_MAX;
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

static int yodopt_lwk_resources(const char *opt)
{
	double fraction = 0.0;

	yodopt_check_for_cpus_already_specified();
	yodopt_check_for_mem_already_specified();

	lwk_req.lwkcpus_resolver = n_cores_lwkcpu_resolver;

	if (strcmp("all", opt) == 0) {
		requested_lwk_cores = INT_MAX;
		requested_lwk_mem = LONG_MAX;
		lwk_req.lwkcpus_resolver = all_available_lwk_cores_resolver;
		lwk_req.memsize_resolver = all_available_memsize_resolver;
		fraction = 1.0;
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
		requested_lwk_mem = (unsigned long)(fraction *
				    yod_get_lwkmem(YOD_DESIGNATED));
		requested_lwk_mem_fraction = fraction;
		lwk_req.memsize_resolver = memsize_by_ratio_resolver;
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
	strncpy(lwk_req.layout_descriptor, descr,
		sizeof(lwk_req.layout_descriptor));
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

static bool yodopt_is_set(const char *opt)
{
	int offs = 0;
	int olen = strlen(opt);
	int maxoffs = lwk_req.options_idx +
		strlen(lwk_req.options + lwk_req.options_idx);

	while (offs < maxoffs) {

		if (lwk_req.options[offs] == '\0') {
			offs++;
			continue;
		}

		if (strncmp(lwk_req.options + offs, opt, olen))
			goto next;

		if (lwk_req.options[offs + olen] == '=')
			return true;
next:
		offs += strlen(lwk_req.options + offs);
	}

	return false;
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

static void yodopt_memory_preference(const char *opt)
{
	char *arg, *pref_s, *scope_s, *threshold_s, *order_s, *group_s;
	int g, s;
	enum mem_scopes_t scope;
	long int threshold;
	enum mem_group_t order[YOD_NUM_MEM_GROUPS];
	int order_i;
	struct memory_preferences_t *pref;

	/* Lazy initialization of preferences -- everything set to default
	 * order:
	 */
	if (!lwk_req.memory_preferences_present) {
		for (s = 0; s < YOD_NUM_MEM_SCOPES; s++) {
			pref = &lwk_req.memory_preferences[s];
			pref->threshold = 1;
			memcpy(pref->lower_order, DEFAULT_MEMORY_ORDER, sizeof(DEFAULT_MEMORY_ORDER));
			memcpy(pref->upper_order, DEFAULT_MEMORY_ORDER, sizeof(DEFAULT_MEMORY_ORDER));
		}

		lwk_req.memory_preferences_present = true;
	}

	arg = strdup(opt);

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
			pref = &lwk_req.memory_preferences[0];
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

	free(arg);
}

static void yodopt_mosview(const char *opt)
{
	if (strcmp(opt, "lwk") && strcmp(opt, "lwk-local") &&
	    strcmp(opt, "all"))
		yod_abort(-EINVAL, "Invalid mOS view specified: %s", opt);
	strncpy(view, opt, sizeof(view));
}

/*
 * Dump the internal state of yod (useful in debugging)
 */

static void show_state(int level)
{
	if (yod_verbosity >= level) {
		char buff1[8192], buff2[8192];

		strncpy(buff1, mos_cpuset_to_list_validate(requested_lwk_cpus),
			sizeof(buff1));
		strncpy(buff2, mos_cpuset_to_mask(requested_lwk_cpus),
			sizeof(buff2));

		YOD_LOG(level, "requested_lwk_cpus: list=[%s] mask=0x%s",
			buff1, buff2);
		YOD_LOG(level, "requested_lwk_cores=%d", requested_lwk_cores);
		YOD_LOG(level, "utility_threads=%d", num_util_threads);
		YOD_LOG(level, "requested_lwk_mem=%lX", requested_lwk_mem);
		YOD_LOG(level, "resource_algorithm=%s",
			ARRAY_ENT(RESOURCE_ALGORITHMS, resource_algorithm_index,
				  name, "?"));
		YOD_LOG(level, "mem_algorithm=%d (%s)", mem_algorithm,
			mem_algorithm < ARRAY_SIZE(YOD_MEM_ALGORITHMS) ?
			YOD_MEM_ALGORITHMS[mem_algorithm] : "?"); /* TODO FIX ME */
		YOD_LOG(level, "verbosity=%d", yod_verbosity);
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
			strncat(target, argv[i], remaining);
			remaining -= strlen(argv[i]);
			strncat(target, " ", remaining);
			remaining--;
		}

		YOD_LOG(level, "target: \"%s\"", target);
	}
}

static void show_mos_state(int level)
{
	if (yod_verbosity >= level) {
		mos_cpuset_t *set;
		size_t val;
		set = mos_cpuset_alloc_validate();
		plugin->get_designated_lwkcpus(set);
		YOD_LOG(level, "Designated mOS lwkcpus  : %s",
			 mos_cpuset_to_list_validate(set));
		plugin->get_reserved_lwk_cpus(set);
		YOD_LOG(level, "Reserved   mOS lwkcpus  : %s",
			mos_cpuset_to_list_validate(set));
		val = yod_get_lwkmem(YOD_DESIGNATED);
		YOD_LOG(level, "Designated mOS lwkmem   : %'ld / 0x%lX", val, val);
		val = yod_get_lwkmem(YOD_RESERVED);
		YOD_LOG(level, "Reserved   mOS lwkmem   : %'ld / 0x%lX", val, val);
		mos_cpuset_free(set);
	}
}

/**
 * Attempts to identify the compute CPUs and also the memory to be
 * reserved for the LWK process being launched.
 * @param[in/out] req The request object.
 */
static void resolve_options(lwk_request_t *req)
{
	int rc;
	size_t i;
	enum mem_group_t g;

	/* --cores/-C requires that --mem/-M is also specified. */

	if ((requested_lwk_cores != -1 || requested_lwk_cpus != NULL) &&
	    no_lwkmem_requested())
		yod_abort(-EINVAL,
			  "--cores/-C requires --mem/-M to also be specified.");

	/* --mem/-M requires that CPUs be specified in some form. */

	if (!no_lwkmem_requested() && requested_lwk_cores == -1 &&
	    requested_lwk_cpus == NULL)
		yod_abort(-EINVAL,
			  "--mem/-M requires either --cores/-C or --cpus/-c to also be specified.");

	/* Fill in any missing resolvers and such. */

	if (!req->memsize_resolver)
		req->memsize_resolver = all_available_memsize_resolver;

	if (!req->lwkcpus_resolver)
		req->lwkcpus_resolver = all_available_lwkcpus_resolver;

	req->lwkcpus_request = mos_cpuset_alloc_validate();
	req->plugin = plugin;

	/* -----------------------------------------------------------------
	 * Step 1: determine the overall amount of LWK memory to be
	 *         reserved for this launch.
	 * ----------------------------------------------------------------- */

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

	/* -----------------------------------------------------------------
	 * Step 2: determine the overall set of LWK CPUs to be requested for
	 *         this launch.
	 * ----------------------------------------------------------------- */

	req->lwkcpus_resolver(req);

	/* -----------------------------------------------------------------
	 * Step 3: Resolve any lingering memory selections.
	 * ----------------------------------------------------------------- */

	rc = req->memory_selection_algorithm(req);
	if (rc)
		yod_abort(rc, "Could not construct LWK memory request.");

	YOD_LOG(YOD_DEBUG, "Requesting LWK CPUs     : %s",
		 mos_cpuset_to_list_validate(req->lwkcpus_request));
	YOD_LOG(YOD_DEBUG, "Requesting LWK memory   : %'ld / 0x%lX", req->lwkmem_size, req->lwkmem_size);

	rc = req->layout_algorithm(req);
	if (rc)
		yod_abort(rc, "Failed in layout algorithm.");

	req->lwkmem_domain_info_str[0] = '\0';

	for (g = 0; g < (int)req->n_groups; g++) {

		if (req->lwkmem_domain_info_len[g] <= 0)
			continue;

		if (strlen(req->lwkmem_domain_info_str) > 0)
			STR_APPEND(req->lwkmem_domain_info_str,
				   sizeof(req->lwkmem_domain_info_str), " ");

		STR_APPEND(req->lwkmem_domain_info_str,
			   sizeof(req->lwkmem_domain_info_str),
			   "%s=", MEM_GROUPS[g]);

		for (i = 0; i < req->lwkmem_domain_info_len[g]; i++)
			STR_APPEND(req->lwkmem_domain_info_str,
				   sizeof(req->lwkmem_domain_info_str),
				   i > 0 ? ",%zd" : "%zd",
				   req->lwkmem_domain_info[g][i]);
	}

	/* -----------------------------------------------------------------
	 * Step 4: Set memory preferences.
	 * ----------------------------------------------------------------- */

	if (lwk_req.memory_preferences_present) {
		char option[8192], buf[1024];
		int s, g, i;
		enum mem_group_t *order;
		struct memory_preferences_t *pref;

		strcpy(option, "lwkmem-memory-preferences=");

		for (s = 0; s < YOD_NUM_MEM_SCOPES; s++) {
			pref = &lwk_req.memory_preferences[s];

			for (i = 0; i < 2; i++) {
				if (i == 0) {
					snprintf(buf, sizeof(buf), "/%s:", SCOPES[s]);
					order = pref->lower_order;
				} else if (pref->threshold > 1) {
					snprintf(buf, sizeof(buf), "/%s:%ld:", SCOPES[s],
						 pref->threshold);
					order =	pref->upper_order;
				} else {
					continue;
				}

				STR_APPEND(option, sizeof(option), buf);

				for (g = 0; g < YOD_NUM_MEM_GROUPS; g++) {
					STR_APPEND(option, sizeof(option), MEM_GROUPS[order[g]]);
					STR_APPEND(option, sizeof(option), ",");
				}
			}
		}

		yodopt_option(option);
	}

}

static void parse_options(int argc, char **argv)
{
	static struct option options[] = {
		{"cpus", required_argument, 0, 'c'},
		{"cores", required_argument, 0, 'C'},
		{"util_threads", required_argument, 0, 'u'},
		{"mem", required_argument, 0, 'M'},
		{"memory-preference", required_argument, 0, 'p'},
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
		{"help", no_argument, 0, 'h'},
		{"verbose", required_argument, 0, 'v'},
		{"dry-run", no_argument, 0, YOD_OPT_DRYRUN},
		{0, 0, 0, 0},
	};

	while (1) {

		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "+c:C:M:p:R:U:u:x:y:o:v:h", options,
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

		case 'u':
			yodopt_util_threads(optarg);
			break;

		case 'M':
			yodopt_mem(optarg);
			break;

		case 'p':
			yodopt_memory_preference(optarg);
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

int main(int argc, char **argv)
{

	char *verbose_env, *tst_plugin, *options, *mpi_env;
	int rc;
	char *timeout_str;
	size_t i, total_mem;
	char build_str[PATH_MAX];
	char mem_str[PATH_MAX];

	verbose_env = getenv("YOD_VERBOSE");
	if (verbose_env)
		yod_verbosity = atoi(verbose_env);

	mpi_env = getenv("MPI_LOCALNRANKS");
	if (mpi_env)
		mpi_localnranks = atoi(mpi_env);

	tst_plugin = getenv("YOD_TST_PLUGIN");
	if (tst_plugin) {
		plugin = init_tst_plugin(tst_plugin);
	}

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

	show_mos_state(YOD_DEBUG);

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
			  mos_cpuset_to_mask(lwk_req.lwkcpus_request),
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

	rc = plugin->request_lwk_memory(lwk_req.lwkmem_request, lwk_req.n_nids);

	if (rc != 0)
		yod_abort(rc, "Could not acquire %zd bytes of LWK memory. (%s)",
			  lwk_req.lwkmem_size, strerror(-rc));

	total_mem = 0;
	mem_str[0] = '\0';

	for (i = 0; i < lwk_req.n_nids; i++)   {
		snprintf(build_str, PATH_MAX, "nid[%zd] %zd MiB, ", i,
			 lwk_req.lwkmem_request[i] >> 20);
		strncat(mem_str, build_str, PATH_MAX);
		total_mem += lwk_req.lwkmem_request[i];
	}

	YOD_LOG(YOD_INFO, "LWK memory requested: %s total %zd MiB",
		mem_str, total_mem >> 20);

	rc = plugin->set_lwkmem_domain_info(lwk_req.lwkmem_domain_info_str);

	if (rc)
		yod_abort(rc, "Could not write memory domain information.");

	YOD_LOG(YOD_INFO, "Domain info: %s", lwk_req.lwkmem_domain_info_str);

	if (!yodopt_is_set("lwkmem-interleave")) {
		for (i = 0; i < lwk_req.n_groups; i++)
			if (lwk_req.lwkmem_domain_info_len[i] > 1) {
				yodopt_option("lwkmem-interleave=2m");
				break;
			}
	}

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
		YOD_ERR("Could not set affinity to %s: %s",
			mos_cpuset_to_list_validate(lwk_req.lwkcpus_request),
			strerror(errno));
		exit(-1);
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
