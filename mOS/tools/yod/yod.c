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
static const char *YOD_MEM_ALGORITHMS[] = { "4kb", "large" };

/*
 * Values for command line options that do not have short
 * versions (used by getopt_long, below)
 */

#define YOD_OPT_BASE 0x1000
#define YOD_OPT_DRYRUN  (YOD_OPT_BASE | 0x0002)
#define YOD_OPT_RESOURCE_ALGORITHM (YOD_OPT_BASE | 0x0004)
#define YOD_OPT_MEM_ALGORITHM (YOD_OPT_BASE | 0x0005)

/*
 * yod state.
 */

static struct map_type_t *yod_maps[YOD_NUM_MAP_ELEMS];

int yod_verbosity = YOD_QUIET;

extern struct yod_plugin mos_plugin;
static struct yod_plugin *plugin = &mos_plugin;
static int dry_run = 0;
static int num_util_threads;
static unsigned long requested_lwk_mem = 0;
static float requested_lwk_mem_fraction = 0.0;
static yod_cpuset_t *requested_lwk_cpus;
static int all_lwk_cpus_specified = 0;
static int requested_lwk_cores = -1;
static unsigned int mem_algorithm = YOD_MEM_ALGORITHM_LARGE;
static yod_cpuset_t *designated_lwkcpus;
static char extra_help[4096];
static unsigned int resource_algorithm_index;

static const char * const mem_group_str[] = {
	"dram",
	"mcdram",
	"?"
};

static double yod_simple_fitness(lwk_request_t *);

static lwk_request_t lwk_req = {
	.layout_algorithm = yod_general_layout_algorithm,
	.fitness = yod_simple_fitness,
};

struct help_text {
	const char *option;
	const char *argument;
	const char *description;
} HELP[] = {
	{"Option", "Argument", "Description",},
	{"----------------", "----------------",
		    "--------------------------------"},
	{"--resources, -R", "<fraction|all>", "Reserves a portion of LWK"},
	{0, 0, "resources."},
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
	{"--verbose, -v", "<level>", "Sets verbosity of yod."},
	{0, 0, "be used for this job."}
};

void yod_abort(int rc, const char* format, ...)
{
	char buffer[4096];
	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	fprintf(stderr, "[yod:%d] %s (rc=%d)\n", getpid(), buffer, rc);
	va_end(args);

	plugin->unlock();
	exit(rc);
}

static lwk_request_t *yod_request_clone(lwk_request_t *req,
					lwk_request_t *clone)
{
	/* Make a deep copy of the request (req) object. */

	if (clone == NULL)
		clone = malloc(sizeof(lwk_request_t));
	else {
		if (clone->lwkcpus_request)
			yod_cpuset_free(clone->lwkcpus_request);
	}

	memcpy(clone, req, sizeof(lwk_request_t));

	clone->lwkcpus_request = yod_cpuset_clone(req->lwkcpus_request);

	return clone;
}

/**
 * Fetch the list of designated LWK CPUs.
 * @todo make this yod_cpuset_t const *
 */

static yod_cpuset_t *get_designated_lwkcpus(void)
{
	if (designated_lwkcpus == 0) {

		designated_lwkcpus = yod_cpuset_alloc();

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
static void yod_get_available_lwkcpus(yod_cpuset_t *set)
{
	yod_cpuset_t *reserved = yod_cpuset_alloc();

	if (plugin->get_designated_lwkcpus(set))
		yod_abort(-1, "Could not obtain LWK CPU list from plugin.");

	if (plugin->get_reserved_lwk_cpus(reserved)) {
		yod_abort(-1,
		  "Could not obtain reserved LWK CPU list from plugin.");
	}

	yod_cpuset_xor(set, set, reserved);

	yod_cpuset_free(reserved);
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

		int i, N;

		yod_maps[typ] = malloc(sizeof(struct map_type_t));

		if (!yod_maps[typ]) {
			yod_abort(-1,
				  "Could not malloc memory for map [%s:%d]",
				  __func__, __LINE__);
		}

		yod_maps[typ]->capacity = 64;
		yod_maps[typ]->size = 0;
		yod_maps[typ]->map = calloc(yod_maps[typ]->capacity, sizeof(yod_cpuset_t *));

		if (!yod_maps[typ]->map) {
			yod_abort(-1,
				  "Could not malloc memory for map [%s:%d]",
				  __func__, __LINE__);
		}

		for (i = 0, N = yod_max_cpus(); i < N; i++) {
			int elem = plugin->map_cpu(i, typ);

			if (elem < 0)
				continue;

			if (elem >= yod_maps[typ]->capacity) {

				/* Double the size, ensuring that the newly
				 * allocated area is cleared out (realloc does
				 * not guarantee this).
				 */

				yod_maps[typ]->capacity <<= 1;
				yod_maps[typ]->map = realloc(yod_maps[typ]->map, sizeof(yod_cpuset_t *) * yod_maps[typ]->capacity);

				if (!yod_maps[typ]->map)
					yod_abort(-1, "Could not malloc memory for map [%s:%d]", __func__, __LINE__);

				memset(yod_maps[typ]->map + (yod_maps[typ]->capacity >> 1), 0, (yod_maps[typ]->capacity >> 1) * sizeof(yod_cpuset_t *));
			}

			if (!yod_maps[typ]->map[elem])
				yod_maps[typ]->map[elem] = yod_cpuset_alloc();

			yod_cpuset_set(i, yod_maps[typ]->map[elem]);

			if (yod_maps[typ]->size <= elem)
				yod_maps[typ]->size = elem + 1;

			YOD_LOG(YOD_GORY,
				"mapping type %d CPU %d to %d  core-list: %s",
				typ, i, elem,
				yod_cpuset_to_list(yod_maps[typ]->map[elem]));
		}
	}

	return yod_maps[typ];
}


/**
 * Counts the number of (entire) elements in the given set.
 * For example, yod_count_by(s, YOD_CORE) counts the number
 * of complete cores in the set s.
 */

int yod_count_by(yod_cpuset_t *set, enum map_elem_t typ)
{
	int i, count = 0;
	yod_cpuset_t *tmp;
	struct map_type_t *m;

	m = yod_get_map(typ);
	tmp = yod_cpuset_alloc();

	for (i = 0; i < m->size; i++) {

		if (!m->map[i])
			continue;

		yod_cpuset_and(tmp, set, m->map[i]);

		if (yod_cpuset_equal(tmp, m->map[i]))
			count++;
	}

	yod_cpuset_free(tmp);
	return count;
}




/**
 * Reduces the given set so that it contains entire elements
 * of the specified type.  Returns the number of entire
 * elements in the reduced set.
 * For example, yod_filter_by(t, s, YOD_CORE) eliminates any
 * "loose" CPUs from s.
 */

static int yod_filter_by(yod_cpuset_t *out, yod_cpuset_t *in,
			 enum map_elem_t typ)
{
	int i, count = 0;
	yod_cpuset_t *tmp, *tmpin = NULL;
	struct map_type_t *m;

	m = yod_get_map(typ);
	tmp = yod_cpuset_alloc();

	/* If the same set is used for both input and output, we
	 * need to create a temporary copy.
	 */
	if (in == out) {
		tmpin = yod_cpuset_alloc();
		yod_cpuset_or(tmpin, in, in);
		in = tmpin;
	}

	yod_cpuset_xor(out, out, out);

	for (i = 0; i < m->size; i++) {

		if (!m->map[i])
			continue;

		yod_cpuset_and(tmp, in, m->map[i]);

		if (yod_cpuset_equal(tmp, m->map[i])) {
			yod_cpuset_or(out, out, tmp);
			count++;
		}
	}

	yod_cpuset_free(tmp);
	if (tmpin)
		yod_cpuset_free(tmpin);
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

int yod_select_by(int n, enum map_elem_t typ, bool ascending, bool partial, yod_cpuset_t *from, yod_cpuset_t *selected)
{
	int i, rc = 0;

	yod_cpuset_t *tmp, *tmpin = NULL;
	struct map_type_t *map;

	map = yod_get_map(typ);
	tmp = yod_cpuset_alloc();

	/* If the same set is used for both input and output, we
	 * need to create a temporary copy.
	 */

	if (from == selected) {
		tmpin = yod_cpuset_clone(from);
		from = tmpin;
	}

	yod_cpuset_xor(selected, selected, selected);

	for (i = ascending ? 0 : map->size - 1; i >= 0 && i < map->size && n > 0; ascending ? i++ : i--) {

		if (!map->map[i])
			continue;

		yod_cpuset_and(tmp, from, map->map[i]);

		if ((partial && !yod_cpuset_is_empty(tmp)) | yod_cpuset_equal(tmp, map->map[i])) {
			yod_cpuset_or(selected, selected, map->map[i]);
			n--;
			rc++;
		}
	}

	if (n > 0)
		rc = -rc;

	yod_cpuset_free(tmp);
	if (tmpin)
		yod_cpuset_free(tmpin);

	return rc;
}

static int yod_nid_to_mem_group(int nid)
{
	int g;
	struct map_type_t *map = yod_get_map(YOD_MEM_GROUP);
	for (g = 0; g < map->size; g++)
		if (yod_cpuset_is_set(nid, map->map[g]))
			return g;
	return -1;
}

static void yod_append_memory_nid(int grp, int nid, lwk_request_t *req)
{
	int i;

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
static int yod_simple_compute_core_algorithm(struct lwk_request_t *this, int num_cores, yod_cpuset_t *available)
{
	return yod_select_by(num_cores, YOD_CORE, true, false, available, this->lwkcpus_request) == num_cores ? 0 : -1;
}

static int yod_simple_memory_selection_algorithm(lwk_request_t *this)
{
	int i, g;
	size_t remainder;

	/* First fit grouped memory into specific NIDs:
	 */

	for (i = 0; i < this->n_nids; i++) {
		g = yod_nid_to_mem_group(i);
		if (this->lwkmem_size_by_group[g]) {
			remainder = this->lwkmem_designated[i] - this->lwkmem_reserved[i] - this->lwkmem_request[i];
			remainder = MIN(remainder, this->lwkmem_size_by_group[g]);
			this->lwkmem_request[i] += remainder;
			this->lwkmem_size_by_group[g] -= remainder;
			yod_append_memory_nid(g, i, this);
			YOD_LOG(YOD_DEBUG,
				"Selecting %'ld bytes from nid %d / group %d ; remaining: %'ld",
				remainder, i, g, this->lwkmem_size_by_group[g]);
		}
		YOD_LOG(YOD_DEBUG, "lwkmem_request[%d] = %'ld (group:%d)",
			i, this->lwkmem_request[i], g);
	}

	for (g = 0; g < this->n_groups; g++)
		if (this->lwkmem_size_by_group[g]) {
			YOD_ERR("Unfulfilled %'ld bytes from group %d",
				this->lwkmem_size_by_group[g], g);
			return -EBUSY;
		}

	for (i = 0; i < this->n_nids && this->lwkmem_size; i++) {
		remainder = this->lwkmem_designated[i] - this->lwkmem_reserved[i] - this->lwkmem_request[i];
		remainder = MIN(remainder, this->lwkmem_size);
		this->lwkmem_request[i] += remainder;
		this->lwkmem_size -= remainder;
		yod_append_memory_nid(yod_nid_to_mem_group(i), i, this);
	}

	return this->lwkmem_size ? -EBUSY : 0;
}

static int yod_select_cores_randomly(int num_cores,
				     yod_cpuset_t *from,
				     yod_cpuset_t *selected)
{
	struct map_type_t *cmap;
	int *core_available;
	yod_cpuset_t *tmp;
	int i;

	YOD_LOG(YOD_GORY, "(>) %s num_cores=%d from=%s", __func__, num_cores, yod_cpuset_to_list(from));

	if (yod_count_by(from, YOD_CORE) < num_cores)
		return -EINVAL;

	cmap = yod_get_map(YOD_CORE);
	core_available = malloc(cmap->size * sizeof(int));
	tmp = yod_cpuset_alloc();

	for (i = 0; i < cmap->size; i++) {
		core_available[i] = 0;
		if (cmap->map[i]) {
			yod_cpuset_and(tmp, cmap->map[i], from);
			core_available[i] = yod_cpuset_equal(tmp, cmap->map[i]);
		}
	}

	while (num_cores > 0) {

		do {
			i = rand() % cmap->size;
		} while (!core_available[i]);

		yod_cpuset_or(selected, selected, cmap->map[i]);
		core_available[i] = 0;
		num_cores--;
		YOD_LOG(YOD_GORY, "(*) %s num_cores=%d selected=%s", __func__, num_cores, yod_cpuset_to_list(selected));
	}

	free(core_available);
	yod_cpuset_free(tmp);

	YOD_LOG(YOD_GORY, "(<) %s num_cores=%d selected=%s", __func__, num_cores, yod_cpuset_to_list(selected));
	return 0;
}

static int yod_random_compute_core_algorithm(lwk_request_t *this, int num_cores,  yod_cpuset_t *available)
{
	return yod_select_cores_randomly(num_cores, available, this->lwkcpus_request);
}

/**
 * Find the node(s) in the specified group that are nearest to the specified
 * domain.
 *
 * @param[in] nid The specified domain.
 * @param[in] grp The specified group.
 * @param[in/out] nrst The node(s) from the specified group that are nearest
 *   to nid.
 * @param[in/out] len As input, the capacity of the "nrst" array. As output,
 *   the actual number of nearest nodes.
 */

static void yod_numa_nearest_nodes(int nid, int grp, size_t *nrst, size_t *len)
{

	size_t min_distance, dmap[YOD_MAX_NIDS];
	int dmap_len, n;

	min_distance = SIZE_MAX;
	dmap_len = ARRAY_SIZE(dmap);

	plugin->get_distance_map(nid, dmap, &dmap_len);

	for (n = 0; n < dmap_len; n++) {
		if (yod_nid_to_mem_group(n) == grp) {
			if (dmap[n] < min_distance) {
				nrst[0] = n;
				*len = 1;
				min_distance = dmap[n];
			} else if (dmap[n] == min_distance) {
				nrst[(*len)++] = n;
			}
		}
	}
}

/**
 * Request memory for a given CPU node and memory group.
 * @param[in] wanted The amount of memory being requested.
 * @param[in] nid The CPU domain.
 * @param[in] grp The memory group being requested.
 * @param[in/out] req The request object.
 * @param[out] total_available The total amount of memory
 *  that is available from this domain/group.  This includes
 *  any memory that is used to fulfill the request.
 * @return The amount of memory reserved (resolved).
 */
static size_t yod_numa_request_for_group_and_nid(size_t wanted, int nid,
		 int grp, lwk_request_t *req, size_t *total_available)
{
	size_t nearest[YOD_MAX_NIDS], n_nearest, n, allocated;

	*total_available = allocated  = 0;
	n_nearest = ARRAY_SIZE(nearest);
	yod_numa_nearest_nodes(nid, grp, nearest, &n_nearest);

	for (n = 0; n < n_nearest; n++) {

		size_t available, delta = 0;

		available = req->lwkmem_designated[nearest[n]] -
			req->lwkmem_reserved[nearest[n]] -
			req->lwkmem_request[nearest[n]];

		*total_available += available;

		/* First, resolve any request for this memory group. */

		if (req->lwkmem_size_by_group[grp] > 0) {
			delta = MIN(wanted, available);

			req->lwkmem_request[nearest[n]] += delta;
			req->lwkmem_size_by_group[grp] -= delta;
			allocated += delta;

			if (wanted > 0)
				yod_append_memory_nid(grp, nearest[n], req);

			wanted -= delta;

			YOD_LOG(YOD_DEBUG,
				"nearest=%ld desig=%'ld avail=%'ld delta=%'ld remaining=%'ld",
				nearest[n], req->lwkmem_designated[nearest[n]],
				available, delta, wanted);
		}

		/* Next, resolve any ungrouped memory request. */
		if (req->lwkmem_size > 0 && available > delta) {
			delta = MIN(available - delta, req->lwkmem_size);
			req->lwkmem_request[nearest[n]] += delta;
			req->lwkmem_size -= delta;
			yod_append_memory_nid(yod_nid_to_mem_group(nearest[n]),
					      nearest[n], req);
			YOD_LOG(YOD_DEBUG,
				"slack-used=%'ld slack-remaining=%'ld",
				delta, req->lwkmem_size);
		}
	}

	return allocated;
}

/**
 * Attempts to fit the given request into the specified domain.
 * @param[in] ncores The number of cores being requested.
 * @param[in] nid The CPU domain being requested.
 * @param[in/out] req The request object.
 * @pre The req object likley contains amounts of memory being requested
 *   by group (lwkmem_size_by_group[g]); this needs to be resolved by
 *   assigning available memory from specific memory domains.
 * @post The req object contains CPUs (lwkcpus_request) and memory
 *   (lwkmem_request) that fulfill the request or exhaust the available
 *   resources for the given CPU domain.  The fits array of the request
 *   object describes the portion of the request that can be fulfilled
 *   an therefore may be used later on to select requests that are better
 *   fits than others.
 * @return True if the request fits, i.e. there are sufficienltly
 *   available cores and nearest memory to fulfill the request. Return
 *   False otherwize
 */
static bool yod_numa_request_from_node(int ncores, int nid, lwk_request_t *req)
{
	yod_cpuset_t *this_node;
	struct map_type_t *node_map;
	int ncores_this_node;
	bool fits; /* Overall status */
	int g, rc;

	YOD_LOG(YOD_DEBUG, "(>) %s ncores=%d nid=%d", __func__, ncores, nid);

	node_map = yod_get_map(YOD_NODE);

	/* Determine how many nodes are available on this node and the ratio
	 * of this to the number of cores being requested. */

	this_node = yod_cpuset_alloc();
	yod_get_available_lwkcpus(this_node);
	yod_cpuset_and(this_node, this_node, node_map->map[nid]);
	ncores_this_node = yod_filter_by(this_node, this_node, YOD_CORE);
	req->fit[YOD_MAX_GROUPS] = MIN((double)ncores_this_node/ncores, 1.0);

	/* Select the requested number of cores or whatever is available and
	 * set the overall status accordingly.  Note that the status may
	 * be downgraded below based on memory availability. */

	rc = yod_select_by(MIN(ncores_this_node, ncores), YOD_CORE, true,
			   false, this_node, this_node);
	yod_cpuset_or(req->lwkcpus_request, req->lwkcpus_request, this_node);
	fits = req->fit[YOD_MAX_GROUPS] == 1.0;

	YOD_LOG(YOD_DEBUG, "n-avail-cores=%d n-selected=%d fit=%f",
		ncores_this_node, rc, req->fit[YOD_MAX_GROUPS]);
	YOD_LOG(YOD_GORY, "lwkcpus_request=%s [%d]",
		yod_cpuset_to_list(req->lwkcpus_request),
		yod_count_by(req->lwkcpus_request, YOD_CORE));

	/* For each memory group (kind), either fulfill the request with
	 * near memory or take whatever is available.  Set the overall
	 * status accordingly. */

	for (g = 0; g < req->n_groups; g++) {

		size_t want_this_grp, got_this_grp, avail_this_grp;

		want_this_grp =	req->lwkmem_size_by_group[g];
		avail_this_grp = 0;

		got_this_grp = yod_numa_request_for_group_and_nid(want_this_grp,
				  nid, g, req, &avail_this_grp);

		req->fit[g] = MIN((double)avail_this_grp / want_this_grp, 1.0);
		if (want_this_grp - got_this_grp > 0)
			fits = false;

		YOD_LOG(YOD_DEBUG,
			"group=%d total-avail=%'ld wanted=%'ld fit=%f",
			g, avail_this_grp, want_this_grp,
			req->fit[g]);

	}

	YOD_LOG(YOD_DEBUG, "(<) %s ncores=%d nid=%d -> fits=%d", __func__,
		ncores, nid, fits);
	return fits;
}

/**
 * A simple measure of fitness.  The CPU availability (fitness) is added to the average
 * of the memory group fitnesses.
 */
static double yod_simple_fitness(lwk_request_t *this)
{
	double total_mem = 0.0;
	int i;

	if (this == NULL)
		return 0.0;

	for (i = 0; i < this->n_groups; i++)
		total_mem += this->fit[i];

	return total_mem / this->n_groups + this->fit[YOD_MAX_GROUPS];
}

/**
 * The core and memory selection algorithm for NUMA.
 */

static int yod_numa_compute_core_algorithm(struct lwk_request_t *this,
					   int n_cores, yod_cpuset_t *available)
{

	lwk_request_t **reqs;
	int n_reqs;
	struct map_type_t *node_map;
	int nid, rc;

	YOD_LOG(YOD_DEBUG, "(>) %s n_cores=%d avail=%d", __func__, n_cores,
		yod_count_by(available, YOD_CORE));

	node_map = yod_get_map(YOD_NODE);

	reqs = calloc(node_map->size, sizeof(lwk_request_t *));
	n_reqs = 0;

	/* Walk the CPU domains in order; if the request fits wholly in a
	 * domain, then use that domain (we're done!). */

	for (nid = 0; nid < node_map->size; nid++) {
		reqs[n_reqs++] = yod_request_clone(this, NULL);
		if (yod_numa_request_from_node(n_cores, nid, reqs[n_reqs-1])) {
			yod_request_clone(reqs[n_reqs-1], this);
			rc = 0;
			goto free_reqs;
		}
	}

	/* Otherwise, multiple domains are necessary to fulfill the request.
	 * Iteratively select the best fitting of the previous requests and
	 * apply it until the entire overall request has been fulfilled. */
	do {
		double best_fit = 0.0, fit;
		int n;

		nid = -1;
		for (n = 0; n < n_reqs; n++) {
			fit = reqs[n] ? reqs[n]->fitness(reqs[n]) : 0.0;
			YOD_LOG(YOD_DEBUG, "fit[%d] = %f", n, fit);
			if (fit > best_fit) {
				nid = n;
				best_fit = fit;
			}
		}

		if (nid >= 0) {
			int remaining = n_cores -
				yod_count_by(this->lwkcpus_request, YOD_CORE);
			YOD_LOG(YOD_DEBUG, "best fit => nid=%d", nid);
			free(reqs[nid]);
			reqs[nid] = 0;
			if (yod_numa_request_from_node(remaining, nid, this)) {
				rc = 0;
				goto free_reqs;
			}
		}
	} while (nid >= 0);

	rc = -1;

 free_reqs:
	for (nid = 0; nid < n_reqs; nid++)
		free(reqs[nid]);

	YOD_LOG(YOD_DEBUG, "(<) %s n_cores=%d selected=%d -> %s", __func__,
		n_cores, yod_count_by(this->lwkcpus_request, YOD_CORE),
		yod_cpuset_to_list(this->lwkcpus_request));

	return rc;
}

static int yod_numa_memory_selection_algorithm(lwk_request_t *this)
{

	int g, n;
	double cpu_ratios[YOD_MAX_NIDS];
	struct map_type_t *nodes;

	if (this->lwkmem_size > 0) {
		/* @todo -  The path here involves an explicit memory size
		 *          request.  This is not yet supported.
		 */
		yod_abort(-EINVAL, "Not yet supported: NUMA and -M option.");
	}

	cpu_ratios[0] = -1.0;
	nodes = yod_get_map(YOD_NODE);

	for (g = 0; g < this->n_groups; g++) {

		if (this->lwkmem_size_by_group[g] > 0 &&
		    cpu_ratios[0] == -1.0) {
			yod_cpuset_t *tmp;
			unsigned count, total = 0;

			tmp = yod_cpuset_alloc();
			for (n = 0; n < nodes->size; n++) {
				yod_cpuset_and(tmp, this->lwkcpus_request,
					       nodes->map[n]);
				count = yod_cpuset_cardinality(tmp);
				cpu_ratios[n] = (double)count;
				total += count;
			}

			for (n = 0; n < nodes->size; n++) {
				cpu_ratios[n] /= total;
				YOD_LOG(YOD_DEBUG, "ratio[nid=%d]=%f",
					n, cpu_ratios[n]);
			}

			yod_cpuset_free(tmp);
		}

		/* Resolve group memory via the CPU ratios.  Do this in two
		 * passes.  The first pass attempts to find memory that
		 * matches the current nid & group.  The second pass, if
		 * necessary, grabs whatever is available.
		 */
		if (this->lwkmem_size_by_group[g] > 0) {

			int pass;
			size_t sz_this_grp = this->lwkmem_size_by_group[g];

			for (pass = 1; pass <= 2; pass++) {
				for (n = 0; n < nodes->size; n++) {
					size_t requested, obtained, available;

					available = 0;
					requested = pass == 1 ?
						(size_t)(cpu_ratios[n] * sz_this_grp) :
						this->lwkmem_size_by_group[g];
					obtained =
						yod_numa_request_for_group_and_nid(
						   requested, n, g, this,
						   &available);

					YOD_LOG(YOD_DEBUG,
						"requested %'ld (nid=%d group=%d) -> %'ld pass=%d",
						requested, n, g, obtained,
						pass);
				}

				if (this->lwkmem_size_by_group[g] == 0)
					break;
			}

			if (this->lwkmem_size_by_group[g] > 0)
				return -EBUSY;
		}
	}

	return 0;
}


enum resource_type_t {
	YOD_DESIGNATED,
	YOD_RESERVED
};

static size_t yod_get_lwkmem(enum resource_type_t typ)
{
	size_t mem[YOD_MAX_NIDS], result;
	int i, n = ARRAY_SIZE(mem);

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

static int label_to_int(const char *lbl, const char *list[], const int length)
{
	int i;

	for (i = 0; i < length; i++) {
		if (strcmp(lbl, list[i]) == 0)
			return i;
	}
	return -1;
}

static void all_available_memsize_resolver(lwk_request_t *this)
{
	int i;

	for (i = 0; i < this->n_nids; i++) {
		this->lwkmem_request[i] = this->lwkmem_designated[i] - this->lwkmem_reserved[i];
		yod_append_memory_nid(yod_nid_to_mem_group(i), i, this);
	}

	this->lwkmem_size = 0; /* resolved */
	memset(this->lwkmem_size_by_group, 0, sizeof(this->lwkmem_size_by_group));
}

static void resolve_by_ratio(lwk_request_t *this, double ratio)
{
	int i, g;

	memset(this->lwkmem_size_by_group, 0, sizeof(this->lwkmem_size_by_group));

	for (i = 0; i < YOD_MAX_NIDS; i++) {
		g = yod_nid_to_mem_group(i);
		if (g == -1)
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
	int i, g;
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
		if (g == -1)
			break;
		per_group[g] += this->lwkmem_designated[i];
		available[g] += this->lwkmem_designated[i] -
			this->lwkmem_reserved[i];
		total += this->lwkmem_designated[i];
	}

	for (g = 0; g < this->n_groups; g++) {
		delta = requested_lwk_mem * (per_group[g] / total);
		delta = MIN(delta, available[g]);
		this->lwkmem_size_by_group[g] += delta;
		this->lwkmem_size -= delta;
		available[g] -= delta;
	}

	/* Pass 2: If there is still some memory that has not yet been dispersed
	 * to a group, borrow from whatever is available:
	 */

	for (g = 0; g < this->n_groups && this->lwkmem_size > 0; g++) {
		delta = MIN(this->lwkmem_size, available[g]);
		if (delta > 0) {
			this->lwkmem_size_by_group[g] += delta;
			this->lwkmem_size -= delta;
			YOD_LOG(YOD_WARN,
				"Borrowing %'ld bytes from %s to fullfil this request.",
				delta, mem_group_str[g]);
		}
	}

	if (this->lwkmem_size)
		yod_abort(-EBUSY, "Not enough memory is available.");
}

/** Checks to see if any CPUs in set are non-LWK CPUs.  If so,
 * returns the set of non-LWK CPUs; otherwise returns NULL.
 * Note that we leak a cpuset in the non-empty case.  So be it.
 */
static yod_cpuset_t *check_for_non_lwk_cpus(yod_cpuset_t *set)
{
	yod_cpuset_t *all_lwkcpus, *non_lwkcpus;

	non_lwkcpus = yod_cpuset_alloc();
	all_lwkcpus = yod_cpuset_alloc();

	if (plugin->get_designated_lwkcpus(all_lwkcpus))
		yod_abort(-1, "Could not obtain LWK CPU list from plugin.");

	yod_cpuset_not(non_lwkcpus, all_lwkcpus);
	yod_cpuset_and(non_lwkcpus, non_lwkcpus, set);

	if (!yod_cpuset_is_empty(non_lwkcpus)) {
		YOD_LOG(YOD_GORY, "Non-LWK CPUs detected - 0x%s",
			yod_cpuset_to_mask(non_lwkcpus));
	} else {
		yod_cpuset_free(non_lwkcpus);
		non_lwkcpus = 0;
	}

	yod_cpuset_free(all_lwkcpus);

	return non_lwkcpus;
}

static void all_available_lwkcpus_resolver(lwk_request_t *this)
{
	/* Resolver for "--cpus all" option */
	yod_get_available_lwkcpus(this->lwkcpus_request);

	if (yod_cpuset_is_empty(this->lwkcpus_request))
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
	yod_cpuset_t *non_lwkcpus;

	/* Resolver for "--cpus <list>" option. It is possible in this path
	 * to ask for some CPU(s) that are not LWK CPUs.  Or that no CPUs
	 * were actually requested.
	 */

	if (yod_cpuset_is_empty(requested_lwk_cpus)) {
		if (all_lwk_cpus_specified)
			yod_abort(-EBUSY, "No LWK CPUs are available.");
		else
			yod_abort(-EINVAL, "No LWK CPUs were requested.");
	}

	non_lwkcpus = check_for_non_lwk_cpus(requested_lwk_cpus);

	if (non_lwkcpus)
		yod_abort(-EINVAL,
			  "One or more requested CPUs (%s) is not an LWK CPU.\n\t%s",
			  yod_cpuset_to_list(non_lwkcpus),
			  extra_help);

	yod_cpuset_or(this->lwkcpus_request, requested_lwk_cpus, requested_lwk_cpus);
}

static void n_cores_lwkcpu_resolver(lwk_request_t *this)
{
	/* Resolver for the --cores <N|FRAC> options. */

	yod_cpuset_t *available_cpus;
	int n_desig;

	n_desig = yod_count_by(get_designated_lwkcpus(), YOD_CORE);

	if (requested_lwk_cores > n_desig)
		yod_abort(-EINVAL, "Your configuration has %d designated LWK cores, but you are asking for %d.",
			  n_desig, requested_lwk_cores);

	available_cpus = yod_cpuset_alloc();
	yod_get_available_lwkcpus(available_cpus);

	if (this->compute_core_algorithm(this, requested_lwk_cores, available_cpus))
		yod_abort(-EBUSY, "There are not enough cores available.");

	assert(yod_cpuset_is_subset(this->lwkcpus_request, available_cpus));
	yod_cpuset_free(available_cpus);
}

/*
 * The yodopt_* routines are handlers for the various command line options.
 */

static void yodopt_check_for_cpus_already_specified(void)
{
	if (requested_lwk_cpus || (requested_lwk_cores != -1))
		yod_abort(-EINVAL, 
			  "Specify only one of --cpus/-c, --cores/-C, --resources/-R."
			  );
}

static void yodopt_check_for_mem_already_specified(void)
{
	if (requested_lwk_mem)
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

	requested_lwk_cpus = yod_cpuset_alloc();

	if (strcmp("all", opt) == 0) {
		yod_get_available_lwkcpus(requested_lwk_cpus);
		lwk_req.lwkcpus_resolver = all_available_lwkcpus_resolver;
		all_lwk_cpus_specified = 1;
	} else {
		if (yodopt_is_mask(opt)) {
			if (yod_parse_cpumask(opt, requested_lwk_cpus))
				yod_abort(-EINVAL,
					  "Could not parse CPU mask \"%s\".",
					  opt);
		} else if (yod_parse_cpulist(opt, requested_lwk_cpus)) {
			yod_abort(-EINVAL, "Could not parse CPU list \"%s\".",
				  opt);
		}

		lwk_req.lwkcpus_resolver = lwkcpus_by_list_resolver;

		/* A common error is to specify "--cpu N" thinking that one
		 * is requesting N CPUs rather than CPU #N.  If a single CPU
		 * is being requested, we'll squirrel away a message that
		 * might be useful later.
		 */
		if (yod_cpuset_cardinality(requested_lwk_cpus) == 1) {
			snprintf(extra_help, sizeof(extra_help),
				 "You specified \"--cpus %s\".  Do you realize that the argument is a list?",
				 yod_cpuset_to_list(requested_lwk_cpus));
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
		requested_lwk_mem = -1;
		lwk_req.memsize_resolver = all_available_memsize_resolver;
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
				size <<= 10;
			case 'G':
			case 'g':
				size <<= 10;
			case 'm':
			case 'M':
				size <<= 10;
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
	double fraction;

	yodopt_check_for_cpus_already_specified();
	yodopt_check_for_mem_already_specified();

	if (requested_lwk_mem != 0)
		yod_abort(-EINVAL,
			  "Specify only one of --mem/-M,  --resources/-R.");

	lwk_req.lwkcpus_resolver = n_cores_lwkcpu_resolver;

	if (strcmp("all", opt) == 0) {
		requested_lwk_cores = INT_MAX;
		lwk_req.lwkcpus_resolver = all_available_lwk_cores_resolver;
		requested_lwk_mem = -1;
		lwk_req.memsize_resolver = all_available_memsize_resolver;
	} else if (yodopt_parse_floating_point(opt, &fraction, 0.0, 1.0) == 0 ||
		   yodopt_parse_rational(opt, &fraction, 0.0, 1.0) == 0) {
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
		yod_abort(-EINVAL, "No compute cores requested.");

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

static void yodopt_option(const char *opt)
{
	int rc;
	size_t len = strlen(lwk_req.options);

	rc = snprintf(lwk_req.options + len,
		      sizeof(lwk_req.options) - len,
		      len ? ",%s" : "%s",
		      opt);

	if (rc != ((int)strlen(opt) + (len ? 1 : 0)))
		yod_abort(-EINVAL, "Overflow in options buffer.");
}

/*
 * Dump the internal state of yod (useful in debugging)
 */

static void show_state(int level)
{
	if (yod_verbosity >= level) {
		char buff1[8192], buff2[8192];

		strncpy(buff1, yod_cpuset_to_list(requested_lwk_cpus),
			sizeof(buff1));
		strncpy(buff2, yod_cpuset_to_mask(requested_lwk_cpus),
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
		yod_cpuset_t *set;
		size_t val;
		set = yod_cpuset_alloc();
		plugin->get_designated_lwkcpus(set);
		YOD_LOG(level, "Designated mOS lwkcpus  : %s", yod_cpuset_to_list(set));
		plugin->get_reserved_lwk_cpus(set);
		YOD_LOG(level, "Reserved   mOS lwkcpus  : %s", yod_cpuset_to_list(set));
		val = yod_get_lwkmem(YOD_DESIGNATED);
		YOD_LOG(level, "Designated mOS lwkmem   : %'ld / 0x%lX", val, val);
		val = yod_get_lwkmem(YOD_RESERVED);
		YOD_LOG(level, "Reserved   mOS lwkmem   : %'ld / 0x%lX", val, val);
		yod_cpuset_free(set);
	}
}

/**
 * Attempts to identify the compute CPUs and also the memory to be
 * reserved for the LWK process being launched.
 * @param[in/out] req The request object.
 */
static void resolve_options(lwk_request_t *req)
{
	int rc, i, g;

	/* --cores/-C requires that --mem/-M is also specified. */

	if ((requested_lwk_cores != -1 || requested_lwk_cpus != NULL) &&
	    requested_lwk_mem == 0)
		yod_abort(-EINVAL,
			  "--cores/-C requires --mem/-M to also be specified.");

	/* --mem/-M requires that CPUs be specified in some form. */

	if (requested_lwk_mem != 0 && requested_lwk_cores == -1 &&
	    requested_lwk_cpus == NULL)
		yod_abort(-EINVAL,
			  "--mem/-M requires either --cores/-C or --cpus/-c to also be specified.");

	/* Fill in any missing resolvers and such. */

	if (!req->memsize_resolver)
		req->memsize_resolver = all_available_memsize_resolver;

	if (!req->lwkcpus_resolver)
		req->lwkcpus_resolver = all_available_lwkcpus_resolver;

	req->lwkcpus_request = yod_cpuset_alloc();

	/* -----------------------------------------------------------------
	 * Step 1: determine the overall amount of LWK memory to be
	 *         reserved for this launch.
	 * ----------------------------------------------------------------- */

	req->n_nids = ARRAY_SIZE(req->lwkmem_designated);
	plugin->get_designated_lwkmem(req->lwkmem_designated, &req->n_nids);
	plugin->get_reserved_lwkmem(req->lwkmem_reserved, &req->n_nids);

	for (i = 0; i < YOD_MAX_NIDS; i++) {
		g = yod_nid_to_mem_group(i);
		if (g == -1)
			break;
		req->n_groups = g < req->n_groups ? req->n_groups : g + 1;
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

	YOD_LOG(YOD_DEBUG, "Requesting LWK CPUs     : %s", yod_cpuset_to_list(req->lwkcpus_request));
	YOD_LOG(YOD_DEBUG, "Requesting LWK memory   : %'ld / 0x%lX", req->lwkmem_size, req->lwkmem_size);

	rc = req->layout_algorithm(req);
	if (rc)
		yod_abort(rc, "Failed in layout algorithm.");

	req->lwkmem_domain_info_str[0] = '\0';

	for (g = 0; g < req->n_groups; g++) {

		if (req->lwkmem_domain_info_len[g] <= 0)
			continue;

		if (strlen(req->lwkmem_domain_info_str) > 0)
			STR_APPEND(req->lwkmem_domain_info_str,
				   sizeof(req->lwkmem_domain_info_str), " ");

		STR_APPEND(req->lwkmem_domain_info_str,
			   sizeof(req->lwkmem_domain_info_str),
			   "%s=", mem_group_str[g]);

		for (i = 0; i < req->lwkmem_domain_info_len[g]; i++)
			STR_APPEND(req->lwkmem_domain_info_str,
				   sizeof(req->lwkmem_domain_info_str),
				   i > 0 ? ",%d" : "%d",
				   req->lwkmem_domain_info[g][i]);
	}
}

static void parse_options(int argc, char **argv)
{
	static struct option options[] = {
		{"cpus", required_argument, 0, 'c'},
		{"cores", required_argument, 0, 'C'},
		{"util_threads", required_argument, 0, 'u'},
		{"mem", required_argument, 0, 'M'},
		{"resources", required_argument, 0, 'R'},
		{"resource_algorithm", required_argument, 0,
		 YOD_OPT_RESOURCE_ALGORITHM},
		{"mem_algorithm", required_argument, 0, YOD_OPT_MEM_ALGORITHM},
		{"layout", required_argument, 0, 'l'},
		{"opt", required_argument, 0, 'o'},
		{"help", no_argument, 0, 'h'},
		{"verbose", required_argument, 0, 'v'},
		{"dry-run", no_argument, 0, YOD_OPT_DRYRUN},
		{0, 0, 0, 0},
	};

	while (1) {

		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "+c:C:M:R:U:u:x:y:o:v:h", options,
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

		case YOD_OPT_RESOURCE_ALGORITHM:
			yodopt_resource_algorithm(optarg);
			break;

		case YOD_OPT_MEM_ALGORITHM:
			yodopt_mem_algorithm(optarg);
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

int main(int argc, char **argv)
{

	char *verbose_env, *tst_plugin, *options;
	char *yod_chrt;
	int rc;
	struct sched_param sp;
	int sched_policy;
	unsigned long lock_timeout;
	char *timeout_str;
	int i;
	size_t total_mem;
	char build_str[PATH_MAX];
	char mem_str[PATH_MAX];

	verbose_env = getenv("YOD_VERBOSE");
	if (verbose_env)
		yod_verbosity = atoi(verbose_env);

	tst_plugin = getenv("YOD_TST_PLUGIN");
	if (tst_plugin) {
		plugin = init_tst_plugin(tst_plugin);
	}

	options = getenv("YOD_OPTIONS");
	if (options)
		strncpy(lwk_req.options, options, sizeof(lwk_req.options));

	setlocale(LC_ALL, "");

	yodopt_resource_algorithm("numa");

	parse_options(argc, argv);

	show_state(YOD_DEBUG);

	if (argc - optind < 1) {
		yod_abort(-EINVAL, "No target specified.");
	}

	show_target(YOD_DEBUG, optind, argc, argv);

	lock_timeout = 60 * 1000; /* one minute */

	timeout_str = getenv("YOD_TIMEOUT");
	if (timeout_str)
		lock_timeout = strtoul(timeout_str, 0, 0);

	if (plugin->lock(lock_timeout) != 0)
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
			  yod_cpuset_to_mask(lwk_req.lwkcpus_request), strerror(-rc));

	YOD_LOG(YOD_INFO, "LWK CPUs reserved:  %s, total: %d",
		yod_cpuset_to_list(lwk_req.lwkcpus_request),
		yod_cpuset_cardinality(lwk_req.lwkcpus_request));

	YOD_LOG(YOD_INFO, "utility_threads=%d", num_util_threads);

	rc = plugin->lwkcpus_sequence_request(lwk_req.layout_request);
	if (rc)
		yod_abort(rc, "Could not write sequence request.");
	YOD_LOG(YOD_INFO, "LWK CPUs sequence: %s", lwk_req.layout_request);

	rc = plugin->set_util_threads(num_util_threads);

	if (rc != 0)
		yod_abort(rc, "Could not set number of utility threads. (%s)",
			  strerror(-rc));

	rc = plugin->request_lwk_memory(lwk_req.lwkmem_request, lwk_req.n_nids);

	if (rc != 0)
		yod_abort(rc, "Could not acquire %ld bytes of LWK memory. (%s)",
			  lwk_req.lwkmem_size, strerror(-rc));

	total_mem = 0;
	mem_str[0] = '\0';

	for (i = 0; i < lwk_req.n_nids; i++)   {
		snprintf(build_str, PATH_MAX, "nid[%d] %ld MiB, ", i,
			 lwk_req.lwkmem_request[i] >> 20);
		strncat(mem_str, build_str, PATH_MAX);
		total_mem += lwk_req.lwkmem_request[i];
	}

	YOD_LOG(YOD_INFO, "memory reserved: %s total %ld MiB",
		mem_str, total_mem >> 20);

	rc = plugin->set_lwkmem_domain_info(lwk_req.lwkmem_domain_info_str);
	if (rc)
		yod_abort(rc, "Could not write memory domain information.");
	YOD_LOG(YOD_INFO, "Domain info: %s", lwk_req.lwkmem_domain_info_str);

	rc = plugin->set_options(lwk_req.options);
	if (rc != 0)
		yod_abort(rc, "Could not set job options \"%s\".",
			  lwk_req.options);
	YOD_LOG(YOD_INFO, "Options: %s", lwk_req.options);

	YOD_LOG(YOD_DEBUG, "Setting affinity to %s",
		yod_cpuset_to_list(lwk_req.lwkcpus_request));

	if (sched_setaffinity(0, yod_setsize(), lwk_req.lwkcpus_request->cpuset)) {
		YOD_ERR("Could not set affinity: %s", strerror(errno));
		exit(-1);
	}


	yod_chrt = getenv("YOD_CHRT"); /* @deprecated */

	if (yod_chrt != 0) {

		/* Support setting the scheduler policy.  The nominal
		 * path is to enable the old K-scheduler.  But other
		 * overrides are available (for experimental reasons)
		 * as well as a bypass.
		 */

		if (strcmp(yod_chrt, "fifo") == 0)
			sched_policy = SCHED_FIFO;
		else if (strcmp(yod_chrt, "batch") == 0)
			sched_policy = SCHED_BATCH;
		else if (strcmp(yod_chrt, "normal") == 0)
			sched_policy = SCHED_OTHER;
		else if (strcmp(yod_chrt, "none") == 0)
			sched_policy = INT_MAX;
		else
			sched_policy = 7; /* aka SCHED_mOS */

		if (sched_policy != INT_MAX) {
			YOD_LOG(YOD_WARN,
				"Deprecated: Setting sched policy to %d (%s)",
				sched_policy, yod_chrt);
			sp.sched_priority = 1;
			if (sched_setscheduler(0, sched_policy, &sp)) {
				YOD_ERR("Could not set scheduler: %s",
					strerror(errno));
				exit(-1);
			}
		}
	}

	plugin->unlock();

	fflush(stdout);
	fflush(stderr);

	execvp(argv[optind], &argv[optind]);

	/* If we got here, something terribly wrong happened */
	yod_abort(-1, "exec failed: %s", strerror(errno));
}
