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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "yod.h"
#include "yod_debug.h"

#define NODE_STR "node"
#define TILE_STR "tile"
#define CORE_STR "core"
#define CPU_STR "cpu"
#define COMPACT_STR "compact"
#define SCATTER_STR "scatter"
#define SCATTER_ALIAS "node,tile,core,cpu"
#define COMPACT_ALIAS "cpu,core,tile,node"

#define NDIMS 4
#define IDX_NODE 0
#define IDX_TILE 1
#define IDX_CORE 2
#define IDX_CPU  3

/**
 * A three dimensional indexing macro for a dyanmically sized,
 * flat underlying array.
 */
#define COORD(n, t, c) (((n) * max_tiles_per_node * max_cores_per_tile) + ((t) * max_cores_per_tile) + (c))

#define MAP_FOR(map, idx) for ((idx) = 0; idx < (map)->size; (idx)++)

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

typedef int (*dim_iterator_t)(int *);

static int nodes_per_system;
static int max_tiles_per_node;
static int max_cores_per_tile;
static int max_cpus_per_core;
static yod_cpuset_t **_system_map;

static void _map_system_layout(void);
static void _get_iterator(dim_iterator_t *, lwk_request_t *);
static void _next(int *, dim_iterator_t *);
static int _get_cpu(int *coords);

int yod_general_layout_algorithm(lwk_request_t *req)
{
	yod_cpuset_t *tmp, *lwkcpus;
	int i, cpu;
	int coord[NDIMS] = { 0, 0, 0, 0};
	dim_iterator_t iterator[NDIMS];

	tmp = yod_cpuset_alloc();
	lwkcpus = yod_cpuset_alloc();

	/* Make a copy of the requested LWK CPUs. */
	yod_cpuset_or(lwkcpus, req->lwkcpus_request, req->lwkcpus_request);

	/* Obtain a canonical mapping of the system. */
	_map_system_layout();

	/* Construct an iterator, according to the layout request. */
	_get_iterator(iterator, req);


	/* Walk the system, in "iterator" order, picking off CPUs
	 * from the requested LWK CPUs list as we encounter them.
	 */

	req->layout_request[0] = '\0';

	for (i = 0; !yod_cpuset_is_empty(lwkcpus); i++) {

		YOD_LOG(YOD_GORY, "Evaluating (%d,%d,%d,%d)",
			coord[IDX_NODE], coord[IDX_TILE],
			coord[IDX_CORE], coord[IDX_CPU]);

		cpu = _get_cpu(coord);

		if (cpu >= 0) {
			size_t len;

			YOD_LOG(YOD_DEBUG,
				"(%d,%d,%d,%d) CPU=%d lwkcpus=%s",
				coord[IDX_NODE], coord[IDX_TILE],
				coord[IDX_CORE], coord[IDX_CPU],
				cpu, yod_cpuset_to_list(lwkcpus));

			yod_cpuset_xor(tmp, tmp, tmp);
			yod_cpuset_set(cpu, tmp);
			yod_cpuset_and(tmp, lwkcpus, tmp);

			if (!yod_cpuset_is_empty(tmp)) {
				yod_cpuset_xor(lwkcpus, lwkcpus, tmp);
				len = strlen(req->layout_request);
				snprintf(req->layout_request + len,
					 sizeof(req->layout_request) - len,
					 len > 0 ? ",%d" : "%d",
					 cpu);
			}
		}

		_next(coord, iterator);
	}

	yod_cpuset_free(tmp);
	yod_cpuset_free(lwkcpus);
	free(_system_map);

	return 0;
}


/**
 * Returns true if s1 and s2 overlap.
 */
static bool _intersects(yod_cpuset_t *s1, yod_cpuset_t *s2, yod_cpuset_t *tmp)
{
	yod_cpuset_and(tmp, s1, s2);
	return yod_cpuset_is_empty(tmp) == 0;
}

/**
 * Construct an ordering of the cores in the system as a
 * N x T x C matrix, where N is the number of nodes, T is
 * the number of tiles per node, and C is the number of
 * cores per tile.  Since these dimensions are not known
 * at compile time, we use a single array and a macro to
 * index into it.  Note that we do not expand the CPUs
 * dimension so that we can avoid a potentially massive
 * expansion; instead we will simply re-use the existing
 * core masks at the lowest level of the map, and then
 * index into those core masks to get at specific CPUs.
 */

void _map_system_layout(void)
{
	struct map_type_t *nodes, *tiles, *cores;
	yod_cpuset_t *tmp;
	int i, N, t, T, c, C;

	nodes = yod_get_map(YOD_NODE);
	tiles = yod_get_map(YOD_TILE);
	cores = yod_get_map(YOD_CORE);

	nodes_per_system = nodes->size;
	max_tiles_per_node = tiles->size / nodes->size;
	max_cores_per_tile = cores->size / tiles->size;
	max_cpus_per_core = yod_cpuset_cardinality(cores->map[0]);

	MAP_FOR(nodes, i) {
	  int count = yod_count_by(nodes->map[i], YOD_TILE);

	  max_tiles_per_node = MAX(max_tiles_per_node, count);
	}

	MAP_FOR(tiles, i) {
	  int count = yod_count_by(tiles->map[i], YOD_CORE);

	  max_cores_per_tile = MAX(max_cores_per_tile, count);
	}

	MAP_FOR(cores, i) {
	  int count = yod_cpuset_cardinality(cores->map[i]);

	  max_cpus_per_core = MAX(max_cpus_per_core, count);
	}

	YOD_LOG(YOD_DEBUG,
		"nodes/system=%d tiles/node=%d cores/tile=%d cpus/core=%d",
		nodes_per_system, max_tiles_per_node,
		max_cores_per_tile, max_cpus_per_core);

	tmp = yod_cpuset_alloc();

	_system_map = calloc(nodes_per_system * max_tiles_per_node * max_cores_per_tile,
			     sizeof(yod_cpuset_t *));

	/* Walk every core mask in the core map, and determine its
	 * node, the tile within that node, and the core within that
	 * tile (N, T and C, respectively).
	 */
	MAP_FOR(cores, i) {

		yod_cpuset_t *core = cores->map[i];

		MAP_FOR(nodes, N) {
			if (_intersects(nodes->map[N], core, tmp))
				break;
		}

		T = -1;
		MAP_FOR(tiles, t) {
			if (_intersects(nodes->map[N], tiles->map[t], tmp)) {
				T++;
				if (_intersects(tiles->map[t], core, tmp))
					break;
			}
		}

		C = -1;
		MAP_FOR(cores, c) {
			if (_intersects(tiles->map[t], cores->map[c], tmp)) {
				C++;
				if (c == i)
					break;
			}
		}

		YOD_LOG(YOD_GORY, "SYSMAP: %s -> (%d,%d,%d)",
			yod_cpuset_to_list(core), N, T, C);

		assert(_system_map[COORD(N, T, C)] == NULL);

		_system_map[COORD(N, T, C)] = core;
	}

	yod_cpuset_free(tmp);
}

/**
 * We define iterator functions for each dimension (node, tile,
 * core, cpu) and a means of selecting these functions by name.
 * This enables us to dynamically construct an iterator for
 * any permutation of these dimensions.
 */

#define ITERATOR(name, idx, max)			\
	static int _increment_ ## name(int *coord)	\
	{						\
		int carry = 0;				\
		coord[idx]++;				\
		if (coord[idx] >= max) {		\
			carry = 1;			\
			coord[idx] = 0;			\
		}					\
		return carry;				\
	}

ITERATOR(node, IDX_NODE, nodes_per_system)
ITERATOR(tile, IDX_TILE, max_tiles_per_node)
ITERATOR(core, IDX_CORE, max_cores_per_tile)
ITERATOR(cpu,  IDX_CPU, max_cpus_per_core)

static struct _iterator_names {
	const char *name;
	dim_iterator_t iterator;
	int selected;
} ITERATORS[] = {
	{ .name = NODE_STR, .iterator = _increment_node },
	{ .name = TILE_STR, .iterator = _increment_tile },
	{ .name = CORE_STR, .iterator = _increment_core },
	{ .name = CPU_STR, .iterator = _increment_cpu },
};

static dim_iterator_t _select_iterator(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ITERATORS); i++)
		if (strcmp(name, ITERATORS[i].name) == 0) {
			if (ITERATORS[i].selected)
				yod_abort(-EINVAL,
					  "Duplicate layout dimension detected: %s.",
					  name);
			ITERATORS[i].selected = 1;
			return ITERATORS[i].iterator;
		}

	return NULL;
}

static void _get_iterator(dim_iterator_t *iterator, lwk_request_t *req)
{
	int n = 0;
	char descr[256], *d;

	if ((strlen(req->layout_descriptor) == 0) ||
	    (strcmp(req->layout_descriptor, SCATTER_STR) == 0))
		strcpy(descr, SCATTER_ALIAS);
	else if (strcmp(req->layout_descriptor, COMPACT_STR) == 0)
		strcpy(descr, COMPACT_ALIAS);
	else
		strcpy(descr, req->layout_descriptor);

	for (n = 0, d = descr; n < NDIMS; n++) {

		char *tok = strsep(&d, ",");

		if (!tok)
			yod_abort(-EINVAL,
				  "All four layout dimensions must be specified.");

		iterator[n] = _select_iterator(tok);
		if (!iterator[n])
			yod_abort(-EINVAL,
				  "Layout dimension \"%s\" is unrecognized.",
				  tok);
	}

	if (d)
		yod_abort(-EINVAL, "Extraneous layout dimensions: %s", d);
}

static void _next(int *coord, dim_iterator_t *iterator)
{
	int i, carry;

	for (i = 0; i < NDIMS; i++) {
		carry = iterator[i](coord);
		if (!carry)
			return;
	}
}

/**
 * Returns the CPU number associated with the given coordinates.
 */
static int _get_cpu(int *coord)
{
	yod_cpuset_t *core = _system_map[COORD(coord[IDX_NODE],
			       coord[IDX_TILE], coord[IDX_CORE])];
	return core ? yod_cpuset_nth_cpu(coord[IDX_CPU] + 1, core) : -1;
}
