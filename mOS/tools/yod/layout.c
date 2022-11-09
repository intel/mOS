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
#include <limits.h>
#include <stdbool.h>

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

static struct _layout_topology {
	const char *name;
	int max_count;
	int max_possible;
} layout_topology[NDIMS] = {
	{ .name = "node", .max_count = -1, .max_possible = -1, },
	{ .name = "tile", .max_count = -1, .max_possible = -1, },
	{ .name = "core", .max_count = -1, .max_possible = -1, },
	{ .name = "cpu",  .max_count = -1, .max_possible = -1, },
};

/**
 * A three dimensional indexing macro for a dyanmically sized,
 * flat underlying array.
 */
#define COORD(n, t, c) ( \
	((n) * layout_topology[IDX_TILE].max_possible * layout_topology[IDX_CORE].max_possible) + \
	((t) * layout_topology[IDX_CORE].max_possible) + \
	(c))

#define MAP_FOR(map, idx) for ((idx) = 0; idx < (map)->size; (idx)++)

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

static mos_cpuset_t **_system_map;

static void _map_system_layout(void);
static void _get_iteration_order(int *, lwk_request_t *);
static void _next(int *, int *);
static int _get_cpu(int *coords);

int yod_general_layout_algorithm(lwk_request_t *req)
{
	mos_cpuset_t *tmp, *lwkcpus;
	int i, cpu;
	bool at_origin;
	int coord[NDIMS] = { 0, 0, 0, 0};
	int order[NDIMS];
	tmp = mos_cpuset_alloc_validate();
	lwkcpus = mos_cpuset_alloc_validate();

	/* Make a copy of the requested LWK CPUs. */
	mos_cpuset_or(lwkcpus, req->lwkcpus_request, req->lwkcpus_request);

	/* Obtain a canonical mapping of the system. */
	_map_system_layout();

	/* Construct an iterator, according to the layout request. */
	_get_iteration_order(order, req);


	/* Walk the system, in "iterator" order, picking off CPUs
	 * from the requested LWK CPUs list as we encounter them.
	 */

	req->layout_request[0] = '\0';

	while (!mos_cpuset_is_empty(lwkcpus)) {

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
				cpu, mos_cpuset_to_list_validate(lwkcpus));

			mos_cpuset_xor(tmp, tmp, tmp);
			mos_cpuset_set(cpu, tmp);
			mos_cpuset_and(tmp, lwkcpus, tmp);

			if (!mos_cpuset_is_empty(tmp)) {
				mos_cpuset_xor(lwkcpus, lwkcpus, tmp);
				len = strlen(req->layout_request);
				snprintf(req->layout_request + len,
					 sizeof(req->layout_request) - len,
					 len > 0 ? ",%d" : "%d",
					 cpu);
			}
		}

		_next(coord, order);

		/* If we have circled all the way back to (0,0,0,0), then
		 * reset the max_counts of all dimensions to their largest
		 * possible vaues.  This allows us to sweep up the remaining
		 * LWK CPUs for the remainder of the sequence.
		 */
		for (i = 0, at_origin = true; i < NDIMS && at_origin; i++)
			at_origin = coord[i] == 0;

		if (at_origin)
			for (i = 0; i < NDIMS; i++)
				layout_topology[i].max_count =
					layout_topology[i].max_possible;

	}

	mos_cpuset_free(tmp);
	mos_cpuset_free(lwkcpus);
	free(_system_map);

	return 0;
}

/**
 * Returns true if s1 and s2 overlap.
 */
static bool _intersects(mos_cpuset_t *s1, mos_cpuset_t *s2, mos_cpuset_t *tmp)
{
	mos_cpuset_and(tmp, s1, s2);
	return mos_cpuset_is_empty(tmp) == 0;
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
	mos_cpuset_t *tmp;
	size_t i, N, t, T, c, C;

	nodes = yod_get_map(YOD_NODE);
	tiles = yod_get_map(YOD_TILE);
	cores = yod_get_map(YOD_CORE);

	layout_topology[IDX_NODE].max_possible = nodes->size;
	layout_topology[IDX_TILE].max_possible = tiles->size / nodes->size;
	layout_topology[IDX_CORE].max_possible = cores->size / tiles->size;
	layout_topology[IDX_CPU].max_possible =
		mos_cpuset_cardinality(cores->map[0]);

	MAP_FOR(nodes, i) {
		layout_topology[IDX_TILE].max_possible =
			MAX(layout_topology[IDX_TILE].max_possible,
			    yod_count_by(nodes->map[i], YOD_TILE));
	}

	MAP_FOR(tiles, i) {
		layout_topology[IDX_CORE].max_possible =
			MAX(layout_topology[IDX_CORE].max_possible,
			    yod_count_by(tiles->map[i], YOD_CORE));
	}

	MAP_FOR(cores, i) {
		layout_topology[IDX_CPU].max_possible =
			MAX(layout_topology[IDX_CPU].max_possible,
			    mos_cpuset_cardinality(cores->map[i]));
	}

	YOD_LOG(YOD_DEBUG,
		"nodes/system=%d tiles/node=%d cores/tile=%d cpus/core=%d",
		layout_topology[IDX_NODE].max_possible,
		layout_topology[IDX_TILE].max_possible,
		layout_topology[IDX_CORE].max_possible,
		layout_topology[IDX_CPU].max_possible);

	tmp = mos_cpuset_alloc_validate();

	_system_map = calloc(layout_topology[IDX_NODE].max_possible *
			     layout_topology[IDX_TILE].max_possible *
			     layout_topology[IDX_CORE].max_possible,
			     sizeof(mos_cpuset_t *));

	/* Walk every core mask in the core map, and determine its
	 * node, the tile within that node, and the core within that
	 * tile (N, T and C, respectively).
	 */
	MAP_FOR(cores, i) {

		mos_cpuset_t *core = cores->map[i];

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

		YOD_LOG(YOD_GORY, "SYSMAP: %s -> (%zd,%zd,%zd)",
			mos_cpuset_to_list_validate(core), N, T, C);

		assert(_system_map[COORD(N, T, C)] == NULL);

		_system_map[COORD(N, T, C)] = core;
	}

	mos_cpuset_free(tmp);
}

static void _get_iteration_order(int *order, lwk_request_t *req)
{
	int i, n;
	char descr[256], *d;

	if ((strlen(req->layout_descriptor) == 0) ||
	    (strcmp(req->layout_descriptor, SCATTER_STR) == 0))
		strcpy(descr, SCATTER_ALIAS);
	else if (strcmp(req->layout_descriptor, COMPACT_STR) == 0)
		strcpy(descr, COMPACT_ALIAS);
	else
		strcpy(descr, req->layout_descriptor);

	for (n = 0, d = descr; n < NDIMS; n++) {

		char *dim;
		long int count = -1;
		char *tok = strsep(&d, ",");

		if (!tok)
			yod_abort(-EINVAL,
				  "All four layout dimensions must be specified.");

		dim = strsep(&tok, ":");

		order[n] = -1;
		for (i = 0; i < NDIMS; i++)
			if (!strcmp(layout_topology[i].name, dim)) {
				order[n] = i;
				break;
			}

		if (order[n] == -1)
			yod_abort(-EINVAL,
				  "Layout dimension \"%s\" is unrecognized.",
				  dim);
		if (tok) {
			if (yodopt_parse_integer(tok, &count, 1, layout_topology[order[n]].max_possible))
				yod_abort(-EINVAL,
					  "Illegal layout count detected in \"%s\".",
					  req->layout_descriptor);
		}

		if (count == -1)
			layout_topology[order[n]].max_count =
					layout_topology[order[n]].max_possible;
		else
			layout_topology[order[n]].max_count = count;
	}

	if (d)
		yod_abort(-EINVAL, "Extraneous layout dimensions: %s", d);
}

static void _next(int *coord, int *order)
{
	int i, carry = 1;

	for (i = 0; i < NDIMS && carry; i++) {
		coord[order[i]]++;
		if (coord[order[i]] < layout_topology[order[i]].max_count)
			carry = 0;
		else
			coord[order[i]] = 0;
	}
}

/**
 * Returns the CPU number associated with the given coordinates.
 */
static int _get_cpu(int *coord)
{
	mos_cpuset_t *core = _system_map[COORD(coord[IDX_NODE],
			       coord[IDX_TILE], coord[IDX_CORE])];
	return core ? mos_cpuset_nth_cpu(coord[IDX_CPU] + 1, core) : -1;
}
