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
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/file.h>

#include "yod.h"
#include "yod_debug.h"

#define MOS_SYSFS_ROOT "/sys/kernel/mOS/"
#define MOS_SYSFS_LWKCPUS (MOS_SYSFS_ROOT "lwkcpus")
#define MOS_SYSFS_LWKCPUS_RESERVED (MOS_SYSFS_ROOT "lwkcpus_reserved")
#define MOS_SYSFS_LWKCPUS_REQUEST (MOS_SYSFS_ROOT "lwkcpus_request")
#define MOS_SYSFS_LWKGPUS (MOS_SYSFS_ROOT "lwkgpus")
#define MOS_SYSFS_LWKGPUS_RESERVED (MOS_SYSFS_ROOT "lwkgpus_reserved")
#define MOS_SYSFS_LWKGPUS_REQUEST (MOS_SYSFS_ROOT "lwkgpus_request")
#define MOS_SYSFS_LWKGPUS_USAGE_COUNT (MOS_SYSFS_ROOT "lwkgpus_usage_count")
#define MOS_SYSFS_LWKGPUS_NUMA (MOS_SYSFS_ROOT "lwkgpus_numa")
#define MOS_SYSFS_UTILTHREADS_SET (MOS_SYSFS_ROOT "lwk_util_threads")
#define MOS_SYSFS_LWKMEM (MOS_SYSFS_ROOT "lwkmem")
#define MOS_SYSFS_LWKMEM_RESERVED (MOS_SYSFS_ROOT "lwkmem_reserved")
#define MOS_SYSFS_LWKMEM_REQUEST (MOS_SYSFS_ROOT "lwkmem_request")
#define MOS_SYSFS_LWKCPUS_SEQUENCE (MOS_SYSFS_ROOT "lwkcpus_sequence")
#define MOS_SYSFS_LWKMEM_MEMPOLICY_INFO (MOS_SYSFS_ROOT "lwkmem_mempolicy_info")
#define MOS_SYSFS_LWK_OPTIONS (MOS_SYSFS_ROOT "lwk_options")
#define MOS_SYSFS_LWK_PROCESSES (MOS_SYSFS_ROOT "lwkprocesses")
#define CPUINFO "/proc/cpuinfo"
#define CPU_ONLINE "/sys/devices/system/cpu/online"
#define NODES_ONLINE "/sys/devices/system/node/online"
#define THREAD_SIBLINGS "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list"
#define CACHE_LEVEL "/sys/devices/system/cpu/cpu%d/cache/index%d/level"
#define L2_SIBLINGS "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list"
#define DISTANCE_MAP "/sys/devices/system/node/node%zd/distance"
#define NODE_CPUS "/sys/devices/system/node/node%zd/cpulist"
#define MOS_LOCAL_RANK_SEQUENCE_FILE "/tmp/yod.local.lock.%s"
#define PROC_MOS_VIEW "/proc/self/mos_view"

#define STARTS_WITH(s, prefix) (strncmp(s, prefix, strlen(prefix)) == 0)

/* maps CPU -> elem where elem is {tile, core, node} */
struct cpu_map_t {
	int elems[YOD_NUM_MAP_ELEMS];
};

static size_t cpu_map_size;
static struct cpu_map_t *cpu_map;
static size_t **distance_map;
static size_t distance_map_size;

static int mos_sysfs_read(const char *file, char *buff, int len)
{
	FILE *fptr;
	int rc;

	YOD_LOG(YOD_GORY, "(>) %s(file=%s buff=%p:%d)",
		__func__, file, buff, len);

	buff[len-1] = '\0';

	fptr = fopen(file, "r");

	if (!fptr) {
		YOD_LOG(YOD_DEBUG, "Could not open \"%s\" for reading.", file);
		return -1;
	}

	rc = fread(buff, 1, len-1, fptr);

	if (rc < 0) {
		YOD_ERR("Could not read \"%s\" (rc = %d)", file, len);
	} else
		buff[rc] = 0; /* force end-of-string */

	fclose(fptr);

	YOD_LOG(YOD_GORY, "(<) %s(file=%s buff=%p:\"%s\":%d)",
		__func__, file, buff, rc > 0 ? buff : "?", rc);
	return rc;
}

static int mos_sysfs_write(const char *file, char *buff, int len)
{
	int fd;
	int rc = 0;

	YOD_LOG(YOD_GORY, "%s(file=%s buff=%p:\"%s\":%d)",
		__func__, file, buff, buff ? buff : "?", len);

	fd = open(file, O_WRONLY);

	if (fd == -1) {
		YOD_ERR("Could not open \"%s\" for writing.", file);
		return -1;
	}

	rc = write(fd, buff, len);

	if (rc != len) {
		YOD_LOG(YOD_WARN, "Could not write to \"%s\" (rc = %d %s)", file, rc, strerror(errno));
		rc--;
	}


	if (close(fd) == -1) {
		YOD_LOG(YOD_WARN, "Could not close \"%s\" (%s)", file, strerror(errno));
		rc--;
	}

	YOD_LOG(YOD_GORY, "(<) %s(file=%s rc=%d", __func__, file, rc);

	return rc < 0 ? rc : 0;
}

static int mos_sysfs_get_cpulist(const char *file, mos_cpuset_t *set)
{
	char buffer[4096];
	int rc;

	rc = mos_sysfs_read(file, buffer, sizeof(buffer));

	if ((rc == 0) || ((rc > 0) && (buffer[0] == '\n'))) {
		mos_cpuset_xor(set, set, set);
		rc = 0;
	} else if (rc > 0) {
		rc = mos_parse_cpulist(buffer, set);
		if (rc)
			yod_abort(-1, "Could not parse %s", buffer);
	}

	YOD_LOG(YOD_GORY, "%s(\"%s\") -> \"%s\" (rc=%d)", __func__,
		file, mos_cpuset_to_list_validate(set), rc);
	return rc;

}

static int mos_sysfs_put_cpulist(const char *file, mos_cpuset_t *set)
{
	int rc;
	char* list;

	list = mos_cpuset_to_list_validate(set);

	rc = mos_sysfs_write(file, list, strlen(list));

	return (rc > 0) ? 0 : rc;
}

static int mos_get_designated_lwkcpus(mos_cpuset_t *set)
{
	return mos_sysfs_get_cpulist(MOS_SYSFS_LWKCPUS, set);
}

static int mos_get_reserved_lwk_cpus(mos_cpuset_t *set)
{
	return mos_sysfs_get_cpulist(MOS_SYSFS_LWKCPUS_RESERVED, set);
}

static int mos_request_lwk_cpus(mos_cpuset_t *set)
{
	return mos_sysfs_put_cpulist(MOS_SYSFS_LWKCPUS_REQUEST, set);
}

static void restrict_to_tile0(mos_cpuset_t *set)
{
	int gpu;

	for (gpu = 0; gpu < MOS_MAX_GPU_TILES; gpu++) {
		if (!mos_cpuset_is_set(gpu, set))
			continue;
		if (gpu % MOS_MAX_TILES_PER_GPU)
			mos_cpuset_clr(gpu, set);
	}
}

static int mos_get_designated_lwkgpus(mos_cpuset_t *set)
{
	int rc;
	long int only_tile0;
	char *only_tile0_str;

	/* Using cpulist library functions to manage gpulist */
	rc = mos_sysfs_get_cpulist(MOS_SYSFS_LWKGPUS, set);

	if ((only_tile0_str = getenv("YOD_ONLY_TILE_0")))
		if (!yod_strtol(only_tile0_str, &only_tile0))
			if (only_tile0 == 1)
				restrict_to_tile0(set);
	return rc;
}

static int mos_get_reserved_lwk_gpus(mos_cpuset_t *set)
{
	/* Using cpulist library functions to manage gpulist */
	return mos_sysfs_get_cpulist(MOS_SYSFS_LWKGPUS_RESERVED, set);
}


static int mos_get_gpu_usage_counts(int *counts, int num)
{
	char buffer[4096];
	char *p, *tok;
	int bytes_read, i;
	int rc = 0;
	char *file = MOS_SYSFS_LWKGPUS_USAGE_COUNT;

	/* initialize the counts */
	for (i = 0; i < num; i++)
		counts[i] = 0;

	bytes_read = mos_sysfs_read(file, buffer, sizeof(buffer));
	if (bytes_read < 0)
		yod_abort(-1,
		    "Could not read GPU usage counts from location %s", file);

	p = buffer;
	i = 0;
	/* Parse comma separated list of integers */
	while ((tok = strsep(&p, ","))) {
		long int count;

		if (strlen(tok) == 0)
			break;

		if (yod_strtol(tok, &count))
			yod_abort(-1, "Error parsing GPU usage counts(%s).", tok);

		if (i >= num)
			yod_abort(-1, "Integer array not large enough for GPU usage counts(%d >= %d.", i, num);

		counts[i++] = (int)count;
	}
	return rc;
}

static int mos_get_gpu_numa(int *nids, int num)
{
	char buffer[4096];
	char *p, *tok;
	int bytes_read, i;
	int rc = 0;
	char *file = MOS_SYSFS_LWKGPUS_NUMA;

	/* initialize the nids */
	for (i = 0; i < num; i++)
		nids[i] = 0;

	bytes_read = mos_sysfs_read(file, buffer, sizeof(buffer));
	if (bytes_read < 0)
		yod_abort(-1,
		    "Could not read GPU usage counts from location %s", file);

	p = buffer;
	i = 0;
	/* Parse comma separated list of integers */
	while ((tok = strsep(&p, ","))) {
		long int nid;

		if (strlen(tok) == 0)
			break;

		if (yod_strtol(tok, &nid)) {
			yod_abort(-1, "Error parsing GPU usage counts(%s).", tok);
		}
		if (i >= num) {
			yod_abort(-1, "Integer array not large enough for GPU usage counts(%d >= %d.", i, num);
		nids[i++] = (int)nid;
		}
	}
	return rc;
}

static int mos_request_lwk_gpus(mos_cpuset_t *gpus, char *new_ze_affinity)
{
	int rc = 0;

	if (mos_cpuset_is_empty(gpus))
		return rc; /* No GPUs exist */

	rc = mos_sysfs_put_cpulist(MOS_SYSFS_LWKGPUS_REQUEST, gpus);
	if (rc)
		return rc;

	YOD_LOG(YOD_GORY, "Setting environment to %s\n", new_ze_affinity);

	if ((setenv("ZE_ENABLE_PCI_ID_DEVICE_ORDER", "1", 1)))
		yod_abort(-1, "Error setting ZE_ENABLE_PCI_ID_DEVICE_ORDER=1. errno=%d", errno);

	if ((setenv("ZE_AFFINITY_MASK", new_ze_affinity, 1)))
		yod_abort(-1, "Error setting ZE_AFFINITY_MASK=%s. errorno=%d", new_ze_affinity, errno);

	return 0;
}

static void mos_populate_gpu_map(void)
{

	int gpu_index = 0;
	int bytes_read;
	char *p, *tok;
	char buffer[4096];

	/* Read the mOS sysfs file that contains the nids for designated GPUs */
	bytes_read = mos_sysfs_read(MOS_SYSFS_LWKGPUS_NUMA, buffer, sizeof(buffer));

	/*
	 *  Walk through the comma-separated list of nids indexed by gpu id
	 *  and set the cpu map
	 */
	if (bytes_read < 0)
		yod_abort(-1,
		    "Could not read GPU numa data from location %s", MOS_SYSFS_LWKGPUS_NUMA);
	p = buffer;
	while ((tok = strsep(&p, ","))) {
		long int nid;

		if (strlen(tok) == 0)
			break;

		if (yod_strtol(tok, &nid)) {
			yod_abort(-1, "Error converting GPU nid to integer(%s).", tok);
		}
		if (nid < 0)
			/* No more entries to process. We are done. */
			break;
		if (gpu_index >= MOS_MAX_GPU_TILES) {
			yod_abort(-1, "Exceeded maximum supported number of GPUs (%d.", MOS_MAX_GPU_TILES);
		}
		if (nid >  YOD_MAX_NIDS) {
			yod_abort(-1, "Numa id from lwkgpus_numa out of range (%d.", nid);
		}
		cpu_map[gpu_index++].elems[YOD_NODE_GPU] = nid;
	}
}

static int mos_set_util_threads(size_t num_util_threads)
{
	char buff[16];

	snprintf(buff, sizeof(buff), "%zd", num_util_threads);
	return mos_sysfs_write(MOS_SYSFS_UTILTHREADS_SET, buff, sizeof(buff));
}

/** Reads the specified sysfs file and populates the CPU map.
 * @param[in] typ The CPU map type being populated.
 * @param[in] pathspec A sysfs path template with one or two substitutable
 *   integer elements (%d).
 * @param[in] idx1 The first substitutable value.
 * @param[in] idx2 The second subtitutable value or -1 if only one value
 *   should be sustituted.
 * @param[in] val The value to be associated with each CPU listed in the
 *   sysfs file and for the given typ.
 */
static void mos_read_and_populate(enum map_elem_t typ, const char *pathspec, int idx1, int idx2, int val)
{
	size_t i;
	int rc;
	char path[4096];
	char buffer[4096];
	mos_cpuset_t *set;

	if (idx2 == -1)
		rc = snprintf(path, sizeof(path), pathspec, idx1);
	else
		rc = snprintf(path, sizeof(path), pathspec, idx1, idx2);

	if (rc >= (int)sizeof(path))
		yod_abort(-1, "Buffer overflow in expanding %s", pathspec);

	set = mos_cpuset_alloc_validate();

	if (mos_sysfs_read(path, buffer, sizeof(buffer)) < 0)
		yod_abort(-1, "Could not read %s", path);

	if (mos_parse_cpulist(buffer, set))
		yod_abort(-1, "Could not parse %s (%s)", path, buffer);

	for (i = 0; i < cpu_map_size; i++) {
		if (mos_cpuset_is_set(i, set))
			cpu_map[i].elems[typ] = val;
	}

	mos_cpuset_free(set);
}

static void mos_init_distance_map(void);

static void mos_init_cpu_map(void)
{
	char buffer[4096], path[4096];
	FILE *f;
	int family = -1, model = -1;
	int found_family = 0, found_model = 0;
	size_t cpu, core, tile, node;
	size_t nc, nr, n_nodes;
	mos_cpuset_t *set;
	int l2_index, rc;

	/* Read /proc/cpuinfo to determine the CPU family and model */

	if (!(f = fopen(CPUINFO, "r")))
		yod_abort(-1, "Could not read %s", CPUINFO);
	while (!(found_family && found_model)) {
		if (fgets(buffer, sizeof(buffer), f) != buffer)
			break;

		sscanf(buffer, "cpu family : %d\n", &family);
		sscanf(buffer, "model : %d\n", &model);

		if (family >= 0)
			found_family = 1;
		if (model >= 0)
			found_model = 1;
	}
	fclose(f);

	if (!found_family || !found_model)
		yod_abort(-1, "Could not parse CPU model (%d/%d)", family, model);

	/* Read the /sys/devices/system/cpu/online file to determine
	 * how many CPUs are actually active for this system.
	 */

	if (mos_sysfs_read(CPU_ONLINE, buffer, sizeof(buffer)) < 0)
		yod_abort(-1, "Could not read %s", CPU_ONLINE);

	set = mos_cpuset_alloc_validate();

	if (mos_parse_cpulist(buffer, set))
		yod_abort(-1, "Could not parse %s (%s)", CPU_ONLINE, buffer);

	cpu_map_size = mos_cpuset_biggest(set) + 1;
	cpu_map = malloc(cpu_map_size * sizeof(struct cpu_map_t));

	if (!cpu_map)
		yod_abort(-1, "Could not allocate space for core map [%s:%d]", __FILE__, __LINE__);

	memset(cpu_map, -1, cpu_map_size * sizeof(struct cpu_map_t));

	/* Determine which index underneath /sys/devices/system/cpu/cpu<N>/cache/index<M>
	 * holds the level 2 data.  Note that no such index is found, we will
	 * abort.
	 */
	for (l2_index = 0; ; l2_index++) {

		char fname[256];

		if (snprintf(fname, sizeof(fname), CACHE_LEVEL, 0, l2_index) >= (int)sizeof(fname))
			yod_abort(-1, "Buffer overflow in expanding %s", CACHE_LEVEL);

		if (mos_sysfs_read(fname, buffer, sizeof(buffer)) < 0)
			yod_abort(-1, "Could not read %s", fname);

		if (atoi(buffer) == 2)
			break;
	}


	/* Now walk the sibling list files, which contain the CPU numbers of
	 * topologically related CPUs.  These files are symmetric by definition
	 * and therefore we can skip reading some of them by filling in data
	 * for all siblings.
	 */

	for (cpu = 0, core = -1, tile = -1; cpu < cpu_map_size; cpu++) {

		if (cpu_map[cpu].elems[YOD_CORE] == -1)
			mos_read_and_populate(YOD_CORE, THREAD_SIBLINGS, cpu, -1, ++core);

		if (cpu_map[cpu].elems[YOD_TILE] == -1)
			mos_read_and_populate(YOD_TILE, L2_SIBLINGS, cpu, l2_index, ++tile);
	}

	/* To construct the node map, we walk the node directory. */

	for (node = 0, n_nodes = 0; ; node++) {

		rc = snprintf(path, sizeof(path), NODE_CPUS, node);

		if (rc >= (int)sizeof(path))
			yod_abort(-1, "Buffer overflow in expanding %s",
				  NODE_CPUS);

		if (mos_sysfs_read(path, buffer, sizeof(buffer)) < 0)
			break;

		if (mos_parse_cpulist(buffer, set))
			yod_abort(-1, "Could not parse %s (%s)", path, buffer);

		if (mos_cpuset_is_empty(set))
			continue;

		n_nodes++;
		for (cpu = 0; cpu < cpu_map_size; cpu++)
			if (mos_cpuset_is_set(cpu, set)) {
				if (cpu_map[cpu].elems[YOD_NODE] != -1)
					yod_abort(-1, "Conflicting data in %s : CPU=%d prev=%d",
						  path, cpu,
						  cpu_map[cpu].elems[YOD_NODE]);
				cpu_map[cpu].elems[YOD_NODE] = node;
			}

	}

	/* Walk the distance map to populate the group mapping.  This is
	 * done based on expected values in the distance map.  Note that
	 * we only process node distance files for nids that have CPUs,
	 * which, after the above code, is [0..node].
	 */
	if (distance_map_size == 0)
		mos_init_distance_map();

	/* Linux exports node distance information derived from the
	 * optional ACPI SLIT (or faked to look like it was); element
	 * [i,j] of the matrix indicates the distance (memory latency)
	 * from node i to node j, scaled such that the diagonal elements
	 * have the value 10.  Element [j,i] need not equal [i,j],
	 * though it often does.  If a node is unreachable from another,
	 * the distance is 255.  Distances 0-9 are reserved.
	 */
	for (nr = 0; nr < n_nodes; nr++) {
		for (nc = 0; nc < distance_map_size; nc++) {
			int type = YOD_DRAM;

			if (nr == nc && distance_map[nr][nc] != 10)
				yod_abort(-1, "Unexpected distance value on diagonal of map (index=%d)", nr);

			/* TODO: Consider reading the HMAT if it exists and fall
			 * back on reading the PMTT if it doesn't, since that
			 * would make us future-proof; instead, we read the
			 * SLIT-derived distances and special case model numbers
			 * using particular values seen in the Intel firmware's
			 * SLIT.
			 */
			if (family == 6 && model == 87) {
				/* KNL
				 *   10 - own node's DDR
				 *   21 - other node's DDR
				 *   31 - own node's MCDRAM (HBM)
				 *   41 - other node's MCDRAM (HBM)
				 */
				switch (distance_map[nr][nc]) {
				case 31:
				case 41:
					type = YOD_HBM;
				default:
					break;
				}
			} else if (family == 6 && model == 143) {
				/* Saphire Rapids
				 *   10 - my socket DDR or if SNC:my quadrant DDR
				 *   12 - SNC4: other quadrant DDR on my socket
				 *   13 - my socket HBM or if SNC:my quadrant HBM
				 *   14 - SNC4: other quadrant HBM on my socket
				 *   21 - other socket DDR
				 *   23 - other socket HBM
				 */
				switch (distance_map[nr][nc]) {
				case 13:
				case 14:
				case 23:
					type = YOD_HBM;
				default:
					break;
				}
			}
			cpu_map[nc].elems[YOD_MEM_GROUP] = type;
		}
	}


	/* Walk the GPU devices and populate the NUMA node that is associated
	 * with each GPU device
	 */
	mos_populate_gpu_map();

	mos_cpuset_free(set);
}

static ssize_t mos_map_cpu(size_t cpu, enum map_elem_t typ)
{
	if (cpu_map_size == 0)
		mos_init_cpu_map();

	return (cpu < cpu_map_size) ? cpu_map[cpu].elems[typ] : -1;
}

static int _mos_read_vector(size_t *vec, size_t *n, const char *filen)
{
	char buffer[4096];
	char *tok, *buff, *save, *remainder, *copy;
	int rc;
	size_t N = *n;  /* max size */

	copy = NULL;

	*n = mos_sysfs_read(filen, buffer, sizeof(buffer));

	if (*n <= 0) {
		rc = -1;
		goto out;
	}

	buff = copy = strdup(buffer);
	*n = 0;

	while ((tok = strtok_r(buff, " \n", &save)) != 0) {

		if (*n == N) {
			YOD_LOG(YOD_WARN,
				"Buffer overrun parsing %s ->\"%s\"",
				filen, buffer);
			rc = -1;
			goto out;
		}

		vec[(*n)++] = strtoul(tok, &remainder, 0);

		if (*remainder != '\0') {
			YOD_LOG(YOD_WARN,
				"Garbage detected in %s ->\"%s\" at offset %zd",
				filen, buffer, remainder - copy);
			rc = -1;
			goto out;
		}

		buff = NULL;
	}

	rc = 0;
 out:
	free(copy);
	return rc;
}

static void mos_init_distance_map(void)
{
	char path[256];
	size_t distances[256], *dptr, len, i, j;
	int rc;

	/* Force at least one iteration.  Note that distance_map_size
	 * will be adjusted after the first file is processed.
	 */
	for (i = 0, distance_map_size = 1; i < distance_map_size; i++) {

		rc = snprintf(path, sizeof(path), DISTANCE_MAP, i);

		if (rc >= (int)sizeof(path))
			yod_abort(-1, "Buffer overflow in expanding %s.", DISTANCE_MAP);

		if (i == 0) {
			len = ARRAY_SIZE(distances);
			dptr = distances;
		} else {
			len = distance_map_size;
			dptr = distance_map[i];
		}

		rc = _mos_read_vector(dptr, &len, path);

		if (rc < 0) {
			YOD_LOG(YOD_WARN, "Could not read %s.", path);
			continue;
		}

		if (i == 0) {
			distance_map_size = len;
			distance_map = calloc(len, sizeof(size_t *));
			for (j = 0; j < distance_map_size; j++)
				distance_map[j] = calloc(len, sizeof(size_t));
			memcpy(distance_map[0], distances, sizeof(size_t) * len);
		}

		if (len != distance_map_size)
			yod_abort(-1,
				  "Unexpected change in distance map width in %s (actual width %zd vs. %zd expected)",
				  path, len, distance_map_size);
	}
}

static void mos_get_distance_map(size_t nid, size_t *dist, size_t *n)
{
	if (distance_map_size == 0)
		mos_init_distance_map();

	if ((size_t)nid >= distance_map_size) {
		YOD_ERR("NID %zd exceeds distance map length (%zd).",
			nid, distance_map_size);
		*n = 0;
		return;
	}

	if (*n < distance_map_size) {
		YOD_ERR("Distance map length (%zd) exceeds buffer size (%zd).",
			distance_map_size, *n);
		*n = 0;
		return;
	}

	memcpy(dist, distance_map[nid], distance_map_size * sizeof(size_t));
	*n = distance_map_size;
}

static void mos_get_designated_lwkmem(size_t *mem, size_t *n)
{
	if (_mos_read_vector(mem, n, MOS_SYSFS_LWKMEM))
		yod_abort(-EINVAL, "Error reading %s", MOS_SYSFS_LWKMEM);
}

static void mos_get_reserved_lwkmem(size_t *mem, size_t *n)
{
	if (_mos_read_vector(mem, n, MOS_SYSFS_LWKMEM_RESERVED))
		yod_abort(-EINVAL, "Error reading %s", MOS_SYSFS_LWKMEM_RESERVED);
}

static int mos_request_lwk_memory(size_t *mem, size_t n)
{
	char buffer[4096];
	char *bypass;
	size_t i, len;
	int rc;

	bypass = getenv("YOD_LWKMEM");
	if (bypass) {
		YOD_LOG(YOD_WARN, "lwkmem_request bypass is enabled.");
		return 0;
	} else {
		buffer[0] = 0;
		for (i = 0; i < n; i++) {
			len = strlen(buffer);
			rc = snprintf(buffer + len, sizeof(buffer) - len, "%s%lu", i > 0 ? " " : "", mem[i]);
			if (rc >= ((int)(sizeof(buffer) - len)))
				yod_abort(-1, "Buffer overflow when writing to %s", MOS_SYSFS_LWKMEM_REQUEST);
		}
		return mos_sysfs_write(MOS_SYSFS_LWKMEM_REQUEST, buffer, strlen(buffer) + 1);
	}
}

/* We re-use cpulist parsing code to read online NUMA nodes */
static int mos_get_numa_nodes_online(mos_cpuset_t *set)
{
	return mos_sysfs_get_cpulist(NODES_ONLINE, set);
}

static int lock_fd = -1;

static int mos_get_local_rank(int *local_rank, int *local_n_ranks)
{
	char *local_rank_str, *local_n_ranks_str;

	local_rank_str = getenv("MPI_LOCALRANKID");
	local_n_ranks_str = getenv("MPI_LOCALNRANKS");

	if (!local_rank_str || !local_n_ranks_str)
		return -1;

	*local_rank = strtol(local_rank_str, &local_rank_str, 10);
	*local_n_ranks = strtol(local_n_ranks_str, &local_n_ranks_str, 10);

	if (*local_rank_str || *local_n_ranks_str || *local_rank < 0 ||
	    *local_n_ranks <= 0) {
		YOD_LOG(YOD_WARN,
			"Bad value for MPI_LOCALRANKID=%s or MPI_LOCALNRANKS=%s",
			getenv("MPI_LOCALRANKID"), getenv("MPI_LOCALNRANKS"));
		return -1;
	}

	return 0;
}

static int lock_active;

static int mos_sysfs_lock(struct lock_options_t *opts)
{
	YOD_LOG(YOD_GORY, "(>) %s(timeout=%ld)",
		__func__, opts->timeout_millis);

	lock_fd = open(MOS_SYSFS_ROOT, O_RDONLY);

	if (lock_fd == -1) {
		YOD_ERR("Could not open %s for locking.", MOS_SYSFS_ROOT);
		goto lock_out;
	}

	long retries = opts->timeout_millis / 10;

	/* Try at least twice. */
	if (retries < 2)
		retries = 2;

	while (retries > 0) {

		if (flock(lock_fd, LOCK_EX | LOCK_NB) == 0) {
			lock_active = 1;
			goto lock_out;
		}

		usleep(10 * 1000); /* 10 millis */
		retries--;
	}

	if (close(lock_fd) != 0)
		YOD_LOG(YOD_WARN, "Could not close \"%s\" (%s)",
			MOS_SYSFS_ROOT, strerror(errno));

	lock_fd = -1;

 lock_out:
	YOD_LOG(YOD_GORY, "(<) %s(timeout=%ld) fd=%d",
		__func__, opts->timeout_millis, lock_fd);

	return (lock_fd == -1) ? -1 : 0;

}

static char *local_rank_sequence_file_path(char *buff, int length)
{
	int rc;
	char *user;

	user = getenv("USER");

	if (!user)
		yod_abort(-1, "Environment variable USER is not set.");

	rc = snprintf(buff, length, MOS_LOCAL_RANK_SEQUENCE_FILE, user);

	if (rc >= length)
		yod_abort(-1, "Buffer overflow in expanding %s",
			  MOS_LOCAL_RANK_SEQUENCE_FILE);

	return buff;
}

static int mos_next_rank(int local_rank, int n_ranks,
			 struct lock_options_t *opts)
{
	int result = -1;

	switch (opts->layout) {

	case YOD_RANK_COMPACT:
		result = local_rank + 1;
		if (result >= n_ranks)
			result = -1;
		break;

	case YOD_RANK_SCATTER:

		/* The stride size by default is the number of compute
		 * node domains.
		 */
		if (opts->stride == -1) {
			struct map_type_t *node_map;

			node_map = yod_get_map(YOD_NODE);
			opts->stride = node_map->size;
		}

		result = local_rank + opts->stride;

		if (result >= n_ranks) {
			result = local_rank % opts->stride + 1;
			if (result == opts->stride)
				result = -1;
		}

		break;

	default:
		yod_abort(-1, "Unsupported rank layout type %d", opts->layout);
	}

	YOD_LOG(YOD_INFO, "(<) %s self=%d / %d ==> %d",
		__func__, local_rank, n_ranks, result);

	return result;
}

static int mos_combo_lock(struct lock_options_t *opts)
{
	/* Some environments (e.g. MPICH) describe the number and id of
	 * each local rank via the environment.  When such information is
	 * present, use it to serialize yod processes by proceeding in
	 * local rank order.  Otherwise, defer to the sysfs lock mechanism,
	 * which does not guarantee order from run-to-run.
	 */

	int local_rank = -1, local_n_ranks = -1, fd, next = -1;
	long retries = opts->timeout_millis / 10;
	ssize_t rc;
	char seq_file[256];

	YOD_LOG(YOD_GORY, "(>) %s(timeout=%ld)",
		__func__, opts->timeout_millis);

	/* Try at least twice. */
	if (retries < 2)
		retries = 2;

	/* If we cannot determine local rank and count, of if rank
	 * sequencing is disabled, defer to the sysfs lock.
	 */
	if ((mos_get_local_rank(&local_rank, &local_n_ranks) < 0) ||
	    opts->layout == YOD_RANK_DISABLE)
		return mos_sysfs_lock(opts);

	local_rank_sequence_file_path(seq_file, sizeof(seq_file));

	/* The first rank (rank 0) proceeds.  Everyone else has to wait their
	 * turn.
	 */
	if (local_rank != 0) {
		while (retries > 0) {
			fd = open(seq_file, O_RDONLY);
			if (fd >= 0) {
				/* Attempt to read the sequence number from the
				 * file.  It is possible that the value has not
				 * arrived yet and therefore we should retry.
				 */
				rc = read(fd, &next, sizeof(int));
				if (rc != (ssize_t)sizeof(int)) {
					if (rc < 0 && errno != EINTR) {
						yod_abort(-EBUSY,
							  "Could not read local lock file %s (rc=%zd, errno=%d).",
							  seq_file, rc, errno);
					} else {
						next = -1; /* retry */
					}
				}
				close(fd);
				if (next == local_rank)
					break;
			}
			usleep(10 * 1000);
			retries--;
		}

		if (local_rank != next) {
			yod_abort(-EBUSY, "Could not acquire lock (%s). Retry?",
				  seq_file);
		}
	}

	YOD_LOG(YOD_GORY, "(<) %s(timeout=%ld) acquired slot (rank=%d/%d)\n",
		__func__, opts->timeout_millis, local_rank, local_n_ranks);

	lock_active = 1;

	return 0;
}


static int mos_sysfs_unlock(__attribute__((unused)) struct lock_options_t *opts)
{

	YOD_LOG(YOD_GORY, "(>) %s() fd=%d", __func__, lock_fd);

	if (lock_fd != -1) {
		if (flock(lock_fd, LOCK_UN) != 0)
			YOD_LOG(YOD_WARN, "Could not release lock on \"%s\" (%s)", MOS_SYSFS_ROOT, strerror(errno));
		if (close(lock_fd) != 0)
			YOD_LOG(YOD_WARN, "Could not close \"%s\" (%s)", MOS_SYSFS_ROOT, strerror(errno));
		lock_fd = -1;
	}

	YOD_LOG(YOD_GORY, "(<) %s() fd=%d", __func__, lock_fd);

	return 0;
}

static int mos_combo_unlock(struct lock_options_t *opts)
{
	int local_rank = -1, local_n_ranks = -1, next_rank;
	int flags = O_WRONLY, mode = 0, fd;
	char seq_file[256];
	char *extra_info = "";

	YOD_LOG(YOD_GORY, "(>) %s()", __func__);

	/* Don't unlock if we have not yet locked or if we have already unlocked */
	if (!lock_active)
		goto out;

	/* Avoid recursive unlocks */
	lock_active = 0;

	if ((mos_get_local_rank(&local_rank, &local_n_ranks) < 0) ||
	    opts->layout == YOD_RANK_DISABLE)
		return mos_sysfs_unlock(opts);

	/* The last rank cleans up.  All others update the sequencing file
	 * to indicate the next rank to proceed.  If the cleanup fails,
	 * we will issue a warning and continue.  Rank 0 may have to create
	 * the file, and does so by making the file globally read/write.
	 */

	local_rank_sequence_file_path(seq_file, sizeof(seq_file));

	next_rank = mos_next_rank(local_rank, local_n_ranks, opts);

	if (next_rank == -1) {
		if (unlink(seq_file))
			YOD_LOG(YOD_WARN,
				"Could not remove local lock file (%s).",
				seq_file);
	} else {
		if (local_rank == 0) {
			/* The first rank will create the file.  We use the EXCL
			 * flag to ensure that the file did not already exist.
			 */

			flags += O_CREAT | O_EXCL;
			mode =	S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP |
				S_IROTH | S_IWOTH;
		}

		fd = open(seq_file, flags, mode);

		if (fd < 0) {

			if (local_rank == 0) {
				if (unlink(seq_file))
					extra_info = "Remove lockfile and restart.";
				else
					extra_info = "Cancel this job and restart.";
			}

			yod_abort(-EBUSY,
				  "%s local lock file (%s).  %s",
				  local_rank ? "Missing" : "Stale",
				  seq_file, extra_info);
		}

		if (write(fd, &next_rank, sizeof(int)) != sizeof(int)) {
			yod_abort(-EBUSY,
				  "Could not update local lock file (%s).",
				  seq_file);
		}

		close(fd);
	}

 out:
	YOD_LOG(YOD_GORY, "(<) %s()", __func__);
	return 0;
}

static int mos_lwkcpus_sequence_request(char *layout)
{
	return mos_sysfs_write(MOS_SYSFS_LWKCPUS_SEQUENCE,
			       layout, strlen(layout));
}

static int mos_set_lwkmem_mempolicy_info(char *mempolicy_info, size_t len)
{
	return mos_sysfs_write(MOS_SYSFS_LWKMEM_MEMPOLICY_INFO,
			       mempolicy_info, len);
}

static int mos_set_options(char *options, size_t len)
{
	return mos_sysfs_write(MOS_SYSFS_LWK_OPTIONS, options, len);
}

static bool mos_get_mos_view(char *mos_view, size_t len)
{
	int nread = mos_sysfs_read(PROC_MOS_VIEW, mos_view, len);

	if (nread > 0 && nread <= (int) len) {
		char *c = strchr(mos_view, '\n');

		if (c)
			*c = '\0';
		return true;
	}
	return false;
}

static bool mos_set_mos_view(char *mos_view)
{
	return mos_sysfs_write(PROC_MOS_VIEW, mos_view, strlen(mos_view)) == 0;
}

static void mos_get_lwk_processes(pid_t *lwkprocs, size_t *n)
{
	size_t N = *n;
	char buff[4096], *tok, *str, *save;
	size_t nread;

	*n = 0;
	nread = mos_sysfs_read(MOS_SYSFS_LWK_PROCESSES, buff, sizeof(buff));

	if (nread <= 0 || nread > sizeof(buff))
		return;

	str = buff;
	while ((tok = strtok_r(str, ",", &save)) != 0) {
		if (*n == N)
			yod_abort(-EINVAL, "Buffer overrun parsing %s", MOS_SYSFS_LWK_PROCESSES);
		lwkprocs[(*n)++] = atoi(tok);
		str = 0;
	}
}

struct yod_plugin mos_plugin = {
	.get_designated_lwkcpus = mos_get_designated_lwkcpus,
	.get_reserved_lwk_cpus = mos_get_reserved_lwk_cpus,
	.request_lwk_cpus = mos_request_lwk_cpus,
	.get_designated_lwkgpus = mos_get_designated_lwkgpus,
	.get_reserved_lwk_gpus = mos_get_reserved_lwk_gpus,
	.get_gpu_usage_counts = mos_get_gpu_usage_counts,
	.get_gpu_numa = mos_get_gpu_numa,
	.request_lwk_gpus = mos_request_lwk_gpus,
	.set_util_threads = mos_set_util_threads,
	.map_cpu = mos_map_cpu,
	.get_designated_lwkmem = mos_get_designated_lwkmem,
	.get_reserved_lwkmem = mos_get_reserved_lwkmem,
	.request_lwk_memory = mos_request_lwk_memory,
	.get_numa_nodes_online = mos_get_numa_nodes_online,
	.lock = mos_combo_lock,
	.unlock = mos_combo_unlock,
	.get_distance_map = mos_get_distance_map,
	.lwkcpus_sequence_request = mos_lwkcpus_sequence_request,
	.set_options = mos_set_options,
	.set_lwkmem_mempolicy_info = mos_set_lwkmem_mempolicy_info,
	.get_mos_view = mos_get_mos_view,
	.set_mos_view = mos_set_mos_view,
	.get_lwk_processes = mos_get_lwk_processes,
};


/* The code below is useful in performing standalone testing and
 * debugging of the plugin.
 */

#ifdef TEST_MOS_PLUGIN

#include <stdarg.h>

int yod_verbosity = YOD_WARN;
void yod_abort(int rc, const char *format, ...)
{
	char buffer[4096];
	va_list args;

	va_start(args, format);
	vsprintf(buffer, format, args);
	fprintf(stderr, "[yod] %s (rc=%d)\n", buffer, rc);
	va_end(args);
	exit(rc);
}

void show(const char *label, mos_cpuset_t *set, int rc)
{
	printf("%-16s rc=%2d mask: %24s", label, rc, mos_cpuset_to_mask(set));
	printf(" list: %s\n", mos_cpuset_to_list_validate(set));
}

const char *T_LABELS[] = { "Core", "Tile", "Node", "Groups" };

void dump_map(enum map_elem_t typ)
{
	int cpu, nothing, t;

	for (t = 0; t < 256; t++) {
		nothing = 1;
		printf("%s %d : ", T_LABELS[typ], t);
		for (cpu = 0; cpu < 1024; cpu++) {
			if (mos_map_cpu(cpu, typ) == t) {
				printf("%d,", cpu);
				nothing = 0;
			}
		}
		printf("\n");
		if (nothing)
			break;
	}
}


int main(int argc, char **argv)
{
	mos_cpuset_t *lwkcpus, *lwkcpus_reserved, *request;
	int rc;
	int cpu, node, core, tile, nothing;

	dump_map(YOD_CORE);
	dump_map(YOD_TILE);
	dump_map(YOD_NODE);
	dump_map(YOD_MEM_GROUP);

	lwkcpus = mos_cpuset_alloc_validate();

	rc = mos_get_designated_lwkcpus(lwkcpus);
	show("lwkcpus", lwkcpus, rc);

	lwkcpus_reserved = mos_cpuset_alloc_validate();
	rc = mos_get_reserved_lwk_cpus(lwkcpus_reserved);
	show("lwkcpus_reserved", lwkcpus_reserved, rc);

	request = mos_cpuset_alloc_validate();

	mos_cpuset_xor(request, lwkcpus, lwkcpus_reserved);
	show("lwkcpus_request", request, 0);

	rc = mos_request_lwk_cpus(request);

	mos_get_designated_lwkcpus(lwkcpus);
	show("updated-lwkcpus", lwkcpus, rc);

	/* try again ... this one should fail */
	rc = mos_request_lwk_cpus(request);

	mos_get_designated_lwkcpus(lwkcpus);
	show("updated-lwkcpus", lwkcpus, rc);
	if (rc >= 0)
		printf("HEY >>> something doesnt look quite right.\n");

}

#endif

