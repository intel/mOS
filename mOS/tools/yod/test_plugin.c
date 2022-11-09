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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <stdbool.h>

#include "yod.h"
#include "yod_debug.h"

#define LWKCPUS "lwkcpus"
#define LWKCPUS_RESERVED "lwkcpus_reserved"
#define LWKGPUS "lwkgpus"
#define LWKGPUS_RESERVED "lwkgpus_reserved"
#define LWKGPUS_USAGE_COUNT "lwkgpus_usage_count"
#define LWKGPUS_NUMA "lwkgpus_numa"
#define REQ_LWKCPUS "lwkcpus_request"
#define REQ_LWKGPUS "lwkgpus_request"
#define LWKMEM "lwkmem"
#define LWKMEM_RESERVED "lwkmem_reserved"
#define LWKMEM_REQUEST "lwkmem_request"
#define SEQUENCE_REQUEST "lwkcpus_sequence"
#define LWK_UTIL_THREADS_REQUEST "lwk_util_threads"
#define LWKMEM_MEMPOLICY_INFO_REQUEST "lwkmem_mempolicy_info"
#define LWK_OPTIONS "lwk_options"
#define DISTANCE_N "distance%zd"
#define MAX_CPUS 1024

static int str_to_long(char *in_str, long int *out_int)
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


static char *tst_get_file_name(const char *name, char *buffer, size_t len)
{
	int n = snprintf(buffer, len, "/tmp/%s/yod/%s", getenv("USER"), name);

	if (n >= (int)len)
		yod_abort(-1, "Buffer overflow constructing test file %s", name);

	return buffer;
}

static int tst_read_raw(const char *filen, char *buffer, size_t length)
{
	size_t n;
	FILE *f;

	f = fopen(filen, "r");

	if (!f)
		yod_abort(-1, "Could not open test file %s", filen);

	n = fread(buffer, 1, length, f);

	if (n == 0)
		yod_abort(-1, "Could not read test file %s", filen);
	else if (n < length)
		buffer[n] = 0;
	else
		yod_abort(-1, "Insufficient buffer space in %s", __func__);

	fclose(f);
	return n;
}

static void tst_write_raw(const char *filen, char *buffer, size_t length)
{
	size_t n;
	FILE *f;

	f = fopen(filen, "w");
	if (!f)
		yod_abort(-1, "Could not open test file %s", filen);

	n = fwrite(buffer, 1, length, f);
	if (n == 0)
		yod_abort(-1, "Could not write test file %s", filen);

	fclose(f);
}

static void tst_read(const char *filen, mos_cpuset_t *set)
{
	char buffer[4096];
	int n;

	n = tst_read_raw(filen, buffer, sizeof(buffer));

	if (n < 0)
		yod_abort(-1, "Could not read test file %s", filen);

	if (buffer[0] == ' ')
		mos_cpuset_xor(set, set, set);
	else if (mos_parse_cpulist(buffer, set))
		yod_abort(-1,
			  "Could not parse test file \"%s\" -> \"%s\" [%zd]",
			  filen, buffer, n);
}

static void tst_write(const char *filen, mos_cpuset_t *set)
{
	size_t n;
	FILE *f;

	f = fopen(filen, "w");
	if (!f)
		yod_abort(-1, "Could not open test file %s", filen);

	mos_cpuset_to_list_validate(set);

	n = fwrite(set->_buffer, 1, strlen(set->_buffer) + 1, f);
	if (n == 0)
		yod_abort(-1, "Could not write test file %s", filen);

	fclose(f);
}

static int tst_get_designated_lwkcpus(mos_cpuset_t *set)
{
	char buffer[256];
	tst_read(tst_get_file_name(LWKCPUS, buffer, sizeof(buffer)), set);
	return 0;
}

static int tst_get_designated_lwkgpus(mos_cpuset_t *set)
{
	char buffer[256];
	tst_read(tst_get_file_name(LWKGPUS, buffer, sizeof(buffer)), set);
	return 0;
}

static void _tst_get_memvec(size_t *mem, size_t *n, const char *path)
{
	char buffer[4096];
	char *tok, *buff, *save;
	size_t N = *n; /* max size */

	*n = tst_read_raw(path, buffer, sizeof(buffer));
	assert(*n > 0);

	*n = 0;
	buff = buffer;
	while ((tok = strtok_r(buff, " ", &save)) != 0) {
		if (*n == N)
			yod_abort(-EINVAL, "Buffer overrun in %s", __func__);
		mem[(*n)++] = strtoul(tok, 0, 0);
		buff = NULL;
	}
}

static void tst_get_designated_lwkmem(size_t *mem, size_t *n)
{
	char buffer[4096];

	_tst_get_memvec(mem, n, tst_get_file_name(LWKMEM, buffer, sizeof(buffer)));
}

static void tst_get_reserved_lwkmem(size_t *mem, size_t *n)
{
	char buffer[4096];

	_tst_get_memvec(mem, n, tst_get_file_name(LWKMEM_RESERVED, buffer, sizeof(buffer)));
}

static int tst_get_reserved_lwk_cpus(mos_cpuset_t *set)
{
	char buffer[256];

	tst_read(tst_get_file_name(LWKCPUS_RESERVED, buffer, sizeof(buffer)), set);
	return 0;
}

static int tst_get_reserved_lwk_gpus(mos_cpuset_t *set)
{
	char buffer[256];

	tst_read(tst_get_file_name(LWKGPUS_RESERVED, buffer, sizeof(buffer)), set);
	return 0;
}

static int tst_get_gpu_usage_counts(int *array_of_counts, int num_counts)
{
	char fbuffer[256];
	char buffer[256];
	char *tok, *p;
	int i = 0;
	long usage_count;

	if (tst_read_raw(tst_get_file_name(LWKGPUS_USAGE_COUNT, fbuffer, sizeof(fbuffer)), buffer, sizeof(buffer)) <= 0)
		yod_abort(-1, "Could not read lwkgpus usage count information (%s)", fbuffer);
	/* Parse string of commas-seperated integers */
	p = tok = buffer;

	while ((tok = strsep(&p, ",")) && (i < num_counts)) {
		if (str_to_long(tok, &usage_count)) {
			YOD_LOG(YOD_WARN, "Failed to convert usage count string(%s) to integer", tok);
			return -1;
		}
		array_of_counts[i++] = usage_count;
	}
	return 0;
}

static int tst_get_gpu_numa(int *array_of_nids, int num_nids)
{
	char fbuffer[256];
	char buffer[256];
	char *tok, *p;
	int i = 0;
	long nid;

	if (tst_read_raw(tst_get_file_name(LWKGPUS_NUMA, fbuffer, sizeof(fbuffer)), buffer, sizeof(buffer)) <= 0)
		yod_abort(-1, "Could not read lwkgpus numa information (%s)", fbuffer);
	/* Parse string of commas-seperated integers */
	p = tok = buffer;

	while ((tok = strsep(&p, ",")) && (i < num_nids)) {
		if (str_to_long(tok, &nid)) {
			YOD_LOG(YOD_WARN, "Failed to convert numa string(%s) to integer", tok);
			return -1;
		}
		array_of_nids[i++] = nid;
	}
	return 0;
}


//#define USE_MASKS

static int tst_request_lwk_cpus(mos_cpuset_t *set)
{
	int rc = 0;
	mos_cpuset_t *reserved, *lwkcpus, *and;
	char buffer[256];

	lwkcpus = mos_cpuset_alloc_validate();
	reserved = mos_cpuset_alloc_validate();
	and = mos_cpuset_alloc_validate();

	tst_read(tst_get_file_name(LWKCPUS, buffer, sizeof(buffer)), lwkcpus);

	/*
	 * Requesting a non-LWK CPU is an error
	 */

	if (!mos_cpuset_is_subset(set, lwkcpus)) {
		rc = -EINVAL;
		YOD_LOG(YOD_WARN, "[%s:%d] non-LWK CPU(s) requested : 0x%20s",
			__func__, __LINE__,
			mos_cpuset_to_mask(set));
		YOD_LOG(YOD_WARN, "[%s:%d] non-LWK CPU(s) requested : %s",
			__func__, __LINE__,
			mos_cpuset_to_list_validate(set));
		goto out;
	}

	tst_read(tst_get_file_name(LWKCPUS_RESERVED, buffer, sizeof(buffer)), reserved);
	mos_cpuset_and(and, reserved, set);

	if (!mos_cpuset_is_empty(and)) {
		rc = -EBUSY;
		YOD_LOG(YOD_WARN,
			"[%s:%d] busy compute CPU(s) requested : 0x%20s",
			__func__, __LINE__,
			mos_cpuset_to_mask(and));
		goto out;
	}

	tst_write(tst_get_file_name(REQ_LWKCPUS, buffer, sizeof(buffer)), set);

	tst_read(tst_get_file_name(LWKCPUS_RESERVED, buffer, sizeof(buffer)), reserved);
	mos_cpuset_or(reserved, reserved, set);
	tst_write(tst_get_file_name(LWKCPUS_RESERVED, buffer, sizeof(buffer)), reserved);
	rc = 0;

 out:
	mos_cpuset_free(reserved);
	mos_cpuset_free(and);
	mos_cpuset_free(lwkcpus);

	return rc;
}

static int tst_request_lwk_gpus(mos_cpuset_t *set, char *ze_mask)
{
	int rc = 0;
	mos_cpuset_t *reserved, *lwkgpus, *and;
	char buffer[256];

	lwkgpus = mos_cpuset_alloc_validate();
	reserved = mos_cpuset_alloc_validate();
	and = mos_cpuset_alloc_validate();

	tst_read(tst_get_file_name(LWKGPUS, buffer, sizeof(buffer)), lwkgpus);

	/*
	 * Requesting a non-LWK GPU is an error
	 */

	if (!mos_cpuset_is_subset(set, lwkgpus)) {
		rc = -EINVAL;
		YOD_LOG(YOD_WARN, "[%s:%d] non-LWK GPU(s) requested : 0x%20s",
			__func__, __LINE__,
			mos_cpuset_to_mask(set));
		YOD_LOG(YOD_WARN, "[%s:%d] non-LWK GPU(s) requested : %s",
			__func__, __LINE__,
			mos_cpuset_to_list_validate(set));
		goto out;
	}

	tst_read(tst_get_file_name(LWKGPUS_RESERVED, buffer, sizeof(buffer)), reserved);
	mos_cpuset_and(and, reserved, set);

	if (!mos_cpuset_is_empty(and)) {
		YOD_LOG(YOD_WARN,
			"[%s:%d] in-use GPU(s) requested : 0x%20s. (allowed)",
			__func__, __LINE__,
			mos_cpuset_to_mask(and));
	}

	tst_write(tst_get_file_name(REQ_LWKGPUS, buffer, sizeof(buffer)), set);

	tst_read(tst_get_file_name(LWKGPUS_RESERVED, buffer, sizeof(buffer)), reserved);
	mos_cpuset_or(reserved, reserved, set);
	tst_write(tst_get_file_name(LWKGPUS_RESERVED, buffer, sizeof(buffer)), reserved);
	YOD_LOG(YOD_WARN,"setenv ZE_AFFINITY=%s", ze_mask);
	rc = 0;

 out:
	mos_cpuset_free(reserved);
	mos_cpuset_free(and);
	mos_cpuset_free(lwkgpus);

	return rc;
}

struct {
	int elems[YOD_NUM_MAP_ELEMS];
} _CPU_INFO[MAX_CPUS];

static ssize_t tst_map_cpu(size_t cpu, enum map_elem_t typ)
{
	if (cpu >= (int)ARRAY_SIZE(_CPU_INFO))
		return -1;
	return _CPU_INFO[cpu].elems[typ];
}

static int tst_request_lwk_memory(size_t *mem, size_t n)
{
	size_t i, desig[1024], resvd[1024], n_tmp = ARRAY_SIZE(desig);
	char buffer[4096], req_buffer[4096], path[4096];

	assert(n < (int)ARRAY_SIZE(desig));

	_tst_get_memvec(desig, &n_tmp, tst_get_file_name(LWKMEM, path, sizeof(path)));
	assert(n_tmp == n);
	_tst_get_memvec(resvd, &n_tmp, tst_get_file_name(LWKMEM_RESERVED, path, sizeof(path)));
	assert(n_tmp == n);

	buffer[0] = 0;
	req_buffer[0] = 0;

	/* Note that we do not write to an auxiliary request file (like the
	 * real mOS), but rather just directly updated the reserved status.
	 */
	for (i = 0; i < n; i++) {
		if (mem[i] > (desig[i] - resvd[i]))
			return -EBUSY;
		STR_APPEND(buffer, sizeof(buffer), "%zu ", resvd[i] + mem[i]);
		STR_APPEND(req_buffer, sizeof(req_buffer), "%zu ", mem[i]);
	}

	tst_write_raw(tst_get_file_name(LWKMEM_RESERVED, path, sizeof(path)), buffer, strlen(buffer)+1);
	tst_write_raw(tst_get_file_name(LWKMEM_REQUEST, path, sizeof(path)), req_buffer, strlen(req_buffer)+1);
	return 0;
}

static int lock_fd = -1;

static int tst_lock(struct lock_options_t *opts)
{
	char buffer[256];

	lock_fd = open(tst_get_file_name("", buffer, sizeof(buffer)), O_RDONLY);

	if (lock_fd == -1) {
		YOD_LOG(YOD_WARN, "Could not open %s for locking.", tst_get_file_name("", buffer, sizeof(buffer)));
		goto lock_out;
	}

	long retries = opts->timeout_millis / 10;

	if (retries < 2)
		retries = 2;

	while (retries > 0) {

		if (flock(lock_fd, LOCK_EX | LOCK_NB) == 0)
			goto lock_out;

		usleep(10 * 1000);
		retries--;
	}

	YOD_ERR("Could not lock %s.", tst_get_file_name("", buffer, sizeof(buffer)));
	close(lock_fd);
	lock_fd = -1;

 lock_out:
	return (lock_fd == -1) ? -1 : 0;

}

static int tst_unlock(__attribute__((unused)) struct lock_options_t *opts)
{

	if (lock_fd != -1) {
		if (flock(lock_fd, LOCK_UN) != 0)
			YOD_ERR("Could not unlock fd=%d.", lock_fd);

		if (close(lock_fd) != 0)
			YOD_ERR("Could not close lock file fd=%d.", lock_fd);
		lock_fd = -1;
	}

	return -1;
}

static void tst_get_distance_map(size_t nid, size_t *dist, size_t *n)
{
	char filen[128];
	char path[256];

	sprintf(filen, DISTANCE_N, nid);
	_tst_get_memvec(dist, n, tst_get_file_name(filen, path, sizeof(path)));
}

static int tst_set_util_threads(size_t num_util_threads)
{
	char path[256];
	char buff[16];

	snprintf(buff, sizeof(buff), "%zd", num_util_threads);
	tst_write_raw(tst_get_file_name(LWK_UTIL_THREADS_REQUEST, path, sizeof(path)),
		      buff, strlen(buff));
	return 0;
}

static int tst_lwkcpus_sequence_request(char *layout)
{
	char path[256];

	tst_write_raw(tst_get_file_name(SEQUENCE_REQUEST, path, sizeof(path)),
		      layout, strlen(layout));
	return 0;
}

static int tst_set_options(char *options, size_t len)
{
	char path[256];
	size_t i;

	/* transform the null characters to new line characters
	 * before writing to the plugin's options file.  Note
	 * that there are two null chars at the end, so we stop
	 * one byte early:
	 */

	for (i = 0; i < len - 1; i++)
		if (options[i] == '\0')
			options[i] = '\n';

	tst_write_raw(tst_get_file_name(LWK_OPTIONS, path, sizeof(path)),
		      options, len);
	return 0;
}

static int tst_set_lwkmem_mempolicy_info(char *info, size_t len)
{
	char path[256];

	tst_write_raw(tst_get_file_name(LWKMEM_MEMPOLICY_INFO_REQUEST, path, sizeof(path)),
		      info, len);
	return 0;
}

static void tst_get_lwk_processes(__attribute__((unused)) pid_t *procs, size_t *n)
{
	YOD_LOG(YOD_WARN, "%s always returns an empty set.", __func__);
	*n = 0;
}

static struct yod_plugin tst_plugin = {
	.get_designated_lwkcpus = tst_get_designated_lwkcpus,
	.get_reserved_lwk_cpus = tst_get_reserved_lwk_cpus,
	.request_lwk_cpus = tst_request_lwk_cpus,
	.set_util_threads = tst_set_util_threads,
	.map_cpu = tst_map_cpu,
	.get_designated_lwkmem = tst_get_designated_lwkmem,
	.request_lwk_memory = tst_request_lwk_memory,
	.get_reserved_lwkmem = tst_get_reserved_lwkmem,
	.lock = tst_lock,
	.unlock = tst_unlock,
	.get_distance_map = tst_get_distance_map,
	.lwkcpus_sequence_request = tst_lwkcpus_sequence_request,
	.set_options = tst_set_options,
	.set_lwkmem_mempolicy_info = tst_set_lwkmem_mempolicy_info,
	.get_lwk_processes = tst_get_lwk_processes,
	.get_designated_lwkgpus = tst_get_designated_lwkgpus,
	.get_reserved_lwk_gpus = tst_get_reserved_lwk_gpus,
	.request_lwk_gpus = tst_request_lwk_gpus,
	.get_gpu_usage_counts = tst_get_gpu_usage_counts,
	.get_gpu_numa = tst_get_gpu_numa,
};

struct yod_plugin *init_tst_plugin(const char *file)
{
	static const char HEADER[] = "CPU,Core,Tile,Node\n";
	static enum mem_group_t mem_groups_order[] = {
		YOD_DRAM, YOD_HBM, YOD_NVRAM};

	char line[4096], path[4096], buffer[4096];
	FILE *f;
	char *tok, *buff, *save, *p;
	mos_cpuset_t *set;
	int i, g, gpuid;

	f = fopen(file, "r");
	assert(f);


	/* all -1's ... */
	memset(_CPU_INFO, -1, sizeof(_CPU_INFO));

	if (fgets(line, sizeof(line), f) == line)
		assert(strncmp(line, HEADER, sizeof(HEADER)) == 0);
	while (fgets(line, sizeof(line), f) == line) {
		int n, cpu, core, tile, node;

		n = sscanf(line, "%d,%d,%d,%d\n", &cpu, &core, &tile, &node);
		assert(n == 4);
		assert(cpu >= 0 && cpu <= MAX_CPUS);

		_CPU_INFO[cpu].elems[YOD_CORE] = core;
		_CPU_INFO[cpu].elems[YOD_NODE] = node;
		_CPU_INFO[cpu].elems[YOD_TILE] = tile;

		YOD_LOG(YOD_GORY, "(*) %s CPU:%d CORE:%d TILE:%d NODE:%d",
			__func__,
			cpu,
			_CPU_INFO[cpu].elems[YOD_CORE],
			_CPU_INFO[cpu].elems[YOD_TILE],
			_CPU_INFO[cpu].elems[YOD_NODE]);
	}

	/* Process the test plugin's memory group descriptor. */

	if (tst_read_raw(tst_get_file_name("lwkmem_groups", path, sizeof(path)), line, sizeof(line)) <= 0)
		yod_abort(-1, "Could not read memory group descriptor (%s)", path);

	set = mos_cpuset_alloc_validate();
	buff = line;
	g = -1;

	while ((tok = strtok_r(buff, " ", &save)) != NULL) {

		g++;
		buff = NULL;

		if ((size_t)g >= ARRAY_SIZE(mem_groups_order))
			yod_abort(-1, "Too many entries in %s\n",
				  tst_get_file_name("lwkmem_groups", path, sizeof(path)));

		/* A "-1" indicates that this group is not present. */

		if (tok && strncmp(tok, "-1", 2)  == 0)
			continue;

		if (mos_parse_cpulist(tok, set))
			yod_abort(-1, "Could not parse entry (\"%s\") in lwkmem_groups.", tok);

		for (i = mos_cpuset_biggest(set); i >= 0; i--)
			if (mos_cpuset_is_set(i, set))
				_CPU_INFO[i].elems[YOD_MEM_GROUP] = mem_groups_order[g];

	}

	gpuid = 0;

	/* Read the test plugins nids file for designated GPUs */
	if (tst_read_raw(tst_get_file_name(LWKGPUS_NUMA, path, sizeof(path)), buffer, sizeof(buffer)) <= 0)
		yod_abort(-1, "Could not read lwkgpus numa information (%s)", path);

	/*
	 *  Walk through the comma-separated list of nids indexed by gpu id
	 *  and set the cpu map
	 */
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
		if (gpuid >= MOS_MAX_GPU_TILES) {
			yod_abort(-1, "Exceeded maximum supported number of GPUs (%d.", MOS_MAX_GPU_TILES);
		}
		if (nid >  YOD_MAX_NIDS) {
			yod_abort(-1, "Numa id from lwkgpus_numa out of range (%d.", nid);
		}
		_CPU_INFO[gpuid++].elems[YOD_NODE_GPU] = nid;
	}

	fclose(f);
	mos_cpuset_free(set);
	return &tst_plugin;
}
