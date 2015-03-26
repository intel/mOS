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
#define REQ_LWKCPUS "lwkcpus_request"
#define LWKMEM "lwkmem"
#define LWKMEM_RESERVED "lwkmem_reserved"
#define LWKMEM_REQUEST "lwkmem_request"
#define SEQUENCE_REQUEST "lwkcpus_sequence"
#define LWK_UTIL_THREADS_REQUEST "lwk_util_threads"
#define LWKMEM_DOMAIN_INFO_REQUEST "lwkmem_domain_info"
#define LWK_OPTIONS "lwk_options"
#define DISTANCE_N "distance%d"
#define MAX_CPUS 512

static char *tst_get_file_name(const char *name, char *buffer)
{
	sprintf(buffer, "/tmp/%s/yod/%s", getenv("USER"), name);
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

static void tst_read(const char *filen, yod_cpuset_t *set)
{
	char buffer[4096];
	int n;

	n = tst_read_raw(filen, buffer, sizeof(buffer));

	if (n < 0)
		yod_abort(-1, "Could not read test file %s", filen);

	if (buffer[0] == ' ')
		yod_cpuset_xor(set, set, set);
	else if (yod_parse_cpulist(buffer, set))
		yod_abort(-1, "Could not parse test file \"%s\" -> \"%s\" [%ld]", filen,
		      buffer, n);
}

static void tst_write(const char *filen, yod_cpuset_t *set)
{
	size_t n;
	FILE *f;

	f = fopen(filen, "w");
	if (!f)
		yod_abort(-1, "Could not open test file %s", filen);

	yod_cpuset_to_list(set);

	n = fwrite(set->_buffer, 1, strlen(set->_buffer) + 1, f);
	if (n == 0)
		yod_abort(-1, "Could not write test file %s", filen);

	fclose(f);
}

static int tst_get_designated_lwkcpus(yod_cpuset_t *set)
{
	char buffer[256];
	tst_read(tst_get_file_name(LWKCPUS, buffer), set);
	return 0;
}

static void _tst_get_memvec(size_t *mem, int *n, const char *path)
{
	char buffer[4096];
	char *tok, *buff, *save;
	int N = *n; /* max size */

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

static void tst_get_designated_lwkmem(size_t *mem, int *n)
{
	char buffer[4096];

	_tst_get_memvec(mem, n, tst_get_file_name(LWKMEM, buffer));
}

static void tst_get_reserved_lwkmem(size_t *mem, int *n)
{
	char buffer[4096];

	_tst_get_memvec(mem, n, tst_get_file_name(LWKMEM_RESERVED, buffer));
}

static int tst_get_reserved_lwk_cpus(yod_cpuset_t *set)
{
	char buffer[256];

	tst_read(tst_get_file_name(LWKCPUS_RESERVED, buffer), set);
	return 0;
}

//#define USE_MASKS

static int tst_request_cpus(yod_cpuset_t *set, const char *target)
{
	int rc = 0;
	yod_cpuset_t *reserved, *lwkcpus, *and;
	char buffer[256];

	lwkcpus = yod_cpuset_alloc();
	reserved = yod_cpuset_alloc();
	and = yod_cpuset_alloc();

	tst_read(tst_get_file_name(LWKCPUS, buffer), lwkcpus);

	/*
	 * Requesting a non-LWK CPU is an error
	 */

	if (!yod_cpuset_is_subset(set, lwkcpus)) {
		rc = -EINVAL;
		YOD_LOG(YOD_WARN, "[%s:%d] non-LWK CPU(s) requested : 0x%20s", __func__, __LINE__, yod_cpuset_to_mask(set));
		YOD_LOG(YOD_WARN, "[%s:%d] non-LWK CPU(s) requested : %s", __func__, __LINE__, yod_cpuset_to_list(set));
		goto out;
	}

	tst_read(tst_get_file_name(LWKCPUS_RESERVED, buffer), reserved);
	yod_cpuset_and(and, reserved, set);

	if (!yod_cpuset_is_empty(and)) {
		rc = -EBUSY;
		YOD_LOG(YOD_WARN, "[%s:%d] busy compute CPU(s) requested : 0x%20s", __func__, __LINE__, yod_cpuset_to_mask(and));
		goto out;
	}

	tst_read(tst_get_file_name(target, buffer), reserved);
	yod_cpuset_or(reserved, reserved, set);
	tst_write(tst_get_file_name(target, buffer), reserved);
	rc = 0;

 out:
	yod_cpuset_free(reserved);
	yod_cpuset_free(and);
	yod_cpuset_free(lwkcpus);

	return rc;
}

static int tst_request_lwk_cpus(yod_cpuset_t *set)
{
	return tst_request_cpus(set, LWKCPUS_RESERVED);
}

struct {
	int elems[YOD_NUM_MAP_ELEMS];
} _CPU_INFO[MAX_CPUS];

static int tst_map_cpu(int cpu, enum map_elem_t typ)
{
	if ((cpu < 0) || (cpu >= (int)ARRAY_SIZE(_CPU_INFO)))
		return -1;
	return _CPU_INFO[cpu].elems[typ];
}

static int tst_request_lwk_memory(size_t *mem, int n)
{
	size_t desig[1024], resvd[1024];
	int i, n_tmp = ARRAY_SIZE(desig);
	char buffer[4096], path[4096];

	assert(n < (int)ARRAY_SIZE(desig));

	_tst_get_memvec(desig, &n_tmp, tst_get_file_name(LWKMEM, path));
	assert(n_tmp == n);
	_tst_get_memvec(resvd, &n_tmp, tst_get_file_name(LWKMEM_RESERVED, path));
	assert(n_tmp == n);

	buffer[0] = 0;

	/* Note that we do not write to an auxiliary request file (like the
	 * real mOS), but rather just directly updated the reserved status.
	 */
	for (i = 0; i < n; i++) {
		if (mem[i] > (desig[i] - resvd[i]))
			return -EBUSY;
		sprintf(buffer + strlen(buffer), "%lu ", resvd[i] + mem[i]);
	}
	tst_write_raw(tst_get_file_name(LWKMEM_RESERVED, path), buffer, strlen(buffer)+1);
	return 0;
}

static int lock_fd = -1;

static int tst_lock(unsigned long timeout_millis)
{
	char buffer[256];

	lock_fd = open(tst_get_file_name("", buffer), O_RDONLY);

	if (lock_fd == -1) {
		YOD_LOG(YOD_WARN, "Could not open %s for locking.", tst_get_file_name("", buffer));
		goto lock_out;
	}

	long retries = timeout_millis / 10;

	if (retries < 2)
		retries = 2;

	while (retries > 0) {

		if (flock(lock_fd, LOCK_EX | LOCK_NB) == 0)
			goto lock_out;

		usleep(10 * 1000);
		retries--;
	}

	YOD_ERR("Could not lock %s.", tst_get_file_name("", buffer));
	close(lock_fd);
	lock_fd = -1;

 lock_out:
	return (lock_fd == -1) ? -1 : 0;

}

static int tst_unlock(void)
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

static void tst_get_distance_map(int nid, size_t *dist, int *n)
{
	char filen[128];
	char path[256];

	sprintf(filen, DISTANCE_N, nid);
	_tst_get_memvec(dist, n, tst_get_file_name(filen, path));
}

static int tst_set_util_threads(int num_util_threads)
{
	char path[256];
	char buff[16];

	if (num_util_threads < 0) {
		YOD_LOG(YOD_WARN,
			"[%s:%d] Attempt to set negative value for utility threads",
			__func__, __LINE__);
		return -EINVAL;
	}

	snprintf(buff, sizeof(buff), "%d", num_util_threads);
	tst_write_raw(tst_get_file_name(LWK_UTIL_THREADS_REQUEST, path),
		      buff, strlen(buff));
	return 0;
}

static int tst_lwkcpus_sequence_request(char *layout)
{
	char path[256];

	tst_write_raw(tst_get_file_name(SEQUENCE_REQUEST, path),
		      layout, strlen(layout));
	return 0;
}
static int tst_set_options(char *options)
{
	char path[256];

	tst_write_raw(tst_get_file_name(LWK_OPTIONS, path),
		      options, strlen(options) + 1);
	return 0;

}


static int tst_set_lwkmem_domain_info(char *info)
{
	char path[256];

	tst_write_raw(tst_get_file_name(LWKMEM_DOMAIN_INFO_REQUEST, path),
		      info, strlen(info) + 1);
	return 0;
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
	.set_lwkmem_domain_info = tst_set_lwkmem_domain_info,
};

struct yod_plugin *init_tst_plugin(const char *file)
{
	static const char HEADER[] = "CPU,Core,Tile,Node\n";

	char line[4096], path[4096];
	FILE *f;
	char *tok, *buff, *save;
	yod_cpuset_t *set;
	int i, g;

	f = fopen(file, "r");
	assert(f);

	/* all -1's ... */
	memset(_CPU_INFO, -1, sizeof(_CPU_INFO));

	if (fgets(line, sizeof(line), f) != 0)
		assert(strncmp(line, HEADER, sizeof(HEADER)-1) == 0);
	while (fgets(line, sizeof(line), f) != 0) {
		int n, cpu, core, tile, node;

		n = sscanf(line, "%d,%d,%d,%d\n", &cpu, &core, &tile, &node);
		assert(n == 4);
		assert(cpu <= MAX_CPUS);

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

	if (tst_read_raw(tst_get_file_name("lwkmem_groups", path), line, sizeof(line)) <= 0)
		yod_abort(-1, "Could not read memory group descriptor (%s)", path);

	set = yod_cpuset_alloc();
	buff = line;
	g = -1;

	while ((tok = strtok_r(buff, " ", &save)) != NULL) {

		g++;
		buff = NULL;

		if (yod_parse_cpulist(tok, set))
			yod_abort(-1, "Could not parse entry (\"%s\") in lwkmem_groups.", tok);

		for (i = yod_cpuset_biggest(set); i >= 0; i--)
			if (yod_cpuset_is_set(i, set))
				_CPU_INFO[i].elems[YOD_MEM_GROUP] = g;

	}

	yod_cpuset_free(set);
	return &tst_plugin;
}
