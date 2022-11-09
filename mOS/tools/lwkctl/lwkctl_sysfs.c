/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2017, Intel Corporation.
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

#include "lwkctl.h"

int mos_sysfs_read(const char *file, char *buff, int len)
{
	FILE *fptr;
	int rc;

	LC_LOG(LC_GORY, "(>) %s(file=%s buff=%p:%d)",
		__func__, file, buff, len);

	fptr = fopen(file, "r");

	if (!fptr) {
		LC_LOG(LC_DEBUG, "Could not open \"%s\" for reading.", file);
		return -1;
	}

	rc = fread(buff, 1, len-1, fptr);
	buff[rc] = '\0';	/* force end-of-string */

	if (ferror(fptr) != 0) {
		LC_ERR("Could not read \"%s\" (rc = %d)", file, rc);
		rc = -1;
	}

	fclose(fptr);

	LC_LOG(LC_GORY, "(<) %s(file=%s buff=%p:\"%s\":%d)",
		__func__, file, buff, rc > 0 ? buff : "?", rc);
	return rc;
}

int mos_sysfs_write(const char *file, char *buff, int len)
{
	int fd;
	int rc = 0;

	LC_LOG(LC_GORY, "%s(file=%s buff=%p:\"%s\":%d)",
		__func__, file, buff, buff ? buff : "?", len);

	fd = open(file, O_WRONLY);

	if (fd == -1) {
		LC_ERR("Could not open \"%s\" for writing.", file);
		return -1;
	}

	rc = write(fd, buff, len);

	if (rc != len) {
		LC_LOG(LC_WARN, "Could not write to \"%s\" (rc = %d %s)",
		       file, rc, strerror(errno));
		rc--;
	}


	if (close(fd) == -1) {
		LC_LOG(LC_WARN, "Could not close \"%s\" (%s)",
		       file, strerror(errno));
		rc--;
	}

	LC_LOG(LC_GORY, "(<) %s(file=%s rc=%d", __func__, file, rc);

	return rc < 0 ? rc : 0;
}


int mos_sysfs_get_cpulist(const char *file, mos_cpuset_t *set)
{
	char buffer[4096];
	int rc;

	rc = mos_sysfs_read(file, buffer, sizeof(buffer));

	if ((rc == 0) || ((rc > 0) && (buffer[0] == '\n'))) {
		mos_cpuset_xor(set, set, set);
		rc = 0;
	} else if (rc > 0)
		rc = mos_parse_cpulist(buffer, set);

	LC_LOG(LC_GORY, "%s(\"%s\") -> \"%s\" (rc=%d)", __func__,
	       file, mos_cpuset_to_list(set), rc);
	return rc;

}

int mos_sysfs_put_cpulist(const char *file, mos_cpuset_t *set)
{
	int rc;
	char *list;

	list = mos_cpuset_to_list(set);

	rc = mos_sysfs_write(file, list, strlen(list));

	return (rc > 0) ? 0 : rc;
}

int mos_sysfs_get_vector(size_t *vec, int *n, const char *filen)
{
	char buffer[4096];
	char *tok, *buff, *save, *remainder, *copy;
	int rc, N;

	N = *n;  /* max size */
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
			LC_LOG(LC_WARN, "Buffer overrun parsing %s ->\"%s\"",
			       filen, buffer);
			rc = -1;
			goto out;
		}

		vec[(*n)++] = strtoul(tok, &remainder, 0);

		if (*remainder != '\0') {
			LC_LOG(LC_WARN, "Garbage in %s ->\"%s\" at offset %ld",
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

int mos_sysfs_set_lwkconfig(char *arg)
{
	int rc = -EINVAL;

	if (!arg)
		goto out;
	if (!strlen(arg))
		goto out;

	LC_LOG(LC_DEBUG, "Writing %s to lwk_config", arg);
	rc = mos_sysfs_write(MOS_SYSFS_LWKCONFIG, arg, strlen(arg));
out:
	return rc;
}

int mos_sysfs_set_linuxcpu(int cpu, bool online)
{
	char *buffer;
	size_t size;
	int rc;

	size = sizeof(char)*4096;
	buffer = (char *)malloc(size);

	if (!buffer)
		return -ENOMEM;

	snprintf(buffer, size, "%scpu%d/online", CPU_SYSFS, cpu);

	rc = mos_sysfs_write(buffer, online ? "1":"0", 1);

	free(buffer);
	return rc;
}

int mos_sysfs_access_linuxcpu(mos_cpuset_t *cs)
{
	int fd;
	size_t size;
	int rc = -1;
	int cpu;
	char *buffer;

	size = sizeof(char)*4096;
	buffer = (char *)malloc(size);

	if (!buffer)
		goto out;

	for (cpu = 0; cpu < mos_max_cpus(); cpu++) {
		if (mos_cpuset_is_set(cpu, cs)) {
			snprintf(buffer, size, "%scpu%d/online",
				 CPU_SYSFS, cpu);
			fd = open(buffer, O_WRONLY);
			if (fd < 0)
				goto out;
			close(fd);
		}
	}
	rc = 0;
out:
	if (buffer)
		free(buffer);
	return rc;
}

int mos_sysfs_int_classes()
{
	int types = 0;
	int ch;
	FILE *fptr;
	const char *file = PROC_INTERRUPTS;

	LC_LOG(LC_GORY, "(>) %s(file=%s)",
	 __func__, file);

	fptr = fopen(file, "r");

	if (!fptr) {
		LC_LOG(LC_DEBUG, "Could not open \"%s\" for reading.", file);
		return -1;
	}
	while ((ch = getc(fptr)) != EOF) {
		if (ch == ':') types++;
	}
	fclose(fptr);

	LC_LOG(LC_GORY, "(<) %s(file=%s):types=%d)",
		__func__, file, types);

	return types;
}

int mos_sysfs_set_lwk_interrupts(char *allowed_drivers)
{
	int rc;

	rc = mos_sysfs_write(MOS_SYSFS_LWK_INTERRUPTS, allowed_drivers,
				strlen(allowed_drivers));

	return (rc > 0) ? 0 : rc;
}

void show(int level, const char *label, mos_cpuset_t *set)
{
	LC_LOG(level, "%-16s %s", label, mos_cpuset_to_list(set));
}


