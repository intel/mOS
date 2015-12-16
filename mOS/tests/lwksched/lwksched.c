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

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include "lwksched.h"

int logging_level = LOG_INFO;

static int hex_char_to_int(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return -1;
}

static char *no_newline(char *s)
{
	s[strcspn(s, "\n")] = '\0';
	return s;
}

void log_msg(enum log_level lvl, const char *format, ...)
{
	static const char * const _PREFIX[] = {
		"FATAL", "E", "W", "I", "D", "*" };

	if (lvl <= logging_level) {
		char buffer[4096];
		time_t t;
		va_list args;

		time(&t);
		va_start(args, format);
		vsnprintf(buffer, sizeof(buffer), format, args);
		fprintf(stdout, "%s [%s] [%03d] [%ld] %s\n",
			no_newline(ctime(&t)),
			(lvl < ARRAY_SIZE(_PREFIX) ? _PREFIX[lvl] : "?"),
			sched_getcpu(),
			syscall(SYS_gettid),
			buffer);
		va_end(args);
	}

	if (lvl == LOG_FATAL)
		exit(-1);
}

int parse_mos_mask(cpu_set_t *set, int setsize, const char *path)
{
	FILE *fptr;
	char buffer[4096 + 1];
	int rc, i, cpu = 0;

	log_msg(LOG_DEBUG, "(>) %s file=%s", __func__, path);

	CPU_ZERO_S(setsize, set);

	fptr = fopen(path, "r");

	if (!fptr) {
		log_msg(LOG_ERR, "Could not open %s for reading. ", path);
		return -1;
	}

	rc = fread(buffer, 1, sizeof(buffer) - 1, fptr);

	if (rc < 0) {
		log_msg(LOG_ERR, "Could not read \"%s\" (rc = %ld)", path, rc);
		goto out;
	}

	buffer[rc] = '\0';

	log_msg(LOG_DEBUG, "Contents: %s (%d)", no_newline(buffer), rc);

	for (i = rc-1; i >= 0; i--) {

		int mask, j;

		if (buffer[i] == '\n' || buffer[i] == ',' || buffer[i] == '\0')
			continue;

		mask = hex_char_to_int(buffer[i]);

		if (mask < 0) {
			log_msg(LOG_ERR, "Invalid character @ %d : (%d) -> %c",
				i, buffer[i], buffer[i]);
			rc = -1;
			goto out;
		}

		for (j = 0; j < 4; j++, cpu++)
			if (mask & (1 << j))
				CPU_SET_S(cpu, setsize, set);

	}

	rc = 0;

 out:
	fclose(fptr);

	log_msg(LOG_DEBUG,
		"(<) %s file=%s set=%s rc=%d",
		__func__, path, cpuset_to_str(set, setsize, buffer,
					      sizeof(buffer)), rc);
	return rc;

}


char *cpuset_to_str(cpu_set_t *set, int setsize, char *buff, size_t buffsize)
{
	int i, offset;

	snprintf(buff, buffsize, "[%d] ", CPU_COUNT_S(setsize, set));
	for (i = 0; i < MAX_CPUS; i++) {
		if (CPU_ISSET_S(i, setsize, set)) {
			offset = strlen(buff);
			snprintf(buff + offset, buffsize - offset, "%d,", i);
		}
	}
	return buff;
}

char *get_affinity(char *buff, size_t buffsize)
{
	cpu_set_t *affinity;
	int setsize;

	affinity = CPU_ALLOC(MAX_CPUS);
	setsize = CPU_ALLOC_SIZE(MAX_CPUS);

	CPU_XOR_S(setsize, affinity, affinity, affinity);

	if (sched_getaffinity(0, setsize, affinity)) {
		log_msg(LOG_FATAL, "Could not obtain affinity: %s",
			strerror(errno));
	}

	cpuset_to_str(affinity, setsize, buff, buffsize);

	CPU_FREE(affinity);
	return buff;
}
