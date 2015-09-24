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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

static int get_sysfs_data(char *buffer, size_t len, const char *sysfsn)
{
	char *fname;
	FILE *f;
	int r = 0;

	if (getenv("YOD_TST_PLUGIN"))
		asprintf(&fname, "/tmp/%s/yod/%s", getenv("USER"), sysfsn);
	else
		asprintf(&fname, "/sys/kernel/mOS/%s", sysfsn);

	f = fopen(fname, "r");
	if (!f) {
		perror(fname);
		goto err_fopen;
	}

	r = fread(buffer, 1, len, f);
	if (r < 0) {
		r = 0;
		perror(fname);
		goto err_fread;
	}

	buffer[r] = '\0';

err_fread:
	fclose(f);
err_fopen:
	free(fname);
	return r;
}

int main(int argc, char **argv)
{
	static const char * const files[] = {
		"lwkcpus_reserved",
		"lwkmem_reserved",
	};

	static char buf[4096];

	int ncpus = CPU_SETSIZE;
	size_t size;
	cpu_set_t *mask = NULL;
	int r, f, i;
	size_t n;

	if (argc >= 2 && strcmp(argv[1], "wait") == 0) {
		fprintf(stderr, "[%d] Waiting...\n", getpid());
		printf("ready\n");
		fflush(stdout);
		fgets(buf, sizeof(buf), stdin);
		fprintf(stderr, "[%d] Finishing...\n", getpid());
	}

	do {
		if (mask)
			CPU_FREE(mask);
		size = CPU_ALLOC_SIZE(ncpus);
		mask = CPU_ALLOC(ncpus);

		CPU_ZERO_S(size, mask);
		r = sched_getaffinity(0, size, mask);

		ncpus += ncpus / 2 + 64;
	} while (r == -1 && errno == EINVAL) ;
	if (r == -1)
		return 1;

	f = 0;
	printf("affinity ");
	for (i = 0; i < ncpus; i++)
		if (CPU_ISSET(i, mask)) {
			printf("%s%d", f ? "," : "", i);
			f = 1;
		}
	printf("\n");

	for (n = 0; n < sizeof(files)/sizeof(*files); n++)
		if (get_sysfs_data(buf, sizeof(buf), files[n]))
			printf("%s %s\n", files[n], buf);

	return 0;
}
