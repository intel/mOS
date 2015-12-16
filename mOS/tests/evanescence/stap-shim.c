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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>

#define ERROR_FD 54321

#define error(msg) \
	do { \
		char *s = strerror(errno); \
		write(ERROR_FD, msg, strlen(msg)); \
		write(ERROR_FD, s, strlen(s)); \
		_exit(42); \
	} while (0)

int main(int argc, char **argv)
{
	int cpu, pid, status;

	close(ERROR_FD);
	if (setsid() < 0)
		error("setsid");

	if (argc < 2)
		error("argc < 2");
	if ((cpu = atoi(argv[1])) >= 0) {
		size_t size = CPU_ALLOC_SIZE(cpu + 1);
		cpu_set_t *set = CPU_ALLOC(cpu + 1);

		if (!set)
			error("CPU_ALLOC");
		CPU_ZERO_S(size, set);
		CPU_SET_S(cpu, size, set);
		if (sched_setaffinity(0, size, set) < 0)
			error("sched_setaffinity");
		CPU_FREE(set);
	}

	if ((pid = fork()) < 0)
		error("fork");

	if (pid == 0 && execvp(argv[2], argv + 2) < 0)
		error("execvp");

	while (wait(&status) != -1 || errno != ECHILD) ;
	return 0;
}
