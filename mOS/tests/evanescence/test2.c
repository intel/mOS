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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static char command[512];

int main(int argc, char **argv)
{
	int to_cpu = atoi(argv[1]);

	/* do some syscalls; they don't have to actually work */
	close(12345);
	read(12345, (void *)42, 6);

	/* external re-affinitization while in a syscall (namely, wait4) */
	sprintf(command, "taskset -c -p %d %d", to_cpu, getpid());
	system(command);

	/* do some syscalls; they don't have to actually work */
	close(12345);
	read(12345, (void *)42, 6);
	return 0;
}
