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
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_BUFFER_SIZE (1<<30)

int main(int argc, char **argv)
{
	long height;
	long buffer_size;
	long timeout = 5;
	unsigned char *p = NULL;
	pid_t pid;
	int i, status;

	if (argc < 3 || argc > 4) {
		fprintf(stderr,
			"Usage: %s <number of processes> <buffer size> [<seconds>|wait]\n",
			argv[0]);
		return 1;
	}

	height = strtol(argv[1], NULL, 10);
	if (height < 1 || height > 255) {
		fprintf(stderr, "Invalid number of processes specified '%s'\n",
			argv[1]);
		return 1;
	}

	buffer_size = strtol(argv[2], NULL, 10);
	if (buffer_size < 1 || buffer_size > MAX_BUFFER_SIZE) {
		fprintf(stderr, "Invalid buffer size '%lu' specified.\n",
			buffer_size);
		return 1;
	}

	if (argc == 4) {
		if (strcmp(argv[3], "wait") == 0)
			timeout = -1;
		else
			timeout = strtol(argv[3], NULL, 10);
	}

	printf("%u", getpid());
	fflush(stdout);

	/* Repeatedly allocate a buffer then fork. Both parent and child fill
	 * buffer with unique data and validate the buffer.
	 */
	while (height-- > 1) {
		p = malloc(buffer_size);
		if (!p)
			return 2;
		memset(p, 0, buffer_size);

		pid = fork();
		if (pid > 0) {
			/* Parent */
			printf(" %u", pid);
			fflush(stdout);

			memset(p, 0xff, buffer_size);
			for (i = 0; i < buffer_size; i++)
				if (p[i] != (unsigned char)0xff)
					break;
			if (i != buffer_size)
				fprintf(stderr, "Invalid parent string p[%u]=%#02x\n", i, p[i]);

			wait(&status);
			free(p);
			return 0;
		} else if (pid < 0) {
			perror("fork failure");
			return 3;
		} else {
			/* Child */
			memset(p, (unsigned char)height, buffer_size);
			for (i = 0; i < buffer_size; i++)
				if (p[i] != (unsigned char)height) {
					fprintf(stderr, "Invalid child string p[%u]=%#02x\n", i, p[i]);
					goto out;
				}
		}
	}

out:
	free(p);
	printf("\n");
	fflush(stdout);
	if (timeout >= 0)
		sleep(timeout);
	else {
		char buf[32];
		fprintf(stderr, "[%d] Waiting...\n", getpid());
		printf("ready\n");
		fflush(stdout);
		fgets(buf, sizeof(buf), stdin);
		fprintf(stderr, "[%d] Finishing...\n", getpid());
	}
	return 0;
}
