/*
 * Multi Operating System (mOS)
 * Copyright (c) 2020, Intel Corporation.
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

static int verbose;
unsigned long page_size;
pid_t ppid;

#define MAGIC_1 0xaa
#define MAGIC_2 0x55

#define ERR	0
#define INFO	1
#define DBG	2

#define LOG(level, format, ...) \
	do { \
		if (verbose >= level) \
			printf("[ %6s : %d ] %s(): " format "\n", \
				ppid == getpid() ? "parent" : "child", \
				getpid(), __func__, ##__VA_ARGS__); \
	} while (0)
#define round_up(sz, ps) ((((sz) + ps - 1) / ps) * ps)

static void usage(void)
{
	printf("Usage: mremap <args>\n");
	printf("  -s/--map_size <size>  : Size of the mmap to be tested\n");
	printf("  -v/--verbose          : Enable verbosity.  May be\n");
	printf("                          specified multiple times ex: -vv\n");
	printf("  -h/--help             : Print this message.\n");
	printf("\n");
}

static void parse_options(int argc, char **argv, unsigned long *map_size)
{
	int c, opt_index;
	static struct option options[] = {
		{ "map-size", required_argument, 0, 's' },
		{ "verbose", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0}
	};

	/* Defaults */
	*map_size = page_size;

	while (1) {
		c = getopt_long(argc, argv, "s:vh",
				options, &opt_index);
		if (c == -1)
			break;

		switch (c) {

		case 's':
			*map_size = strtoul(optarg, 0, 0);
			break;

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'v':
			verbose += 1;
			break;

		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (optind != argc) {
		printf("optind=%d argc=%d\n", optind, argc);
		usage();
		exit(EXIT_FAILURE);
	}
}

static int write_pages(unsigned char *start, unsigned char *end,
		       unsigned char magic)
{
	if (start >= end) {
		LOG(ERR, "Invalid range [%#lx, %#lx) %x",
		(unsigned long) start, (unsigned long) end, magic);
		return EINVAL;
	}

	LOG(DBG, "Writing MAGIC_%s to [%#lx, %#lx)",
		magic == MAGIC_1 ? "1" :
		magic == MAGIC_2 ? "2" : "unknown!",
		(unsigned long)start, (unsigned long) end);

	while (start < end) {
		*start = magic;
		start += page_size;
	}
	return 0;
}
 
static int verify_pages(unsigned char *start, unsigned char *end,
			unsigned char magic)
{
	unsigned long stride = magic ? page_size : 1;

	if (start >= end || (magic && (end - start) < page_size)) {
		LOG(ERR, "Invalid args, range [%#lx, %#lx) magic %x",
		(unsigned long) start, (unsigned long) end, magic);
		return EINVAL;
	}

	LOG(DBG, "Verifying [%#lx, %#lx) for %s", (unsigned long)start,
		(unsigned long) end,
		magic == 0 ? "zeros" :
		magic == MAGIC_1 ? "MAGIC_1" :
		magic == MAGIC_2 ? "MAGIC_2" : "unknown!");

	while (start < end) {
		if (*start != magic) {
			LOG(ERR, "Err! at %#lx expected %#x present %#x",
				(unsigned long)start, magic, *start);
			return -1;
		}
		start += stride;
	}
	return 0;
}

static int write_and_verify(unsigned char *start, unsigned char *end,
			    unsigned char magic)
{
	LOG(DBG, "writing [%#lx, %#lx) with %s",
		(unsigned long) start, (unsigned long) end,
		magic == MAGIC_1 ? "MAGIC_1" :
		magic == MAGIC_2 ? "MAGIC_2" :
		magic == 0 ? "zeros" : "??");

	if (write_pages(start, end, magic)) {
		LOG(ERR, "Err! writing %s [%#lx, %#lx)",
			magic == MAGIC_1 ? "MAGIC_1" :
			magic == MAGIC_2 ? "MAGIC_2" :
			magic == 0 ? "zeros" : "??",
			(unsigned long) start, (unsigned long) end);
		return -1;
	}

	if (verify_pages(start, end, magic)) {
		LOG(ERR, "Err! verifying %s [%#lx, %#lx)",
			magic == MAGIC_1 ? "MAGIC_1" :
			magic == MAGIC_2 ? "MAGIC_2" :
			magic == 0 ? "zeros" : "??",
			(unsigned long) start, (unsigned long) end);
		return -1;
	}

	LOG(INFO, "written [%#lx, %#lx) with %s",
		(unsigned long) start, (unsigned long) end,
		magic == MAGIC_1 ? "MAGIC_1" :
		magic == MAGIC_2 ? "MAGIC_2" :
		magic == 0 ? "zeros" : "??");
	return 0;
}

static int test_fork(unsigned long map_size)
{
	int rc = -1;
	int wstatus = 0;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int prots = PROT_READ | PROT_WRITE;
	void *start, *end;
	pid_t pid;

	start = mmap(NULL, map_size, prots, flags, -1, 0);
	if (start == MAP_FAILED) {
		rc = errno;
		LOG(ERR, "Err! mmap rc=%d size=%lu prot=%#x flag=%#x",
			rc, map_size, prots, flags);
		return EXIT_FAILURE;
	}
	end = start + map_size;
	LOG(INFO, "mapped [%#lx, %#lx)", (unsigned long) start,
		(unsigned long) end);

	rc = EXIT_FAILURE;
	/* Fill the mapped memory [start, end) with MAGIC_1 */
	if (write_and_verify(start, end, MAGIC_1))
		goto out;

	pid = fork();
	if (pid < 0) {
		rc = errno;
		LOG(ERR, "Fork failed rc=%d", rc);
		rc = EXIT_FAILURE;
		goto out;
	} else if (pid) {
		/* Parent */
		LOG(INFO, "forked child pid %d", pid);
		do {
			LOG(INFO, "Waiting for child to exit");
			rc = wait(&wstatus);
			if (rc < 0) {
				rc = errno;
				LOG(INFO, "Wait failed rc=%d", rc);
				rc = EXIT_FAILURE;
				goto out;
			}
			LOG(INFO, "Wait over, child %d [%s]", pid,
				WIFEXITED(wstatus) ? "exited" :
				WIFSIGNALED(wstatus) ? "killed" :
				WIFSTOPPED(wstatus) ? "stopped" :
				WIFCONTINUED(wstatus) ? "continued" : "???");
		} while (WIFSTOPPED(wstatus) || WIFCONTINUED(wstatus));

		rc = EXIT_FAILURE;
		if (!WIFEXITED(wstatus))
			goto out;
		if (WEXITSTATUS(wstatus) != EXIT_SUCCESS)
			goto out;
		/*
		 * Child should not have shared [start, end) with parent, so the
		 * contents of memory [start, end) should be unaltered after
		 * child writes to its copy in the range and exits.
		 */
		LOG(INFO, "re-verifying [%#lx, %#lx) for MAGIC_1",
			(unsigned long) start, (unsigned long) end);

		if (verify_pages(start, end, MAGIC_1)) {
			LOG(ERR, "Err! read, re-verify MAGIC_1 [%#lx, %#lx)",
			(unsigned long) start, (unsigned long) end);
			goto out;
		}

		/* Make sure parent can write again */
		if (write_and_verify(start, end, MAGIC_2))
			goto out;
		rc = EXIT_SUCCESS;
	} else {
		/* Child */
		rc = EXIT_FAILURE;
		/*
		 * Verify that child sees what parent has written to the range
		 * [start, end) to begin with. We can not verify yet if it is
		 * child's private copy of physical memory or shared copy from
		 * parent's physical memory.
		 */
		LOG(INFO, "Verifying [%#lx, %#lx) for MAGIC_1 by parent",
			(unsigned long) start, (unsigned long) end);
		if (verify_pages(start, end, MAGIC_1)) {
			LOG(ERR, "Err! read, verify MAGIC_1 [%#lx, %#lx)",
				(unsigned long) start, (unsigned long) end);
		} else {
			/*
			 * Write a different magic number to the range
			 * [start, end). Parent should not see this change
			 * if child received a private copy of physical memory.
			 */
			if (write_and_verify(start, end, MAGIC_2))
				goto out;
			LOG(INFO, "Written [%#lx, %#lx) with MAGIC_2",
				(unsigned long) start, (unsigned long) end);
			rc = EXIT_SUCCESS;
		}
	}
out:
	/* Clear out everything */
	if (munmap(start, map_size)) {
		LOG(ERR, "Failed to clear map [%#lx, %#lx)",
			(unsigned long) start,
			(unsigned long) end);
	}
	return rc;
}

int main(int argc, char **argv)
{
	int rc = EXIT_FAILURE;
	unsigned long map_size;

	ppid = getpid();
	map_size = page_size = sysconf(_SC_PAGESIZE);
	parse_options(argc, argv, &map_size);

	/* Round up size to page_size boundary */
	map_size = round_up(map_size, page_size);
	if (!map_size) {
		LOG(ERR, "Invalid map size");
	} else  {
		LOG(INFO, "Args: map size %lu page size %lu",
			map_size, page_size);

		/* Kick off the test */
		rc = test_fork(map_size);
	}

	if (ppid == getpid())
		printf("\n(I) Test %s.\n",
			rc == EXIT_FAILURE ? "FAILED" : "PASSED");
	LOG(INFO, "Exiting");
	return rc;
}
