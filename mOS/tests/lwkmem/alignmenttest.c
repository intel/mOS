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

/*#define _LARGEFILE64_SOURCE*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <math.h>


static int verbose;

static void usage(void);
static int parse_options(int argc, char **argv, size_t *size, size_t *align,
			 int *iters);
static int do_mmap(size_t size, size_t alignment);

int main(int argc, char **argv)
{
	size_t size = 0, alignment = 0;
	int rc = 0, iters = 2, i;

	rc = parse_options(argc, argv, &size, &alignment, &iters);

	if (rc)
		goto out;

	if (!size || !alignment) {
		printf("(E) The --size and --alignment arguments are required.\n");
		rc = -1;
		goto out;
	}

	for (i = 0; i < iters && rc == 0; i++)
		rc = do_mmap(size, alignment);

out:
	printf("(I) Test %s.\n", rc ? "FAILED" : "PASSED");
	return rc;
}


static void usage(void)
{
	printf("alignmenttest --size <size> --alignment <alignment> [--iterations <N>] [--verbose] [--help]\n");
}


static int parse_options(int argc, char **argv, size_t *size, size_t *align,
			 int *iters)
{
	static struct option options[] = {
		{ "size", required_argument, 0, 's' },
		{ "alignment", required_argument, 0, 'a' },
		{ "iterations", required_argument, 0, 'i'},
		{ "verbose", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0}
	};

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "s:a:i:vh",
				options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 's': {
			*size = strtoul(optarg, 0, 0);
			break;
		}

		case 'a': {
			*align = strtoul(optarg, 0, 0);
			break;
		}

		case 'i': {
			*iters = atoi(optarg);
			break;
		}

		case 'h': {
			usage();
			exit(0);
			break;
		}

		case 'v': {
			verbose = 1;
			break;
		}

		default: {
			usage();
			return -1;
			}
		}
	}

	if (optind != argc) {
		printf("optind=%d argc=%d\n", optind, argc);
		usage();
		return -1;
	}

	return 0;
}

static int do_mmap(size_t size, size_t alignment)
{

	int prot = PROT_READ | PROT_WRITE;
	int flgs = MAP_PRIVATE | MAP_ANONYMOUS;
	void *va;
	unsigned long addr;

	va = mmap(NULL, size, prot, flgs, -1, 0);

	if (va == MAP_FAILED) {
		perror("Failed mmap.");
		return -1;
	}

	addr = (unsigned long)va;

	if (verbose) {
		printf("(D) addr=%016lx\n", addr);
		printf("(D) algn=%016lX\n", alignment-1);
	}

	if (addr & (alignment-1)) {
		printf("(E) Alignment failure on address %016lx (alignment: %lx)\n",
		       addr, alignment-1);
		return -1;
	}

	return 0;
}

