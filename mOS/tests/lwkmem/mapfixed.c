/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018, Intel Corporation.
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

#define INFO	1
#define DBG	2
#define KB(v)	((v) * (1 << 10))
#define MB(v)	((v) * (1 << 20))
#define GB(v)	((v) * (1 << 30))

#define LOG(level, format, ...) \
	do { \
		if (verbose >= level) \
			printf("map-fixed: " format "\n", ##__VA_ARGS__);\
	} while (0)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

static void usage(void)
{
	printf("Usage: mapfixed <args>\n");
	printf("  -s/--map_size <size>  : Specifies the size of the region\n");
	printf("                          to be mapped.\n");
	printf("  -p/--page <size>      : Specifies a valid page size\n");
	printf("                          to align start of mapping.\n");
	printf("  -v/--verbose          : Enable verbosity.  May be\n");
	printf("                          specified multiple times.\n");
	printf("  -h/--help             : Print this message.\n");
	printf("\n");
}

static void parse_options(int argc, char **argv, unsigned long *map_size,
			  unsigned long *page_size)
{
	static struct option options[] = {
		{ "map-size", required_argument, 0, 's' },
		{ "page-size", required_argument, 0, 'p' },
		{ "verbose", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0}
	};

	*map_size = *page_size = 0;
	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "s:p:vh",
				options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 's':
			*map_size = strtoul(optarg, 0, 0);
			break;

		case 'p':
			*page_size = strtoul(optarg, 0, 0);
			if (*page_size != KB(4) && *page_size != MB(2) &&
			    *page_size != MB(4) && *page_size != GB(1)) {
				fprintf(stderr, "Invalid page type\n");
				usage();
				exit(-1);
			}
			break;
		case 'h':
			usage();
			exit(0);

		case 'v':
			verbose += 1;
			break;

		default:
			usage();
			exit(-1);
		}
	}

	if (optind != argc) {
		printf("optind=%d argc=%d\n", optind, argc);
		usage();
		exit(-1);
	}

	if (!*map_size || !*page_size || *map_size < *page_size) {
		fprintf(stderr, "Invalid inputs\n");
		usage();
		exit(-1);
	}
}

static int map_fixed(unsigned long size, unsigned long page_size)
{
	int rc = -1;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int prots = PROT_READ | PROT_WRITE;
	void *start = NULL;
	void *start_fixed = NULL;
	void  *end = NULL;
	unsigned long aligned_start = 0;
	unsigned long page_mask = 0;

	LOG(DBG, "map_size [%ld] page_size [%ld]", size, page_size);
	/* Round up size to page_size boundary */
	size = ((size + page_size - 1) / page_size) * page_size;

	/* Allocate extra 1 page to account for aligning of unaligned start */
	size += page_size;

	start = mmap(NULL, size, prots, flags, -1, 0);
	if (start == MAP_FAILED) {
		perror("mmap failed");
		goto out;
	}
	end = start + size;

	LOG(DBG, "start [0x%lx] end [0x%lx]", (unsigned long)start,
		(unsigned long) end);

	/* We don't need the original virtual memory mapping anymore */
	munmap(start, size);


	/* Compute start address which is aligned on page_size boundary */
	aligned_start = (unsigned long) start;
	/* Unaccount the extra page size added before. */
	size -= page_size;

	if (aligned_start % page_size) {
		page_mask = ~(page_size - 1);
		aligned_start = (aligned_start & page_mask) + page_size;
	}

	LOG(DBG, "start [0x%lx] (aligned to page size [0x%lx])",
	    aligned_start, page_size);

	if (((void *) aligned_start + size) > end) {
		fprintf(stderr,
			"Can't align mmap [0x%lx - 0x%lx] to %ld page size\n",
			(unsigned long)start, (unsigned long)end, page_size);
		goto out;
	}

	start_fixed = mmap((void *)aligned_start, size, prots,
			   flags | MAP_FIXED, -1, 0);
	LOG(DBG, "mmap MAP_FIXED addr [0x%lx] size [%ld] returned [0x%lx]",
	    aligned_start, size, (unsigned long)start_fixed);

	if (!start_fixed) {
		perror("mmap(MAP_FIXED) failed");
		goto out;
	}
	rc = (unsigned long) start_fixed == aligned_start ? 0 : -1;
	munmap(start_fixed, size);
out:
	return rc;
}

int main(int argc, char **argv)
{
	unsigned long map_size;
	unsigned long page_size;
	int rc;

	parse_options(argc, argv, &map_size, &page_size);
	rc = map_fixed(map_size, page_size);
	printf("(I) Test %s.\n", rc ? "FAILED" : "PASSED");
	return rc;
}
