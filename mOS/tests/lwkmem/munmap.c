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

#define DEBUG(lvl, msg) do { if (verbose >= (lvl)) printf msg ; } while (0)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

static void usage(void);
static int parse_options(int argc, char **argv, size_t *map_size,
			 size_t *unmap_size, size_t *offset,
			 size_t *page_size);
static int validate_options(size_t map_size, size_t unmap_size, size_t offset,
			    size_t page_size);

static int map_and_color(void **addr, size_t size, size_t page_size,
			 unsigned long color);
static int test_coloring(void *addr, size_t size, size_t page_size,
			 unsigned long color);

int main(int argc, char **argv)
{
	size_t map_size = 0, unmap_size = 0, offset = 0, page_size = 4096;
	int rc = 0, i;
	void *addr[3] = {0, 0, 0};
	size_t size[3] = {0, 0, 0};
	const unsigned long COLOR1 = 0x1111111111111111;
	const unsigned long COLOR2 = 0x2222222222222222;

	rc = parse_options(argc, argv, &map_size, &unmap_size, &offset,
			   &page_size);
	if (rc)
		goto out;

	rc = validate_options(map_size, unmap_size, offset, page_size);
	if (rc)
		goto out;

	/*
	 *  addr[0]      addr[1]      addr[2]
	 *  ^            ^            ^
	 *  +------------+------------+------------+
	 *  | region 0   | region 1   | region 2   |
	 *  +------------+------------+------------+
	 *  | map_size                             |
	 *  +------------+------------+------------+
	 *  | offset     | unmap_size |
	 *  +------------+------------+
	 *
	 *  This test will mmap a region.  It then unmaps
	 *  a region at the specified offset and length,
	 *  designated as region 1 in the above diagram.
	 *  The offset may be zero, which results in an
	 *  unmap of the left portion of the original region.
	 *  If offset is non-zero, either a middle section
	 *  or the right end of the original region is unmapped.
	 *  The latter is true when the sum of offset and
	 *  unmap_size is equal to the map_size.
	 *
	 *  In all cases, the unmapped region is mapped
	 *  a second time.
	 *
	 *  All mapped segments are colored with a well
	 *  known patter so that they can be tested for
	 *  corruption.
	 */

	addr[0] = 0;
	rc = map_and_color(&addr[0], map_size, page_size, COLOR1);
	if (rc)
		goto out;

	rc = test_coloring(addr[0], map_size, page_size, COLOR1);
	if (rc)
		goto out;

	addr[1] = addr[0] + offset;
	addr[2] = addr[1] + unmap_size;
	size[0] = offset;
	size[1] = unmap_size;
	size[2] = map_size > (offset + unmap_size) ?
		map_size - (offset + unmap_size) : 0;

	rc = munmap(addr[1], unmap_size);
	if (rc) {
		perror("Unmap failed.");
		goto out;
	}

	rc = map_and_color(&addr[1], unmap_size, page_size, COLOR2);
	if (rc)
		goto out;

	for (i = 0; i < 3; i++)
		if (size[i]) {
			rc = test_coloring(addr[i], size[i], page_size,
					   i % 2 ? COLOR2 : COLOR1);
			if (rc)
				goto out;
		}

out:
	printf("(I) Test %s.\n", rc ? "FAILED" : "PASSED");
	return rc;
}


static void usage(void)
{
	printf("Usage: munmap <args>\n");
	printf("  -s/--map_size <sz>    : Specifies the size of the region\n");
	printf("                          to be mapped. [required]\n");
	printf("  -u/--unumap_size <sz> : Specifies the size of the region\n");
	printf("                          to be unmapped [required]\n");
	printf("  -o/--offset <sz>      : Specifies the offset within the\n");
	printf("                          mapped region where the unmap\n");
	printf("                          will occur [default=0]\n");
	printf("  -p/--page_size <sz>   : Specifies the page size to be\n");
	printf("                          used for coloring [default=4096]\n");
	printf("  -v/--verbose          : Enable verbosity.  May be\n");
	printf("                          specified multiple times.\n");
	printf("  -h/--help             : Print this message.\n");
	printf("\n");
	printf("Restrictions:\n");
	printf("  1. The map_size, unmap_size and offset sizes must all be\n");
	printf("     multiples of the page_size.\n");
	printf("  2. The sum of offset and unmap_size must be no larger\n");
	printf("     than the map_size.\n");
}


static int parse_options(int argc, char **argv, size_t *map_size,
			 size_t *unmap_size, size_t *offset, size_t *page_size)
{
	static struct option options[] = {
		{ "map-size", required_argument, 0, 's' },
		{ "unmap-size", required_argument, 0, 'u' },
		{ "offset", required_argument, 0, 'o' },
		{ "page-size", required_argument, 0, 'p' },
		{ "verbose", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0}
	};

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "s:u:o:p:n:vh",
				options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 's': {
			*map_size = strtoul(optarg, 0, 0);
			break;
		}
		case 'u': {
			*unmap_size = strtoul(optarg, 0, 0);
			break;
		}
		case 'o': {
			*offset = strtoul(optarg, 0, 0);
			break;
		}
		case 'p': {
			*page_size = strtoul(optarg, 0, 0);
			break;
		}
		case 'h': {
			usage();
			exit(0);
			break;
		}
		case 'v': {
			verbose += 1;
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

static int validate_options(size_t map_sz, size_t unmap_sz, size_t offset,
			    size_t page_size)
{
	int i;
	static const char * const labels[] = {
		"map_size", "unmap_size", "offset", "page_size"};
	size_t cant_be_zero[] = {map_sz, unmap_sz, 1, page_size};
	size_t must_be_page_aligned[] = {map_sz, unmap_sz, offset, page_size};

	for (i = 0; i < ARRAY_SIZE(cant_be_zero); i++)
		if (cant_be_zero[i] == 0) {
			fprintf(stderr, "%s must be specified.\n", labels[i]);
			return -1;
		}

	for (i = 0; i < ARRAY_SIZE(must_be_page_aligned); i++)
		if (must_be_page_aligned[i] % page_size) {
			fprintf(stderr,
				"%s (%ld) must be a multiple of page_size (%ld)\n",
				labels[i], must_be_page_aligned[i], page_size);
			return -1;
		}

	if (offset + unmap_sz > map_sz) {
		fprintf(stderr,
			"(offset + unmap_size) must be less than or equal to map_size\n");
		return -1;
	}

	return 0;
}

static int map_and_color(void **addr, size_t size, size_t page_size,
			 unsigned long color)
{
	unsigned long i;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int prots = PROT_READ | PROT_WRITE;
	void *addr_in = *addr;

	if (addr_in)
		flags |= MAP_FIXED;

	*addr = mmap(addr_in, size, prots, flags, -1, 0);
	if (*addr == MAP_FAILED) {
		perror("Failed mmap.");
		return -1;
	}

	if (addr_in && (addr_in != *addr))
		fprintf(stderr,
			"(W) fixed mmap not honored: wanted: %p but got %p\n",
			addr_in, *addr);

	DEBUG(1, ("mmap: [%p-%p) len=%lx\n", *addr, *addr + size, size));

	for (i = 0; i < size; i += page_size) {
		unsigned long *pg = (unsigned long *)(*addr + i);

		DEBUG(2, ("Coloring page %p\n", pg));
		pg[0] = color;
		pg[page_size / sizeof(unsigned long) - 1] = color;
	}

	return 0;
}

static int test_coloring(void *addr, size_t size, size_t page_size,
			 unsigned long color)
{
	unsigned long i, j;

	size_t first = 0, last = page_size / sizeof(unsigned long) - 1;

	DEBUG(1, ("Testing coloring in page %p\n", addr));

	for (i = 0; i < size; i += page_size) {

		unsigned long *pg = (unsigned long *)(addr + i);
		unsigned long *addrs[2] = { &pg[first], &pg[last]};
		unsigned long values[2] = { pg[first], pg[last] };

		for (j = 0; j < 2; j++)  {
			DEBUG(2, ("Testing coloring @ %p : %lx vs. %lx (expected)\n",
				  addrs[j], values[j], color));

			if (values[j] != color) {
				fprintf(stderr,
					"Coloring error @ %p  ==> %lx (expected %lx)\n",
					addrs[j], values[j], color);
				return -1;
			}
		}
	}

	return 0;
}
