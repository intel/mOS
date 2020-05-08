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
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

static int verbose;
unsigned long page_size;

#define MAGIC_1 0xaa
#define MAGIC_2 0x55

#define ERR	0
#define INFO	1
#define DBG	2

#define LOG(level, format, ...) \
	do { \
		if (verbose >= level) \
			printf("mremap [%-14s] " format "\n", \
				__func__, ##__VA_ARGS__); \
	} while (0)
#define LOG_CASE(level, tc) \
	do { \
		if (verbose >= level) \
			printf("\nmremap test case: %d\n", tc); \
	} while (0)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define round_up(sz, ps) ((((sz) + ps - 1) / ps) * ps)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

static void usage(void)
{
	printf("Usage: mremap <args>\n");
	printf("  -s/--map_size <size>  : Size of the original mmap region\n");
	printf("                          to be mapped.\n");
	printf("  -f/--factor           : Expand/Shrink scale, default 2\n");
	printf("                          i.e. expand to <size> x 2.\n");
	printf("                          i.e. shrink to <size> / 2.\n");
	printf("  -v/--verbose          : Enable verbosity.  May be\n");
	printf("                          specified multiple times.\n");
	printf("  -h/--help             : Print this message.\n");
	printf("\n");
}

static void parse_options(int argc, char **argv, unsigned long *map_size,
			  unsigned long *scale)
{
	static struct option options[] = {
		{ "map-size", required_argument, 0, 's' },
		{ "factor", required_argument, 0, 'f' },
		{ "verbose", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0}
	};

	/* Defaults */
	*map_size = page_size;
	*scale = 2;

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "s:f:vh",
				options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 's':
			*map_size = strtoul(optarg, 0, 0);
			break;

		case 'f':
			*scale = strtoul(optarg, 0, 0);
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

	if (!*map_size || !*scale) {
		fprintf(stderr, "Invalid inputs\n");
		usage();
		exit(-1);
	}
}

static int write_pages(unsigned char *start, unsigned char *end,
		       unsigned char magic)
{
	if (start >= end) {
		LOG(ERR, "Invalid range [%#lx, %#lx) %x", (unsigned long) start,
		(unsigned long) end, magic);
		return -1;
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
		return -1;
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

static int verify_memory_pre_mremap(unsigned char *start, unsigned char *end,
				    bool write_before)
{
	int rc;

	if (!write_before)
		return 0;

	rc = write_pages(start, end, MAGIC_1);
	if (rc) {
		LOG(ERR, "Err! writing MAGIC_1 [%#lx, %#lx)",
			(unsigned long) start, (unsigned long) end);
		return rc;
	}

	rc = verify_pages(start, end, MAGIC_1);
	if (rc) {
		LOG(ERR, "Err! read, verify MAGIC_1 [%#lx, %#lx)",
			(unsigned long) start, (unsigned long) end);
	}
	return rc;
}

static int verify_memory_post_mremap(unsigned char *start,
				     unsigned long oldsize,
				     unsigned long newsize,
				     bool write_before)
{
	int rc;

	if (write_before) {
		/* Verify the contents written before mremap */
		rc = verify_pages(start, start + min(oldsize, newsize),
				  MAGIC_1);
		if (rc) {
			LOG(ERR, "Err! verifying MAGIC_1 [%#lx, %#lx)",
				(unsigned long) start,
				(unsigned long) start + min(oldsize, newsize));
			return rc;
		}

		/* If expanding make sure expanded region has zeros */
		if (newsize > oldsize) {
			rc = verify_pages(start + oldsize, start + newsize, 0);
			if (rc) {
				LOG(ERR, "Failed to verify 0 in [%#lx, %#lx)",
					(unsigned long) start + oldsize,
					(unsigned long) start + newsize);
				return rc;
			}
		}
	}

	/* Write and verfiy after mremap */
	rc = write_pages(start, start + newsize, MAGIC_2);
	if (rc) {
		LOG(ERR, "Err! writing MAGIC_2 [%#lx, %#lx)",
			(unsigned long) start, (unsigned long) start + newsize);
		return rc;
	}

	rc = verify_pages(start, start + newsize, MAGIC_2);
	if (rc) {
		LOG(ERR, "Err! verifying MAGIC_2 [%#lx, %#lx)",
			(unsigned long) start, (unsigned long) start + newsize);
	}
	return rc;
}


static int mremap_fixed(unsigned long oldsize, unsigned long newsize,
			bool write_before, int *tc)
{
	int rc = -1;
	int mremap_flags = MREMAP_FIXED | MREMAP_MAYMOVE;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int prots = PROT_READ | PROT_WRITE;
	void *start, *end, *addr;

	LOG_CASE(INFO, (*tc)++);
	LOG(INFO, "oldsize=%lu newsize=%lu write_before=%s",
		oldsize, newsize, write_before ?  "y" : "n");

	/* Reserve the virtual memory required for the test */
	start = mmap(NULL, oldsize + newsize, prots, flags, -1, 0);
	if (start == MAP_FAILED) {
		rc = errno;
		LOG(ERR, "Err! mmap rc=%d size=%lu prot=%#x flags=%#x",
			rc, oldsize + newsize, prots, flags);
		return rc;
	}
	end = start + oldsize;

	LOG(DBG, "mapped [%#lx, %#lx)", (unsigned long)start,
		(unsigned long) end + newsize);
	/*
	 * Unmap the second half of the map so that we can remap
	 * first half into it with newsize.
	 */
	rc = munmap(end, newsize);
	if (rc) {
		rc = errno;
		LOG(ERR, "Err! unmap second part [%#lx, %#lx) rc=%d",
			(unsigned long) end, (unsigned long) end + newsize, rc);
		goto out;
	}
	LOG(DBG, "unmapped [%#lx, %#lx)", (unsigned long)end,
		(unsigned long) end + newsize);

	/* Write before mremap? */
	rc = verify_memory_pre_mremap(start, end, write_before);
	if (rc)
		goto out;

	/* Remap first half to second half with newsize */
	addr = mremap(start, oldsize, newsize, mremap_flags, end);
	if (addr == MAP_FAILED || addr != end) {
		rc = addr == MAP_FAILED ? errno : -1;

		if (addr != MAP_FAILED) {
			LOG(ERR, "Err! not moved to fixed %#lx instead to %#lx",
				(unsigned long) end, (unsigned long) addr);

			/* Unmap moved map */
			if (munmap(addr, newsize)) {
				LOG(ERR, "Err! unmap moved [%#lx, %#lx)",
					(unsigned long) addr,
					(unsigned long) addr + newsize);
			}
		}
		goto out;
	}
	LOG(DBG, "remapped [%#lx, %#lx) -> [%#lx, %#lx)",
		(unsigned long) start, (unsigned long) end,
		(unsigned long) addr, (unsigned long) addr + newsize);

	rc = verify_memory_post_mremap(addr, oldsize, newsize, write_before);
out:
	/* Clear out everthing */
	if (munmap(start, oldsize + newsize)) {
		LOG(ERR, "Failed to clear mappings in [%#lx, %#lx)",
			(unsigned long) start,
			(unsigned long) start + oldsize + newsize);
	}

	LOG(INFO, "rc=%d [%s]", rc, rc ? "FAIL" : "PASS");
	return rc;
}

static int mremap_inplace(unsigned long oldsize, unsigned long newsize,
			  bool write_before, int *tc)
{
	int rc = -1;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int prots = PROT_READ | PROT_WRITE;
	void *start, *end, *addr;

	/* Skip test case if size doesn't change for inplace test */
	if (newsize == oldsize)
		return 0;

	LOG_CASE(INFO, (*tc)++);
	LOG(INFO, "oldsize=%lu newsize=%lu write_before=%s", oldsize, newsize,
		write_before ?  "y" : "n");
	/*
	 * Reserve the extra virtual memory required for the test if mremap
	 * expands the oldmap in place. This ensures that there is sufficient
	 * gap in the virtual memory for us to expand inplace.
	 */
	if (newsize > oldsize) {
		start = mmap(NULL, newsize, prots, flags, -1, 0);
		if (start == MAP_FAILED) {
			rc = errno;
			LOG(ERR, "Err! mmap rc=%d size=%lu prot=%#x flag=%#x",
				rc, newsize, prots, flags);
			return rc;
		}
		LOG(DBG, "mapped [%#lx, %#lx)", (unsigned long) start,
			(unsigned long) start + newsize);
		/*
		 * Unmap the extra reserved virtual memory so that we can expand
		 * oldmap inplace to newsize.
		 */
		rc = munmap(start + oldsize, newsize - oldsize);
		if (rc) {
			rc = errno;
			LOG(ERR, "Err! to unmap extra [%#lx, %#lx) rc=%d",
				(unsigned long) start + oldsize,
				(unsigned long) start + newsize, rc);
			goto out;
		}
		LOG(DBG, "unmapped extra reserved [%#lx, %#lx)",
			(unsigned long) start + oldsize,
			(unsigned long) start + newsize);
	} else {
		start = mmap(NULL, oldsize, prots, flags, -1, 0);
		if (start == MAP_FAILED) {
			rc = errno;
			LOG(ERR, "Err! mmap rc=%d size=%lu prot=%#x flag=%#x",
				rc, oldsize, prots, flags);
			return rc;
		}
		LOG(DBG, "mapped [%#lx, %#lx)", (unsigned long) start,
			(unsigned long) start + oldsize);
	}
	end = start + oldsize;

	rc = verify_memory_pre_mremap(start, end, write_before);
	if (rc)
		goto out;

	/* Remap to newsize in place */
	addr = mremap(start, oldsize, newsize, 0);
	if (addr == MAP_FAILED || addr != start) {
		rc = addr == MAP_FAILED ? errno : -1;

		if (addr != MAP_FAILED) {
			LOG(ERR, "ERR! map moved [%#lx, %#lx) -> [%#lx, %#lx)",
				(unsigned long) start, (unsigned long) end,
				(unsigned long) addr,
				(unsigned long) addr + newsize);

			/* Unmap moved map */
			if (munmap(addr, newsize)) {
				LOG(ERR, "Failed to unmap [%#lx, %#lx)",
					(unsigned long) addr,
					(unsigned long) addr + newsize);
			}
		}
		goto out;
	}
	LOG(DBG, "remapped [%#lx, %#lx) -> [%#lx, %#lx)",
		(unsigned long)start, (unsigned long) end,
		(unsigned long)addr, (unsigned long) addr + newsize);

	rc = verify_memory_post_mremap(addr, oldsize, newsize, write_before);
out:
	/* Clear out everything */
	if (munmap(start, max(oldsize, newsize))) {
		LOG(ERR, "Failed to clear mappings in [%#lx, %#lx)",
			(unsigned long) start,
			(unsigned long) start + max(oldsize, newsize));
	}
	LOG(INFO, "rc=%d [%s]", rc, rc ? "FAIL" : "PASS");
	return rc;
}

static int mremap_move(unsigned long oldsize, unsigned long newsize,
		 bool write_before, int *tc)
{
	int rc = -1;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	int prots = PROT_READ | PROT_WRITE;
	void *start, *end, *addr;

	/*
	 * Only expanding mremap can move the map to new virtual memory range
	 * when mremap is not to a fixed address, so skip shrinking mremap or
	 * if the size doesn't change.
	 */
	if (newsize <= oldsize)
		return 0;

	LOG_CASE(INFO, (*tc)++);
	LOG(INFO, "oldsize=%lu newsize=%lu write_before=%s", oldsize, newsize,
		write_before ?  "y" : "n");
	/*
	 * Reserve a page of extra virtual memory (later mapped as prot none)
	 * next to the mmap being remapped so that the expanding mremap is
	 * forced to move the map to new virtual memory range.
	 */
	start = mmap(NULL, oldsize + page_size, prots, flags, -1, 0);
	if (start == MAP_FAILED) {
		rc = errno;
		LOG(ERR, "Err! mmap rc=%d size=%lu prot=%#x flag=%#x",
			rc, newsize, prots, flags);
		return rc;
	}
	end = start + oldsize;
	LOG(DBG, "mapped [%#lx, %#lx)", (unsigned long) start,
		(unsigned long) end + page_size);
	/*
	 * Unmap the extra reserved virtual memory so that we can create a
	 * prot none map of page_size that inhibits expanding oldmap inplace.
	 */
	rc = munmap(end, page_size);
	if (rc) {
		rc = errno;
		LOG(ERR, "Err! to unmap extra [%#lx, %#lx) rc=%d",
			(unsigned long) end,
			(unsigned long) end + page_size, rc);
		goto out;
	}
	LOG(DBG, "unmapped extra reserved [%#lx, %#lx)",
		(unsigned long) end,
		(unsigned long) end + page_size);

	addr = mmap(end, page_size, PROT_NONE, MAP_FIXED | flags, -1, 0);
	if (addr == MAP_FAILED || addr != end) {
		rc = addr == MAP_FAILED ? errno : -1;
		LOG(ERR, "Err! mmap rc=%d addr=%#lx sz=%lu prot=%#x flag=%#x",
			rc, (unsigned long)end, page_size, PROT_NONE,
			MAP_FIXED | flags);

		/* Try to unmap map created if one */
		if (addr != MAP_FAILED && munmap(addr, page_size))
			LOG(ERR, "Err! failed to unmap [%#lx, %#lx)",
				(unsigned long) addr,
				(unsigned long) addr + page_size);
		goto out;
	}
	LOG(DBG, "mapped extra prot none page [%#lx, %#lx)",
		(unsigned long) end, (unsigned long) end + page_size);

	rc = verify_memory_pre_mremap(start, end, write_before);
	if (rc)
		goto out;

	/* Remap to newsize in place */
	addr = mremap(start, oldsize, newsize, MREMAP_MAYMOVE);
	if (addr == MAP_FAILED || addr == start) {
		rc = addr == MAP_FAILED ? errno : -1;

		if (addr != MAP_FAILED) {
			LOG(ERR, "Err! did not move [%#lx, %#lx) [%#lx, %#lx)",
				(unsigned long) start, (unsigned long) end,
				(unsigned long) addr,
				(unsigned long) addr + newsize);

		}

		if (addr == start && munmap(addr, newsize))
			LOG(ERR, "Failed to unmap [%#lx, %#lx)",
				(unsigned long) addr,
				(unsigned long) addr + newsize);
		goto out;
	}
	LOG(DBG, "remapped [%#lx, %#lx) -> [%#lx, %#lx)",
		(unsigned long)start, (unsigned long) end,
		(unsigned long)addr, (unsigned long) addr + newsize);

	rc = verify_memory_post_mremap(addr, oldsize, newsize, write_before);
	/* Unmap moved map */
	if (munmap(addr, newsize)) {
		LOG(ERR, "Failed to unmap [%#lx, %#lx)",
			(unsigned long) addr, (unsigned long) addr + newsize);
	}
out:
	/* Clear out everything */
	if (munmap(start, oldsize + page_size)) {
		LOG(ERR, "Failed to clear mappings in [%#lx, %#lx)",
			(unsigned long) start,
			(unsigned long) start + oldsize + page_size);
	}
	LOG(INFO, "rc=%d [%s]", rc, rc ? "FAIL" : "PASS");
	return rc;
}

int (*test[]) (unsigned long, unsigned long, bool, int *) = {
	mremap_fixed,
	mremap_inplace,
	mremap_move
};

int main(int argc, char **argv)
{
	int i, j, k, tc, rc = EINVAL;
	unsigned long scale;
	unsigned long oldsize;
	unsigned long newsize[3] = {0};
	bool wr_before[2] = { true, false };

	page_size = sysconf(_SC_PAGESIZE);
	parse_options(argc, argv, &oldsize, &scale);

	/* Round up size to page_size boundary */
	oldsize = round_up(oldsize, page_size);
	if (!oldsize) {
		LOG(ERR, "Invalid map size");
		goto out;
	}

	if (!scale) {
		LOG(ERR, "Invalid scale value");
		goto out;
	}

	if ((oldsize / scale) < page_size) {
		LOG(ERR, "EINVAL, can not shrink mremaps size %ld scale %ld",
			oldsize, scale);
		goto out;
	}

	LOG(INFO, "Args: mapsize %lu page_size %lu scale %lu",
		oldsize, page_size, scale);

	newsize[0] = oldsize;
	newsize[1] = round_up(oldsize / scale, page_size);
	newsize[2] = round_up(oldsize * scale, page_size);

	for (tc = 1, i = 0; i < ARRAY_SIZE(test); i++) {
		for (j = 0; j < ARRAY_SIZE(wr_before); j++) {
			for (k = 0; k < ARRAY_SIZE(newsize); k++) {
				/*
				 * Skip shrinking mremap if newsize is less
				 * than one page size
				 */
				if (newsize[k] < page_size)
					continue;

				rc = test[i](oldsize, newsize[k],
					     wr_before[j], &tc);
				if (rc)
					goto out;
			}
		}
	}

out:
	printf("\n(I) Test %s.\n", rc ? "FAILED" : "PASSED");
	return rc;
}
