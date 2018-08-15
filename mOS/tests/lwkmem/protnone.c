/*
 * Multi Operating System (mOS)
 * Copyright (c) 2019, Intel Corporation.
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
#include <stdbool.h>
#include <sys/mman.h>
#include <getopt.h>
#include <locale.h>

struct options_t {
	int verbosity;
} opts = {
	.verbosity = 1,
};

static void usage(void);
static int parse_options(int argc, char **argv, struct options_t *options);

static int test_simple_mmap_reclamation(void);
static int test_simple_mprotect_reclamation(void);
static int test_advanced_lots_of_holes(void);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define KB(v)	((v) * (1 << 10))
#define MB(v)	((v) * (1 << 20))
#define GB(v)	((v) * (1 << 30))

#define INFO(s)  do { if (opts.verbosity > 0) printf s ; } while (0)
#define DEBUG(s) do { if (opts.verbosity > 1) printf s ; } while (0)

int main(int argc, char **argv)
{
	//unsigned long addr0, addr1, addr2;
	int i;
	int rc;

	struct {
		int (*test)(void);
		const char *label;
	}
	basic_tests[] = {
		{ test_simple_mmap_reclamation, "mmap reclamation", },
		{ test_simple_mprotect_reclamation, "mprotect reclamation", },
	},
	advanced_tests[] = {
		{ test_advanced_lots_of_holes, "mmap reclamation - holes", },
	};


	setlocale(LC_ALL, "");

	rc = parse_options(argc, argv, &opts);

	if (rc)
		goto out;

	for (i = 0; i < ARRAY_SIZE(basic_tests); i++) {
		INFO(("--- Executing %s ---\n", basic_tests[i].label));
		rc += basic_tests[i].test();
		INFO(("\trc=%d\n", rc));
	}

	if (rc) {
		printf("(E) One or more basic tests failed.  Skipping advanced tests.\n");
		goto out;
	}

	INFO(("All simple tests complete.  Now executing advanced tests.\n"));

	for (i = 0; i < ARRAY_SIZE(advanced_tests); i++) {
		INFO(("--- Executing %s ---\n", advanced_tests[i].label));
		rc += advanced_tests[i].test();
		INFO(("\trc=%d\n", rc));
	}

 out:

	return rc;

}

static void *map(void *hint, unsigned long length, int flags, int prot)
{

	void *addr;

	DEBUG(("\n(>) %s hint=%p len=%'ld flags=%x prot=%x\n",
	       __func__, hint, length, flags, prot));

	addr = mmap(hint, length, prot, flags, -1, 0);

	if (addr == MAP_FAILED) {
		perror("mmap failed.");
		INFO(("(E) hint=%p length=%'ld flags=%x prot=%x\n",
		      hint, length, flags, prot));
		goto out;
	}


	DEBUG(("(*) mmap ret=[%p,%p) len=%'ld\n", addr, addr + length, length));

 out:
	DEBUG(("(<) %s ret=%p\n", __func__, addr));

	return addr;
}

static int unmap(void *addr, unsigned long length)
{
	int ret;

	DEBUG(("\n(>) %s addr=[%p,%p) len=%'ld\n",
	       __func__, addr, addr + length, length));

	ret = munmap(addr, length);

	DEBUG(("(<) %s ret=%d\n", __func__, ret));
	return ret;

}

static int protect(void *addr, unsigned long length, int prot)
{
	int ret;

	DEBUG(("\n(>) %s addr=[%p,%p) len=%'ld prot=%x\n",
	       __func__, addr, addr + length, length, prot));

	ret = mprotect(addr, length, prot);

	DEBUG(("(<) %s ret=%d\n", __func__, ret));
	return ret;
}

static void usage(void)
{
	printf("Usage: protnone <options>\n");
	printf("\t-q, --quiet : suppress informational output.\n");
	printf("\t-v, --verbose : be verbose.\n");
}



static int parse_options(int argc, char **argv, struct options_t *opts)
{
	static struct option options[] = {
		{ "verbose", no_argument, 0, 'v' },
		{ "quiet", no_argument, 0, 'q'},
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0}
	};

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, ":vqh", options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 'q': {
			opts->verbosity = 0;
			break;
		}

		case 'h': {
			usage();
			exit(0);
			break;
		}

		case 'v': {
			opts->verbosity++;
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

static int test_simple_mmap_reclamation(void)
{
	/*
	 * Map an area that is inaccessible.  Then reclaim an
	 * interior region of that area via an overlapping
	 * mmap.  Limit the outer region to less the 2MiB so
	 * that only 4K pages are involved and hence we have
	 * no VMA splitting concerns in mOS.
	 */

	void *addr0, *addr1;

	addr0 = map(0, MB(2) - KB(4),
		    MAP_PRIVATE | MAP_ANONYMOUS,
		    PROT_NONE);
	if (addr0 == MAP_FAILED)
		return -1;

	addr1 = map(addr0 + KB(16), KB(4),
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		    PROT_EXEC | PROT_READ | PROT_WRITE);
	if (addr1 == MAP_FAILED)
		return -1;

	/* Touch the memory to prove that it is accessible:*/

	*((int *)addr1) = 0xc00df00d;

	return unmap(addr0, MB(2) - KB(4));
}

static int test_simple_mprotect_reclamation(void)
{

	/*
	 * Map an area that is inaccessible.  Then reclaim an
	 * interior region of that area via an mprotect
	 * call.  Limit the outer region to less the 2MiB so
	 * that only 4K pages are involved and hence we have
	 * no VMA splitting concerns in mOS.
	 */

	void *addr0, *addr1;
	int rc;

	addr0 = map(0, MB(2) - KB(4),
		    MAP_PRIVATE | MAP_ANONYMOUS,
		    PROT_NONE);
	if (addr0 == MAP_FAILED)
		return -1;

	addr1 = addr0 + KB(16);
	rc = protect(addr1, KB(4), PROT_EXEC | PROT_READ | PROT_WRITE);

	if (rc)
		return -1;

	/* Touch the memory to prove that it is accessible:*/

	*((int *)addr1) = 0xc00df00d;

	return unmap(addr0, MB(2) - KB(4));

	return 0;
}

static int test_advanced_lots_of_holes(void)
{
	/*
	 * Map an area that is accessible and scribble something
	 * in each 4K page.  Then punch a series of holes via
	 * munmaps.  Then mmap one more time, overlaying some of
	 * the holes.
	 */

	void *addr0, *addr1;
	int i, N, incr, starti, endi;
	unsigned long *ptr, expected;

	addr0 = map(0, MB(2) - KB(4),
		    MAP_PRIVATE | MAP_ANONYMOUS,
		    PROT_READ | PROT_WRITE);
	if (addr0 == MAP_FAILED)
		goto error;

	ptr = (unsigned long *)addr0;
	N = (MB(2) - KB(4))/sizeof(unsigned long);
	incr = KB(4) / sizeof(unsigned long);

	for (i = 0; i < N; i += incr)
		ptr[i] = 0xc00df00d0000 + i;

	/* unmap 1 page  at the   3rd page boundary == 2**2 - 1
	 * unmap 2 pages at the  14th page boundary == 2**4 - 2
	 * unmap 4 pages at the  60th page boundary == 2**6 - 4
	 */
	for (i = 1; i <= 3; i++) {
		addr1 = addr0 + ((1 << (2*i)) - (1 << (i-1))) * KB(4);
		if (unmap(addr1, (1 << (i-1)) * KB(4)))
			goto error;
	}

	addr1 = map(addr0 + KB(4), KB(63*4),
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		    PROT_READ | PROT_WRITE);
	if (addr1 == MAP_FAILED)
		return -1;

	starti = 0;
	endi = KB(64*4) / sizeof(unsigned long);

	for (i = 0 ; i < N; i += incr) {

		if (i <= starti || i >= endi)
			expected =  0xc00df00d0000 + i;
		else
			expected = 0;

		if (ptr[i] != expected) {
			printf("(E) Miscompare @%p i=%d\n\t(actual  ) %016lx vs.\n\t(expected) %016lx\n",
			       ptr + i, i, ptr[i], expected);
			goto error;
		}

		/* Touch the memory to prove that it is accessible:*/

		ptr[i] = 0xc00df00d0000 + i;
	}

	return unmap(addr0, MB(2) - KB(4));

 error:
	return -1;
}
