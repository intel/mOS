/*
 * Multi Operating System (mOS)
 * Copyright (c) 2017, Intel Corporation.
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
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <numa.h>
#include <numaif.h>
#include <mos.h>

#define SMALL_ALLOC_SIZE	(128)
#define ALLOC_SIZE		(256 * 1024 * 1024)

static void usage(char *pname)
{
	fprintf(stderr,
		"Usage: %s [-s <size>] [-v {-v}] [-h]\n"
		"    -s <size>    Amount of memory to allocate. Default %d bytes\n"
		"    -v           Increase verbosity\n"
		"    -h           Display this help info\n",
		pname, ALLOC_SIZE);
}

/* Show a number in human-readable untis */
static char *hunit(int n)
{
	if (n == 1024 * 1024 * 1024)
		return "1 GB";
	else if (n == 2 * 1024 * 1024)
		return "2 MB";
	else if (n == 4 * 1024)
		return "4 kB";

	return "?";
}

/* Make sure the return values from mos_get_addr_info() make sense */
static int
sanity_check(unsigned long addr, unsigned long phys_addr, int numa_domain,
	int page_size)
{
	if (numa_domain < 0 || numa_domain > numa_max_node()) {
		fprintf(stderr,
			"\tERROR: mos_get_addr_info(addr 0x%lx) returned NUMA domain %d, which is not a legal NID.\n",
			addr, numa_domain);
		return -1;
	}

	if ((phys_addr < 0x100000) || (phys_addr & 0x03))   {
		fprintf(stderr,
			"\tERROR: mos_get_addr_info(addr 0x%lx) returned non-sensical phys addr: 0x%lx!\n",
			addr, phys_addr);
		return -1;
	}

	if (strcmp("?", hunit(page_size)) == 0)   {
		fprintf(stderr,
			"\tERROR: mos_get_addr_info(addr 0x%lx) returned non-sensical page size of %d bytes!\n",
			addr, page_size);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ch, error;
	int verbose;

	int rc;
	unsigned long addr;
	unsigned long phys_addr;
	int numa_domain;
	int page_size;
	long alloc_sz;
	long small_alloc_sz;
	unsigned long node_mask;

	/* Defaults */
	error = 0;
	verbose = 0;
	small_alloc_sz = SMALL_ALLOC_SIZE;
	alloc_sz = ALLOC_SIZE;

	/* check command line args */
	while ((ch = getopt(argc, argv, "hs:v")) != EOF) {
		switch (ch) {
		case 'h':
			error = 1;
			break;
		case 's':
			alloc_sz = strtol(optarg, NULL, 10);
			break;
		case 'v':
			verbose++;
			break;
		default:
			error = 1;
			break;
		}
	}

	if (error) {
		usage(argv[0]);
		return -1;
	}

	printf("Testing the mos_get_addr_info() system call\n");
	printf("===========================================\n");



	printf("calloc(%ld) test:\n", small_alloc_sz);
	addr = (unsigned long)calloc(small_alloc_sz, 1);
	if ((void *)addr == 0)   {
		fprintf(stderr, "\tcalloc(%ld) failed\n", small_alloc_sz);
		goto err;
	}

	rc = mos_get_addr_info(addr, &phys_addr, &numa_domain, &page_size);
	if (rc != 0)   {
		fprintf(stderr,
			"\tmos_get_addr_info(0x%" PRIx64 ") failed: %s\n",
			addr, strerror(errno));
		goto err;
	}

	if (sanity_check(addr, phys_addr, numa_domain, page_size))
		goto err;

	printf("\tVirtual 0x%016" PRIx64 " is phys 0x%016" PRIx64
		". Page size %s, NUMA domain %d\n", addr, phys_addr,
		hunit(page_size), numa_domain);

	free((void *)addr);



	printf("mmap(len %ld) test:\n", alloc_sz);
	addr = (unsigned long)mmap(NULL, alloc_sz, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if ((void *)addr == MAP_FAILED)   {
		fprintf(stderr, "\tERROR: mmap(len %ld) failed!\n", alloc_sz);
		goto err;
	}

	/* Make sure the page is mapped */
	*((int *)addr) = 1;

	rc = mos_get_addr_info(addr, &phys_addr, &numa_domain, &page_size);
	if (rc != 0)   {
		fprintf(stderr, "\tmos_get_addr_info(0x%" PRIx64
			") failed: %s\n", addr, strerror(errno));
		goto err;
	}

	if (sanity_check(addr, phys_addr, numa_domain, page_size))
		goto err;

	printf("\tVirtual 0x%016" PRIx64 " is phys 0x%016" PRIx64
		". Page size %s, NUMA domain %d\n",
		addr, phys_addr, hunit(page_size), numa_domain);
	munmap((void *)addr, alloc_sz);


	/* One more time. This time, bind it domain 0 */
	printf("mmap(len %ld) test and bind to domain 0:\n", alloc_sz);
	addr = (unsigned long)mmap(NULL, alloc_sz, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if ((void *)addr == MAP_FAILED)   {
		fprintf(stderr, "\tERROR: mmap(len %ld) failed!\n", alloc_sz);
		goto err;
	}

	node_mask = 1;
	rc = mbind((void *)addr, alloc_sz, MPOL_BIND, &node_mask,
		sizeof(unsigned long), 0);
	if (rc < 0)   {
		fprintf(stderr, "\tmbind(0x%" PRIx64 ", len %ld) failed: %s\n",
			addr, alloc_sz, strerror(errno));
		goto err;
	}

	*((int *)addr) = 1;
	rc = mos_get_addr_info(addr, &phys_addr, &numa_domain, &page_size);
	if (rc != 0)   {
		fprintf(stderr,
			"\tmos_get_addr_info(0x%" PRIx64 ") failed: %s\n", addr,
			strerror(errno));
		goto err;
	}

	if (sanity_check(addr, phys_addr, numa_domain, page_size))
		goto err;

	if (numa_domain != 0)   {
		fprintf(stderr,
			"\tWARNING: Expected NUMA domain 0, but got %d\n",
			numa_domain);
		fprintf(stderr,
			"\tWARNING: This will only work with a working mOS mbind()\n");
		fprintf(stderr, "\tWARNING: Ignoring for now\n");
		//goto err;
	}

	printf("\tVirtual 0x%016" PRIx64 " is phys 0x%016" PRIx64
		". Page size %s, NUMA domain %d\n",
		addr, phys_addr, hunit(page_size), numa_domain);

	munmap((void *)addr, alloc_sz);



	printf("SUCCESS\n");
	return 0;

err:
	printf("FAIL\n");
	return -1;
}
