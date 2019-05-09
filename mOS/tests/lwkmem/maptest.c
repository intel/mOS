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

#define MAP "/proc/self/maps"
#define NOT_LWKMEM "(E) mapping not demarked as LWK memory: %s"
#define IS_LWKMEM "(I) mapping looks like LWK memory: %s"


static int verbose;
static char *argv0;
static uintptr_t page_size;

#define round_page(ptr) ((uintptr_t)(ptr) & ~(page_size - 1))
#define same_page(ptr1, ptr2) (round_page(ptr1) == round_page(ptr2))


struct allocation {
	size_t size;
	unsigned *data;
	struct allocation *next;
};

enum mapping_type { ANONYMOUS, DATA, HEAP, STACK, TEXT };


static void usage(void);
static int test_map(enum mapping_type type, struct allocation *nodes,
		    unsigned long num);
static int parse_options(int argc, char **argv, long *num_allocations,
			 size_t *size, size_t *min, size_t *max,
			 enum mapping_type *type, unsigned *iterations);
static long long get_lwkmem_free(void);
static struct allocation *create_mappings(enum mapping_type type,
					  long *num_mappings,
					  size_t size, size_t min,
					  size_t max);
static void destroy_mappings(enum mapping_type type,
			     struct allocation *head);

int main(int argc, char **argv)
{
	long num_allocations = 0;
	size_t size = 0;
	size_t min = 32, max = 127 * 1024;
	struct allocation *head = NULL;
	enum mapping_type type = -1;
	unsigned iterations = 1, i;
	int rc = 0;

	/* Save the name of this program. */
	argv0 = strrchr(argv[0], '/');
	if (!argv0)
		argv0 = argv[0];
	else
		argv0++;

	page_size = sysconf(_SC_PAGESIZE);

	rc = parse_options(argc, argv, &num_allocations, &size, &min, &max,
			   &type, &iterations);
	if (rc)
		goto out;

	for (i = 0; i < iterations && rc == 0; i++) {
		if (type == HEAP)
			head = create_mappings(type, &num_allocations, size,
					       min, max);
		else if (type == ANONYMOUS) {
			if (size & (page_size - 1)) {
				printf("Mapping size must be page aligned.\n");
				rc = -EINVAL;
			} else
				head = create_mappings(type, &num_allocations,
						       size, min, max);
		} else if (type == STACK) {
			head = malloc(sizeof(*head));
			if (head) {
				head->data = (unsigned *) &num_allocations;
				head->size = sizeof(num_allocations);
				head->next = NULL;
				num_allocations = 1;
			} else
				printf("(E) Out of memory!\n");
		} else if (type == TEXT) {
			head = malloc(sizeof(*head));
			if (head) {
				head->data = (unsigned *) main;
				head->size = sizeof(void *);
				head->next = NULL;
				num_allocations = 1;
			} else
				printf("(E) Out of memory!\n");
		} else {
			printf("Invalid type specified.\n");
			usage();
			goto out;
		}

		if (head) {
			rc = test_map(type, head, num_allocations);

			destroy_mappings(type, head);
		} else
			rc = -ENOMEM;
	}

out:
	printf("(I) Test %s.\n", rc ? "FAILED" : "PASSED");
	return rc;
}


static void usage(void)
{
	printf("maptest --type <heap | stack | text | anonymous>\n");
	printf("[--num <num-mappings> --size <size>] [--verbose] [--help]\n");
	printf("        [--min <size>] [--max <size>] [--seed <num>]\n");
	printf("        [--iterations <N>]\n");
	printf("  --num <num-allocations> specifies the number of regions\n");
	printf("         to allocate/map.  If -1 is specified then an\n");
	printf("         attempt is made to allocate nearly all LWK memory.\n");
	printf("  --size <size> specifies the data size of each region or\n");
	printf("         \"random\".  If random is specified, the --min\n");
	printf("         and --max options may be used to control the\n");
	printf("         minimum and maximum data region size.\n");
}


static int parse_options(int argc, char **argv, long *num_allocations,
			 size_t *size, size_t *min, size_t *max,
			 enum mapping_type *type, unsigned *iterations)
{
	static struct option options[] = {
		{ "num", required_argument, 0, 'n' },
		{ "size", required_argument, 0, 's' },
		{ "min", required_argument, 0, 'm' },
		{ "max", required_argument, 0, 'M' },
		{ "seed", required_argument, 0, 'S' },
		{ "verbose", no_argument, 0, 'V' },
		{ "help", no_argument, 0, 'h' },
		{ "type", required_argument, 0, 't' },
		{ "iterations", required_argument, 0, 'i' },
		{ 0, 0, 0, 0}
	};

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "n:s:m:M:S:v:h:t:i:",
				options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 'n': {
			*num_allocations = atoi(optarg);
			break;
		}

		case 's': {
			if (strcmp(optarg, "random") == 0) {
				time_t seed;
				*size = SIZE_MAX;
				seed = time(NULL);
				srand(seed);
				printf("(I) seed %ld\n", seed);
			} else
				*size = strtoul(optarg, 0, 0);
			break;
		}

		case 'm': {
			*min = atoi(optarg);
			break;
		}

		case 'M': {
			*max = atoi(optarg);
			break;
		}

		case 'S': {
			srand(strtoul(optarg, 0, 0));
			break;
		}

		case 'h': {
			usage();
			exit(0);
			break;
		}

		case 'V': {

			verbose = 1;
			break;
		}

		case 't': {
			if (strcmp(optarg, "anonymous") == 0)
				*type = ANONYMOUS;
			else if (strcmp(optarg, "data") == 0)
				*type = DATA;
			else if (strcmp(optarg, "heap") == 0)
				*type = HEAP;
			else if (strcmp(optarg, "stack") == 0)
				*type = STACK;
			else if (strcmp(optarg, "text") == 0)
				*type = TEXT;
			else
				*type = -1;
			break;
		}

		case 'i': {
			*iterations = atoi(optarg);
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



/* Open and parse /proc/self/maps, verifying that the specified
 * type of mappings use LWK memory.
 * Parameters:
 *	type		- type of mapping to verify
 *	head		- list of mappings of the specified type
 *	num_mappings	- number of mappings to verify
 *
 * The mappings in /proc/self/maps look like the following:
 *
 * 00400000-0040b000 r-xp 00000000 fe:00 135053901         /usr/bin/cat
 * 0060b000-0060c000 r--p 0000b000 fe:00 135053901         /usr/bin/cat
 * 0060c000-0060d000 rw-p 0000c000 fe:00 135053901         /usr/bin/cat
 * 02364000-02385000 rw-p 00000000 00:00 0                 [heap] LWK
 * 2ab550eb3000-2ab550eb4000 rw-p 00000000 00:00 0  LWK
 * 2ab550eb4000-2ab550eb5000 rw-p 00000000 00:00 0  LWK
 * 2ab550eb5000-2ab550eb7000 rw-p 00000000 00:00 0  LWK
 * 7ff14b0ec000-7ff151613000 r--p 00000000 fe:00 22549389  /usr/lib/locale
 * 7ff151613000-7ff1517c9000 r-xp 00000000 fe:00 201382981 /usr/lib64/libc.so
 * 7ff1517c9000-7ff1519c9000 ---p 001b6000 fe:00 201382981 /usr/lib64/libc.so
 * 7ff1519c9000-7ff1519cd000 r--p 001b6000 fe:00 201382981 /usr/lib64/libc.so
 * 7ff1519cd000-7ff1519cf000 rw-p 001ba000 fe:00 201382981 /usr/lib64/libc.so
 * 7ff1519cf000-7ff1519d4000 rw-p 00000000 00:00 0
 * 7ff1519d4000-7ff1519f5000 r-xp 00000000 fe:00 201383069 /usr/lib64/ld.so
 * 7ff151bf5000-7ff151bf6000 r--p 00021000 fe:00 201383069 /usr/lib64/ld.so
 * 7ff151bf6000-7ff151bf7000 rw-p 00022000 fe:00 201383069 /usr/lib64/ld.so
 * 7ff151bf7000-7ff151bf8000 rw-p 00000000 00:00 0
 * 7ffeae424000-7ffeae445000 rw-p 00000000 00:00 0         [stack]
 * 7ffeae5ae000-7ffeae5b0000 r--p 00000000 00:00 0         [vvar]
 */
static int test_map(enum mapping_type type, struct allocation *head,
		    unsigned long num_mappings)
{
	FILE *fptr;
	char buffer[4096];
	char *pathname = NULL;
	struct allocation *node, *copy;
	int rc = 0;

	fptr = fopen(MAP, "r");
	if (!fptr) {
		printf("(E) Could not open %s for reading. ", MAP);
		return -1;
	}

	/* Create a copy of the mapping list so we can destructively
	 * process the list.
	 */
	copy = malloc(num_mappings * sizeof(struct allocation));
	if (!copy) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(copy, head, num_mappings * sizeof(struct allocation));
	head = copy;

	while (fgets(buffer, sizeof(buffer), fptr) != NULL) {
		char read, write, execute, privacy;
		char device[8];
		unsigned long map_start, map_end, offset, inode;
		struct allocation *prev;

		if (verbose)
			printf("(maps): %s", buffer);

		/* Determine start and end address of this region. */
		if (sscanf(buffer, "%lx-%lx %c%c%c%c %lx %s %lu %m[^\n]",
			   &map_start, &map_end, &read, &write,
			   &execute, &privacy, &offset, device,
			   &inode, &pathname) < 9) {
			rc = -1;
			goto out;
		}

		/* Verify that heap mapping is marked as LWK memory. */
		if (type == HEAP && strstr(buffer, "[heap]") &&
		    !strstr(buffer, "LWK")) {
			printf("(E) heap mapping not LWK memory: %s", buffer);
			rc = -1;
			goto out;
		}

		/* Verify that stack mapping is marked as LWK memory. */
		if (type == STACK && strstr(buffer, "[stack]") &&
		    !strstr(buffer, "LWK")) {
			printf("(E) stack mapping not LWK memory: %s", buffer);
			rc = -1;
			goto out;
		}

		/* Verify that text mapping is marked as LWK memory. */
		if (type == TEXT && read == 'r' && write == '-' &&
		    execute == 'x' && strstr(buffer, argv0) &&
		    !strstr(buffer, "LWK")) {
			printf("(E) text mapping not LWK memory: %s", buffer);
			rc = -1;
			goto out;
		}

		/* Find the node that matches this region. */
		for (node = head, prev = NULL; node != NULL;
		     node = node->next) {
			unsigned long node_start = (unsigned long) node->data;
			unsigned long node_end = node_start + node->size;

			if ((map_start <= node_start &&
			     map_end > node_start) ||
			    (map_end >= node_end &&
			     map_start < node_end)) {
				if (!strstr(buffer, "LWK")) {
					printf(NOT_LWKMEM, buffer);
					rc--;
				}

				/* Remove this node from the list. */
				if (prev)
					prev->next = node->next;
				else
					head = node->next;
			} else
				prev = node;
		}

		if (pathname) {
			free(pathname);
			pathname = NULL;
		}
	}

	/* If all mappings were verified then the list should be empty. */
	if (head) {
		printf("Failed to locate one or more mappings!\n");
		rc = -EINVAL;
	}

out:
	if (pathname)
		free(pathname);

	if (copy)
		free(copy);

	fclose(fptr);

	return rc;
}


static long long get_lwkmem_free(void)
{
	char buffer[4096];
	FILE *fptr = NULL;
	long long rc;

	fptr = fopen("/proc/meminfo", "r");
	if (!fptr) {
		printf("(E) Could not open %s for reading. ", "/proc/meminfo");
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fptr) != NULL) {
		if (sscanf(buffer, "MemFree: %lld kB", &rc) == 1) {
			rc *= 1024;
			break;
		}
	}

	fclose(fptr);

	if (verbose)
		printf("There are %lld bytes of free memory.\n", rc);

	return rc;
}


static struct allocation *create_mappings(enum mapping_type type,
					  long *num_mappings, size_t size,
					  size_t min, size_t max)
{
	long i, j;
	long long remainder, free_mem;
	long long min_size = (type == ANONYMOUS ? page_size : 1);
	struct allocation *head = NULL, *prev = NULL, *node;
	unsigned *last_data = NULL;
	unsigned long total_bytes_allocated = 0;

	if (*num_mappings == 0 || size <= 0) {
		printf("(E) Specify both number and size of allocations.\n");
		usage();
		return NULL;
	}

	if (min > max) {
		printf("(E) Minimum must be less than maximum.\n");
		usage();
		return NULL;
	}

	/* If num_mappings < 0 then we exhaust available LWK memory. */
	if (*num_mappings < 0) {
		size_t s = size;

		/* Determine how many allocations are needed to use most
		 * of the memory.  Due to overhead we stop about .7% short.
		 */
		*num_mappings = 0;
		free_mem = get_lwkmem_free();
		free_mem = remainder = free_mem * .993;
		while (free_mem >= min_size) {
			while (s > free_mem && s > min_size)
				s >>= 1;
			free_mem -= s;
			(*num_mappings)++;
		}
		remainder -= (*num_mappings * sizeof(struct allocation));
	} else
		remainder = *num_mappings * size;

	/* Construct a list of data areas per the input parameters.
	 * The data area of each node is colored with its index.
	 */
	head = malloc(sizeof(struct allocation) * *num_mappings);
	if (!head) {
		printf("(E) Out of memory!\n");
		return NULL;
	}

	if (verbose)
		printf("[----] nodes=%p sizeof=%zd num=%ld\n",
			head, sizeof(*head), *num_mappings);

	for (i = 1, node = head; i <= *num_mappings; i++, node++) {

		if (size == SIZE_MAX)
			node->size = min + rand() % (max - min);
		else {
			while (size > remainder && size > min_size)
				size >>= 1;
			node->size = size;
		}

		if (prev)
			prev->next = node;
		prev = node;
		node->next = NULL;

		if (type == HEAP)
			node->data = malloc(node->size);
		else if (type == ANONYMOUS) {
			node->data = mmap(NULL, node->size, PROT_READ |
					  PROT_WRITE, MAP_PRIVATE |
					  MAP_ANONYMOUS, -1, 0);
			if (node->data == MAP_FAILED) {
				perror("Failed mmap.");
				goto free_nodes;
			}
		} else {
			printf("Unsupported type %u\n", type);
			goto free_nodes;
		}

		if (!node->data) {
			printf("(E) Out of memory!\n");
			goto free_nodes;
		}

		remainder -= node->size;
		total_bytes_allocated += node->size;

		/* Color this node. */
		for (j = 0; j < node->size; j += page_size)
			node->data[j/sizeof(*node->data)] = i;

		if (verbose && (size == SIZE_MAX || i < 16 || !same_page(last_data, node->data))) {
			printf("[%4ld] %p [%ld]\n",
				i, node->data, node->size);
			last_data = node->data;
		}
	}

	if (verbose)
		printf("%ld total bytes allocated.\n", total_bytes_allocated);

	/* Walk the list, ensuring that the coloring is correct. */
	for (i = 1, node = head; i <= *num_mappings; i++, node++)
		for (j = 0; j < node->size; j += page_size)
			if (node->data[j/sizeof(*node->data)] != i) {
				printf("(E) miscompare in node %ld at %ld: %d\n"
					, i, j, node->data[j]);
				goto free_nodes;
			}

	return head;

free_nodes:
	destroy_mappings(type, head);
	return NULL;
}


static void destroy_mappings(enum mapping_type type, struct allocation *head)
{
	struct allocation *node;

	for (node = head; node != NULL; node = node->next)
		if (node->data) {
			if (type == HEAP)
				free(node->data);
			else if (type == ANONYMOUS)
				munmap(node->data, node->size);
		}

	free(head);
}
