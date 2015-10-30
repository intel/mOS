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

/*
** Test whether get_user_pages() works on mOS.
** LWK memory has no struct pages, so we have to make sure this function works.
**
** Make sure the gup_module kernel module has been inserted into the kernel,
** and the device /dev/gup_test exists and is writable:
**     sudo mknod /dev/gup_test c <major> 0
**     sudo chmod 222 /dev/gup_test
** where the <major> number is supplied by the kernel module when it is
** inserted.
**
** We have these types of memory:
**     stack
**     bss
**     heap
**     anonymous mmap
**     file-backed mmap
**
** As of this writing, only anonymous mmap is LWK memory in mOS. Large enough
** maloc() calls get turned into anonymous mmap by the C library and also get
** allocated from LWK memory.
** There are plans to move some of the other segments, but not file-backed mmap
** into LWK memory.
**
** The gup_module module uses get_user_pages() to get access to these pages
** like a DMA driver would and performs the copy. To keep things simple,
** source and destination addresses are aligned to page boundaries, and lengths
** are multiples of page size.
** This program uses each of the memory types above at least once as a source,
** and at least once as a destination.
**
** Rolf Riesen, November 2015, Intel
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <alloca.h>

#define PAGE_SIZE		(4096)
#define ALIGN			(int64_t)(~(PAGE_SIZE - 1))
#define DEFAULT_SMALL_SIZE	(PAGE_SIZE)
#define DEFAULT_LARGE_SIZE	(256 * PAGE_SIZE)
#define TwoGig			((size_t)2 * 1024 * 1024 * 1024)

#define MAX_TEST_NUM	11
typedef enum { t_alloc, t_fill, t_copy, t_check, t_max } time_cat_t;
double times[t_max][MAX_TEST_NUM];

static void usage(char *pname)
{
	fprintf(stderr,
		"Usage: %s [-f] [-s <small>] [-S <large>] [-v {-v}] [-h]\n"
		"    -f           Force it to run, even on non-mOS systems\n"
		"    -s <small>   Allocation on stack. Default %d bytes\n"
		"    -S <large>   Allocation on heap and mmap. Default %d bytes\n"
		"    -v           Increase verbosity\n"
		"    -h           Display this help info\n",
		pname, DEFAULT_SMALL_SIZE, DEFAULT_LARGE_SIZE);
}

static char *get_mOS_version(void)
{
#define BUF_SIZE	(256)
	FILE *fp;
	static char buf[BUF_SIZE];

	fp = fopen("/sys/kernel/mOS/version", "r");
	if (fp == NULL)
		return NULL;

	fread(buf, 1, BUF_SIZE, fp);
	if (ferror(fp))
		return NULL;

	return buf;
}

#define CLK_ID	(CLOCK_MONOTONIC_RAW)
static double mysecond(void)
{
	int rc;
	struct timespec tm;

	rc = clock_gettime(CLK_ID, &tm);
	if (rc) {
		perror("clock_gettime() failed!");
		abort();
	}
	return tm.tv_sec + tm.tv_nsec / 1000000000.0;
}

static void print_clock_res(void)
{
	int rc;
	struct timespec tm;

	rc = clock_getres(CLK_ID, &tm);
	if (rc) {
		perror("clock_getres() failed!");
		abort();
	}
	printf("Clock resolution is %ld.%09ld seconds\n", (long)tm.tv_sec,
	       tm.tv_nsec);
}

static void do_kernel_copy(int fd, void *src, void *dst, unsigned long len,
			   int verbose)
{
	struct {
		void *src;
		void *dst;
		unsigned long len;
		int verbose;
	} args;

	int rc;

	args.src = src;
	args.dst = dst;
	args.len = len;
	args.verbose = verbose;

	rc = write(fd, &args, sizeof(args));
	if (rc != sizeof(args)) {
		fprintf(stderr, "Write to device failed: %s\n",
			strerror(errno));
		exit(1);
	}
}

#define alloc_stack(size, t, verbose)					\
({									\
	double __t0;							\
	void *ptr;							\
									\
	/* alloca() doesn't return NULL on error */			\
	if (verbose > 0) {						\
		printf("  %-14s (alloca)         %14zd bytes\n", "stack", size);	\
	}								\
	__t0 = mysecond();						\
	ptr = (void *)(((int64_t)alloca(size + PAGE_SIZE) + PAGE_SIZE) &ALIGN);		\
	t = mysecond() - __t0;						\
	ptr;								\
})

static char bss_base[DEFAULT_SMALL_SIZE + PAGE_SIZE];
static void *bss;
static void *alloc_bss(size_t size, double *t, int verbose)
{
	double t0;

	t0 = mysecond();
	bss = (void *)(((int64_t) bss_base + PAGE_SIZE) & ALIGN);
	*t = mysecond() - t0;
	if (verbose > 0) {
		printf("  %-14s                  %14zd bytes\n", "bss area",
		       size);
	}

	return bss;
}

static void *alloc_heap(size_t size, double *t, int verbose)
{
	void *ptr;
	double t0;

	t0 = mysecond();
	ptr = malloc(size + PAGE_SIZE);
	*t = mysecond() - t0;

	if (ptr == NULL) {
		fprintf(stderr, "FAILED: Malloc for %zd bytes failed!\n", size);
		exit(2);
	}
	ptr = (void *)(((int64_t) ptr + PAGE_SIZE) & ALIGN);
	if (verbose > 0)
		printf("  %-14s (malloced)       %14zd bytes\n", "heap", size);

	return ptr;
}

static void *alloc_file(size_t size, double *t, int verbose)
{
#define INIT_BLOCK_SIZE	(2048)
	void *ptr;
	char ftemplate[] = "SomeFileXXXXXX";
	char init_block[INIT_BLOCK_SIZE];
	int tmp_fd;
	int i;
	double t0;

	t0 = mysecond();
	tmp_fd = mkostemp(ftemplate, O_RDWR | O_CREAT);
	if (tmp_fd == -1) {
		fprintf(stderr, "FAILED: open(): %s\n", strerror(errno));
		exit(3);
	}

	/* The actual unlink will happen on close */
	unlink(ftemplate);

	/* Needed so we can mmap it */
	for (i = 0; i < size + PAGE_SIZE; i = i + INIT_BLOCK_SIZE)
		write(tmp_fd, init_block, INIT_BLOCK_SIZE);

	ptr = mmap(NULL, size + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE,
		   tmp_fd, 0);
	*t = mysecond() - t0;
	if (ptr == MAP_FAILED) {
		fprintf(stderr,
			"FAILED: file-backed mmap() of size %zd failed: %s\n",
			size + PAGE_SIZE, strerror(errno));
		exit(4);
	}
	ptr = (void *)(((int64_t) ptr + PAGE_SIZE) & ALIGN);
	if (verbose > 0) {
		printf("  %-14s (not LWK memory) %14zd bytes\n", "mmap file",
		       size);
	}

	return ptr;
}

static void *alloc_anonymous(size_t size, double *t, int verbose)
{
	void *ptr;
	double t0;

	t0 = mysecond();
	ptr = mmap(NULL, size + PAGE_SIZE, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	*t = mysecond() - t0;
	if (ptr == MAP_FAILED) {
		fprintf(stderr, "FAILED: mmap() of size %zd failed: %s\n",
			size + PAGE_SIZE, strerror(errno));
		exit(5);
	}
	ptr = (void *)(((int64_t) ptr + PAGE_SIZE) & ALIGN);
	if (verbose > 0) {
		printf("  %-14s (LWK memory)     %14zd bytes\n",
		       "mmap anonymous", size);
	}

	return ptr;
}

static void fill_data(void *mem, size_t size, int test_num)
{
	int num_ints;
	int i;
	int *ptr;
	double t0;

	num_ints = size / sizeof(int);
	ptr = (int *)mem;

	t0 = mysecond();
	for (i = 0; i < num_ints; i++) {
		*ptr = random();
		ptr++;
	}
	times[t_fill][test_num] = mysecond() - t0;
}

static void check_data(void *src, void *dst, size_t size, int test_num,
		       int verbose)
{
	int num_ints;
	int i;
	int *ptr1, *ptr2;
	double t0;

	num_ints = size / sizeof(int);
	ptr1 = (int *)src;
	ptr2 = (int *)dst;

	t0 = mysecond();
	for (i = 0; i < num_ints; i++) {
		if (*ptr1 != *ptr2) {
			fprintf(stderr, "FAILED: Test %d. index %d: %d != %d\n",
				test_num, i, *ptr1, *ptr2);
			exit(6);
		}
		ptr1++;
		ptr2++;
	}
	times[t_check][test_num] = mysecond() - t0;

	if (verbose > 1) {
		printf("       %10zd bytes from %p to %p succeeded\n", size,
		       src, dst);
	}
}

static void do_test(int fd, int test_num, void *src, void *dst, size_t size,
		    char *src_name, char *dst_name, int verbose)
{
	double t0;

	fill_data(src, size, test_num);
	printf("%5d: %s memory to %s\n", test_num, src_name, dst_name);
	t0 = mysecond();
	do_kernel_copy(fd, src, dst, size, verbose);
	times[t_copy][test_num] = mysecond() - t0;
	check_data(src, dst, size, test_num, verbose);
}

static void do_operlap_test(int fd, int test_num, void *start, size_t size,
			    int verbose)
{
	int64_t chksum1, chksum2;
	int *ptr;
	int num_ints, i;
	double t0;

	/* Overlapping region */
	printf("%5d: Overlapping LWK region\n", test_num);
	fill_data(start, size, test_num);
	num_ints = (size - PAGE_SIZE) / sizeof(int);
	ptr = start + PAGE_SIZE;
	chksum1 = 0;
	for (i = 0; i < num_ints; i++) {
		chksum1 = chksum1 + *ptr;
		ptr++;
	}

	t0 = mysecond();
	do_kernel_copy(fd, start + PAGE_SIZE, start, size - PAGE_SIZE, verbose);
	times[t_copy][test_num] = mysecond() - t0;

	ptr = start;
	chksum2 = 0;
	for (i = 0; i < num_ints; i++) {
		chksum2 = chksum2 + *ptr;
		ptr++;
	}

	if (chksum1 == chksum2) {
		if (verbose > 1) {
			printf
			    ("       %10zd bytes from %p to %p succeeded. Check sum %ld\n",
			     size, start + PAGE_SIZE, start, chksum1);
		}
	} else {
		fprintf(stderr, "FAILED: Test %d. Check sum %ld != %ld\n",
			test_num, chksum1, chksum2);
		exit(7);
	}
}

int main(int argc, char *argv[])
{
	int ch, error;
	int verbose;
	int force;

	size_t large_size;
	size_t small_size;
	size_t bss_size;

	int dev_fd;
	char *ver;

	void *mem_heap_small;
	void *mem_heap_large;
	void *mem_stack;
	void *mem_anonymous;
	void *mem_file;
	void *mem_bss;

	int test_num;
	double t0;
	int i;

	/* Defaults */
	error = 0;
	force = 0;
	verbose = 0;
	test_num = 1;
	large_size = DEFAULT_LARGE_SIZE;
	small_size = DEFAULT_SMALL_SIZE;
	bss_size = DEFAULT_SMALL_SIZE;

	/* check command line args */
	while ((ch = getopt(argc, argv, "fhs:S:v")) != EOF) {
		switch (ch) {
		case 'f':
			force = 1;
			break;
		case 'h':
			error = 1;
			break;
		case 's':
			small_size = strtol(optarg, NULL, 0);
			if (small_size < 1) {
				fprintf(stderr, "-s must be > 0!\n");
				error = 1;
			}
			if (small_size < DEFAULT_SMALL_SIZE) {
				/* Only use requested size for bss if it fits */
				bss_size = small_size;
			}
			break;
		case 'S':
			large_size = strtol(optarg, NULL, 0);
			if (large_size < PAGE_SIZE) {
				fprintf(stderr, "-S must be >= %d!\n",
					PAGE_SIZE);
				error = 1;
			}
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
		return 10;
	}

	if ((verbose > 0) && (small_size > bss_size)) {
		printf("Warning: Will use %zd bss, not requested %zd\n",
		       bss_size, small_size);
	}

	ver = get_mOS_version();
	if (ver) {
		printf("mOS system version %s\n", ver);
	} else if (force) {
		printf("Not an mOS system; continuing anyway\n");
	} else {
		fprintf(stderr, "FAILED: This is not an mOS system\n");
		return 11;
	}
	print_clock_res();

	dev_fd = open("/dev/gup_test", O_WRONLY);
	if (dev_fd < 0) {
		fprintf(stderr, "FAILED: open(/dev/gup_test) failed: %s\n",
			strerror(errno));
		return 12;
	}

	/* Initialize the random number generator */
	srandom(time(NULL));

	/* Make sure all sizes are multiple of PAGE_SIZE */
	large_size = large_size & ALIGN;
	small_size = small_size & ALIGN;
	bss_size = bss_size & ALIGN;

	/* Allocate memory */
	if (verbose > 0)
		printf("Allocate memory:\n");

	mem_stack = alloc_stack(small_size, t0, verbose);
	times[t_alloc][0] = t0;
	mem_bss = alloc_bss(bss_size, &t0, verbose);
	times[t_alloc][1] = t0;
	mem_heap_small = alloc_heap(small_size, &t0, verbose);
	times[t_alloc][2] = t0;
	mem_heap_large = alloc_heap(large_size, &t0, verbose);
	times[t_alloc][3] = t0;
	mem_file = alloc_file(large_size, &t0, verbose);
	times[t_alloc][4] = t0;
	mem_anonymous = alloc_anonymous(large_size, &t0, verbose);
	times[t_alloc][5] = t0;

	if (verbose > 0)
		printf("\n");

	if (verbose > 1) {
		printf("Addresses:\n");
		printf("  stack                         %16p\n", mem_stack);
		printf("  bss                           %16p\n", mem_bss);
		printf("  heap (small)                  %16p\n",
		       mem_heap_small);
		printf("  heap (large)                  %16p\n",
		       mem_heap_large);
		printf("  mmap file                     %16p\n", mem_file);
		printf("  mmap anonymous                %16p\n", mem_anonymous);
		printf("\n");
	}

	/* stack, bss, heap, and file-backed to anonymous */
	printf("Tests:\n");
	do_test(dev_fd, test_num++, mem_stack, mem_anonymous, small_size,
		"stack", "(LWK) anonymous memory", verbose);
	do_test(dev_fd, test_num++, mem_bss, mem_anonymous, bss_size,
		"bss", "(LWK) anonymous memory", verbose);
	do_test(dev_fd, test_num++, mem_heap_small, mem_anonymous, small_size,
		"heap (small)", "(LWK) anonymous memory", verbose);
	do_test(dev_fd, test_num++, mem_heap_large, mem_anonymous, large_size,
		"heap (large)", "(LWK) anonymous memory", verbose);
	if (large_size <= (TwoGig - PAGE_SIZE)) {
		do_test(dev_fd, test_num++, mem_file, mem_anonymous, large_size,
			"file-backed mmap", "(LWK) anonymous memory", verbose);
	} else {
		printf("%5d: Not doing %s memory to %s: File too large!\n",
		       test_num, "file-backed mmap", "(LWK) anonymous memory");
	}

	/* anonymous to stack, bss, heap, and file-backed */
	do_test(dev_fd, test_num++, mem_anonymous, mem_stack, small_size,
		"(LWK) anonymous", "stack", verbose);
	do_test(dev_fd, test_num++, mem_anonymous, mem_bss, bss_size,
		"(LWK) anonymous", "bss", verbose);
	do_test(dev_fd, test_num++, mem_anonymous, mem_heap_small, small_size,
		"(LWK) anonymous", "heap (small)", verbose);
	do_test(dev_fd, test_num++, mem_anonymous, mem_heap_large, large_size,
		"(LWK) anonymous", "heap (large)", verbose);
	if (large_size <= (TwoGig - PAGE_SIZE)) {
		do_test(dev_fd, test_num++, mem_anonymous, mem_file, large_size,
			"(LWK) anonymous", "file-backed mmap", verbose);
	} else {
		printf("%5d: Not doing %s memory to %s: File too large!\n",
		       test_num, "(LWK) anonymous", "file-backed mmap");
	}

	do_operlap_test(dev_fd, test_num++, mem_anonymous, large_size, verbose);

	if (verbose > 1) {
		printf("Allocation Times:\n");
		printf("  stack                            %10.6f s\n",
		       times[t_alloc][0]);
		printf("  bss                              %10.6f s\n",
		       times[t_alloc][1]);
		printf("  heap (small)                     %10.6f s\n",
		       times[t_alloc][2]);
		printf("  heap (large)                     %10.6f s\n",
		       times[t_alloc][3]);
		printf("  mmap file                        %10.6f s\n",
		       times[t_alloc][4]);
		printf("  mmap anonymous                   %10.6f s\n",
		       times[t_alloc][5]);
		printf("\n");

		printf("Test Times:\n");
		printf("Numt         Fill           Copy          Check\n");
		for (i = 0; i < test_num - 1; i++) {
			printf("%2d   %10.6f s   %10.6f s   %10.6f s\n", i + 1,
			       times[t_fill][i], times[t_copy][i],
			       times[t_check][i]);
		}
	}

	printf("SUCCESS\n");
	return 0;
}
