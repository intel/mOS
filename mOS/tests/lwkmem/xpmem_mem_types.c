/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018 Intel Corporation.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <xpmem.h>
#include "xpmem_utils.h"

#define OWNER				0
#define NONOWNER			1

#define SHMEM_FILE			"/tmp/xpmem.file"
#define SHMEM_TEST_FILE			"/tmp/xpmem.test.file"

/* Flags to synchronize owner and non-owner accesses */
#define STAT_OWNER_READY		(1 << 0)
#define STAT_OWNER_DONE			(1 << 1)
#define STAT_NONOWNER_READY		STAT_OWNER_READY
#define STAT_NONOWNER_DONE		STAT_OWNER_DONE
#define WAIT_FOR_BITCLR			0
#define WAIT_FOR_BITSET			1
#define TIMEOUT				120 /* seconds */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (4096)
#endif

#define LOG(format, ...) \
	printf("[%-9s : pid %d] " format "\n",\
			proc_types[proc], getpid(), ##__VA_ARGS__)
#define MATCH(a, b)	(strcmp(a, b) == 0)

/* Flags for types of memory area */
#define bit(N)			(((unsigned long) 0x1) << (N))
#define data_bss		bit(0)
#define heap			bit(1)
#define mmap_anon_private	bit(2)
#define mmap_anon_shared	bit(3)
#define mmap_file		bit(4)
#define stack_main		bit(5)
#define stack_thread		bit(6)
#define entire_address_space	bit(7)	/* Note: this may not be equivalent  */
					/* to specifying all of the above.   */
#define mmap_anon_mixed		bit(8)
#define mmap_anon_mixed_inv	bit(9)
#define KB(v)	(((unsigned long)(v)) << 10)
#define MB(v)	(((unsigned long)(v)) << 20)
#define GB(v)	(((unsigned long)(v)) << 30)

/* Flags to assist data verification */
#define ACTION_RDONLY           	0
#define ACTION_RW               	1

/**
 * The following data is shared between processes.  Traditional Linux shared
 * memory mechanisms are used.
 *
 * 1. Owner process creates an XPMEM share covering the range of virtual address
 *    space of specified memory type. I
 * 2. Owner fills the XPMEM shared memory with the pre-defined data and writes
 *    the corresponding magic number using the below shared memory structure.
 * 3. Non-owner process attaches the XPMEM shared segment and verfifies the
 *    data using magic number written by the owner.
 * 4. If the share is a read/write memory type then the non-owner re-fills the
 *    region and overwrites the magic number.
 * 5. Owner process upon complettion signal from non-owner verifies the buffer
 *    data using the magic number.
 *
 */
struct shinfo_t {
	/* XPMEM share info. */
	xpmem_segid_t segid;
	unsigned long data_size;
	/* offset where there is valid mappings. Hint for non-owner */
	unsigned long offset;

	/* Magic number anticipated at the start of a share. */
	unsigned long magic;
	/* Expected action from non-owner. */
	int rw;

	/* Synchronization flags. Can do better job using file locks.*/
	/* This should be sufficient for the given test envionment.  */
	unsigned long status[2];
};

/* Common globals */
struct memory {
	unsigned long type;
	char *opt;
	char *desc;
} mems[] = {
	{ data_bss,		"static",	  ".data/.bss area" },
	{ heap,			"heap",		  "Process heap" },
	{ mmap_anon_private,	"anon_private",	  "Anonymous private mmap" },
	{ mmap_anon_shared,	"anon_shared",	  "Anonymous shared mmap" },
	{ mmap_file,		"mmap_file",	  "File backed mmap" },
	{ stack_main,		"stack_main",	  "Process stack" },
	{ stack_thread,		"stack_thread",   "Thread stack" },
	{ entire_address_space,	"eas",		  "Entire address space" },
	{ mmap_anon_mixed,	"anon_mixed",	  "Anon private and shared" },
	{ mmap_anon_mixed_inv,	"anon_mixed_inv", "Anon shared and private" },
};

unsigned long page_sizes[] = { KB(4), MB(2), MB(4), GB(1) };
char *proc_types[] = { "owner", "non-owner" };
int proc;
struct shinfo_t *shmem;
unsigned long m_types;
unsigned long m_size;
unsigned long m_align;

/* Fixed sized data/bss region */
unsigned char data_bss_buffer[MB(128)] __attribute__((aligned(MB(2))));
unsigned long data_bss_buffer_size = MB(128);

/* Functions for handling data */

/* Buffer format,
 *
 * <Virtual address>   < Data >
 *                     +-------+
 *  addr               |addr   |
 *  addr+8             |addr+8 |
 *  addr+16            |addr+16|
 *     .               |   .   |
 *     .               |   .   |
 *                     +-------+
 *
 * shmem->magic = addr
 *
 * For fill_buffer,
 *  In Owner process,     addr -> Starting address of XPMEM shared segment.
 *  In Non-owner process, addr -> Starting address of XPMEM attachment.
 *
 * Exception to this rule is for memtype 'eas'. In this case owner process
 * shares its entire virtual address space. But that could have holes in it.
 * So we use the data/bss buffer of the owner to attach to in the non-owner
 * and verification of data. So for this case addr will be the start of
 * data_bss_buffer in the owner process and the owner process fills it and
 * sets the offset and magic value. The non-owner uses the offset during
 * attachment and verifies the data and re-fills it with new data.
 *
 * In order to save time, we only write and verify the first entry (64 bits)
 * of every 4KiB page.
 */
static void fill_buffer(unsigned char *buffer, unsigned long size,
		unsigned long magic)
{
	unsigned long *ptr = (unsigned long *) buffer;
	unsigned long i, count = size / sizeof(unsigned long);
	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);

	LOG("Writing to buffer");
	for (i = 0; i < count; i += stride, ptr += stride)
		*ptr = magic + i * sizeof(magic);
}

static int verify_buffer(unsigned char *buffer, unsigned long size,
		unsigned long magic)
{
	unsigned long *ptr = (unsigned long *) buffer;
	unsigned long i, count = size / sizeof(unsigned long);
	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);

	LOG("Verifying buffer contents");
	for (i = 0; i < count; i += stride, ptr += stride) {
		if (*ptr != magic + i * sizeof(magic)) {
			LOG("Mismatch at %p [count = %ld] expected %lx got %lx",
					ptr, i, magic + i * sizeof(magic),
					*ptr);
			return -1;
		}
	}
	return 0;

}

/*
 * Common interface helpers for allocation/deallocation of buffers and alignment.
 */
static unsigned char *allocate_buffer(unsigned long type, unsigned long *size,
				      int *rw, unsigned char **map1,
				      unsigned  char **map2)
{
	unsigned char *buffer = NULL;
	unsigned long part, map1_flags, map2_flags;
	*rw = ACTION_RW;

	switch (type) {
	case data_bss:
		buffer = data_bss_buffer;
		*size = data_bss_buffer_size;
		break;

	case heap:
		buffer = (unsigned char *) malloc(*size);
		break;

	case mmap_anon_private:
		buffer = mmap(NULL, *size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		break;

	case mmap_anon_shared:
		buffer = mmap(NULL, *size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		break;

	case mmap_file:
		buffer = create_shared_mem(SHMEM_TEST_FILE, *size, O_CREAT);
		break;

	case stack_thread:
		buffer = mmap(NULL, *size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK |
			      MAP_NORESERVE, -1, 0);
		break;

	case entire_address_space:
		*size = -1;
		break;

	case mmap_anon_mixed:
	case mmap_anon_mixed_inv:
		if (*size < KB(16)) {
			LOG("%s(): size (%ld) need to be atleast 4*4kb long",
			    __func__, *size);
			break;
		}
		if (!map1 || !map2) {
			LOG("%s(): Invalid params map1 = %p map2 = %p",
			    __func__, map1, map2);
			break;
		}

		buffer = mmap(NULL, *size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (munmap(buffer, *size)) {
			LOG("%s() Failed to unmap buffer", __func__);
			break;
		}

		part = *size / 2;
		/* aligned to 4k pages */
		part = (part / KB(4)) * KB(4);
		map1_flags = map2_flags = MAP_ANONYMOUS | MAP_FIXED;

		if (type == mmap_anon_mixed) {
			map1_flags |= MAP_PRIVATE;
			map2_flags |= MAP_SHARED;
		} else {
			map1_flags |= MAP_SHARED;
			map2_flags |= MAP_PRIVATE;
		}

		*map1 = mmap(buffer, part, PROT_READ | PROT_WRITE,
			     map1_flags, -1, 0);
		if (*map1 == NULL) {
			LOG("%s() Failed to map first half", __func__);
			buffer = NULL;
			break;
		}
		*map2 = mmap(buffer + part, *size - part,
			     PROT_READ | PROT_WRITE,
			     map2_flags, -1, 0);
		if (*map2 == NULL || *map2 != (buffer + part)) {
			munmap(*map1, part);
			if (*map2)
				munmap(*map2, *size - part);
			LOG("%s() Failed to map second half", __func__);
			buffer = NULL;
			break;
		}
		break;
	default:
		LOG("%s: Invalid type %ld", __func__, type);
		break;
	}
	return buffer;
}

static int deallocate_buffer(unsigned long type, unsigned char *buffer,
		unsigned long size)
{
	int status = -1;

	switch (type) {
	case data_bss:
	case entire_address_space:
		status = 0;
		break;

	case heap:
		free(buffer);
		status = 0;
		break;

	case mmap_anon_private:
	case mmap_anon_shared:
	case mmap_anon_mixed:
	case mmap_anon_mixed_inv:
	case mmap_file:
	case stack_thread:
		status = munmap(buffer, size);
		if (type == mmap_file) {
			if (remove(SHMEM_TEST_FILE))
				LOG("Failed to delete: %s", SHMEM_TEST_FILE);
			else
				LOG("Deleted file: %s", SHMEM_TEST_FILE);
		}
		break;

	default:
		LOG("%s: Invalid type %ld", __func__, type);
		break;
	}
	return status;
}

static void *align_address(void *addr, unsigned long align)
{
	unsigned long aligned_addr = (unsigned long) addr;
	unsigned long offset;

	if ((unsigned long)addr % align) {
		offset = align - ((unsigned long)addr % align);
		aligned_addr += offset;
	}
	return (void *) aligned_addr;
}

/* Helper functions for XPMEM transfer synchronization */
static inline void setflags(unsigned long flags)
{
	shmem->status[proc] |= flags;
}

static inline void clrflags(unsigned long flags)
{
	shmem->status[proc] &= ~flags;
}

/*
 * Check if any of the specified flags are set. Caller responsibility to
 * test again the bit of interest to check if that was originally set.
 */
static inline int testflags(unsigned long flags)
{
	int i = proc == OWNER ? NONOWNER : OWNER;

	return (shmem->status[i] & flags) != 0;
}

static int wait(unsigned long flags, int for_bitset)
{
	int udelay = 10000; /* 10 millis */
	int timeout = 1000000 / udelay * TIMEOUT; /* iterations */
	int cond = 1;

	while (cond && timeout--) {
		cond = for_bitset ? !testflags(flags) : testflags(flags);
		if (cond)
			usleep(udelay);
	}

	if (timeout < 0) {
		LOG("Timeout");
		return -1;
	}
	return 0;
}

/* Command line parsing */
static int get_mem_types(char *input)
{
	char *copy = strdup(input);
	char *buffer = copy;
	char *tok;
	int i, match;

	m_types = 0;
	tok = strtok(copy, ",");
	while (tok) {
		match = 0;
		if (MATCH(tok, "all")) {
			for (i = 0; i < ARRAY_SIZE(mems); i++)
				m_types |= mems[i].type;
			break;
		}
		for (i = 0; i < ARRAY_SIZE(mems); i++) {
			if (MATCH(tok, mems[i].opt)) {
				m_types |= mems[i].type;
				match = 1;
				break;
			}
		}

		if (!match)
			LOG("WARN: Invalid mem type: [%s]", tok);
		tok = strtok(NULL, ",");
	}

	if (buffer)
		free(buffer);
	return m_types ? 0 : -1;
}

static int parse_args(int argc, char **argv)
{
	int i, j = 1;
	long size;
	long align;

	if (MATCH(argv[1], "--help"))

		goto help;

	if (MATCH("--owner", argv[1])) {
		if (argc > 8 || argc < 4)
			goto help;
		proc = OWNER;
	} else if (MATCH("--nonowner", argv[1])) {
		if (argc != 2)
			goto help;
		proc = NONOWNER;
	} else {
		printf("(E) Specify --owner/--nonowner as first argument.\n");
		return -1;
	}

	shmem = create_shared_mem(SHMEM_FILE, sizeof(struct shinfo_t),
			proc == OWNER ? O_CREAT : 0);
	if (!shmem) {
		printf("Failed to open shared memory\n");
		return -1;
	}

	if (proc == OWNER) {
		m_types = 0;
		m_size  = 0;
		m_align = 0;

		for (j = 2; j < argc; j++) {
			if (MATCH(argv[j], "--type")) {
				if (++j >= argc)
					goto help;
				if (get_mem_types(argv[j]))
					goto help;
			} else if (MATCH(argv[j], "--size")) {
				if (++j >= argc)
					goto help;
				size = strtol(argv[j], NULL, 10);
				if (size > 0)
					m_size = size;
				else {
					printf("Invalid --size %s\n", argv[j]);
					goto help;
				}
			} else if (MATCH(argv[j], "--align")) {
				if (++j >= argc)
					goto help;
				align = strtol(argv[j], NULL, 10);
				for (i = 0; i < ARRAY_SIZE(page_sizes); i++) {
					if (align == page_sizes[i])
						break;
				}
				if (i == ARRAY_SIZE(page_sizes)) {
					printf("Invalid --align %s\n",
						argv[j]);
					goto help;
				}
				m_align = align;
			} else {
				printf("Invalid option %s\n", argv[j]);
				goto help;
			}
		}
		/* Set defaults. */
		if (!m_types) {
			printf("No memory type specified, setting to all\n");
			/* By default perform all tests. */
			for (i = 0; i < ARRAY_SIZE(mems); i++)
				m_types |= mems[i].type;
		}
		if (!m_size) {
			printf("No memory size specified, setting to 4KB\n");
			m_size = KB(4);
		}
		if (!m_align) {
			printf("No memory align specified, setting to 4KB\n");
			m_align = KB(4);
		}
		if (m_size % m_align) {
			m_size += m_align - (m_size % m_align);
			printf("Rounding memory size to align, new size %ld",
					m_size);
		}
		shmem->status[OWNER] = 0;
		shmem->status[NONOWNER] = 0;
		shmem->segid = -1;
		shmem->data_size = 0;
		shmem->offset = 0;
	}
	return 0;

help:
	printf("Usage:  %s {--owner|--nonowner} [options]\n", argv[0]);
	printf("\nOwner options:\n");
	printf("--type <mlist> Comma separated memory type list\n");
	for (i = 0; i < ARRAY_SIZE(mems); i++)
		printf("\t%-15s  -  %s\n", mems[i].opt, mems[i].desc);
	printf("\t%-15s  -  %s\n", "all", "All types specified above.");
	printf("--size <S>  Size of memory type in bytes\n");
	printf("--align <A> Alignment of start of memory in bytes\n\n");
	return -1;
}

/*
 * Owner functions
 */

/*
 *          Owner address space
 *              |      |
 *   buffer --->+------+^             ^
 * 	     ^  |      || offset      |
 *           |  |------|X             |
 *    size   |  |//////|| data_size   | XPEM shared segment
 *           |  |------|V             |
 *           |  |      |              |
 *           v  +------+              v
 *              |      |
 */
static int owner_test_common(unsigned char *buffer, unsigned long size,
			     unsigned long offset,  unsigned long data_size,
			     int rw)
{
	int status = -1;
	unsigned char *data = buffer + offset;

	LOG("%s(): buffer %p size %ld offset %ld data_size %ld",
	    __func__, buffer, size, offset, data_size);

	LOG("Waiting for non-owner to be ready");
	if (wait(STAT_NONOWNER_READY | STAT_NONOWNER_DONE, WAIT_FOR_BITSET))
		return status;

	if (testflags(STAT_NONOWNER_DONE)) {
		LOG("Non-owner has exited already! Owner exiting...");
		return 0;
	}

	/* Create a valid XPMEM share */
	shmem->segid = xpmem_make(buffer, size, XPMEM_PERMIT_MODE,
			(void *)0666);
	if (shmem->segid < 0) {
		perror("xpmem_make");
		return status;
	}

	shmem->offset = offset;
	shmem->data_size = data_size;
	shmem->magic = (unsigned long) data;
	shmem->rw = rw;

	if (rw == ACTION_RW)
		fill_buffer(data, data_size, shmem->magic);

	LOG("Signal non-owner that owner is ready");
	setflags(STAT_OWNER_READY);

	LOG("Waiting till non-owner is done");
	status = wait(STAT_NONOWNER_READY, WAIT_FOR_BITCLR);

	if (!status && rw == ACTION_RW)
		status = verify_buffer(data, data_size, shmem->magic);

	if (shmem->segid >= 0) {
		if (xpmem_remove(shmem->segid)) {
			perror("xpmem_remove");
			status = -1;
		}
		shmem->segid = -1;
		shmem->data_size  = 0;
	}

	/* Reset owner state */
	LOG("Signal non-owner that owner has completed this transfer");
	clrflags(STAT_OWNER_READY);
	return status;
}

static int owner_test_stack_main(void)
{
	/* Allocating on process stack */
	unsigned char *buffer = alloca(m_size + m_align);

	/* Align the start address to page size */
	unsigned char *aligned_start = align_address(buffer, m_align);

	LOG("%s(): buffer %p-%p [ Allocated %ld bytes ]", __func__,
			buffer, buffer + m_size + m_align - 1,
			m_size + m_align);
	LOG("%s(): buffer %p-%p [ Aligned to %ld ]", __func__,
			aligned_start, aligned_start + m_size - 1, m_align);

	if (aligned_start >= (buffer + m_size + m_align) ||
	    (buffer + m_size + m_align - aligned_start) < m_align) {
		LOG("%s(): buffer not big enough for alignment %ld",
		    __func__, m_align);
		return -1;
	}
	return owner_test_common(aligned_start, m_size, 0, m_size, ACTION_RW);
}

static int owner_test_anon_mixed(unsigned char *buffer, unsigned long size,
				 int rw, unsigned char *map1,
				 unsigned char *map2)
{
	unsigned char *vstart = buffer;
	unsigned char *vend = buffer + size;
	unsigned long map1_size = map2 - map1;
	unsigned long map2_size = (buffer + size) - map2;
	unsigned long base_offset, offset, data_size;
	int test_case, max_test_cases = 5;

	if (map1 < vstart || map1 >= vend) {
		LOG("%s(): map1 %p out of bound %p-%p",
		    __func__, map1, vstart, vend);
		return -1;
	}
	if (map2 < vstart || map2 >= vend) {
		LOG("%s(): map2 %p out of bound %p-%p",
		    __func__, map2, vstart, vend);
		return -1;
	}
	if (map1_size < KB(8)) {
		LOG("%s(): map1 size (%ld) needs to be alteast 2*4kb",
		    __func__, map1_size);
		return -1;
	}
	if (map2 < map1 || map2_size < KB(8)) {
		LOG("%s(): map2 size (%ld) needs to be alteast 2*4kb",
		    __func__, map2_size);
		return -1;
	}

	base_offset = map1 - buffer;

	for (test_case = 0; test_case < max_test_cases; test_case++) {
		switch (test_case) {
		case 0:
			offset = base_offset;
			data_size = size - base_offset;
			break;
		case 1:
			offset = base_offset;
			data_size = map1_size;
			break;
		case 2:
			offset = base_offset +
				 ((map1_size / (2 * KB(4))) * KB(4));
			data_size = map1_size;
			break;
		case 3:
			offset = base_offset + map1_size;
			data_size = map2_size;
			break;
		case 4:
			offset = base_offset + map1_size +
				 ((map2_size / (2 * KB(4))) * KB(4));
			data_size = map2_size -
				    ((map2_size / (2 * KB(4))) * KB(4));
			break;
		default:
			LOG("%s(): Unsupported case %d",
			    __func__, test_case);
			continue;
		}
		LOG("%s(): Testing case %d", __func__, test_case);
		LOG("%s(): buffer %p-%p", __func__, vstart, vend);
		LOG("%s(): map1   %p-%p", __func__, map1, map1 + map1_size);
		LOG("%s(): map2   %p-%p", __func__, map2, map2 + map2_size);
		LOG("%s(): Attached region %p-%p", __func__, buffer + offset,
		    buffer + offset + data_size);
		if (owner_test_common(buffer, size, offset, data_size, rw)) {
			LOG("%s(): Test case %d failed", __func__, test_case);
			return -1;
		}
	}
	return 0;
}

static int owner_test_others(unsigned long type)
{
	int rw;
	int status = -1;
	unsigned char *buffer = NULL;
	unsigned char *buffer_aligned = NULL;
	unsigned long size = m_size + m_align;
	unsigned long share_size;
	unsigned long offset, data_size;
	unsigned char *map1, *map2;

	map1 = map2 = NULL;
	buffer = allocate_buffer(type, &size, &rw, &map1, &map2);
	buffer_aligned = buffer;
	share_size = size;
	offset = 0;

	if (type != entire_address_space) {
		if (!buffer) {
			LOG("%s(): Failed to allocate buffer", __func__);
			return -1;
		}
		buffer_aligned = align_address(buffer, m_align);
		if (buffer_aligned >= (buffer +  size) ||
				(buffer + size - buffer_aligned) < m_align) {
			LOG("%s(): buffer not big enough for alignment %ld",
					__func__, m_align);
			goto out;
		}
		share_size = size - (buffer_aligned - buffer);

		/* Round down share size */
		if (share_size < KB(4)) {
			LOG("%s(): XPMEM share size %ld is less than 4k",
			    __func__, share_size);
			goto out;
		}
		/* Round down the share size to page boundary */
		share_size = share_size & ~0xfff;
		data_size = share_size;

		LOG("%s(): buffer %p-%p [ Allocated %ld bytes ]",
		    __func__, buffer, buffer + size - 1, size);
		LOG("%s(): buffer %p-%p [ Aligned to %ld, size %ld ]",
		    __func__, buffer_aligned, buffer_aligned + share_size - 1,
		    m_align, share_size);

		if (type & (mmap_anon_mixed |  mmap_anon_mixed_inv)) {
			if (buffer_aligned >= map2) {
				LOG("%s(): buffer is small for alignment %ld",
				     __func__, m_align);
				goto out;
			}
			map1 = buffer_aligned;
			status = owner_test_anon_mixed(buffer_aligned,
					share_size, rw, map1, map2);
			goto out;
		}
	} else {
		offset = (unsigned long) data_bss_buffer;
		data_size = data_bss_buffer_size;
	}

	status = owner_test_common(buffer_aligned, share_size,
				   offset, data_size, rw);
out:
	if (deallocate_buffer(type, buffer, size)) {
		LOG("Failed to deallocate buffer %p [%ld]", buffer, size);
		if (!status)
			status = -1;
	}
	return status;
}

static int owner(void)
{
	int i, rc = 0;

	LOG("%s(): Starting", __func__);
	for (i = 0; i < ARRAY_SIZE(mems) && m_types; i++) {
		if (mems[i].type & m_types) {
			LOG("Testing xpmem share: %s", mems[i].desc);
			m_types &= ~mems[i].type;
			if (mems[i].type == stack_main)
				rc = owner_test_stack_main();
			else
				rc = owner_test_others(mems[i].type);
		}
	}
	LOG("Signaling owner done");
	setflags(STAT_OWNER_DONE);
	return rc;
}

/*
 * Non-owner functions
 */
static int nonowner_test_common(void)
{
	struct xpmem_addr addr;
	void *attachment = NULL;
	int status = -1;

	LOG("Signal owner that non-owner ready");
	setflags(STAT_NONOWNER_READY);

	LOG("Waiting for owner to be ready");
	if (wait(STAT_OWNER_READY | STAT_OWNER_DONE, WAIT_FOR_BITSET))
		return status;

	if (testflags(STAT_OWNER_DONE)) {
		LOG("Owner exited already! Non-owner exiting...");
		return 0;
	}

	addr.apid = xpmem_get(shmem->segid, XPMEM_RDWR,
			XPMEM_PERMIT_MODE, (void *)0666);
	if (addr.apid < 0) {
		perror("xpmem_get");
		goto out;
	}

	addr.offset = shmem->offset;
	attachment = xpmem_attach(addr, shmem->data_size, 0);
	if (attachment == (void *)-1) {
		perror("xpmem_attach");
		goto out;
	}

	LOG("XPMEM offset 0x%lx attachment %p",
	    addr.offset, attachment);

	status = verify_buffer(attachment, shmem->data_size, shmem->magic);
	if (!status && shmem->rw == ACTION_RW) {
		shmem->magic = (unsigned long) attachment;
		fill_buffer(attachment, shmem->data_size, shmem->magic);
	}
out:
	if (attachment) {
		if (xpmem_detach(attachment)) {
			perror("xpmem_detach");
			status = -1;
		}
	}
	if (addr.apid >= 0) {
		if (xpmem_release(addr.apid)) {
			perror("xpmem_release");
			status = -1;
		}
	}
	LOG("Signal owner that the non-owner has completed this transfer");
	clrflags(STAT_NONOWNER_READY);

	LOG("Waiting for owner to complete this transfer");
	if (wait(STAT_OWNER_READY, WAIT_FOR_BITCLR))
		status = -1;
	return status;
}

static int nonowner(void)
{
	int failures = 0;

	LOG("%s(): Starting", __func__);
	while (!testflags(STAT_OWNER_DONE)) {
		if (nonowner_test_common())
			failures++;
	}
	LOG("%s(): Number of failures %d.", __func__, failures);
	setflags(STAT_NONOWNER_DONE);
	return failures ? -1 : 0;
}

int main(int argc, char **argv)
{
	unsigned int version = 0;

	if (parse_args(argc, argv))
		return -1;

	version = xpmem_version();
	LOG("XPMEM version %d.%x", version >> 16, version & ~(~0 << 16));

	if (proc  == OWNER)
		return owner();
	else
		return nonowner();
}
