/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016 - 2017, Intel Corporation.
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

#include <linux/list.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/sizes.h>
#include <linux/sched.h>	/* For task_struct */
#include <linux/mutex.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/printk.h>
#include <linux/mos.h>
#include <linux/rmap.h>
#include <linux/pkeys.h>
#include <linux/hugetlb.h>
#include <linux/memory.h>
#include <linux/ftrace.h>
#include <asm/setup.h>
#include <asm/tlbflush.h>
#include "lwkmem.h"
#include "lwkctrl.h"
#include "../mm/internal.h"

#include <trace/events/lwkmem.h>

#undef pr_fmt
#define pr_fmt(fmt)	"mOS-mem: " fmt
#define STRBUF_LEN		(256)
#define kaddr_to_pfn(va)	(__pa(va) >> PAGE_SHIFT)

static size_t lwkmem_n_online_nodes;

#define ADDR_MASK 0x000ffffffffff000
#define PG2M_MASK 0x000fffffffe00000
#define PG1G_MASK 0x000fffffc0000000

/*
 * LWK page size masks and shifts
 */

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
static int64_t kind_size[kind_last] = {SZ_4K, SZ_2M, SZ_1G};
unsigned long lwk_page_shift[kind_last] = {12, 21, 30};
static unsigned long lwk_page_size[kind_last] = { (1UL << 12), (1UL << 21),
			(1UL << 30)};
static unsigned long lwk_page_mask[kind_last] = { ~((1UL << 12) - 1),
			~((1UL << 21) - 1), ~((1UL << 30) - 1)};
#define MIN_CHUNK_SIZE (SZ_2M)
#else
static int64_t kind_size[kind_last] = {SZ_4K, SZ_4M, SZ_1G};
unsigned long lwk_page_shift[kind_last] = {12, 22, 30};
static unsigned long lwk_page_size[kind_last] = { (1UL << 12), (1UL << 22),
			(1UL << 30)};
static unsigned long lwk_page_mask[kind_last] = { ~((1UL << 12) - 1),
			~((1UL << 22) - 1), ~((1UL << 30) - 1)};
#define MIN_CHUNK_SIZE (SZ_4M)
#endif
static const char * const lwkmem_type_str[lwkmem_type_last] = {
	"dram", "hbm", "nvram"
};
static const char * const lwkmem_site_str[lwkmem_site_last] = {
	"mmap", "brk", "static", "stack"
};

static inline void lwkmem_page_init(struct page *p)
{
	SetPagePrivate(p);
	set_bit(PG_writeback, &p->flags);
	SetPageActive(p);
	SetPageUnevictable(p);
	SetPageMlocked(p);
	p->private = _LWKPG;
	init_page_count(p);
	if (unlikely(is_lwkpg_dirty(p))) {
		/*
		 * Its highly unusual that we get here, unless something
		 * went wrong before during unmapping of page table.
		 */
		trace_mos_lwkpage_dirty_error(page_to_pfn(p));
		pr_debug("%s(): pfn was dirty: %ld\n",
			 __func__, page_to_pfn(p));
		memset((void *) page_to_virt(p), 0, PAGE_SIZE);
		clear_lwkpg_dirty(p);
	}
}

static inline void lwkmem_page_deinit(struct page *p)
{
	ClearPagePrivate(p);
	clear_bit(PG_writeback, &p->flags);
	ClearPageActive(p);
	ClearPageUnevictable(p);
	ClearPageMlocked(p);
	p->private = 0;
	page_mapcount_reset(p);
	p->mapping = NULL;
	p->index = 0;
}

static const char *lwkmem_name(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	const char *name = arch_vma_name(vma);

	if (!name) {
		if (!mm)
			name = "[vdso] LWK";
		else if (vma->vm_start <= mm->brk &&
			vma->vm_end >= mm->start_brk)
			name = "[heap] LWK";
		else if (vma->vm_start <= mm->start_stack &&
			vma->vm_end >= mm->start_stack)
			name = "[stack] LWK";
		else
			name = "LWK";
	}

	return name;
}

#define ZCHECK_FREE     1
#define ZCHECK_ALLOCATE 2
#define ZCHECK_RELEASE  4
#define ZCHECK_FIX      8

static inline bool lwkmem_zeroes_check_enabled(int flag)
{
	struct mos_process_t *mosp = current->mos_process;

	return mosp && ((mosp->lwkmem_zeroes_check & flag) != 0);
}

/**
 * Test and possibly clear memory that is expected to be zero.
 * The (addr,length) pair describe the region that is to be tested
 * and may span multiple pages.  If mm is passed, the address is
 * a user-space address; otherwise it is a kernel address.  The
 * return value is either 0 (no problems detected) or the address
 * of the first non-zero doubleword.
 */

static unsigned long lwkmem_check_for_zero(unsigned long addr,
			   unsigned long length, struct mm_struct *mm,
			   const char *msg)
{
	unsigned int size = 0;
	unsigned long *wrd, i, N, rc = 0;
	struct page *page = 0;
	bool fixup = lwkmem_zeroes_check_enabled(ZCHECK_FIX);

	while (length) {
		bool warned = false; /* One message per page */

		if (mm) {
			page = lwkmem_user_to_page(mm, addr, &size);
			wrd = (unsigned long *)page_to_virt(page);
		} else {
			size = SZ_4K;
			wrd = (unsigned long *)addr;
		}

		for (i = 0, N = size / sizeof(unsigned long); i < N; i++) {
			if (wrd[i]) {
				if (!warned) {
					mos_ras(MOS_LWKMEM_PROCESS_WARNING,
						"%s: Non-zero bytes have been detected at %p (%lx) ==> %lx [%s].",
						__func__, wrd + i, addr, wrd[i],
						msg);
					warned = true;
					rc = rc ? rc : addr;
				}

				if (fixup)
					wrd[i] = 0;
				else
					goto out;
			}
		}

		if (fixup && page)
			clear_lwkpg_dirty(page);

		addr += size;
		length -= min_t(unsigned long, length, size);
	}

out:
	return rc;
}


static const struct vm_operations_struct lwkmem_vm_ops = {
	.name = lwkmem_name,
};


int lwkmem_index_of(const char *s, const char * const lst[], const size_t len,
		    int case_insensitive)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (case_insensitive && strcasecmp(s, lst[i]) == 0)
			return i;
		else if (strcmp(s, lst[i]) == 0)
			return i;

	return -1;
}

static inline unsigned long block_addr(struct blk_list *b)
{
	return (unsigned long)b->phys->base + b->offset;
}

unsigned long block_size_virt(struct blk_list *b, enum lwkmem_kind_t k)
{
	return kind_size[k] * (1 + (b->num_blks - 1) * b->stride);
}

static int lwkmem_type_of(int nid, struct mos_process_t *mosp)
{
	int i, t;

	for (t = 0; t < lwkmem_type_last; t++)
		for (i = 0; i < mosp->domain_info_len[t]; i++)
			if (mosp->domain_info[t][i] == nid)
				return t;

	return -1;
}

/*
 * List all free memory blocks during early boot
 */
static void __init memblock_dump_free(void)
{
	uint64_t idx;
	phys_addr_t this_start, this_end, size;
	int p_nid;
	int i = 0;

	for_each_free_mem_range(idx, NUMA_NO_NODE, MEMBLOCK_NONE, &this_start,
			&this_end, &p_nid) {
		size = this_end - this_start + 1;
		memblock_dbg(" free[0x%x]\t[%#016llx-%#016llx], 0x%llx bytes on node %d\n",
			i++, (unsigned long long)this_start,
			(unsigned long long)this_end, size, p_nid);
	}

} /* end of memblock_dump_free() */

/*
 * List and summarize the memory granules in a list
 */
static void dump_granule_list(struct list_head *dump_list)
{
	struct mos_lwk_mem_granule *g;
	uint64_t total_bytes = 0;
	unsigned num_granules = 0;

	list_for_each_entry(g, dump_list, list) {
		pr_debug("\t[%pK-%pK], 0x%llx bytes (%lld MiB), owner %d nid %d\n",
			g->base, g->base + g->length - 1, g->length,
			g->length >> 20, g->owner, g->nid);
		total_bytes = total_bytes + g->length;
		num_granules++;
	}
	pr_debug("Total %llu bytes (%llu MB) in %d granules\n", total_bytes,
		total_bytes >> 20, num_granules);

} /* end of dump_granule_list() */

/*
 * List and summarize the block lists
 */
static void trace_block_lists(struct mos_process_t *mosp)
{
	struct blk_list *bl;
	unsigned long free_blocks, allocated_blocks;
	enum lwkmem_kind_t k;
	int n;

	for (k = kind_4k; k < kind_last; k++) {

		for_each_online_node(n) {

			free_blocks = allocated_blocks = 0;

			list_for_each_entry(bl, &mosp->free_list[k][n], list) {

				if (mosp->trace_block_list_details)
					trace_mos_mem_block_dump(0, 0,
						 block_addr(bl),
						 bl->num_blks * kind_size[k],
						 k, bl->num_blks, 1,
						 bl->phys->nid, current->tgid);

				free_blocks += bl->num_blks;
			}

			list_for_each_entry(bl, &mosp->busy_list[k][n], list) {

				if (mosp->trace_block_list_details)
					trace_mos_mem_block_dump(bl->vma_addr,
						 block_size_virt(bl, k),
						 block_addr(bl),
						 kind_size[k] * bl->num_blks, k,
						 bl->num_blks, bl->stride,
						 bl->phys->nid, current->tgid);

				allocated_blocks += bl->num_blks;
			}

			if (!mosp->trace_block_list_details &&
			    (free_blocks || allocated_blocks)) {

				/* In summary dumps, we will denote free totals with
				 * a virtual address region of 0, and allocated totals
				 * with a virtual address of 0xFF...FF.
				 */

				trace_mos_mem_block_dump(0, 0, 0,
					 free_blocks * kind_size[k], k,
					 free_blocks, 1, n, current->tgid);

				trace_mos_mem_block_dump(-1, 0, 0,
					 allocated_blocks * kind_size[k], k,
					 allocated_blocks, 1, n, current->tgid);
			}
		}
	}
}

/*
 * During early boot, designate regions of memory per the lwkmem kernel
 * argument.  These granules are retained in a list; list node data is
 * stored in the granules (boot memory) since it is not used for anything
 * else during this phase.
 */
__initdata LIST_HEAD(mos_lwk_boot_list);

static uint64_t __init _lwkmem_designate_by_nid(
			 uint64_t lwk_mem_requested, int nid)
{
	struct mos_lwk_mem_granule *g;
	uint64_t lwk_mem_needed = 0;
	uint64_t lwk_mem_designated = 0;
	uint64_t block_size, try_size;

	/* Round up to the next 2 MB boundary */
	lwk_mem_needed = roundup(lwk_mem_requested, MIN_CHUNK_SIZE);

	memblock_dbg("Designating %lld (%lld) bytes from nid %d\n",
		     lwk_mem_requested, lwk_mem_needed, nid);

	/* No point in searching for something much larger than we need. */

	block_size = roundup_pow_of_two(lwk_mem_needed);

	/* While memory is desired from this NUMA domain, attempt to grab
	 * the largest block possible.
	 */

	while ((lwk_mem_needed > 0) && (block_size > 0)) {

		/* Is there a block of this size we can request? */
		try_size = min(lwk_mem_needed, block_size);

		memblock_dbg("Is there a block of size %lld? I need %lld more\n",
			     block_size, lwk_mem_needed);

		if (memblock_find_in_range_node(try_size, block_size, 0,
			BOOTMEM_ALLOC_ACCESSIBLE, nid, MEMBLOCK_NONE)) {

			/* Yes! Grab and use it */
			g = memblock_virt_alloc_try_nid_nopanic(try_size,
				block_size, 0, BOOTMEM_ALLOC_ACCESSIBLE, nid);
			if (!g) {
				mos_ras(MOS_LWKMEM_BOOT_WARNING,
					"%s: Designating a block of %lld bytes failed.",
					__func__, try_size);
				goto allocerr;
			}

			g->base = g;
			g->length = try_size;
			g->nid = nid;
			memblock_dbg("granule 0x%16p, 0x%llx bytes (%lld) nid=%d\n",
				     g->base, g->length, g->length, nid);
			list_add_tail(&g->list, &mos_lwk_boot_list);

			lwk_mem_needed -= try_size;
			lwk_mem_designated += try_size;
		} else {
			/* No block of that size available try a smaller block
			 * size.
			 */
			block_size >>= 1;
		}
	}

	if (lwk_mem_needed > 0)
		mos_ras(MOS_LWKMEM_BOOT_WARNING,
			"%s: Could not designate %lld bytes of memory in NUMA domain %d.",
			__func__, lwk_mem_requested, nid);

 allocerr:
	return lwk_mem_designated;

}

static int __init mos_lwkmem_setup(char *s)
{
	uint64_t total_designated, total_requested, designated, requested;
	char *nidstr, *memstr;
	int failures, nid, rc;
	static char tmp[COMMAND_LINE_SIZE] __initdata;

	total_designated = total_requested = failures = 0;

	/* If the mOS memory partitioning is not static then we just record the
	 * lwkmem specification in lwkctrl and use it later during the default
	 * boot partition creation.
	 *
	 * For legacy static memory partitioning we proceed to use memblock
	 * reserved memory for LWKMEM.
	 */
	if (!lwkmem_static_enabled)
		return 0;

	/* Determine the number of NUMA domains. */
	for_each_online_node(nid)
		if (lwkmem_n_online_nodes < (nid + 1))
			lwkmem_n_online_nodes = nid + 1;

	pr_info("There are %ld on-line NUMA domains.\n", lwkmem_n_online_nodes);

	memblock_dbg("Early memblock info ---------------------------------------\n");
	memblock_dump_all();
	memblock_dump_free();

	s = strcpy(tmp, s);

	while ((nidstr = strsep(&s, ","))) {

		memstr = strchr(nidstr, ':');
		if (!memstr) {
			nid = NUMA_NO_NODE;
			memstr = nidstr;
		} else {
			*(memstr++) = '\0';
			rc = kstrtoint(nidstr, 0, &nid);
			if (rc || nid < 0 || nid >= lwkmem_n_online_nodes) {
				mos_ras(MOS_LWKMEM_BOOT_WARNING,
					"%s: Invalid NUMA domain: \"%s\".",
					__func__, nidstr);
				nid = NUMA_NO_NODE;
			}
		}

		requested = memparse(memstr, 0);
		total_requested += requested;

		if (nid == NUMA_NO_NODE) {
			requested /= lwkmem_n_online_nodes;
			for_each_online_node(nid) {
				designated =
					_lwkmem_designate_by_nid(requested, nid);
				total_designated += designated;
				if (designated < requested)
					failures++;
			}
		} else {
			designated = _lwkmem_designate_by_nid(requested, nid);
			total_designated += designated;
			if (designated < requested)
				failures++;
		}
	}

	if (failures > 0)
		mos_ras(MOS_LWKMEM_BOOT_WARNING,
			"%s: Only designated %lld of %lld bytes of LWK memory.",
			__func__, total_designated, total_requested);
	else
		pr_info("Designated %lld bytes of LWK memory.\n",
			total_designated);

	return -failures;
}

__setup("lwkmem=", mos_lwkmem_setup);

static int lwkmem_process_init(struct mos_process_t *mosp)
{
	enum lwkmem_kind_t k;
	enum lwkmem_type_t m;
	enum allocate_site_t s;
	struct memory_preference_t *mpref;
	enum lwkmem_type_t *default_order;

	mosp->lwkmem = 0;
	mosp->brk = mosp->brk_end = 0;
	mosp->lwkmem_brk_disable = false;
	mosp->max_page_size = SZ_1G;
	mosp->heap_page_size = SZ_2M;
	mosp->lwkmem_mmap_aligned_threshold = SZ_2M;
	mosp->lwkmem_mmap_alignment = SZ_1G;
	mosp->lwkmem_next_addr = 0x300000000000;
	mosp->brk_clear_len = 4096;
	mosp->lwkmem_interleave_disable = false;
	mosp->lwkmem_load_elf_segs = true;
	mosp->lwkmem_interleave = 0;
	mosp->trace_block_list_addr = 0;
	mosp->trace_block_list_details = false;
	mosp->lwkmem_zeroes_check = 0;
	mosp->lwkmem_prot_none_delegation = false;

	/* Initialize all memory preferences */
	default_order = mosp->memory_preference[lwkmem_mmap].lower_type_order;
	default_order[0] = lwkmem_hbm;
	default_order[1] = lwkmem_dram;
	default_order[2] = lwkmem_nvram;

	for (s = 0; s < lwkmem_site_last; s++) {
		mpref = &mosp->memory_preference[s];
		mpref->threshold = 1;
		if (s != lwkmem_mmap)
			memcpy(mpref->lower_type_order, default_order,
			       sizeof(mpref->lower_type_order));
		memcpy(mpref->upper_type_order, default_order,
			       sizeof(mpref->upper_type_order));
	}

	/* Don't randomize address space for LWK processes! */
	current->personality |= ADDR_NO_RANDOMIZE;

	INIT_LIST_HEAD(&mosp->lwkmem_list);
	for (k = kind_4k; k < kind_last; k++) {
		int n;

		mosp->num_blks[k] = 0;
		for_each_online_node(n) {
			INIT_LIST_HEAD(&mosp->free_list[k][n]);
			INIT_LIST_HEAD(&mosp->busy_list[k][n]);
			mosp->blks_in_use[k][n] =
			mosp->blks_allocated[k][n] = 0;
		}
	}

	mosp->report_blks_allocated = 0;
	for (m = lwkmem_dram; m < lwkmem_type_last; m++) {
		for (k = kind_4k; k < kind_last; k++)
			mosp->domain_order_index[m][k] = 0;
		mosp->domain_info_len[m] = 0;
	}
	init_xpmem_stats(mosp);

	return 0;
}

static int partition_task_mem(struct mos_process_t *, int64_t);

static int lwkmem_process_start(struct mos_process_t *mosp)
{
	int rc;

	rc = partition_task_mem(mosp, mosp->lwkmem);
	if (rc)
		return -ENOMEM;

	return 0;
}

static struct mos_process_callbacks_t lwkmem_callbacks = {
	.mos_process_init = lwkmem_process_init,
	.mos_process_start = lwkmem_process_start,
	.mos_process_exit = lwkmem_release,
};

static int lwkmem_brk_disable_cb(const char *ignored,
				 struct mos_process_t *mosp)
{
	pr_debug("(!) lwkmem brk support is disabled.\n");
	mosp->lwkmem_brk_disable = true;

	return 0;
}

static int lwkmem_max_pg_size_cb(const char *val, struct mos_process_t *mosp)
{
	if (!val)
		goto err;

	if (strcasecmp(val, "4k") == 0)
		mosp->max_page_size = SZ_4K;
	else if (strcasecmp(val, "2m") == 0)
		mosp->max_page_size = SZ_2M;
	else if (strcasecmp(val, "4m") == 0)
		mosp->max_page_size = SZ_4M;
	else if (strcasecmp(val, "1g") == 0)
		mosp->max_page_size = SZ_1G;
	else
		goto err;

	pr_debug("Maximum LWK page size set to %s\n", val);

	return 0;

 err:
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Invalid maximum page size: %s", __func__, val);
	return -EINVAL;
}

static int lwkmem_heap_pg_size_cb(const char *val, struct mos_process_t *mosp)
{
	if (!val)
		goto err;

	if (strcasecmp(val, "4k") == 0)
		mosp->heap_page_size = SZ_4K;
	else if (strcasecmp(val, "2m") == 0)
		mosp->heap_page_size = SZ_2M;
	else if (strcasecmp(val, "4m") == 0)
		mosp->heap_page_size = SZ_4M;
	else if (strcasecmp(val, "1g") == 0)
		mosp->heap_page_size = SZ_1G;
	else
		goto err;

	pr_debug("LWK heap page size set to %s\n", val);

	return 0;

 err:
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Invalid LWK heap page size: %s", __func__, val);
	return -EINVAL;
}

static int lwkmem_memory_preferences_cb(const char *val,
				 struct mos_process_t *mosp)
{
	char *opt, *pref_s, *scope_s, *thresh_s, *order_s, *mtype_s;
	unsigned long thresh;
	enum allocate_site_t scope;
	struct memory_preference_t *mpref;
	enum lwkmem_type_t *order;
	int t;

	if (!val)
		goto invalid;

	pr_debug("(>) %s val=%s\n", __func__, val);

	opt = kstrdup(val, GFP_KERNEL);
	if (!opt)
		return -ENOMEM;

	/* Format: /scope[:thresh]:order/+ */
	while ((pref_s = strsep(&opt, "/"))) {

		if (strlen(pref_s) == 0)
			continue;

		scope_s = strsep(&pref_s, ":");
		thresh_s = strsep(&pref_s, ":");
		order_s = strsep(&pref_s, ":");

		pr_debug("(*) %s:%d scope=%s thresh=%s order=%s\n", __func__, __LINE__, scope_s, thresh_s, order_s);

		if (pref_s) {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Extraneous characters after %s:%s:%s",
				 __func__, scope_s, thresh_s, order_s);
			goto invalid;
		}

		if (!order_s) {
			order_s = thresh_s;
			thresh = 1;
		} else if (kstrtoul(thresh_s, 0, &thresh)) {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Illegal threshold: %s",
				__func__, thresh_s);
			goto invalid;
		}

		scope = lwkmem_index_of(scope_s, lwkmem_site_str,
				       sizeof(lwkmem_site_str), false);
		if (scope < 0) {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Illegal scope: %s",
				__func__, scope_s);
			goto invalid;
		}

		mpref = &mosp->memory_preference[scope];
		mpref->threshold = thresh;
		order = mpref->upper_type_order;
		t = 0;

		while ((mtype_s = strsep(&order_s, ","))) {

			pr_debug("(*) %s:%d   type=%s\n", __func__, __LINE__, mtype_s);

			if (strlen(mtype_s) == 0)
				continue;

			if (t >= lwkmem_type_last) {
				mos_ras(MOS_LWKMEM_PROCESS_ERROR,
					"%s: overflow in order string.",
					__func__);
				goto invalid;
			}

			order[t] = lwkmem_index_of(mtype_s, lwkmem_type_str,
						   lwkmem_type_last, false);
			if (order[t] < 0) {
				mos_ras(MOS_LWKMEM_PROCESS_ERROR,
					"%s: Illegal memory type: %s",
					__func__, mtype_s);
			}

			t++;
		}
	}

	kfree(opt);
	pr_debug("(<) %s val=%s\n", __func__, val);
	return 0;

 invalid:
	kfree(opt);
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Illegal value detected: %s", __func__, val);
	return -EINVAL;
}

static int lwkmem_aligned_mmap_cb(const char *val, struct mos_process_t *mosp)
{
	int rc;
	unsigned long threshold, alignment = 0;
	char *start, *tok, *opt;

	if (!val)
		return -EINVAL;

	opt = kstrdup(val, GFP_KERNEL);
	if (!opt)
		return -ENOMEM;

	start = opt;
	tok = strsep(&opt, ":");
	rc = kstrtoul(tok, 0, &threshold);
	if (rc)
		goto invalid;

	if (threshold) {
		alignment = mosp->lwkmem_mmap_alignment;
		tok = strsep(&opt, ":");
		if (tok) {
			rc = kstrtoul(tok, 0, &alignment);
			if (rc)
				goto invalid;
			if (opt && *opt != '\0')
				mos_ras(MOS_LWKMEM_PROCESS_WARNING,
					"%s: Ignoring extraneous arguments.",
					__func__);
		}
	}

	mosp->lwkmem_mmap_aligned_threshold = threshold;
	mosp->lwkmem_mmap_alignment = alignment;
	pr_debug("(*) lwkmem-aligned-mmap=%lx:%lx\n",
		 mosp->lwkmem_mmap_aligned_threshold,
		 mosp->lwkmem_mmap_alignment);

	kfree(start);
	return 0;

 invalid:
	kfree(start);
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Illegal value detected: %s", __func__, val);
	return -EINVAL;
}

static int lwkmem_blocks_allocated_cb(const char *val,
					struct mos_process_t *mosp)
{
	int n;

	mosp->report_blks_allocated = 1;

	for_each_node_mask(n, node_online_map)
		mosp->max_allocated[n] = 0;

	pr_debug("(*) lwkmem-blocks-allocated\n");

	return 0;
}

static int lwkmem_brk_clear_len_cb(const char *val, struct mos_process_t *mosp)
{
	int rc;

	if (!val)
		goto invalid;

	rc = kstrtol(val, 0, &mosp->brk_clear_len);

	if (rc)
		goto invalid;

	pr_debug("(*) lwkmem-brk-clear-len=%lx\n", mosp->brk_clear_len);

	return 0;

 invalid:
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Illegal value detected: %s", __func__, val);
	return -EINVAL;
}

static int lwkmem_interleave_disable_cb(const char *val,
					struct mos_process_t *mosp)
{
	mosp->lwkmem_interleave_disable = true;
	pr_debug("(*) lwkmem-interleave-disable\n");
	return 0;
}

static int lwkmem_load_elf_disable_cb(const char *val,
				      struct mos_process_t *mosp)
{
	mosp->lwkmem_load_elf_segs = false;
	pr_debug("(*) lwkmem_load_elf_segs set to false\n");
	return 0;
}

static int lwkmem_prot_none_delegation_enable_cb(const char *val,
				      struct mos_process_t *mosp)
{
	mosp->lwkmem_prot_none_delegation = true;
	pr_debug("(*) %s PROT_NONE delegation enabled.\n", __func__);
	return 0;
}

static int lwkmem_interleave_cb(const char *val, struct mos_process_t *mosp)
{
	if (!val)
		goto invalid;

	if (strcasecmp(val, "4k") == 0)
		mosp->lwkmem_interleave = SZ_4K;
	else if (strcasecmp(val, "2m") == 0)
		mosp->lwkmem_interleave = SZ_2M;
	else if (strcasecmp(val, "4m") == 0)
		mosp->lwkmem_interleave = SZ_4M;
	else if (strcasecmp(val, "1g") == 0)
		mosp->lwkmem_interleave = SZ_1G;
	else if (strcasecmp(val, "0") == 0)
		mosp->lwkmem_interleave = 0;
	else
		goto invalid;

	if (mosp->lwkmem_interleave)
		mosp->max_page_size = mosp->lwkmem_interleave;

	pr_debug("LWK memory interleave size set to %s\n", val);

	return 0;

 invalid:
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Illegal value detected: %s", __func__, val);
	return -EINVAL;
}

static int lwkmem_trace_block_lists_cb(const char *val,
			  struct mos_process_t *mosp)
{
	int rc;
	char *tok, *opt, *dup = 0;

	if (!val)
		goto invalid;

	dup = opt = kstrdup(val, GFP_KERNEL);
	if (!opt)
		return -ENOMEM;

	tok = strsep(&opt, ":");

	rc = kstrtol(tok, 0, &mosp->trace_block_list_addr);

	if (rc)
		goto invalid;

	mosp->trace_block_list_details = false;
	if (opt) {
		if (strcasecmp(opt, "details") == 0)
			mosp->trace_block_list_details = true;
		else if (strcasecmp(opt, "summary") == 0)
			mosp->trace_block_list_details = false;
		else
			goto invalid;
	}

	kfree(dup);
	pr_debug("(*) lwkmem-trace-block-list=%lx details=%d\n",
		 mosp->trace_block_list_addr, mosp->trace_block_list_details);

	return 0;

invalid:
	kfree(dup);
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Illegal value detected: %s",
		__func__, val ? val : "null");
	return -EINVAL;
}

static int lwkmem_zeroes_check_cb(const char *val, struct mos_process_t *mosp)
{
	char *tok, *opt, *dupd = 0;

	pr_debug("(*) %s val=%s\n", __func__, val);

	if (!val)
		goto invalid;

	dupd = kstrdup(val, GFP_KERNEL);
	if (!dupd)
		return -ENOMEM;

	opt = dupd;

	while ((tok = strsep(&opt, ","))) {
		if (strcasecmp(tok, "free") == 0)
			mosp->lwkmem_zeroes_check |= ZCHECK_FREE;
		else if (strcasecmp(tok, "alloc") == 0)
			mosp->lwkmem_zeroes_check |= ZCHECK_ALLOCATE;
		else if (strcasecmp(tok, "release") == 0)
			mosp->lwkmem_zeroes_check |= ZCHECK_RELEASE;
		else if (strcasecmp(tok, "all") == 0)
			mosp->lwkmem_zeroes_check |=
				(ZCHECK_FREE | ZCHECK_ALLOCATE |
				 ZCHECK_RELEASE);
		else if (strcasecmp(tok, "fix") == 0)
			mosp->lwkmem_zeroes_check |= ZCHECK_FIX;
		else
			goto invalid;
	}

	pr_debug("(!) %s check=%x\n", __func__, mosp->lwkmem_zeroes_check);
	kfree(dupd);
	return 0;

 invalid:
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Illegal value (%s) detected.",
		__func__, val);
	kfree(dupd);
	return -EINVAL;
}

static int lwkmem_xpmem_stats_cb(const char *val, struct mos_process_t *mosp)
{
	mosp->report_xpmem_stats = true;
	pr_debug("(*) lwkmem-xpmem-stats\n");

	return 0;
}

void insert_granule(struct mos_lwk_mem_granule *g, struct list_head *head)
{
	struct mos_lwk_mem_granule *e;

	list_for_each_entry(e, head, list) {
		if ((g->base + g->length) < e->base)
			break;
	}
	list_add_tail(&g->list, head);
}

static unsigned long lwkmem_get_dynamic_memory(int nid, unsigned long size,
					       struct list_head *head)
{
	int rc;
	unsigned long flags, nr_pages;
	unsigned long total_size, block_size;
	unsigned long start_pfn, end_pfn, pfn, pfn_next;

	struct page *page;
	struct list_head blk_list;
	struct mos_lwk_mem_granule *curr, *next;
	pg_data_t *pgdat = NODE_DATA(nid);
	struct zone *zone_movable = pgdat->node_zones + ZONE_MOVABLE;

	INIT_LIST_HEAD(&blk_list);
	total_size = 0;

	lock_device_hotplug();
	mem_hotplug_begin();

	if (!node_online(nid))
		goto out;

	/* Create a list of contig physical memory ranges that we can offline */
	spin_lock_irqsave(&zone_movable->lock, flags);
	if (zone_is_empty(zone_movable)) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Node %d has no ZONE_MOVABLE memory and cannot host LWK memory.",
			__func__, nid);
		spin_unlock_irqrestore(&zone_movable->lock, flags);
		goto out;
	}

	/* Find the start and end of movable region on this node */
	start_pfn = zone_movable->zone_start_pfn;
	end_pfn = zone_end_pfn(zone_movable);
	start_pfn = SECTION_ALIGN_UP(start_pfn);
	end_pfn = SECTION_ALIGN_DOWN(end_pfn);

	while (start_pfn < end_pfn && total_size < size) {
		/* Get the next available contiguous region */
		block_size = 0;
		pfn = start_pfn = SECTION_ALIGN_UP(start_pfn);
		while (pfn < end_pfn) {
			page = pfn_to_page(pfn);
			if (!pfn_present(pfn) || !pfn_valid(pfn) ||
			     PageReserved(page)) {
				if (pfn == start_pfn) {
					start_pfn++;
					start_pfn = SECTION_ALIGN_UP(start_pfn);
					pfn = start_pfn;
					continue;
				}
				break;
			}
			block_size += PAGE_SIZE;
			pfn++;
			if ((total_size + block_size) >= size)
				break;
		}
		pfn_next = pfn + 1;

		if (!IS_ALIGNED(pfn, PAGES_PER_SECTION)) {
			pfn = SECTION_ALIGN_DOWN(pfn);
			if (pfn <= start_pfn) {
				start_pfn = pfn_next;
				continue;
			}
			block_size = (pfn - start_pfn) * PAGE_SIZE;
		}

		if (likely(block_size >= MIN_CHUNK_SIZE)) {
			curr = kmalloc(sizeof(struct mos_lwk_mem_granule),
				       GFP_KERNEL);
			if (!curr) {
				spin_unlock_irqrestore(&zone_movable->lock,
						       flags);
				goto out;
			}
			curr->base = pfn_to_kaddr(start_pfn);
			curr->owner = -1;
			curr->length = block_size;
			curr->nid = nid;
			list_add_tail(&curr->list, &blk_list);
			total_size += block_size;
			pr_info("Node %d: va 0x%p pa 0x%lx pfn %ld-%ld : %ld\n",
				nid, curr->base, __pa(curr->base), start_pfn,
				pfn - 1,  pfn - start_pfn);
		}
		start_pfn = pfn_next;
	}
	spin_unlock_irqrestore(&zone_movable->lock, flags);

	/* Offline pages and add the granule to the requested list_head */
	list_for_each_entry_safe(curr, next, &blk_list, list) {
		start_pfn = kaddr_to_pfn(curr->base);
		nr_pages = curr->length / PAGE_SIZE;
		pr_info("Node %d: offlining va 0x%p pa 0x%lx pfn %ld-%ld:%ld\n",
			nid, curr->base, __pa(curr->base), start_pfn,
			start_pfn + nr_pages - 1, nr_pages);

		do {
			/* We don't need a timeout here. Linux kernel 4.15
			 * onwards offline_pages() doesn't implement timeout
			 * anymore. It repeats until it sees an error -EINTR,
			 * -EBUSY or -ENOMEM based on the error condition.
			 * So we can safely retry here upon -EAGAIN which is
			 * the correct behavior even with the future rebases.
			 */
			rc = offline_pages(start_pfn, nr_pages);
		} while (rc == -EAGAIN);

		if (rc) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Could not offline pages for node %d.  Address:0x%p Count:%ld: status:%d.",
				__func__, nid, curr->base, nr_pages, rc);
			total_size -= curr->length;
		} else {
			while (nr_pages--) {
				lwkmem_page_init(pfn_to_page(start_pfn));
				start_pfn++;
			}
			memzero_explicit(curr->base, curr->length);
			list_del(&curr->list);
			insert_granule(curr, head);
		}
	}
out:
	/* Free up the list entries which could not be offlined */
	list_for_each_entry_safe(curr, next, &blk_list, list) {
		list_del(&curr->list);
		kfree(curr);
	}

	mem_hotplug_done();
	unlock_device_hotplug();
	return total_size;
}

/*
 * Later during boot, gather all of the memory granules into a
 * consolidated list.  The list meta data is migrated from the
 * memory granules into kmalloc'd data.
 */
LIST_HEAD(mos_lwk_memory_list);

static int __init mos_collect_bootmem(void)
{
	struct mos_lwk_mem_granule *g;
	unsigned long total_bytes = 0;
	struct page *p;
	long i, nr_pages;

	list_for_each_entry(g, &mos_lwk_boot_list, list) {
		struct mos_lwk_mem_granule *newg;

		newg = kmalloc(sizeof(struct mos_lwk_mem_granule), GFP_KERNEL);
		if (!newg)
			goto collect_err;

		/* Mark as free */
		g->owner = -1;
		memcpy(newg, g, sizeof(struct mos_lwk_mem_granule));

		/*
		 * Space for the struct page entries has already been allocated
		 * by the kernel. Make sure the flags are as we need them.
		 */
		p = virt_to_page(g->base);
		nr_pages = g->length / PAGE_SIZE;
		for (i = 0; i < nr_pages; i++, p++)
			lwkmem_page_init(p);

		/* This sorts granules by size, not phys location. May want to
		 * change this sometime in the future. */
		list_add_tail(&newg->list, &mos_lwk_memory_list);
		total_bytes += newg->length;
	}

	list_for_each_entry(g, &mos_lwk_memory_list, list) {
		/* Clear the granule */
		memzero_explicit(g->base, g->length);
	}
	return 0;

collect_err:
	return -ENOMEM;

} /* end of mos_collect_bootmem() */

int mos_mem_init(nodemask_t *nodes, resource_size_t *requests)
{
	int n;
	resource_size_t sz, sz_req, sz_alloc, sz_dist;
	nodemask_t mask;

	sz_req = 0;
	sz_alloc = 0;

	if (lwkmem_static_enabled)
		return -EINVAL;

	pr_info("Initializing memory management\n");
	lwkmem_n_online_nodes = 0;
	nodes_clear(mask);
	nodes_or(mask, mask, *nodes);

	WARN(!list_empty(&mos_lwk_memory_list),
	     "LWK memory list is not empty");

	/* Determine the number of NUMA domains. */
	for_each_online_node(n)
		if (lwkmem_n_online_nodes < (n + 1))
			lwkmem_n_online_nodes = n + 1;

	for_each_node_mask(n, *nodes) {
		node_clear(n, mask);
		if (!requests[n]) {
			node_clear(n, *nodes);
			continue;
		}
		sz = lwkmem_get_dynamic_memory(n, requests[n],
					       &mos_lwk_memory_list);
		pr_info("Node %d: Requested %lld MB Allocated %lld MB\n",
			n, requests[n] >> 20, sz >> 20);
		if (sz != requests[n]) {
			sz_dist = requests[n] - sz;
			pr_info("Unallocated %lld bytes req to node(s):%*pbl\n",
				sz_dist, nodemask_pr_args(&mask));
			if (lwkmem_distribute_request(sz_dist, &mask,
						      requests)) {
				mos_ras(MOS_LWKCTL_FAILURE,
					"%s: Could not distribute the request for %lld bytes of LWK memory.",
					__func__, sz_dist);
				sz_req += sz_dist;
			}
			/* Update request with what is actually allocated */
			requests[n] = sz;
		}

		sz_alloc += sz;
		sz_req += requests[n];

		/* Clear the node bit on which we could not allocate */
		if (!sz)
			node_clear(n, *nodes);
	}
	if (sz_alloc != sz_req)
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Could not allocate all requested LWK memory.  Requested:%lld Allocated:%lld",
			__func__, sz_req, sz_alloc);

	pr_warn("Requested %lld MB Allocated %lld MB\n",
		sz_req >> 20, sz_alloc >> 20);

	return sz_alloc ? 0 : -ENOMEM;
}

int mos_mem_free(void)
{
	struct mos_lwk_mem_granule *curr, *next;
	unsigned long start_pfn, nr_pages, i;

	if (lwkmem_static_enabled)
		return -EINVAL;

	pr_info("Returning memory back to Linux\n");
	lock_device_hotplug();
	mem_hotplug_begin();
	list_for_each_entry_safe(curr, next, &mos_lwk_memory_list, list) {
		if (curr->owner != -1) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Block is in use.  block:[%pK-%pK] length:0x%llx owner:%d node:%d",
				__func__, curr->base,
				curr->base + curr->length - 1,
				curr->length, curr->owner, curr->nid);
		}
		list_del(&curr->list);

		nr_pages = curr->length / PAGE_SIZE;
		start_pfn = kaddr_to_pfn(curr->base);

		for (i = 0 ; i < nr_pages; i++)
			lwkmem_page_deinit(pfn_to_page(start_pfn + i));

		pr_info("Node %d: onlining va 0x%p pa 0x%lx pfn %ld-%ld :%ld\n",
			curr->nid, curr->base, __pa(curr->base), start_pfn,
			start_pfn + nr_pages - 1,  nr_pages);
		if (online_pages(start_pfn, nr_pages, MMOP_ONLINE_KEEP)) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Could not online pages.  node:%d address:0x%p pages:%lu",
				__func__, curr->nid, curr->base, nr_pages);
		}
		kfree(curr);
	}
	mem_hotplug_done();
	unlock_device_hotplug();
	pr_info("Exiting memory management\n");
	return 0;
}

static void mos_register_lwkmem_callbacks(void)
{
	mos_register_process_callbacks(&lwkmem_callbacks);

	mos_register_option_callback("lwkmem-brk-disable",
				     lwkmem_brk_disable_cb);
	mos_register_option_callback("lwkmem-max-page-size",
				     lwkmem_max_pg_size_cb);
	mos_register_option_callback("lwkmem-memory-preferences",
				     lwkmem_memory_preferences_cb);
	mos_register_option_callback("lwkmem-aligned-mmap",
				     lwkmem_aligned_mmap_cb);
	mos_register_option_callback("lwkmem-heap-page-size",
				     lwkmem_heap_pg_size_cb);
	mos_register_option_callback("lwkmem-blocks-allocated",
				     lwkmem_blocks_allocated_cb);
	mos_register_option_callback("lwkmem-brk-clear-len",
				     lwkmem_brk_clear_len_cb);
	mos_register_option_callback("lwkmem-interleave-disable",
				     lwkmem_interleave_disable_cb);
	mos_register_option_callback("lwkmem-load-elf-disable",
				     lwkmem_load_elf_disable_cb);
	mos_register_option_callback("lwkmem-interleave",
				     lwkmem_interleave_cb);
	mos_register_option_callback("lwkmem-trace-block-list",
				     lwkmem_trace_block_lists_cb);
	mos_register_option_callback("lwkmem-zeroes-check",
				     lwkmem_zeroes_check_cb);
	mos_register_option_callback("lwkmem-prot-none-delegation-enable",
				     lwkmem_prot_none_delegation_enable_cb);
	mos_register_option_callback("lwkmem-xpmem-stats",
				     lwkmem_xpmem_stats_cb);

}

static int __init __mos_collect_bootmem(void)
{
	if (lwkmem_static_enabled)
		mos_collect_bootmem();
	mos_register_lwkmem_callbacks();
	return 0;
}
subsys_initcall(__mos_collect_bootmem);

void list_vmas(struct mm_struct *mm)
{
	struct vm_area_struct *start;
	struct vm_area_struct *vma;
	char len_str[STRBUF_LEN];
	char lwk_str[STRBUF_LEN];

	start = mm->mmap;
	vma = start;
	while (vma) {
		unsigned long len;

		len = vma->vm_end - vma->vm_start;
		if (len < (1 << 10))
			snprintf(len_str, STRBUF_LEN, "%6ld  ", len);
		else if (len < (1 << 20))
			snprintf(len_str, STRBUF_LEN, "%6ldk ", len >> 10);
		else if (len < (1 << 30))
			snprintf(len_str, STRBUF_LEN, "%6ldM ", len >> 20);
		else
			snprintf(len_str, STRBUF_LEN, "%6ldG ", len >> 30);

		if (is_lwkmem(vma))
			snprintf(lwk_str, STRBUF_LEN, " LWK");
		else
			snprintf(lwk_str, STRBUF_LEN, "    ");

		pr_info("[0x%016lx - 0x%016lx] len %s flags 0x%8lx %s file %p\n",
			vma->vm_start, vma->vm_end, len_str, vma->vm_flags,
			lwk_str, vma->vm_file);

		vma = vma->vm_next;
		if (vma == start)
			/* Wrapped around. Just in case this is possible */
			return;
	}

	return;

} /* list_vmas() */

/**
 * Construct a block list of the specified length and kind using
 * the granule.
 */
static struct blk_list *create_and_link_block(struct lwk_process_granule *pgran,
			      uint64_t length, enum lwkmem_kind_t knd,
			      struct mos_process_t *mosp)
{
	struct blk_list *newb;
	uint64_t addr;

	newb = kmalloc(sizeof(struct blk_list), GFP_KERNEL);
	if (!newb)
		return NULL;

	newb->offset = pgran->offset;
	newb->num_blks = length / kind_size[knd];
	newb->phys = pgran->granule;
	newb->vma_addr = 0;
	newb->stride = 1;
	list_add(&newb->list, &mosp->free_list[knd][newb->phys->nid]);

	/* Move the watermark in the process granule: */
	pgran->offset += length;

	/* Incr. the block count for this TLB size: */
	mosp->num_blks[knd] += newb->num_blks;

	addr = block_addr(newb);

	if (addr != roundup(addr, kind_size[knd]))
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: Block list %#016llx [%s] is not aligned (%#llX).",
			__func__, addr, kind_str[knd], kind_size[knd]-1);

	if (pgran->offset > pgran->granule->length) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: Block list %#016llx [%s] overflows granule [%#016llx-%#016llX).",
			__func__, addr, kind_str[knd],
			(uint64_t)pgran->granule->base,
			(uint64_t)pgran->granule->base + pgran->granule->length);
	}

	trace_mos_mem_block_reserved(0, 0, addr, length, knd, newb->num_blks,
				     1, newb->phys->nid, current->tgid);

	return newb;
}


static int partition_task_mem(struct mos_process_t *mosp, int64_t reserved)
{
	struct lwk_process_granule *g;
	int knd, nxt;
	uint64_t addr, delta;

	list_for_each_entry(g, &mosp->lwkmem_list, list) {
		/* Incrementally align with the next sized TLB or until the
		 * task's maximum page size is hit.
		 */
		for (knd = 0; knd < kind_last - 1; knd++) {

			if (kind_size[knd] == mosp->max_page_size)
				break;

			nxt = knd + 1;

			addr = (uint64_t)g->granule->base + g->offset;

			/* If we are not aligned with the next sized TLB, then
			 * construct a block list that consumes the region
			 * between the current location and the next alignment
			 * boundary.
			 */
			if (nxt < kind_last && (addr & (kind_size[nxt] - 1))) {
				delta = roundup(addr, kind_size[nxt]) - addr;
				delta = min(delta, g->granule->length -
					    g->offset);
				if (!delta)
					continue;
				if (!create_and_link_block(g, delta, knd, mosp))
					return -1;
			}
		}

		/* We are now aligned to the largest TLB boundary.  Consume
		 * the remainder of the granule in the largest possible blocks:
		 */

		for (knd = kind_last - 1; knd >= 0; knd--) {

			if (kind_size[knd] > mosp->max_page_size)
				continue;

			if (g->offset >= g->granule->length)
				break;

			delta = rounddown(g->granule->length - g->offset,
					  kind_size[knd]);
			if (!delta)
				continue;

			if (!create_and_link_block(g, delta, knd, mosp))
				return -1;
		}
	}

	return 0;
}

static struct mos_lwk_mem_granule *find_free_granule_for_nid(int nid)
{
	struct mos_lwk_mem_granule *g;

	list_for_each_entry(g, &mos_lwk_memory_list, list) {
		if (g->owner <= 0 && (g->nid == nid || nid == NUMA_NO_NODE))
			return g;
	}

	return NULL;
}

/*
 * Free the memory used to store the block lists and mark the corresponding
 * physical regions as free
 */
static void release_task_mem_blocks(void)
{
	struct blk_list *bl;
	struct blk_list *tmp;
	struct mos_process_t *mos_p;
	enum lwkmem_kind_t k;
	unsigned long addr, len;

	mos_p = current->mos_process;
	if (!mos_p)
		return;

	for (k = kind_4k; k < kind_last; k++) {
		int n;

		for_each_online_node(n) {
			list_for_each_entry_safe(bl, tmp,
						 &mos_p->free_list[k][n],
						 list) {

				addr = block_addr(bl);
				len = bl->num_blks * kind_size[k];

				trace_mos_mem_block_released(0, 0, addr, len, k,
				     bl->num_blks, 1, bl->phys->nid,
				     current->tgid);

				if (lwkmem_zeroes_check_enabled(ZCHECK_RELEASE))
					lwkmem_check_for_zero(addr, len, NULL, "release");

				bl->phys->owner = -1;
				list_del(&bl->list);
				kfree(bl);
			}
			list_for_each_entry_safe(bl, tmp,
						 &mos_p->busy_list[k][n],
						 list) {

				addr = block_addr(bl);
				len = min_t(unsigned long, bl->phys->length
					    - bl->offset,
					    bl->num_blks * kind_size[k]);

				trace_mos_mem_block_released(bl->vma_addr,
				     block_size_virt(bl, k), addr,
				     bl->num_blks * kind_size[k], k,
				     bl->num_blks, 1, bl->phys->nid,
				     current->tgid);

				memset((void *)addr, 0, len);
				bl->phys->owner = -1;
				list_del(&bl->list);
				kfree(bl);
			}
		}
		mos_p->num_blks[k] = 0;
	}
} /* end of release_task_mem_blocks() */

/*
 * This mOS process is going away. Release all resources related to LWK memory.
 * We assume that freeing all data structures realted to the vma will be done
 * by Linux when the process exits.
 */
void lwkmem_release(struct mos_process_t *mos_p)
{
	struct lwk_process_granule *p_granule;
	struct lwk_process_granule *tmp;
	struct mos_lwk_mem_granule *elt;
	struct mos_lwk_mem_granule *next;
	struct mos_lwk_mem_granule *save;

	release_task_mem_blocks();

	/* There is a problem, if lwkmem_list is empty */
	if (list_empty(&(mos_p->lwkmem_list))) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: Process %d has no LWK memory.",
			__func__, current->pid);
		return;
	}

	if (mos_p->report_blks_allocated) {
		int n, rc;
		enum lwkmem_kind_t k;
		char str[MAX_NUMNODES*16];

		/* Output process memory information header. */
		pr_info("PID %u memory usage:\n", mos_p->tgid);
		rc = snprintf(str, sizeof(str), "mem/nid\t");
		for_each_node_mask(n, node_online_map)
			rc += snprintf((str+rc), sizeof(str)-rc, "%8u ", n);
		pr_info("%s\n", str);

		/* Output block usage data. */
		for (k = kind_4k; k < kind_last; k++) {
			rc = snprintf(str, sizeof(str), "%s\t", kind_str[k]);
			for_each_node_mask(n, node_online_map)
				rc += snprintf((str+rc), sizeof(str)-rc, "%8lu ",
						mos_p->blks_allocated[k][n]);
			pr_info("%s\n", str);
		}

		pr_info("PID %u max memory usage by domain:\n", mos_p->tgid);
		rc = snprintf(str, sizeof(str), "mem/nid\t");
		for_each_node_mask(n, node_online_map)
			rc += snprintf((str+rc), sizeof(str)-rc, "%8u ", n);
		pr_info("%s\n", str);

		/* Output block usage data. */
		rc = snprintf(str, sizeof(str), "Max:\t");
		for_each_node_mask(n, node_online_map)
			rc += snprintf((str+rc), sizeof(str)-rc, "%8lu ",
				       mos_p->max_allocated[n]);
		pr_info("%s\n", str);
	}

	/* Reset the granules that were assigned to this process in the
	 * global mos_lwk_memory_list.
	 */
	list_for_each_entry_safe(p_granule, tmp, &mos_p->lwkmem_list, list) {
		p_granule->granule->owner = -1;
		p_granule->granule = NULL;
		list_del(&p_granule->list);
		kfree(p_granule);
	}

	/* (Re)Merge granules that are physically adjacent */
	list_for_each_entry_safe(elt, save, &mos_lwk_memory_list, list) {
		next = list_next_entry(elt, list);
		if ((elt->base + elt->length == next->base) &&
				(elt->owner == -1) && (next->owner == -1)) {
			next->base = elt->base;
			next->length = next->length + elt->length;
			list_del(&elt->list);
			kfree(elt);
		}
	}
	show_xpmem_stats(mos_p);
}

/*
 * Returns total designated LWK memory @totalram and total un reserved
 * memory in @freeram
 *
 * @nid, if set to a valid NUMA node number then the function returns the
 *       node specific info
 *
 *       if set to NUMA_NO_NODE then the function returns the accumulated
 *       info of all online NUMA nodes.
 */
static void lwkmem_globalmem(unsigned long *totalram, unsigned long *freeram,
			     int nid)
{
	unsigned long total[MAX_NUMNODES] = {0};
	unsigned long res[MAX_NUMNODES] = {0};
	size_t n = ARRAY_SIZE(total);

	if (!totalram || !freeram)
		return;

	lwkmem_get(total, &n);
	lwkmem_reserved_get(res, &n);
	*totalram = *freeram = 0;

	if (nid == NUMA_NO_NODE) {
		for_each_online_node(n) {
			*totalram += total[n];
			*freeram += (total[n] - res[n]);
		}
	} else {
		*totalram = total[nid];
		*freeram = total[nid] - res[nid];
	}
	*totalram >>= PAGE_SHIFT;
	*freeram  >>= PAGE_SHIFT;
}

/*
 * For the current task this function returns,
 *         total memory in the busy list of @nid in @alloc
 *         total memory in the free list of @nid in @avail
 *
 * Assumes caller holds read side of mm->mmap_sem
 */
static void _lwkmem_taskmem(unsigned long *alloc, unsigned long *avail,
			    int nid)
{
	enum lwkmem_kind_t k;
	struct blk_list *p_blk;
	struct mos_process_t *mos_p = current->mos_process;
	unsigned long t_avail = 0;
	unsigned long t_alloc = 0;

	for (k = kind_4k; k < kind_last; k++) {
		list_for_each_entry(p_blk,
			&mos_p->free_list[k][nid], list)
			t_avail += p_blk->num_blks * kind_size[k];
		list_for_each_entry(p_blk, &mos_p->busy_list[k][nid], list)
			t_alloc += p_blk->num_blks * kind_size[k];
	}
	*alloc = t_alloc;
	*avail = t_avail;
}

/*
 * Returns total reserved memory of the current task in @totalram and
 * total memory in the free list of the task in @freeram
 *
 * @nid, if set to a valid NUMA node number then the function returns the
 *       node specific info
 *       if set to NUMA_NO_NODE then the function returns the accumulated
 *       info of all online NUMA nodes.
 */
static void lwkmem_taskmem(unsigned long *totalram, unsigned long *freeram,
			   int nid)
{
	unsigned long avail, total_avail = 0;
	unsigned long alloc, total_alloc = 0;
	int n;

	if (!totalram || !freeram)
		return;

	down_read(&current->mm->mmap_sem);

	if (nid == NUMA_NO_NODE) {
		for_each_online_node(n) {
			_lwkmem_taskmem(&alloc, &avail, n);
			total_alloc += alloc;
			total_avail += avail;
		}
	} else
		_lwkmem_taskmem(&total_alloc, &total_avail, nid);
	up_read(&current->mm->mmap_sem);

	*totalram = (total_alloc + total_avail) >> PAGE_SHIFT;
	*freeram = total_avail >> PAGE_SHIFT;
}

/* Populate memory info in the sysinfo. This function is mOS view aware,
 * For Linux tasks,
 *   if mOS view is,
 *      linux: Don't modify val
 *
 *      lwk  : totalram is set to the total designated LWK memory
 *             freeram is set to the total unreserved LWK memory
 *             all other memory related fields are set to 0
 *
 *      all  : totalram, the total designated LWK memory is added
 *             to totalram of val
 *             freeram, the total unreserved LWK memory is added
 *             to the freeram of val
 *
 * For mOS tasks irrespective of the mOS view,
 *   totalram is set to the total reserved LWK memory of that task.
 *   freeram is set to the total memory in the free list of that task.
 *   All other memory related fields are set to 0.
 */
void si_meminfo_node_mos(struct sysinfo *val, int nid)
{
	unsigned long total = 0;
	unsigned long free = 0;
	bool lwkview_local = IS_MOS_VIEW(current, MOS_VIEW_LWK_LOCAL);

	if (!lwkview_local && IS_MOS_VIEW(current, MOS_VIEW_LINUX))
		return;

	if (lwkview_local || IS_MOS_VIEW(current, MOS_VIEW_LWK)) {
		if (lwkview_local)
			lwkmem_taskmem(&val->totalram, &val->freeram, nid);
		else
			lwkmem_globalmem(&val->totalram, &val->freeram, nid);
		val->sharedram = 0;
		val->bufferram = 0;
		val->totalswap = 0;
		val->freeswap  = 0;
		val->totalhigh = 0;
		val->freehigh  = 0;
		val->mem_unit = PAGE_SIZE;
	} else if (IS_MOS_VIEW(current, MOS_VIEW_ALL)) {
		lwkmem_globalmem(&total, &free, nid);
		val->totalram += total;
		val->freeram += free;
		val->mem_unit = PAGE_SIZE;
	}
}

/*
 * For a given kind; e.g., 1g, 4m, 2m, or 4k, figure out how many blocks we
 * should allocate. Return the appropriate number of blocks.
 */
static int64_t blocks_wanted(int64_t len, int64_t *wanted,
			  struct allocate_options_t *options)
{
	int64_t total = 0;
	enum lwkmem_kind_t k;

	for (k = kind_last - 1; (int)k >= 0 && len > 0; k--) {
		if (kind_size[k] > options->max_page_size)
			continue;

		wanted[k] = len / kind_size[k];

		len -= wanted[k] * kind_size[k];
		total += wanted[k] * kind_size[k];
	}

	return total;
}

/*
** Convert a user virtual address to a pointer to the corresponding struct
** page. LWK memory is always pinned, so there is always a struct page for
** an LWK memory user address.
*/
struct page *lwkmem_user_to_page(struct mm_struct *mm, unsigned long addr,
				 unsigned int *size)
{
	unsigned long *PML4E;
	unsigned long *PDPTE;
	unsigned long *PDE;
	unsigned long *PTE;
	pgd_t *pgd;
	long int offset;
	struct page *pg;

	pgd = pgd_offset(mm, addr);
	PML4E = (unsigned long *)mm->pgd;
	PDPTE = __va(PML4E[pgd_index(addr)] & PHYSICAL_PAGE_MASK);
	if (PDPTE[pud_index(addr)] & _PAGE_PSE) {
		/* This is a pointer to a 1g page */
		pg = virt_to_page(__va(PDPTE[pud_index(addr)] & PG1G_MASK));
		offset = addr & 0x03fffffff;
		pg = pg + (offset / PAGE_SIZE);
		*size = SZ_1G;
		return pg;
	}
	PDE = __va(PDPTE[pud_index(addr)] & PHYSICAL_PAGE_MASK);
	if (PDE[pmd_index(addr)] & _PAGE_PSE) {
		/* This is a pointer to a 2m page */
		pg = virt_to_page(__va(PDE[pmd_index(addr)] & PG2M_MASK));
		offset = addr & 0x0001fffff;
		pg = pg + (offset / PAGE_SIZE);
		*size = SZ_2M;
		return pg;
	}
	PTE = __va(PDE[pmd_index(addr)] & PHYSICAL_PAGE_MASK);
	if (PTE[pte_index(addr)] & _PAGE_PRESENT) {
		/* This is a pointer to a 4k page */
		pg = virt_to_page(__va(PTE[pte_index(addr)] & ADDR_MASK));
		/* No need to adjust; offset is < PAGE_SIZE */
		*size = SZ_4K;
		return pg;
	}
	return NULL;

} /* end of lwkmem_user_to_page() */

/*
 * Print CR3 and page table entry structure flags for IA=32e paging mode
 * From Fugure 4-11 in Intel 64 and IA-32 Architectures Software Developer's
 * Manual, Volume 3A: System Programming Guide, Part 1
 * lvl are {CR3 = 0, PML4E = 1, PDPTE = 2, PDE = 3, PTE = 4}
 */
static char *print_flags(int lvl, unsigned long entry)
{
	static char buf1[STRBUF_LEN];
	static char buf2[STRBUF_LEN];

	switch (lvl) {
	case 0:
		snprintf(buf1, STRBUF_LEN, "CR3:   ");
		break;
	case 1:
		snprintf(buf1, STRBUF_LEN, "PML4E: ");
		break;
	case 2:
		snprintf(buf1, STRBUF_LEN, "PDPTE: ");
		break;
	case 3:
		snprintf(buf1, STRBUF_LEN, "PDE:   ");
		break;
	case 4:
		snprintf(buf1, STRBUF_LEN, "PTE:   ");
		break;
	default:
		snprintf(buf1, STRBUF_LEN, "unknown paging entry level\n");
		return buf1;
	}

	if (lvl == 0) {
		snprintf(buf2, STRBUF_LEN, "PML4 table at     0x%016lx",
			entry & ADDR_MASK);
		strcat(buf1, buf2);
		if (entry & _PAGE_PWT)
			strcat(buf1, " PWT");
		if (entry & _PAGE_PCD)
			strcat(buf1, " PCD");
		strcat(buf1, "\n");
		return buf1;
	}

	if (!(entry & _PAGE_PRESENT)) {
		strcat(buf1, "not present\n");
		return buf1;
	}

	if (lvl == 1) {
		/* PML4E */
		snprintf(buf2, STRBUF_LEN, "page dir table at 0x%016lx",
			entry & ADDR_MASK);
		strcat(buf1, buf2);
	} else if (lvl == 2) {
		/* PDPTE */
		if (entry & _PAGE_PSE) {
			snprintf(buf2, STRBUF_LEN, "1GB page frame at 0x%016lx",
				entry & PG1G_MASK);
			strcat(buf1, buf2);
			if (entry & _PAGE_PAT_LARGE)
				strcat(buf1, " large PAT");
		} else {
			snprintf(buf2, STRBUF_LEN, "page dir at       0x%016lx",
				entry & ADDR_MASK);
			strcat(buf1, buf2);
		}
	} else if (lvl == 3) {
		/* PDE */
		if (entry & _PAGE_PSE) {
			snprintf(buf2, STRBUF_LEN, "2MB page frame at 0x%016lx",
				entry & PG2M_MASK);
			strcat(buf1, buf2);
			if (entry & _PAGE_PAT_LARGE)
				strcat(buf1, " large PAT");
		} else {
			snprintf(buf2, STRBUF_LEN, "page table at     0x%016lx",
				entry & ADDR_MASK);
			strcat(buf1, buf2);
		}
	} else {
		/* PTE */
		snprintf(buf2, STRBUF_LEN, "4kB page frame at 0x%016lx",
			entry & ADDR_MASK);
		strcat(buf1, buf2);
		if (entry & _PAGE_PAT)
			strcat(buf1, " PAT");
	}

	/* Common flags for entries that are present */
	if (entry & _PAGE_GLOBAL)
		strcat(buf1, " global");

	if (entry & _PAGE_DIRTY)
		strcat(buf1, " dirty");

	if (entry & _PAGE_ACCESSED)
		strcat(buf1, " accessed");

	if (entry & _PAGE_PCD)
		strcat(buf1, " cache disabled");

	if (entry & _PAGE_PWT)
		strcat(buf1, " write through");

	if (entry & _PAGE_USER)
		strcat(buf1, " user space");

	if (entry & _PAGE_RW)
		strcat(buf1, " writeable");

	strcat(buf1, "\n");
	return buf1;

} /* end of print_flags() */

static void print_cr3(char *str, unsigned long cr3)
{
	unsigned long PML4_addr;
	char buf1[STRBUF_LEN];

	PML4_addr = (cr3 & 0x0fffffffffffff000);

	snprintf(buf1, STRBUF_LEN, "%sPML4 table address is 0x%016lx Flags:",
		str, PML4_addr);
	if (cr3 & _PAGE_PWT)
		strcat(buf1, " PWT");
	if (cr3 & _PAGE_PCD)
		strcat(buf1, " PCD");
	pr_info("%s\n", buf1);

} /* end of print_cr3() */

static void idx_range(int idx, int max, int *idx_start, int *idx_end)
{
	*idx_end = *idx_start = idx;
	if (*idx_start > 0)
		*idx_start = *idx_start - 1;
	else
		*idx_end = *idx_end + 1;
	if (*idx_end < (max - 1))
		*idx_end = *idx_end + 1;
	else
		*idx_start = *idx_start - 1;

} /* end of idx_range() */

void print_pgd(pgd_t *cr3, unsigned long addr)
{
	unsigned long *PML4E;
	unsigned long *PDPTE;
	unsigned long *PDE;
	unsigned long *PTE;
	int idx_start, idx_end, i;
	int count;
#ifdef DEBUG_DEBUG
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct page *page = NULL;
#endif /* DEBUG_DEBUG */

	print_cr3("", native_read_cr3_pa());
	PML4E = (unsigned long *)cr3;
#ifdef DEBUG_DEBUG
	pgd = pgd_offset(current->mm, addr);
	pr_err("pgd_offset(mm)  is 0x%016lx\n", pgd_val(*pgd));
#endif /* DEBUG_DEBUG */

	/* I want to print 3 PML4E entries near idx */
	idx_range(pgd_index(addr), PTRS_PER_PGD, &idx_start, &idx_end);

	count = 0;
	for (i = 0; i < PTRS_PER_PGD; i++)
		if (PML4E[i] & _PAGE_PRESENT)
			count++;

	pr_info("Looking up virtual address 0x%016lx\n", addr);
	pr_info("PML4E at 0x%016lx has %d entries present\n",
		(unsigned long)PML4E, count);
	for (i = idx_end; i >= idx_start; i--) {
		if (i == pgd_index(addr))
			pr_info(" --->[%3d] %s", i,
				print_flags(1, PML4E[i]));
		else
			pr_info("     [%3d] %s", i,
				print_flags(1, PML4E[i]));
	}

	PDPTE = __va(PML4E[pgd_index(addr)] & PHYSICAL_PAGE_MASK);
#ifdef DEBUG_DEBUG
	pud = pud_offset(pgd, addr);
	pr_err("pud_offset(pgd) is 0x%016lx\n", pud_val(*pud));
#endif /* DEBUG_DEBUG */

	idx_range(pud_index(addr), PTRS_PER_PUD, &idx_start, &idx_end);

	count = 0;
	for (i = 0; i < PTRS_PER_PUD; i++)
		if (PDPTE[i] & _PAGE_PRESENT)
			count++;

	pr_info("PDPTE at 0x%016lx has %d entries present\n",
		(unsigned long)PDPTE, count);
	for (i = idx_end; i >= idx_start; i--) {
		if (i == pud_index(addr))
			pr_info(" --->[%3d] %s", i, print_flags(2, PDPTE[i]));
		else
			pr_info("     [%3d] %s", i, print_flags(2, PDPTE[i]));
	}

	if (PDPTE[pud_index(addr)] & _PAGE_PSE) {
		/* This is a pointer to a 1g page */
		pr_info("addr 0x%lx is in a 1g page at %p and offset %ld\n",
			addr, __va(PDPTE[pud_index(addr)] & PG1G_MASK),
			addr & 0x03fffffff);
		return;
	}

	/* This is a pointer to a page directory */
	PDE = __va(PDPTE[pud_index(addr)] & PHYSICAL_PAGE_MASK);
#ifdef DEBUG_DEBUG
	pmd = pmd_offset(pud, addr);
	pr_err("pud_offset(pud) is 0x%016lx\n", pmd_val(*pmd));
#endif /* DEBUG_DEBUG */

	idx_range(pmd_index(addr), PTRS_PER_PMD, &idx_start, &idx_end);

	count = 0;
	for (i = 0; i < PTRS_PER_PMD; i++)
		if (PDE[i] & _PAGE_PRESENT)
			count++;

	pr_info("PDE at 0x%016lx has %d entries present\n",
		(unsigned long)PDE, count);
	for (i = idx_end; i >= idx_start; i--) {
		if (i == pmd_index(addr))
			pr_info(" --->[%3d] %s", i, print_flags(3, PDE[i]));
		else
			pr_info("     [%3d] %s", i, print_flags(3, PDE[i]));
	}

	if (PDE[pmd_index(addr)] & _PAGE_PSE) {
		/* This is a pointer to a 2m page */
		pr_info("addr 0x%lx is in a 2m page at %p and offset %ld\n",
			addr, __va(PDE[pmd_index(addr)] & PG2M_MASK),
			addr & 0x0001fffff);
		return;
	}

	/* This is a pointer to a page table */
	PTE = __va(PDE[pmd_index(addr)] & PHYSICAL_PAGE_MASK);
#ifdef DEBUG_DEBUG
	pte = pte_offset_map(pmd, addr);
	pr_err("pte_offset(pmd) is 0x%016lx\n", pte_val(*pte));
#endif /* DEBUG_DEBUG */


	idx_range(pte_index(addr), PTRS_PER_PTE, &idx_start, &idx_end);

	count = 0;
	for (i = 0; i < PTRS_PER_PTE; i++)
		if (PTE[i] & _PAGE_PRESENT)
			count++;

	pr_info("PTE at 0x%016lx has %d entries present\n",
		(unsigned long)PTE, count);
	for (i = idx_end; i >= idx_start; i--) {
		if (i == pte_index(addr))
			pr_info(" --->[%3d] %s", i, print_flags(4, PTE[i]));
		else
			pr_info("     [%3d] %s", i, print_flags(4, PTE[i]));
	}

	if (PTE[pte_index(addr)] & _PAGE_PRESENT) {
		/* This is a pointer to a 4k page */
		pr_info("addr 0x%lx is in a 4k page at %p and offset %ld\n",
			addr, __va(PTE[pte_index(addr)] & ADDR_MASK),
			addr & 0x000000fff);
		return;
	}
	pr_info("addr 0x%lx is NOT fully mapped. PTE is 0x%lx\n", addr,
		PTE[pte_index(addr)]);
#ifdef DEBUG_DEBUG
	page = pte_page(*pte);
	if (!page)
		pr_err("There is No struct page for this 4k page!\n");
	else {
		pr_err("There IS a struct page for this 4k page! PFN %ld, pfn_valid %d\n",
			pte_pfn(*pte), pfn_valid(pte_pfn(*pte)));
	}
	pte_unmap(pte);
#endif /* DEBUG_DEBUG */

	return;

} /* end of print_pgd() */

/*
 * Build the page table entries for this vma
 * Each lwkmem vma covers a physically contigous range of memory of a given
 * page size specified by knd. The memory range starts at phys.
 */
int build_pagetbl(enum lwkmem_kind_t knd, struct vm_area_struct *vma,
		  unsigned long phys, unsigned long addr, unsigned long end,
		  unsigned int stride)
{
	unsigned long i, nr_pages;
	struct mm_struct *mm = current->mm;
	int rc = 0;

	phys = (phys + lwk_page_size[knd] - 1) & lwk_page_mask[knd];
	while (addr < end) {
		struct page *p;
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		spinlock_t *ptl;

		pgd = pgd_offset(mm, addr);
		p4d = p4d_alloc(mm, pgd, addr);

		if (!p4d) {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Page table allocation failure: P4D",
				__func__);
			rc = -ENOMEM;
			goto pagetbl_err;
		}

		pud = pud_alloc(mm, p4d, addr);
		if (!pud) {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Page table allocation failure: PUD",
				__func__);
			rc = -ENOMEM;
			goto pagetbl_err;
		}

		if (knd == kind_1g) {
			/* Use cpu_has_gbpages from asm/cpufeature.h for 1g */
			/* Have a look at setup_hugepagesz() */
			pud_t entry;

			ptl = &mm->page_table_lock;
			spin_lock(ptl); /* Not sure this is actually needed */

			/* Setup the PUD (for a 1g page) */
			entry = __pud(((phys_addr_t)phys) |
					massage_pgprot(vma->vm_page_prot));

			/* _PAGE_PWT cache write combining */
			/* _PAGE_PCD */
			/* _PAGE_PCD | _PAGE_PWT == uncached; don't want that */
			entry =  __pud(native_pud_val(entry) & ~(_PAGE_PWT|
					_PAGE_PCD|_PAGE_DIRTY));

			entry = __pud(native_pud_val(entry) | (_PAGE_PRESENT|
					_PAGE_USER|_PAGE_RW|_PAGE_ACCESSED|
					_PAGE_PSE));

			/* *pud = entry */
			set_pud(pud, entry);

			if (!is_lwkxpmem(vma)) {
				/* Initialize pages and add mapping. */
				p = pud_page(entry);
				prep_compound_page(p, PUD_SHIFT - PAGE_SHIFT);
				lwkpage_add_rmap(p, vma, addr & PUD_MASK);

				nr_pages = 1 << (PUD_SHIFT - PAGE_SHIFT);
				for (i = 0; i < nr_pages; i++)
					lwkmem_page_init(p + i);
			}

			spin_unlock(ptl);

			if (!is_lwkxpmem(vma) &&
			    lwkmem_zeroes_check_enabled(ZCHECK_ALLOCATE))
				lwkmem_check_for_zero(addr, kind_size[knd], mm,
						      "alloc");

		} else if (knd == kind_2m) {
			pmd_t entry;

			pmd = pmd_alloc(mm, pud, addr);
			if (!pmd) {
				mos_ras(MOS_LWKMEM_PROCESS_ERROR,
					"%s: Page table allocation failure: PMD",
					__func__);
				rc = -ENOMEM;
				goto pagetbl_err;
			}
			ptl = pmd_lock(mm, pmd);

			/* Setup the PMD (for a 2m page) */
			entry = pfn_pmd(phys >> PAGE_SHIFT, vma->vm_page_prot);

			/* _PAGE_PWT cache write combining */
			/* _PAGE_PCD */
			/* _PAGE_PCD | _PAGE_PWT == uncached; don't want that */
			entry = pmd_clear_flags(entry, _PAGE_PWT|_PAGE_PCD|
						_PAGE_DIRTY);

			entry = pmd_set_flags(entry, _PAGE_PRESENT|_PAGE_USER|
					_PAGE_RW|_PAGE_ACCESSED|_PAGE_PSE);

			/* *pmd = entry */
			set_pmd_at(mm, addr, pmd, entry);

			if (!is_lwkxpmem(vma)) {
				/* Initialize pages and add mapping. */
				p = pmd_page(entry);

				prep_compound_page(p, HPAGE_PMD_ORDER);
				lwkpage_add_rmap(p, vma, addr & HPAGE_PMD_MASK);

				nr_pages = 1 << HPAGE_PMD_ORDER;
				for (i = 0; i < nr_pages; i++)
					lwkmem_page_init(p + i);
			}

			spin_unlock(ptl);

			if (!is_lwkxpmem(vma) &&
			    lwkmem_zeroes_check_enabled(ZCHECK_ALLOCATE))
				lwkmem_check_for_zero(addr, kind_size[knd], mm,
						      "alloc");

		} else if (knd == kind_4k) {
			pte_t entry;

			pmd = pmd_alloc(mm, pud, addr);
			if (!pmd) {
				mos_ras(MOS_LWKMEM_PROCESS_ERROR,
					"%s: Page table allocation failure: PMD",
					__func__);
				rc = -ENOMEM;
				goto pagetbl_err;
			}

			pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
			if (!pte) {
				mos_ras(MOS_LWKMEM_PROCESS_ERROR,
					"%s: Page table allocation failure: PTE",
					__func__);
				rc = -ENOMEM;
				goto pagetbl_err;
			}

			entry = pfn_pte((phys >> PAGE_SHIFT),
					vm_get_page_prot(vma->vm_flags));

			/* _PAGE_PCD | _PAGE_PWT == uncached; don't want that */
			entry = pte_clear_flags(entry, _PAGE_PWT|_PAGE_PCD|
						_PAGE_DIRTY);

			entry = pte_set_flags(entry, _PAGE_PRESENT|_PAGE_USER|
					_PAGE_RW|_PAGE_ACCESSED);
			/* *pte = entry */
			set_pte_at(mm, addr, pte, entry);

			if (!is_lwkxpmem(vma)) {
				/* Initialize page and add mapping. */
				p = pte_page(entry);
				ClearPageHead(p);
				clear_compound_head(p);
				lwkpage_add_rmap(p, vma, addr);
				lwkmem_page_init(p);
			}
			pte_unmap_unlock(pte, ptl);

			if (!is_lwkxpmem(vma) &&
			    lwkmem_zeroes_check_enabled(ZCHECK_ALLOCATE))
				lwkmem_check_for_zero(addr, kind_size[knd], mm,
						      "alloc");

		} else {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Page table allocation failure: Page size not supported (%d)",
				__func__, knd);
			rc = -ENOMEM;
			goto pagetbl_err;
		}

		addr += (kind_size[knd] * stride);
		phys += kind_size[knd];
	}

pagetbl_err:
	return rc;

} /* end of build_pagetbl() */

static long build_lwkvma(enum lwkmem_kind_t knd, unsigned long addr,
			 unsigned long len, unsigned long prot,
			 unsigned long mmap_flags, unsigned long pgoff,
			 unsigned long total_length,
			 struct vm_area_struct **vma)
{

	int rc = 0;
	int pkey = 0;
	struct mm_struct *mm = current->mm;
	vm_flags_t vm_flags;
	struct rb_node **rb_link, *rb_parent;
	struct vm_area_struct *prev;

	/* Ignore those per man page */
	mmap_flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	/* There is no need to align the length. This function gets called
	 * with len requests of multiples of blocks sizes. */
	if (unlikely(len != ALIGN(len, lwk_page_size[knd])))
		return -EINVAL;

	/* Too many mappings? */
	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	if (mmap_flags & MAP_FIXED) {
		if (addr == 0)
			/* Supposed to map at 0. Let Linux do that. */
			return -ENOSYS;
		if ((addr & (lwk_page_size[knd] - 1)) != 0) {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Hint address 0x%lx not aligned with %s page.",
				__func__, addr, kind_str[knd]);
			return -ENOSYS;
		}
	} else {
		struct vm_unmapped_area_info info;

		info.flags = 0;
		info.length = total_length;
		info.low_limit = current->mm->mmap_legacy_base;
		info.high_limit = TASK_SIZE;
		info.align_mask = lwk_page_size[knd] - 1;
		info.align_offset = 0;

		/* x86_64 arch_get_unmapped_area() -> vm_unmapped_area()
		 * -> unmapped_area()
		 * We can't use get_unmapped_area because we really want to
		 * align addr to lwk_page_size[knd].
		 */
		addr = unmapped_area(&info);
	}

	if (prot == PROT_EXEC) {
		pkey = execute_only_pkey(mm);
		if (pkey < 0)
			pkey = 0;
	}

	vm_flags = calc_vm_prot_bits(prot, pkey) |
		calc_vm_flag_bits(mmap_flags) | mm->def_flags | VM_MAYREAD |
		VM_MAYWRITE | VM_MAYEXEC | VM_READ | VM_WRITE | VM_ACCOUNT |
		VM_LWK;

	if (knd != kind_4k)
		vm_flags |= VM_HUGEPAGE;
	if (knd == kind_1g)
		vm_flags |= VM_LWK_1G;

	/* Pretend I/O space, but map cacheable (see below)
	 * We don't want to set VM_HUGETLB in vm_flags because we are doing
	 * things not entirely compatible with hugeTLB.
	 * However, there are places in Linux where that flag gets checked.
	 * In some of those, we need to insert our own code to handle LWK mem.
	 * Look for places where is_vm_hugetlb_page() gets called.
	 * PAT reserves whole VMA at once (x86).  We aren't setting VM_PAT
	 * to get out from untrack_pfn() faster.
	 */

	switch (mmap_flags & MAP_TYPE) {
	case MAP_SHARED:
		if (vm_flags & (VM_GROWSDOWN | VM_GROWSUP))
			return -EINVAL;
		/* Ignore pgoff. */
		pgoff = 0;
		vm_flags |= VM_SHARED | VM_MAYSHARE;
		break;
	case MAP_PRIVATE:
		/* Set pgoff according to addr for anon_vma. */
		pgoff = addr >> PAGE_SHIFT;
		break;
	default:
		return -EINVAL;
	}

	/* find_vma_links() finds the place where this vm entry should go */
	rc = find_vma_links(mm, addr, addr + len, &prev, &rb_link, &rb_parent);
	if (rc) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: find_vma_links(%p, 0x%lx, 0x%lx, ...)=%i",
			__func__, mm, addr, addr + len, rc);
		goto out;
	}

	/* See if we can merge with an existing VMA */
	*vma = vma_merge(mm, prev, addr, addr + len, vm_flags, NULL,
			 NULL, pgoff, NULL, prev->vm_userfaultfd_ctx);
	if (!*vma) {
		/* Get us some memory to store our vm_area_struct structure */
		*vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
		if (!vma) {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: kmem_cache_zalloc() failed to allocate a VMA.",
				__func__);
			goto out;
		}

		(*vma)->vm_mm = mm;
		(*vma)->vm_start = addr;
		(*vma)->vm_end = addr + len;
		(*vma)->vm_flags = vm_flags;
		(*vma)->vm_page_prot = vm_get_page_prot(vm_flags);
		(*vma)->vm_pgoff = pgoff;
		(*vma)->vm_ops = &lwkmem_vm_ops;

		/* Now link our entry into the vma list */
		INIT_LIST_HEAD(&(*vma)->anon_vma_chain);
		vma_link(mm, *vma, prev, rb_link, rb_parent);
	}

	rc = anon_vma_prepare(*vma);
	if (rc) {
		kmem_cache_free(vm_area_cachep, *vma);
		addr = rc;
		goto out;
	}

	vm_stat_account(mm, vm_flags, len >> PAGE_SHIFT);
	perf_event_mmap(*vma);

out:
	return rc ? rc : addr;

} /* end of build_lwkvma() */

static DEFINE_MUTEX(lwkmem_mutex);

/**
 * For the given block size, obtains a free block of a larger size and
 * turns it into a (free) block of the given kind.  Returns the
 * number of blocks created; or negative if there is no free space.
 */
static struct blk_list *divide_block(enum lwkmem_kind_t knd,
			      struct allocate_options_t *opts)
{
	enum lwkmem_kind_t nxt;
	struct blk_list *elt = 0, *newb = 0;

	/* Find the next larger sized block that is actually used: */
	nxt = knd + 1;
	if (nxt >= kind_last) {
		pr_debug("Cannot divide %s blocks\n", kind_str[knd]);
		return 0;
	}

	elt = opts->find_available(nxt, opts);

	/* If there are no blocks of the next larger size available,
	 * then recurse.
	 */
	if (!elt) {
		elt = divide_block(nxt, opts);

		if (!elt)
			return 0;
	}

	/* If there is more than one free block of the next larger
	 * size, then consume just the first free block.  Otherwise
	 * the entire block needs to be consumed.
	 */
	if (elt->num_blks > 1) {
		newb = kmalloc(sizeof(struct blk_list), GFP_KERNEL);
		if (!newb)
			return 0;
		newb->phys = elt->phys;
		newb->offset = elt->offset;
		newb->num_blks = kind_size[nxt] / kind_size[knd];
		newb->vma_addr = 0;
		newb->stride = 1;
		elt->num_blks--;
		elt->offset += kind_size[nxt];
	} else {

		list_del(&(elt->list));

		newb = elt;
		newb->num_blks *= (kind_size[nxt] / kind_size[knd]);
	}


	/* Add the block to the list */
	list_add(&newb->list, &opts->mosp->free_list[knd][newb->phys->nid]);

	/* Update block counts */
	opts->mosp->num_blks[knd] += newb->num_blks;
	opts->mosp->num_blks[nxt] -= 1;

	trace_mos_mem_block_divided(0, 0, block_addr(newb), kind_size[knd+1],
	    knd, newb->num_blks, 1, newb->phys->nid, current->tgid);

	return newb;
}

static struct blk_list *find_available_by_nid(enum lwkmem_kind_t knd, int nid,
		       struct allocate_options_t *opts)
{
	int count = 0;
	int n = (nid >= 0 ? nid : 0);
	struct blk_list *elt, *blk = NULL;

	list_for_each_entry(elt, &opts->mosp->free_list[knd][n], list) {
		count++;

		if (elt->phys->nid == nid || nid == -1) {
			blk = elt;
			break;
		}
	}

	return blk;
}

static struct blk_list *find_available_by_nid_list(enum lwkmem_kind_t knd,
					 struct allocate_options_t *opts)
{
	struct blk_list *elt;
	int i, nid;
	enum lwkmem_kind_t k;
	struct mos_process_t *mosp = opts->mosp;

	for (i = 0; i < lwkmem_type_last; i++) {
		int start_domain_index;
		enum lwkmem_type_t t = opts->type_order[i];

		if (opts->nid_order_len[t] == 0)
			continue;

		if (opts->mosp->lwkmem_interleave_disable)
			mosp->domain_order_index[t][knd] = 0;

		start_domain_index = mosp->domain_order_index[t][knd];

		do {
			int domain_index = mosp->domain_order_index[t][knd]++;

			nid = opts->nid_order[t][domain_index];
			mosp->domain_order_index[t][knd] %=
				opts->nid_order_len[t];

			for (k = knd; k < kind_last; k++) {
				elt = find_available_by_nid(k, nid, opts);
				if (elt) {

					/* If we found a block but it is of
					 * a larger size, then exit now,
					 * returning NULL.  This will allow the
					 * calling code to subdivide a block
					 * from this highest priority NID versus
					 * finding a block of the requested size
					 * from a lower priority NID.
					 */
					if (k > knd)
						elt = NULL;

					return elt;
				}
			}
		} while (mosp->domain_order_index[t][knd] !=
			 start_domain_index);
	}

	return 0;
}

struct blk_list *split_block(struct blk_list *bl, enum lwkmem_kind_t k,
			     unsigned long offset, struct mos_process_t *mosp);

static void update_max_allocated(struct mos_process_t *mosp)
{
	unsigned long total;
	int k, n;

	for_each_node_mask(n, node_online_map) {
		total = 0;
		for (k = kind_4k; k < kind_last; k++)
			total += kind_size[k] * mosp->blks_in_use[k][n];
		if (mosp->max_allocated[n] < total)
			mosp->max_allocated[n] = total;
	}
}

static long allocate_blocks(unsigned long addr, int64_t len,
		     unsigned long prot, unsigned long mmap_flags,
		     unsigned long pgoff, struct allocate_options_t *opts)
{
	int64_t wanted[kind_last] = {0};
	int64_t total = 0;
	struct blk_list *elt, *new_blk;
	enum lwkmem_kind_t k;
	long new_addr;
	long first_addr = 0;
	struct mos_process_t *mosp = opts->mosp;
	unsigned long phys;
	struct vm_area_struct *vma;
	int64_t sublen;

	/* Round up to the nearest, smallest page */
	len = roundup(len, kind_size[0]);
	total = opts->blocks_wanted(len, wanted, opts);

	/* Go through and map the allocated blocks */
	for (k = kind_last - 1; (int)k >= 0; k--) {
		if (wanted[k] <= 0)
			continue;

		while (wanted[k] > 0) {
			elt = opts->find_available(k, opts);
			if (!elt) {
				elt = opts->divide_block(k, opts);

				if (!elt && k > 0) {
					wanted[k - 1] += wanted[k] *
						kind_size[k] / kind_size[k - 1];
					wanted[k] = 0;
					continue;
				}
			}

			if (!elt) {
				mos_ras(MOS_LWKMEM_PROCESS_ERROR,
					"%s: Block list for %s pages is empty.",
					__func__, kind_str[k]);
				new_addr = -ENOMEM;
				goto alloc_err;
			}

			phys = virt_to_phys((void *)block_addr(elt));

			/* Let's grab some or all of this block */
			if (wanted[k] < elt->num_blks) {

				sublen = wanted[k] * kind_size[k];

				/* Split block in two and grab first one */
				new_addr = build_lwkvma(k, addr, sublen, prot,
						mmap_flags, pgoff, len, &vma);
				if (new_addr <= 0)
					goto alloc_err;

				new_blk = split_block(elt, k, sublen, mosp);

				if (!new_blk) {
					new_addr = -ENOMEM;
					goto alloc_err;
				}

				elt->vma_addr = new_addr;
				elt->stride = 1;

				list_move(&elt->list,
					  &mosp->busy_list[k][elt->phys->nid]);
				list_add(&new_blk->list,
					 &mosp->free_list[k][elt->phys->nid]);

				addr = new_addr + sublen;
				if (!first_addr) {
					first_addr = new_addr;
					mmap_flags |= MAP_FIXED;
				}
				total -= sublen;
				mosp->num_blks[k] -= wanted[k];
				wanted[k] = 0;
			} else {
				/* Grab the whole block */
				new_addr = build_lwkvma(k, addr,
						elt->num_blks * kind_size[k],
						prot, mmap_flags, pgoff, len,
						&vma);
				if (new_addr <= 0)
					goto alloc_err;

				elt->vma_addr = new_addr;
				elt->stride = 1;

				list_move(&elt->list,
					  &mosp->busy_list[k][elt->phys->nid]);
				wanted[k] -= elt->num_blks;
				sublen = elt->num_blks * kind_size[k];
				total -= sublen;
				addr = new_addr + sublen;
				if (!first_addr) {
					first_addr = new_addr;
					mmap_flags |= MAP_FIXED;
				}
				mosp->num_blks[k] -= elt->num_blks;
			}

			new_addr = build_pagetbl(k, vma, phys, new_addr,
				new_addr + sublen, elt->stride);
			if (new_addr)
				goto alloc_err;

			trace_mos_mem_block_allocated(
			  elt->vma_addr, sublen,
			  block_addr(elt), sublen,
			  k, elt->num_blks, elt->stride, elt->phys->nid,
			  mosp->tgid);


			if (mosp->report_blks_allocated) {
				mosp->blks_allocated[k][elt->phys->nid] += elt->num_blks;
				mosp->blks_in_use[k][elt->phys->nid] += elt->num_blks;
			}
		}
	}

	if (mosp->report_blks_allocated)
		update_max_allocated(mosp);

	if (mosp->trace_block_list_addr == -1 ||
	    mosp->trace_block_list_addr == first_addr)
		trace_block_lists(mosp);

	if (total != 0) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: %lld bytes were not allocated.",
			__func__, total);
		new_addr = -ENOMEM;
		goto alloc_err;
	}

	return first_addr;

alloc_err:
	if (first_addr && (len - total > 0LL))
		deallocate_blocks(first_addr, len - total, mosp, current->mm);

	return new_addr;

} /* end of allocate_blocks() */

unsigned long allocate_blocks_fixed(unsigned long inaddr, unsigned long len,
				    unsigned long prot, unsigned long flags,
				    enum allocate_site_t site)
{
	enum lwkmem_kind_t knd, nxt;
	struct allocate_options_t *opts = 0;
	unsigned long addr = inaddr, boundary, delta, ret;
	struct mos_process_t *mosp;

	if (addr == 0 || !(flags & MAP_FIXED))
		return -EINVAL;

	mosp = current->mos_process;

	for (knd = 0; knd < kind_last; knd++) {
		if (knd < kind_last - 1) {
			/* Find the next larger sized TLB that is actually
			 * used:
			 */
			nxt = knd + 1;

			/* The amount to allocate in this pass is the lesser of
			 * the distance to the next sized boundary and the
			 * amount remaining.  This value needs to be adjusted
			 * down to a multiple the current TLB size.
			 */
			boundary = roundup(addr, kind_size[nxt]);
			delta = boundary - addr;
			delta = min(delta, len);
			delta = rounddown(delta, kind_size[knd]);
		} else {
			/* On the last pass, allocate whatever is left. */
			delta = len;
		}

		if (delta == 0)
			continue;

		opts = allocate_options_factory(site, delta, flags, mosp);
		if (unlikely(!opts)) {
			ret = -ENOMEM;
			goto out;
		}

		ret = opts->allocate_blocks(addr, delta, prot, flags, 0, opts);
		kfree(opts);
		if (ret != addr) {
			ret = -ENOMEM;
			goto out;
		}

		addr += delta;
		len -= delta;
	}

	ret = inaddr;

 out:
	return ret;
}

static struct blk_list *find_available_interleaved(enum lwkmem_kind_t knd,
					   struct allocate_options_t *opts)
{
	struct blk_list *b, *newb;
	int i = 0, j = 0, k, nid, domain_index;
	struct mos_process_t *mosp = opts->mosp;

	/* Search each kind of memory in the established order (e.g. HBM first,
	 * DRAM second, etc.).  But only search the most preferred domain of
	 * that type.  If unavailable, go onto the next memory type rather than
	 * searching another domain of the same type.  This results in better
	 * interleaving for very large allocations and has no impact on small
	 * allocations for which there is sufficiently available memory.
	 */

	while (1) {

		int t = opts->type_order[i];

		if (opts->nid_order_len[t] == 0) {
			pr_debug("(*) %s No memory of type %d (%s)\n",
				 __func__, t, lwkmem_type_str[t]);
			goto next;
		}

		domain_index = (mosp->domain_order_index[t][knd] + j) %
			opts->nid_order_len[t];
		nid = opts->nid_order[t][domain_index];

		pr_debug("(*) %s searching NID=%d starting with %s\n",
			 __func__, nid, kind_str[knd]);

		for (k = knd; k < kind_last; k++) {
			b = find_available_by_nid(k, nid, opts);
			if (!b)
				continue;

			/* If we obtained a block of a larger size than
			 * what we want, tear the first block off and
			 * subdivide it.  Do this interatively until we
			 * have a block of the appropriate size.
			 */
			while (k > knd) {

				if (b->num_blks > 1) {
					newb = split_block(b, k,
							   kind_size[k], mosp);
					list_add(&newb->list,
						 &mosp->free_list[k][nid]);
				}

				b->num_blks = kind_size[k] / kind_size[k-1];
				list_move(&b->list, &mosp->free_list[k-1][nid]);

				mosp->num_blks[k]--;
				mosp->num_blks[k-1] += b->num_blks;

				k--;

				trace_mos_mem_block_divided(0, 0, block_addr(b),
				    kind_size[k+1], k, b->num_blks, 1,
				    b->phys->nid, current->tgid);
			}

			pr_debug("(<) %s block phys=%lx nid=%d size=%s num=%lld\n",
				 __func__, block_addr(b), nid, kind_str[knd],
				 b->num_blks);

			return b;
		}
next:
		i++;
		if (i >= lwkmem_type_last) {
			i = 0;
			j++;

			if (j >= MAX_NIDS) {
				pr_debug("(<) %s b=NONE\n", __func__);
				return 0;
			}
		}
	}
}

static long allocate_blocks_interleaved(unsigned long addr, int64_t len,
		     unsigned long prot, unsigned long mmap_flags,
		     unsigned long pgoff, struct allocate_options_t *opts)
{

	int64_t total, wanted[kind_last] = {0};
	long base_addr = 0, vma_addr = addr, sub_addr;
	int knd = kind_4k;
	unsigned int sub_wanted;
	int i, t, N, nid;
	struct vm_area_struct *vma;
	unsigned long sub_len;
	struct mos_process_t *mosp = opts->mosp;
	struct blk_list *b, *nwb;
	int t_used[lwkmem_type_last], t_n, t_nid, t_preferred;

	/* Round up to the nearest, smallest page */
	len = roundup(len, kind_size[0]);

	/* Determine how many blocks of each size is wanted, irresspective,
	 * of any interleaving.
	 */
	total = opts->blocks_wanted(len, wanted, opts);

	/* Use the domain count for the most preferred type of memory when
	 * determining how many domains to interleave.
	 */

	t = 0;
	while (!(N = opts->nid_order_len[opts->type_order[t]]))
		t++;
	t_preferred = opts->type_order[t];

	for (knd = kind_last - 1; knd >= 0; knd--) {

		if (unlikely(!wanted[knd]))
			continue;

		/* Construct a VMA that spans all blocks of this size,
		 * irrespective of interleaving.
		 */

		vma_addr = build_lwkvma(knd, vma_addr,
					wanted[knd] * kind_size[knd], prot,
					mmap_flags, pgoff, len, &vma);

		if (unlikely(vma_addr <= 0))
			goto alloc_error;

		if (!base_addr) {
			base_addr = vma_addr;
			mmap_flags |= MAP_FIXED;
		}

		/* For each of the N domains, get blocks until the request is
		 * fulfilled.  Use the stride and block size to interleave
		 * the block lists in virtual space.
		 */
		for (i = 0; i < N; i++) {

			/* Divide the number of wanted blocks for this size
			 * equally (or nearly equally) among the N domains:
			 */

			sub_wanted = (wanted[knd] / N) +
				(wanted[knd] % N > i ? 1 : 0);

			if (unlikely(!sub_wanted))
				break;

			t_n = 0; /* no types allocated yet */
			sub_addr = vma_addr + (i * kind_size[knd]);

			pr_debug("(*) %s N=%d/%d want=%d prefer:%d->%s:%d addr:%lx\n",
				 __func__, i, N, sub_wanted,
				 mosp->domain_order_index[t_preferred][knd],
				 lwkmem_type_str[t_preferred],
				 opts->nid_order[t_preferred][mosp->domain_order_index[t_preferred][knd]],
				 sub_addr);

			while (sub_wanted) {

				b = opts->find_available(knd, opts);

				if (unlikely(!b))
					goto alloc_error;

				sub_len = sub_wanted * kind_size[knd];
				nid = b->phys->nid;

				/* If the located free block is larger than what
				 * we need, then split off what we need.
				 * Otherwise, consume the entire block.
				 */
				if (likely(sub_wanted < b->num_blks)) {
					nwb = split_block(b, knd, sub_len, mosp);
					if (!nwb)
						goto alloc_error;

					list_add(&nwb->list,
						 &mosp->free_list[knd][nid]);
					sub_wanted = 0;
				} else {
					sub_wanted -= b->num_blks;
					nwb = NULL;
				}

				b->vma_addr = sub_addr;
				b->stride = N;
				list_move(&b->list, &mosp->busy_list[knd][nid]);

				sub_len  = b->num_blks * kind_size[knd];
				total -= sub_len;

				if (build_pagetbl(knd, vma,
					  virt_to_phys((void *)block_addr(b)),
					  sub_addr,
					  sub_addr + sub_len * N,
					  N))
					goto alloc_error;

				trace_mos_mem_block_allocated(
					  b->vma_addr, block_size_virt(b, knd),
					  block_addr(b), sub_len, knd,
					  b->num_blks, b->stride, b->phys->nid,
					  mosp->tgid);

				/* Increment the next virtual address for this
				 * NID using the stride.
				 */
				if (unlikely(sub_wanted))
					sub_addr += (sub_len * N);

				mosp->num_blks[knd] -= b->num_blks;
				if (mosp->report_blks_allocated) {
					mosp->blks_allocated[knd][nid] +=
						b->num_blks;
					mosp->blks_in_use[knd][nid] +=
						b->num_blks;
				}

				/* Keep track of the types of memory allocated
				 * so that we can increment the interleaving
				 * indices later.
				 */

				t_nid = lwkmem_type_of(nid, mosp);
				if (!t_n || t_used[t_n - 1] != t_nid)
					t_used[t_n++] = t_nid;
			}

			/* Now that we have fulfilled the wanted blocks for a
			 * given NUMA domain, increment to the next preferred
			 * domain(s).
			 */

			for (t = 0; t < t_n; t++) {
				mosp->domain_order_index[t_used[t]][knd]++;
				mosp->domain_order_index[t_used[t]][knd] %=
					opts->nid_order_len[t_used[t]];
			}
		}

		/* Advance the address for the next VMA and set of interleaved
		 * blocks.
		 */
		vma_addr += wanted[knd] * kind_size[knd];
	}

	if (mosp->report_blks_allocated)
		update_max_allocated(mosp);

	if (mosp->trace_block_list_addr == -1 ||
	    mosp->trace_block_list_addr == base_addr)
		trace_block_lists(mosp);

	return base_addr;

 alloc_error:
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Request failed.", __func__);
	if (base_addr && (len - total > 0LL))
		deallocate_blocks(base_addr, len - total, mosp, current->mm);

	return -ENOMEM;

}

static int _all_granules(struct mos_lwk_mem_granule *g)
{
	return 1;
}

static int _in_use_granules(struct mos_lwk_mem_granule *g)
{
	return g->owner > 0;
}

static int _lwkmem_get(unsigned long *lwkm, size_t *n,
		       int (*filter)(struct mos_lwk_mem_granule *))
{
	struct mos_lwk_mem_granule *g;
	int rc;

	rc = 0;

	if (*n < lwkmem_n_online_nodes) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: Request array length too small.  actual:%ld expected:%ld.",
			__func__, *n, lwkmem_n_online_nodes);
		rc = -EINVAL;
		goto out;
	}

	memset(lwkm, 0, lwkmem_n_online_nodes * sizeof(unsigned long));

	mutex_lock(&lwkmem_mutex);

	list_for_each_entry(g, &mos_lwk_memory_list, list) {

		if (g->nid >= 0 && g->nid < *n) {
			if (filter(g))
				lwkm[g->nid] += g->length;
		} else {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Invalid NID. granule addr:%pS length:%lld nid:%d owner:%d",
				__func__, g->base, g->length, g->nid, g->owner);
			rc = -EINVAL;
			goto unlock;
		}
	}

	*n = lwkmem_n_online_nodes;

 unlock:
	mutex_unlock(&lwkmem_mutex);

 out:
	return rc;
}

int lwkmem_get(unsigned long *lwkm, size_t *n)
{
	return _lwkmem_get(lwkm, n, _all_granules);
}


int lwkmem_reserved_get(unsigned long *lwkm, size_t *n)
{
	return _lwkmem_get(lwkm, n, _in_use_granules);
}


int lwkmem_request(struct mos_process_t *mos_p, unsigned long *req, size_t n)
{
	size_t i;
	int rc;
	unsigned long wanted;
	struct mos_lwk_mem_granule *elt;
	struct mos_lwk_mem_granule *newg;
	struct lwk_process_granule *p_granule;

	rc = 0;
	mos_p->lwkmem = 0;

	if (list_empty(&mos_lwk_memory_list)) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: The LWK memory list is empty.", __func__);
		return -EINVAL;
	}

	/* There should be no memory reserved for this process yet */
	if (!list_empty(&(mos_p->lwkmem_list))) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: The LWK memory list for process %d is not empty.",
			__func__, current->pid);
		return -EINVAL;
	}

	mutex_lock(&lwkmem_mutex);

	for (i = 0; i < n ; i++) {
		if (req[i] == 0)
			continue;

		wanted = max_t(unsigned long, rounddown(req[i], MIN_CHUNK_SIZE),
				MIN_CHUNK_SIZE);
		pr_debug("Requesting %lu bytes from nid %ld\n", wanted, i);

		while (wanted > 0) {
			elt = find_free_granule_for_nid(i);
			if (!elt) {
				rc = -ENOMEM;
				goto unlock;
			}

			if (wanted < elt->length) { /* Split granule into two */
				newg =
				kmalloc(sizeof(struct mos_lwk_mem_granule),
					GFP_KERNEL);
				if (!newg) {
					rc = -ENOMEM;
					goto unlock;
				}

				newg->base = elt->base + elt->length - wanted;
				list_add(&newg->list, &elt->list);

				newg->length = wanted;
				newg->owner = current->pid;
				newg->nid = elt->nid;
				elt->length -= wanted;

				pr_debug("Split granule : new [addr=%p len=%9lluMB owner=%d]\n",
					 newg->base, newg->length >> 20,
					 newg->owner);
				pr_debug("Split granule:  rem [addr=%p len=%9lluMB owner=%d]\n",
					 elt->base, elt->length >> 20,
					 elt->owner);

				/* We should be done */
				elt = newg;
				mos_p->lwkmem += wanted;
				wanted = 0;

			} else { /* Consume entire granule */
				elt->owner = current->pid;
				mos_p->lwkmem += elt->length;
				wanted = wanted - elt->length;

				pr_debug("Entire granule : [addr=%pS len=%lluMB owner=%d] remaining=%lu\n",
					 elt->base, elt->length >> 20,
					 elt->owner, wanted);
			}

			/* Add this granule to the processes' list */
			p_granule = kmalloc(sizeof(struct lwk_process_granule),
					    GFP_KERNEL);
			if (!p_granule) {
				rc = -ENOMEM;
				goto unlock;
			}
			p_granule->granule = elt;
			p_granule->offset = 0;
			list_add(&p_granule->list, &mos_p->lwkmem_list);
		}
	}

	pr_debug("Reserved %llu MiB of LWK memory for PID %d\n",
		 mos_p->lwkmem >> 20, current->pid);
	dump_granule_list(&mos_lwk_memory_list);

 unlock:
	mutex_unlock(&lwkmem_mutex);
	return rc;
}

struct allocate_options_t *allocate_options_factory(enum allocate_site_t site,
			    unsigned long len, unsigned long flags,
			    struct mos_process_t *mosp)
{
	struct allocate_options_t *options;
	enum lwkmem_type_t *order;
	int i;

	options = kmalloc(sizeof(struct allocate_options_t), GFP_KERNEL);
	if (!options)
		return NULL;

	options->mosp = mosp;
	options->blocks_wanted = blocks_wanted;
	options->find_available = find_available_by_nid_list;
	options->divide_block = divide_block;
	options->allocate_blocks = allocate_blocks;

	if (mosp->lwkmem_interleave) {
		options->allocate_blocks = allocate_blocks_interleaved;
		options->find_available = find_available_interleaved;
		options->max_page_size = mosp->lwkmem_interleave;
	} else {
		options->max_page_size = mosp->max_page_size;
	}

	if (site == lwkmem_brk && mosp->heap_page_size < options->max_page_size)
		options->max_page_size = mosp->heap_page_size;
	else if (site == lwkmem_mmap && (flags & (MAP_STACK | MAP_NORESERVE)))
		site = lwkmem_stack;

	if (len >= mosp->memory_preference[site].threshold)
		order = mosp->memory_preference[site].upper_type_order;
	else
		order = mosp->memory_preference[site].lower_type_order;

	memcpy(options->type_order, order,
	       sizeof(mosp->memory_preference[0].lower_type_order));

	for (i = 0; i < lwkmem_type_last; i++) {
		int index = options->type_order[i];

		memcpy(options->nid_order[index], mosp->domain_info[index],
		       mosp->domain_info_len[index] * sizeof(int));
		options->nid_order_len[index] = mosp->domain_info_len[index];
	}

	return options;
}

int lwkmem_set_domain_info(struct mos_process_t *mos_p, enum lwkmem_type_t typ,
			   unsigned long *nids, size_t n)
{
	size_t i;

	if (n > ARRAY_SIZE(mos_p->domain_info[0]))
		return -EINVAL;

	for (i = 0; i < n; i++) {
		mos_p->domain_info[typ][i] = nids[i];
		pr_debug("domain_info[%s][%ld] = %ld\n", lwkmem_type_str[typ],
			 i, nids[i]);
	}

	mos_p->domain_info_len[typ] = n;

	return 0;
}

unsigned long next_lwkmem_address(unsigned long len, struct mos_process_t *mosp)
{

	unsigned long addr;

	mutex_lock(&lwkmem_mutex);
	addr = mosp->lwkmem_next_addr;
	mosp->lwkmem_next_addr = roundup(mosp->lwkmem_next_addr + len,
					 mosp->lwkmem_mmap_alignment);
	mutex_unlock(&lwkmem_mutex);

	return addr;
}

/*
 * In LWK we use pages from kernel direct mapped page table to
 * allocate user pages. So we can use the direct mapped page table to
 * look up kernel virtual address from user pfn.
 */
static void clear_user_lwkpg(struct mm_struct *mm, unsigned long uva,
			     int pte_dirty)
{
	unsigned int size = 0;
	struct page *page = 0;
	unsigned long nr_pages = 0;

	if (!mm)
		goto warn;

	page = lwkmem_user_to_page(mm, uva, &size);

	if (!page)
		goto warn;

	lwkpage_remove_rmap(page);

	if (is_lwkpg_dirty(page) || pte_dirty) {
		memset((void *) page_to_virt(page), 0, size);
		clear_lwkpg_dirty(page);
	}

	nr_pages = size / PAGE_SIZE;
	while (nr_pages--) {
		/*
		 * When huge pages are XPMEM shared. It is possible that only
		 * parts of the huge page are attached/mapped with different
		 * lower sized TLBs in the non-owner process. In that case only
		 * a portion of the original huge page which was shared may get
		 * dirtied. We mark all base pages corresponding to the dirtied
		 * shared region as dirty during page table clearing of the
		 * non-owner process. So here we catch such base pages and
		 * clear them.
		 */
		if (is_lwkpg_dirty(page)) {
			memset((void *) page_to_virt(page), 0, PAGE_SIZE);
			clear_lwkpg_dirty(page);
		}
		page->mapping = NULL;
		page_mapcount_reset(page);
		clear_compound_head(page);
		page++;
	}
			
	if (lwkmem_zeroes_check_enabled(ZCHECK_FREE))
		lwkmem_check_for_zero(uva, size, mm, "free");

	return;

 warn:
	mos_ras(MOS_LWKMEM_PROCESS_WARNING,
		"%s: Did not clear memory. address:%lx size:%x mm:%p page:%p",
		__func__, uva, size, mm, page);
}

/* Note on TLB flush:
 * Currently we need to invalidate the TLB before dropping the PTL so that a
 * concurrent thread can see the change. This function can be further optimized
 * for performance by avoiding repeated locking and unlocking to same higher
 * level page table when clearing the lower level page table entries with a
 * common higher level page table entry and with that the no.of TLB flushes can
 * also be reduced. But for this change the caller needs to ensure that virtual
 * address range @addr to @end is contig i.e with stride=1.
 */
int unmap_pagetbl(enum lwkmem_kind_t k, unsigned long addr, unsigned long end,
		  unsigned int stride, struct mm_struct *mm, bool lwkxpmem)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned long size = kind_size[k];
	unsigned long remain = end - addr;

	if (mm == NULL) {
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: no mm context.", __func__);
		return -EINVAL;
	}

	for (; addr < end; addr += (size * stride), remain -= size) {

		pgd = pgd_offset(mm, addr);
		if (!pgd_present(*pgd)) {
			mos_ras(MOS_LWKMEM_PROCESS_WARNING,
				"%s: PGD not present for address:%lx size:%s",
				__func__, addr, kind_str[k]);
			continue;
		}

		p4d = p4d_offset(pgd, addr);
		
		if (!p4d_present(*p4d))
			continue;

		pud = pud_offset(p4d, addr);

		if (!pud_present(*pud)) {
			mos_ras(MOS_LWKMEM_PROCESS_WARNING,
				"%s: PUD not present for address:%lx size:%s",
				 __func__, addr, kind_str[k]);
			continue;
		}

		if (size == SZ_1G) {
			ptl = &mm->page_table_lock;
			spin_lock(ptl);
			clear_user_lwkpg(mm, addr,
			       (pud_flags(*pud) & _PAGE_DIRTY) != 0);
			pud_clear(pud);
			flush_tlb_mm_range(mm, addr, addr+size, 0);
			spin_unlock(ptl);
		} else if (size == SZ_2M) {
			pmd = pmd_offset(pud, addr);
			ptl = pmd_lock(mm, pmd);
			if (pmd_present(*pmd)) {
				clear_user_lwkpg(mm, addr,
				       pmd_dirty(*pmd) != 0);
				pmd_clear(pmd);
				flush_tlb_mm_range(mm, addr, addr+size, 0);
			} else
				mos_ras(MOS_LWKMEM_PROCESS_WARNING,
					"%s: PMD not present for address:%lx size:%s",
					__func__, addr, kind_str[k]);
			spin_unlock(ptl);
		} else if (size == SZ_4K) {
			pmd = pmd_offset(pud, addr);
			if (pmd_present(*pmd)) {
				pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
				if (!pte) {
					mos_ras(MOS_LWKMEM_PROCESS_WARNING,
						"%s: PTE not found for address:%lx size:%s",
						__func__, kind_str[k], addr);
					continue;
				}
				if (pte_present(*pte)) {
					clear_user_lwkpg(mm, addr,
					       pte_dirty(*pte) != 0);
					pte_clear(mm, addr, pte);
					flush_tlb_mm_range(mm, addr,
						addr+size, 0);
				} else
					mos_ras(MOS_LWKMEM_PROCESS_WARNING,
						"%s: PTE not present for address:%lx size:%s",
						__func__, addr, kind_str[k]);
				pte_unmap_unlock(pte, ptl);
			} else
				mos_ras(MOS_LWKMEM_PROCESS_WARNING,
					"%s: PMD not present for address:%lx size:%s",
					__func__, addr, kind_str[k]);
		} else {
			mos_ras(MOS_LWKMEM_PROCESS_ERROR,
				"%s: Page size %lu not supported.", size);
			return -EINVAL;
		}
	}

	return 0;
}

struct blk_list *split_block(struct blk_list *bl, enum lwkmem_kind_t k,
			     unsigned long offset, struct mos_process_t *mosp)
{
	struct blk_list *newb;
	unsigned long blks = offset / kind_size[k];

	if (unlikely((blks >= bl->num_blks) || (offset & (kind_size[k] - 1)))) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: Cannot split block.  size:%s address:%#016lx count:%lld offset:%lx blocks:%ld",
			__func__, kind_str[k], block_addr(bl), bl->num_blks,
			offset, blks);
		return NULL;
	}

	newb = kmalloc(sizeof(struct blk_list), GFP_KERNEL);
	if (!newb)
		return NULL;

	newb->phys = bl->phys;
	newb->offset = bl->offset + offset;
	newb->num_blks = bl->num_blks - blks;
	newb->vma_addr = bl->vma_addr + blks * bl->stride * kind_size[k];
	newb->stride = bl->stride;
	bl->num_blks = blks;

	INIT_LIST_HEAD(&newb->list);

	return newb;
}

static long deallocate_block(unsigned long addr, unsigned long len,
			     struct mos_process_t *mosp,
			     struct mm_struct *mm)
{
	long rc = 0;
	enum lwkmem_kind_t k;
	int n;
	long freed = 0;

	for (k = kind_4k; k < kind_last; k++) {
		for_each_online_node(n) {
			struct blk_list *bl, *newb, *tmp, *freebl;

			list_for_each_entry_safe_reverse(bl, tmp,
						 &mosp->busy_list[k][n], list) {
				int left, right;
				unsigned long offset, free_sz, block_sz;
				char annot;

				block_sz = bl->num_blks * kind_size[k];

				if (bl->stride != 1) {
					mos_ras(MOS_LWKMEM_PROCESS_ERROR,
						"%s: Stride must be 1.",
						__func__);
					return -1;
				}

				if (addr < bl->vma_addr ||
				    addr >= bl->vma_addr + block_sz)
					continue;

				if (addr & (kind_size[k] - 1)) {
					mos_ras(MOS_LWKMEM_PROCESS_ERROR,
						"%s: Address is not left aligned.  addr:%lx size:%s",
						__func__, addr, kind_str[k]);
					return -1;
				}

				left = addr == bl->vma_addr;
				right = (addr + len) >= (bl->vma_addr + block_sz);

				if (!right && ((addr + len) & (kind_size[k] - 1))) {
					mos_ras(MOS_LWKMEM_PROCESS_ERROR,
						"%s: Address is not right aligned. Addr+length=%lx+%ld=%lx size:%s",
						__func__, addr, len, addr + len,
						kind_str[k]);
					return -1;
				}

				annot = left & right ? 'X' :
					(left ? 'L' : (right ? 'R' : 'M'));

				pr_debug("%s %#016lx,%ld -> <%c> [%#016lx-%#016lx] [%#016lx] %3lld x %s = %ld\n",
					 __func__, addr, len, annot,
					 bl->vma_addr,
					 bl->vma_addr + block_sz - 1,
					 block_addr(bl), bl->num_blks,
					 kind_str[k], block_sz);

				offset = addr - bl->vma_addr;

				if (left && right) {
					/* deallocate entire block */
					list_move(&bl->list,
						  &mosp->free_list[k][n]);
					freebl = bl;
				} else if (left) {
					/* deallocate left side of the block */
					newb = split_block(bl, k, len, mosp);
					if (!newb)
						return -ENOMEM;
					list_add(&newb->list,
						 &mosp->busy_list[k][n]);
					list_move(&bl->list,
						  &mosp->free_list[k][n]);
					freebl = bl;
				} else if (right) {
					/* deallocate right side of the block */
					newb = split_block(bl, k, offset, mosp);
					if (!newb)
						return -ENOMEM;
					list_add(&newb->list,
						 &mosp->free_list[k][n]);
					freebl = newb;
				} else {
					/* deallocate middle of the block */
					unsigned long offs2 = addr + len -
						bl->vma_addr;

					/* Split at end of address range. */
					newb = split_block(bl, k, offs2, mosp);
					if (!newb)
						return -ENOMEM;
					list_add(&newb->list,
						 &mosp->busy_list[k][n]);

					/* Split at start of address range. */
					newb = split_block(bl, k, offset, mosp);
					if (!newb)
						return -ENOMEM;
					list_add(&newb->list,
						 &mosp->free_list[k][n]);
					freebl = newb;
				}

				free_sz = freebl->num_blks * kind_size[k];
				rc = unmap_pagetbl(k, freebl->vma_addr,
					   freebl->vma_addr + free_sz, 1, mm,
					   false);

				if (rc)
					goto out;

				trace_mos_mem_block_deallocated(freebl->vma_addr,
					free_sz, block_addr(freebl), free_sz, k,
					freebl->num_blks, 1, freebl->phys->nid,
					mosp->tgid);

				freebl->vma_addr = 0;
				mosp->num_blks[k] += freebl->num_blks;

				if (mosp->report_blks_allocated)
					mosp->blks_in_use[k][n] -= freebl->num_blks;

				addr += free_sz;
				len -= free_sz;
				freed += free_sz;
				if (!len)
					goto out;
			}
		}
	}

 out:
	return rc ? rc : freed;
}

/* Compute the overlap of a block relative to the interval
 * [addr, addr + len).  The result is in terms of the offset
 * (in blocks) within the block, and the number of blocks that
 * are covered.
 */

static void block_overlap(struct blk_list *b, unsigned long addr,
			  unsigned long len, enum lwkmem_kind_t knd,
			  unsigned long *offset, unsigned long *count)
{
	unsigned long right, i, bl_addr;

	right = b->vma_addr + block_size_virt(b, knd);

	*offset = 0;
	*count = 0;

	if (addr >= right || (addr + len) < b->vma_addr)
		return;

	if (addr <= b->vma_addr && right <= (addr + len)) {
		*count = b->num_blks;
		return;
	}

	for (i = 0; i < b->num_blks; i++) {
		bl_addr = b->vma_addr + i * b->stride * kind_size[knd];

		if (bl_addr < addr)
			(*offset)++;
		if (bl_addr >= addr && bl_addr < (addr + len))
			(*count)++;
	}
}

static long deallocate_blocks_interleaved(unsigned long addr, unsigned long len,
				   struct mos_process_t *mosp,
				   struct mm_struct *mm)
{
	int k, n;
	long rc;
	unsigned long remaining = len;
	struct blk_list *bl, *newb, *tmp, *freed;
	unsigned long offs, cnt;
	struct list_head *freel, *busyl;

	for (k = kind_4k; k < kind_last; k++) {
		for_each_online_node(n) {

			freel = &mosp->free_list[k][n];
			busyl = &mosp->busy_list[k][n];

			list_for_each_entry_safe(bl, tmp, busyl, list) {

				block_overlap(bl, addr, len, k, &offs, &cnt);

				if (!cnt)
					continue;

				/* Some or all of the block is being freed.  A
				 * non-zero offset indicates that a portion of
				 * the left side of the block will remain busy.
				 * After accounting for that region, we can
				 * determine if a portionon the right side will
				 * also remain busy.
				 */

				if (likely(offs == 0))
					freed = bl;
				else {
					freed = split_block(bl, k,
						    offs * kind_size[k],
						    mosp);
					if (unlikely(!freed))
						goto err;
				}

				if (unlikely(cnt < freed->num_blks)) {
					newb = split_block(freed, k,
						   cnt * kind_size[k],
						   mosp);
					if (unlikely(!newb))
						goto err;
					list_add(&newb->list, busyl);
				}

				rc = unmap_pagetbl(k, freed->vma_addr,
					   freed->vma_addr + block_size_virt(freed, k),
					   freed->stride, mm, false);

				if (rc)
					goto err;

				trace_mos_mem_block_deallocated(
				    freed->vma_addr, block_size_virt(freed, k),
				    block_addr(freed),
				    freed->num_blks * kind_size[k], k,
				    freed->num_blks, freed->stride,
				    freed->phys->nid, mosp->tgid);

				list_move(&freed->list, freel);

				mosp->num_blks[k] += freed->num_blks;
				remaining -= freed->num_blks * kind_size[k];

				if (mosp->report_blks_allocated)
					mosp->blks_in_use[k][n] -=
						freed->num_blks;

				if (!remaining)
					goto out;
			}
		}
	}

 out:
	if (mosp->trace_block_list_addr == -1 ||
	    mosp->trace_block_list_addr == addr)
		trace_block_lists(mosp);

	return 0;

 err:
	mos_ras(MOS_LWKMEM_PROCESS_ERROR,
		"%s: Failed.", __func__);
	return -1;
}


long deallocate_blocks(unsigned long addr, unsigned long len,
		       struct mos_process_t *mosp,
		       struct mm_struct *mm)
{
	long ret = 0;
	unsigned long addr_in = addr;

	if (mosp->lwkmem_interleave)
		return deallocate_blocks_interleaved(addr, len, mosp, mm);

	len = roundup(len, kind_size[0]);

	while (len > 0) {
		ret = deallocate_block(addr, len, mosp, mm);
		if (ret <= 0)
			goto out;

		len -= ret;
		addr += ret;
	}

 out:

	if (mosp->trace_block_list_addr == -1 ||
	    mosp->trace_block_list_addr == addr_in)
		trace_block_lists(mosp);

	return ret;
}
