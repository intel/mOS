/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2020 Intel Corporation.
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

#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <linux/percpu-rwsem.h>
#include <linux/delay.h>
#include <linux/mos.h>
#include <trace/events/lwkmem.h>

/* Private headers */
#include "lwk_mm_private.h"
#include "../lwkctrl.h"

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
#define MIN_CHUNK_SIZE		(SZ_2M)
#else
#define MIN_CHUNK_SIZE		(SZ_4M)
#endif

#define MFMT "Node%3d: %-10s [%#018lx-%#018lx] pfn [%lu-%lu] [%lu] pages\n"
#define LWKMEM_NODE_CLR_WAIT 10     /* ms */
#define LWKMEM_NODE_CLR_POLL 30000  /* = 30000 x (10ms) = 300 sec = 5 mins */
#define LWKMEM_NODE_CLR_TIMEOUT (LWKMEM_NODE_CLR_POLL * LWKMEM_NODE_CLR_WAIT)
//#define DEBUG_MEMORY_CLEARING

/*
 * lwkmem[MAX_NUMNODES],
 *   Used to track all the physical memory ranges designated to LWK.
 *   An element at index N gives the lwkmem_designated structure that
 *   embeds the list head for all designated memory granules and
 *   keeps the counters that indicate number of free and available
 *   memory in terms of pages on that NUMA node.
 *
 *   lwkmem[NID]           lwkmem_granule         lwkmem_granule
 *   +--------------+      +-----------------+    +-----------------+
 *   | list         |----->| list_designated |--->| list_designated |
 *   | n_resv_pages |      | list_reserved   |    | list_reserved   |
 *   | n_free_pages |      | base            |    | base            |
 *   +--------------+      | length          |    | length          |
 *                         | owner           |    | owner           |
 *                         +-----------------+    +-----------------+
 */
static struct lwkmem_designated lwkmem[MAX_NUMNODES];
/*
 * lwkmem_gsem, lock that protects global designated memory tracking
 * structure lwkmem[MAX_NUMNODES]. No use in fine grained locking to
 * each NUMA nodes as yod serializes per rank LWK memory requests.
 */
DEFINE_STATIC_PERCPU_RWSEM(lwkmem_gsem);
static size_t lwkmem_n_online_nodes;

/* Per CPU data for clearing LWK memory in parallel */
struct lwkmem_clear_info {
	nodemask_t nodemask;		/* NUMA nodes to be cleared         */
	cpumask_t cpumask;		/* CPUs to use for clearing         */
	atomic_t errors;		/* Incremented on error on a CPU    */
	atomic_t done;			/* Incremented on exit              */
	unsigned long npages_total;     /* Total pages(in 4k) to clear      */
};

/*
 * The function returns 'true' if there is no designated LWK memory
 * returns 'false' otherwise. Caller needs to hold at minimum reader
 * lock on lwkmem_gsem.
 */
static bool lwkmem_empty(void)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid++)
		if (!list_empty(&lwkmem[nid].list))
			return false;
	return true;
}

/*
 * Given a physical memory granule insert it into the list in ascending
 * order of physical address. Called to insert the physical memory
 * granules in list of designated memory after we offline a physical
 * memory range from Linux. Caller needs to ensure serialized access
 * to the list being modified.
 */
static void lwkmem_insert_granule(int nid, struct lwkmem_granule *g)
{
	struct lwkmem_granule *e;
	struct list_head *head = &lwkmem[nid].list;

	list_for_each_entry(e, head, list_designated) {
		if ((g->base + g->length) <= e->base) {
			list_add_tail(&g->list_designated,
				      &e->list_designated);
			return;
		}
	}
	/* Either head list is empty or the new element fits at the end */
	list_add_tail(&g->list_designated, head);
}

/*
 * Splits a given memory granule into two and returns the
 * pointer to the second half which is of length=newlen.
 */
static struct lwkmem_granule *lwkmem_split_granule(struct lwkmem_granule *g,
					unsigned long newlen)
{
	struct lwkmem_granule *newg;

	newg = kmalloc(sizeof(struct lwkmem_granule), GFP_KERNEL);
	if (!newg)
		return NULL;
	newg->base = g->base + g->length - newlen;
	newg->length = newlen;
	g->length -= newlen;
	return newg;
}

/*
 * For a given NUMA node id, searches for a memory granule that is
 * unreserved. If @nid is set to NUMA_NO_NODE then the function
 * searches in all available NUMA nodes starting at nid=0 and returns
 * the first free granule found. If no free granules are found then
 * the function returns NULL.
 *
 * The function assumes that the caller holds atleast the reader
 * lock on lwkmem_gsem.
 */
static struct lwkmem_granule *lwkmem_find_free_granule(int nid)
{
	struct lwkmem_granule *g;
	int n = nid == NUMA_NO_NODE ? 0 : nid;
	int n_max = nid == NUMA_NO_NODE ? MAX_NUMNODES : nid + 1;

	for (; n < n_max; n++) {
		list_for_each_entry(g, &lwkmem[n].list, list_designated) {
			if (g->owner <= 0)
				return g;
		}
	}
	return NULL;
}

/*
 * Merges the adjacent free memory granules for a given NUMA node.
 */
static void lwkmem_merge_free_granules(int nid)
{
	struct list_head *head;
	struct lwkmem_granule *curr, *next;
	int n = nid == NUMA_NO_NODE ? 0 : nid;
	int n_max = nid == NUMA_NO_NODE ? MAX_NUMNODES : nid + 1;

	for (; n < n_max; n++) {
		head = &lwkmem[n].list;
		list_for_each_entry_safe(curr, next, head, list_designated) {
			/* For last element there is nothing to merge with */
			if (curr->list_designated.next == head)
				break;
			/* Merge only free granules */
			if (curr->owner != -1)
				continue;
			if ((curr->base + curr->length == next->base) &&
			    (curr->owner == next->owner)) {
				next->base = curr->base;
				next->length += curr->length;
				list_del(&curr->list_designated);
				kfree(curr);
			}
		}
	}
}

#ifdef DEBUG
/*
 * List and summarize the memory granules in a list
 */
static void lwkmem_print_list(void)
{
	int nid;
	struct lwkmem_granule *g;
	unsigned long total_bytes = 0;
	unsigned long node_total_bytes = 0;
	unsigned long num_granules = 0;
	unsigned long node_num_granules = 0;

	pr_info("LWK memory list:");
	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		node_total_bytes = 0;
		node_num_granules = 0;
		list_for_each_entry(g, &lwkmem[nid].list, list_designated) {
			pr_info("\tNode%3d: [%#018lx-%#018lx] 0x%lx (%ld MiB) owner %d\n",
				nid, __pa(g->base),
				__pa(g->base) + g->length - 1,
				g->length, g->length >> 20, g->owner);
			node_total_bytes += g->length;
			node_num_granules++;
		}
		if (node_num_granules != 0) {
			pr_info("\tNode%3d: Total %lu (%lu MB) in %ld granules\n",
				nid, node_total_bytes, node_total_bytes >> 20,
				node_num_granules);
			num_granules += node_num_granules;
			total_bytes += node_total_bytes;
		}
	}
	pr_info("Total %lu (%lu MB) in %ld granules\n", total_bytes,
		total_bytes >> 20, num_granules);
}
#else
#define lwkmem_print_list()
#endif

/*
 * Resets struct page members. The fields of struct page are reset in the
 * order they are defined in the structure. Unused fields are untouched.
 */
static void lwkpage_deinit(struct page *p)
{
	/* Reset flags we set */
	ClearPagePrivate(p);
	clear_bit(PG_writeback, &p->flags);
	ClearPageActive(p);
	ClearPageUnevictable(p);

	/* Initialize 5 words union */
	INIT_LIST_HEAD(&p->lru);
	p->mapping = NULL;
	p->index = 0;
	p->private = 0;
	/* Reset mapcount */
	page_mapcount_reset(p);
	/* Reset refcount */
	init_page_count(p);
	/* We do not use other remaining fields */
}

/*
 * Initializes the struct page for use in LWKMEM. Called when
 * pages are first offlined from Linux and used as LWKMEM.
 */
static void lwkpage_init(struct page *p)
{
	lwkpage_deinit(p);
	SetPagePrivate(p);
	set_bit(PG_writeback, &p->flags);
	SetPageActive(p);
	SetPageUnevictable(p);
	p->private = _LWKPG;
}

#ifdef DEBUG_MEMORY_CLEARING
static void lwkmem_set_granule_memory(struct lwkmem_granule *granule)
{
	unsigned long size, total_size;
	u8 *ptr;

	if (granule) {
		ptr = granule->base;
		total_size = granule->length;

		while (total_size && ptr >= (u8 *)granule->base) {
			size = min_t(unsigned long, total_size, SZ_1G);
			memset(ptr, 0xff, size);
			cond_resched();
			ptr += size;
			total_size -= size;
		}
	}
}

static int lwkmem_verify_designated(void)
{
	int nid;
	u8 *start, *end;
	u64 size;
	struct lwkmem_granule *g;

	for_each_node(nid) {
		if (list_empty(&lwkmem[nid].list) || !lwkmem[nid].n_free_pages)
			continue;
		list_for_each_entry(g, &lwkmem[nid].list, list_designated) {
			start = g->base;
			end = start + g->length;
			size = 0;
			while (start < end && !*start) {
				start++;
				size++;
				if (size == SZ_1G) {
					cond_resched();
					size = 0;
				}
			}

			if (start < end) {
				LWKMEM_ERROR("Node%3d: [%#lx-%#lx) 0x%p(0x%x)",
					     nid, g->base, end, start, *start);
				return -EINVAL;
			}
		}
	}
	return 0;
}
#endif

static void clear_lwk_memory(void *data)
{
	unsigned long  memsize_in_pages;
	unsigned long addr, mem_offset;
	unsigned long ncpus, npages;
	struct lwkmem_granule *g;
	struct lwkmem_clear_info *info = data;
	int cpu, cpu_curr, pos, n;

	/* CPU running this function */
	cpu = smp_processor_id();

	if (!info) {
		LWKMEM_WARN("CPU%3d: Invalid argument", cpu);
		return;
	}

	/* No pages to clear */
	if (info->npages_total == 0)
		goto done;

	if (nodes_empty(info->nodemask)) {
		LWKMEM_WARN("CPU%3d: Nodemask is empty", cpu);
		goto error;
	}

	ncpus = cpumask_weight(&info->cpumask);
	if (ncpus == 0) {
		LWKMEM_ERROR("Unexpected error, cpumask empty");
		goto error;
	}

	if (!cpumask_test_cpu(cpu, &info->cpumask)) {
		LWKMEM_ERROR("Unexpected error CPU%3d not present in [%*pbl]",
			     cpu, cpumask_pr_args(&info->cpumask));
		goto error;
	}

	/* Pages to clear per CPU. */
	npages = info->npages_total / ncpus;

	/*
	 * Not enough memory to parallelize, only first CPU in @cpumask
	 * will clear and noop for others.
	 */
	if (npages == 0 && cpu != cpumask_first(&info->cpumask))
		goto done;
	if (npages && ncpus > 1) {
		pos = 0;
		for_each_cpu(cpu_curr, &info->cpumask) {
			if (cpu_curr == cpu)
				break;
			pos++;
		}

		if (pos >= ncpus) {
			LWKMEM_ERROR("CPU%3d not in cpumask [%*pbl]",
				cpu, cpumask_pr_args(&info->cpumask));
			goto error;
		}

		/* Compute the offset to start clearing pages for @cpu */
		mem_offset = npages * pos;
		/* Let the last CPU clear remainder if any */
		if (cpu == cpumask_last(&info->cpumask))
			npages += info->npages_total % ncpus;
	} else {
		/*
		 * @cpu is the first CPU in @cpumask and not enough
		 * memory for parallel work. Let this @cpu clear
		 * everything.
		 */
		npages = info->npages_total;
		mem_offset = 0;
	}

	for_each_node_mask(n, info->nodemask) {
		list_for_each_entry(g, &lwkmem[n].list, list_designated) {
			if (!npages)
				goto done;
			/*
			 * Skip all memory granules before the offset
			 * from where we need to start memory clearing.
			 */
			memsize_in_pages = bytes_to_pages(g->length);
			if (!memsize_in_pages)
				continue;
			if (mem_offset >= memsize_in_pages) {
				mem_offset -= memsize_in_pages;
				continue;
			}

			addr = (unsigned long) g->base;
			if (mem_offset) {
				addr += pages_to_bytes(mem_offset);
				memsize_in_pages -= mem_offset;
				/*
				 * We are in the usable memory range and we
				 * do not need offset anymore.
				 */
				mem_offset = 0;
			}
			memsize_in_pages = min(memsize_in_pages, npages);
			memzero_explicit((void *)addr,
					 pages_to_bytes(memsize_in_pages));
			npages -= memsize_in_pages;
		}
	}
done:
	atomic_inc(&info->done);
	return;
error:
	atomic_inc(&info->errors);
	atomic_inc(&info->done);
}

/*
 * Walks through list of memory ranges offlined previously for LWK usage and
 * tries to return them to Linux by onlining the memory range to the zone
 * ZONE_MOVABLE. In case of error on a NUMA node it makes best efforts to
 * continue to release memory held on other NUMA nodes and eventually return
 * error code for the last failure.
 */
static int free_memory_to_linux(int nid)
{
	struct lwkmem_granule *curr, *next;
	unsigned long start_pfn, nr_pages, i;
	int error, rc = 0;
	struct zone *zone;


	lock_device_hotplug();
	list_for_each_entry_safe(curr, next, &lwkmem[nid].list,
				 list_designated) {
		if (curr->owner != -1) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: [%pK-%pK] 0x%llx owner:%d nid:%d busy!",
				__func__, curr->base,
				curr->base + curr->length - 1,
				curr->length, curr->owner, nid);
		}
		list_del(&curr->list_designated);

		start_pfn = kaddr_to_pfn(curr->base);
		nr_pages = bytes_to_pages(curr->length);
		zone = zone_for_pfn_range(MMOP_ONLINE_MOVABLE, nid, start_pfn, nr_pages);

		for (i = 0 ; i < nr_pages; i++)
			lwkpage_deinit(pfn_to_page(start_pfn + i));

		pr_info(MFMT, nid, "Onlining", __pa(curr->base),
			__pa(curr->base) + curr->length - 1, start_pfn,
			start_pfn + nr_pages - 1,  nr_pages);

		error = online_pages(start_pfn, nr_pages, zone);
		if (error) {
			rc = error;
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: hotplug error, node:%d pfn:%ld pages:%lu",
				__func__, nid, start_pfn, nr_pages);
		}
		kfree(curr);
	}
	unlock_device_hotplug();
	return rc;
}

/*
 * Given a pfn range [start_pfn, end_pfn) checks if the range is
 * available for hotplugging.
 */
static bool pfn_range_available(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *page;
	unsigned long pfn;
	struct zone *zone;

	if (end_pfn <= start_pfn)
		return false;

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		page = pfn_to_page(pfn);
		zone = page_zone(page);
		if (!pfn_in_present_section(pfn) || !pfn_valid(pfn) ||
		    PageReserved(page) || PageHWPoison(page) || page_maybe_dma_pinned(page) ||
		    zone_idx(zone) != ZONE_MOVABLE)
			return false;
	}
	return true;
}

/*
 * Given a pfn range [start_pfn, end_pfn) the function searches for a
 * contiguous free physical memory range which is atleast unitsize bytes
 * or upto maxsize bytes large in size. Returns the start pfn of the
 * found free range, its size and start pfn of next range to inspect.
 */
static int find_contig_free_pfn_range(unsigned long start_pfn,
		unsigned long end_pfn, unsigned long unitsize,
		unsigned long maxsize, unsigned long *range_start_pfn,
		unsigned long *range_next_start_pfn, unsigned long *range_size)
{
	unsigned long pfn, pps = bytes_to_pages(unitsize);

	if ((start_pfn >= end_pfn) ||		/* Empty range */
	    (end_pfn < pps) ||			/* Underflow   */
	    (start_pfn > end_pfn - pps) || 	/* Range < unitsize */
	    (unitsize == 0) || (maxsize < unitsize)) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: EINVAL, range [%ld, %ld), unit %ld, max %ld",
			__func__, start_pfn, end_pfn, unitsize, maxsize);
		return -EINVAL;
	}

	*range_size = 0;
	*range_next_start_pfn = start_pfn;
	/* Retry until we get a free contig memory range of minimum unit size */
	while (*range_size < unitsize) {
		/* Reset the working range */
		*range_size = 0;
		*range_start_pfn = *range_next_start_pfn;

		/* See how far the range grows within set bounds. */
		pfn = *range_start_pfn;
		while (pfn <= end_pfn - pps && *range_size < maxsize) {
			if (!pfn_range_available(pfn, pfn + pps)) {
				/* Skip this range next time */
				*range_next_start_pfn = pfn + pps;
				break;
			}
			pfn += pps;
			*range_size += unitsize;
			*range_next_start_pfn = pfn;
		}

		/* Are we done searching the entire range? */
		if (pfn > end_pfn - pps)
			break;
	}

	/*
	 * This function needs maxsize to be multiple of unitsize,
	 * so it is an unexpected error for search to return a range
	 * greater than maxsize. The range_size is always <= maxsize.
	 */
	if (*range_size > maxsize) {
		*range_size = 0;
		*range_next_start_pfn = 0;
		*range_next_start_pfn = 0;
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Unexpected error rs %ld maxsize %ld unitsize %ld",
			__func__, *range_size, maxsize, unitsize);
		return -EINVAL;
	}
	return 0;
}

/*
 * The function searches the ZONE_MOVABLE zone of a given NUMA node for
 * contig free physical memory ranges that can be offlined from Linux.
 * An offlined physical memory range is recorded as an LWK memory granule
 * and added to the list of designated memory of the NUMA node id specified.
 */
static unsigned long allocate_memory_from_linux(int nid, unsigned long size)
{
	int rc = 0;
	unsigned long flags, nr_pages;
	unsigned long total_size, block_size, section_size;
	unsigned long start_pfn, end_pfn, pfn, pfn_next;

	struct list_head granules;
	struct lwkmem_granule *curr, *next;
	pg_data_t *pgdat = NODE_DATA(nid);
	struct zone *zone_movable = pgdat->node_zones + ZONE_MOVABLE;

	INIT_LIST_HEAD(&granules);
	total_size = 0;

	/* Round down the request to section size boundary */
	section_size = 1UL << SECTION_SIZE_BITS;
	size = round_down(size, section_size);
	if (size < section_size) {
		mos_ras(MOS_LWKCTL_WARNING,
			"Node %d: size %ld bytes is less than min(%ld bytes)!",
			nid, size, section_size);
		return 0;
	}

	lock_device_hotplug();
	if (!node_online(nid))
		goto out;

	/* Create a list of contig physical memory ranges that we can offline */
	spin_lock_irqsave(&zone_movable->lock, flags);
	if (zone_is_empty(zone_movable)) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"Node %d: no ZONE_MOVABLE memory, cannot host LWKMEM.",
			nid);
		spin_unlock_irqrestore(&zone_movable->lock, flags);
		goto out;
	}

	/* Find the start and end of movable region on this node */
	start_pfn = zone_movable->zone_start_pfn;
	end_pfn = zone_end_pfn(zone_movable);

	/* Hotplug in granularity of memory section size */
	start_pfn = SECTION_ALIGN_UP(start_pfn);
	end_pfn = SECTION_ALIGN_DOWN(end_pfn);

	if (start_pfn < zone_movable->zone_start_pfn || /* Overflow? */
	    end_pfn <= start_pfn) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"Node %d: low ZONE_MOVABLE, min aligned %ld MB needed",
			nid, section_size >> 20);
		spin_unlock_irqrestore(&zone_movable->lock, flags);
		goto out;
	}

	while (start_pfn < end_pfn && total_size < size) {
		/* Get the next available contiguous memory region */
		rc = find_contig_free_pfn_range(start_pfn, end_pfn,
				section_size, size - total_size,
				&pfn, &pfn_next, &block_size);
		if (rc || block_size == 0)
			break;

		curr = kmalloc(sizeof(struct lwkmem_granule), GFP_KERNEL);
		if (!curr) {
			rc = -ENOMEM;
			mos_ras(MOS_LWKCTL_FAILURE,
				"Node %d: no free mem to allocate a granule",
				nid);
			break;
		}
		curr->base = pfn_to_kaddr(pfn);
		curr->owner = -1;
		curr->length = block_size;
		list_add_tail(&curr->list_designated, &granules);
		total_size += block_size;
		pr_info(MFMT, nid, "Free range", __pa(curr->base),
			__pa(curr->base) + block_size - 1, pfn,
			pfn + bytes_to_pages(block_size) - 1,
			bytes_to_pages(block_size));

		start_pfn = pfn_next;
	}
	spin_unlock_irqrestore(&zone_movable->lock, flags);

	/* Skip hotplugging memory if something went wrong during the search */
	if (rc)
		goto out;

	/* Offline pages and add the granule to the requested list_head */
	list_for_each_entry_safe(curr, next, &granules, list_designated) {
		start_pfn = kaddr_to_pfn(curr->base);
		nr_pages = bytes_to_pages(curr->length);
		pr_info(MFMT, nid, "Offlining", __pa(curr->base),
			__pa(curr->base) + curr->length - 1, start_pfn,
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
				"Node %d: hotplug error pfn %ld nr %ld rc %d",
				nid, start_pfn, nr_pages, rc);
		} else {
			while (nr_pages--) {
				lwkpage_init(pfn_to_page(start_pfn));
				start_pfn++;
			}
#ifdef DEBUG_MEMORY_CLEARING
			lwkmem_set_granule_memory(curr);
#endif
			list_del(&curr->list_designated);
			lwkmem_insert_granule(nid, curr);
		}
	}
out:
	/* Free up the list entries which where not offlined */
	list_for_each_entry_safe(curr, next, &granules, list_designated) {
		list_del(&curr->list_designated);
		total_size -= curr->length;
		kfree(curr);
	}
	unlock_device_hotplug();
	return total_size;
}

/*
 * mos_mem_free
 *   Returns memory back to Linux which was previously offlined and provisioned
 *   to LWK. In case of error on a NUMA node makes best efforts to continue to
 *   release memory held on NUMA nodes and eventually return error code for the
 *   last failure. This function is called from lwkctrl.c when the LWK memory
 *   partition is being deleted. Also called from mos_mem_init() to release the
 *   intermediated memory offlined and designated to LWK upon an error.
 */
int mos_mem_free(void)
{
	int nid, error, rc = 0;

	pr_info("Returning memory back to Linux\n");

	for_each_node(nid) {
		if (list_empty(&lwkmem[nid].list) || !lwkmem[nid].n_free_pages)
			continue;
		error = free_memory_to_linux(nid);
		if (error)
			rc = error;
		/* Reset designated memory counters */
		lwkmem[nid].n_free_pages = 0;
		lwkmem[nid].n_resv_pages = 0;
	}
	pr_info("Exiting memory management\n");
	return rc;
}

static void lwkmem_clear_wait(struct lwkmem_clear_info *info, nodemask_t *mask)
{
	int poll = LWKMEM_NODE_CLR_POLL;
	int num_cpus = cpumask_weight(&info->cpumask);

	if (num_cpus) {
		while (poll-- && atomic_read(&info->done) != num_cpus)
			msleep(LWKMEM_NODE_CLR_WAIT);
		if (!poll && atomic_read(&info->done) != num_cpus) {
			LWKMEM_WARN("Node[%*pbl] timeout %ds %d/%d",
				nodemask_pr_args(&info->nodemask),
				LWKMEM_NODE_CLR_TIMEOUT,
				atomic_read(&info->done), num_cpus);
			atomic_inc(&info->errors);
		} else {
			if (!atomic_read(&info->errors)) {
				/* Success! clear this node */
				nodes_andnot(*mask, *mask, info->nodemask);
			}
		}
	}
}


int mos_mem_clear_memory(void)
{
	int i, nid, num_nodes, rc = -EINVAL;
	struct lwkmem_clear_info *info = NULL;
	cpumask_var_t cpumask;
	nodemask_t nodemask, nodemask_mem_only, nodemask_all;

	if (!zalloc_cpumask_var(&cpumask, GFP_KERNEL)) {
		rc = -ENOMEM;
		goto out;
	}

	/* Calculate number of NUMA nodes with LWK CPUs and LWK memory */
	num_nodes = 0;
	nodes_clear(nodemask);
	nodes_clear(nodemask_mem_only);
	nodes_clear(nodemask_all);
	for_each_node(nid) {
		/* Skip NUMA domains that does not have LWK memory */
		if (list_empty(&lwkmem[nid].list) || !lwkmem[nid].n_free_pages)
			continue;
		/*
		 * Create nodemask of CPUless NUMA domains and skip counting it
		 * for clearing memory in the first pass.
		 */
		cpumask_and(cpumask, cpu_online_mask, cpumask_of_node(nid));
		if (cpumask_weight(cpumask) == 0) {
			node_set(nid, nodemask_mem_only);
			continue;
		}
		node_set(nid, nodemask);
		num_nodes++;
	}

	nodes_or(nodemask_all, nodemask, nodemask_mem_only);

	info = kcalloc(num_nodes, sizeof(struct lwkmem_clear_info), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(info)) {
		info = kcalloc(1, sizeof(struct lwkmem_clear_info), GFP_KERNEL);
		if (!info) {
			rc = -ENOMEM;
			LWKMEM_ERROR("Failed to alloate lwkmem_clear_info");
			goto out;
		}
		if (!num_nodes)
			goto cpuless_clear;
		else
			goto clear_serial;
	}

	pr_info("Clearing memory in parallel on NUMA domains[%*pbl]\n",
		nodemask_pr_args(&nodemask));
	i = 0;
	/* Clear memory of NUMA nodes that has CPUs */
	for_each_node_mask(nid, nodemask) {
		nodes_clear(info[i].nodemask);
		node_set(nid, info[i].nodemask);
		cpumask_and(&info[i].cpumask, cpu_online_mask,
			    cpumask_of_node(nid));
		atomic_set(&info[i].errors, 0);
		atomic_set(&info[i].done, 0);
		info[i].npages_total = lwkmem[i].n_free_pages;

		/* Clear memory on @nid in parallel */
		on_each_cpu_mask(&info[i].cpumask, clear_lwk_memory,
				 &info[i], false);
		i++;
	}

	/* Wait till all NUMA nodes with CPUs selected above are cleared */
	for (i = 0; i < num_nodes; i++)
		lwkmem_clear_wait(&info[i], &nodemask);

	/*
	 * If all NUMA nodes are not serviced then fallback
	 * to clearing serially for remaining NUMA nodes.
	 */
	if (!nodes_empty(nodemask))
		goto clear_serial;
	if (atomic_read(&info->errors)) {
		pr_info("Err parallel clearing, trying serial\n");
		nodes_and(nodemask, nodemask_all, nodemask_all);
		goto clear_serial;
	}

	/*
	 * Ok. now we have successfully cleared all NUMA nodes that have both
	 * CPUs and memory. Each NUMA domain used all online CPUs of corresp-
	 * -onding NUMA domain to do so. Now let us use all online CPUs to
	 * clear memory of CPUless NUMA nodes that have LWK memory.
	 */
cpuless_clear:
	num_nodes = nodes_weight(nodemask_mem_only);
	if (num_nodes) {
		/* Memory only NUMA nodes remain to retry in case of errors. */
		nodes_and(nodemask_all, nodemask_mem_only, nodemask_mem_only);

		/* Construct info for parallel memory clearing */
		info[0].npages_total = 0;
		for_each_node_mask(nid, nodemask_mem_only)
			info[0].npages_total += lwkmem[nid].n_free_pages;

		nodes_and(info[0].nodemask, nodemask_mem_only,
			  nodemask_mem_only);
		cpumask_copy(&info[0].cpumask, cpu_online_mask);
		atomic_set(&info[0].errors, 0);
		atomic_set(&info[0].done, 0);

		pr_info("Clearing memory in parallel on NUMA domains[%*pbl]\n",
			nodemask_pr_args(&nodemask_mem_only));
		/* Clear memory in parallel */
		on_each_cpu_mask(&info[0].cpumask, clear_lwk_memory,
				 &info[0], false);
		lwkmem_clear_wait(&info[0], &nodemask_mem_only);
		if (!nodes_empty(nodemask_mem_only))
			goto clear_serial;
		if (atomic_read(&info->errors)) {
			pr_info("Err parallel clearing memonly, try serial\n");
			nodes_and(nodemask, nodemask_all, nodemask_all);
			goto clear_serial;
		}
	}
	rc = 0;
	goto out;

clear_serial:
	/* Consider all remaining NUMA nodes */
	nodes_or(nodemask, nodemask, nodemask_mem_only);
	if (!nodes_empty(nodemask)) {
		info[0].npages_total = 0;
		for_each_node_mask(nid, nodemask)
			info[0].npages_total += lwkmem[nid].n_free_pages;
		nodes_and(info[0].nodemask, nodemask, nodemask);
		cpumask_clear(&info[0].cpumask);
		cpumask_set_cpu(smp_processor_id(), &info[0].cpumask);
		atomic_set(&info[0].errors, 0);
		atomic_set(&info[0].done, 0);
		pr_info("Clearing memory in serial on NUMA domains[%*pbl]\n",
			nodemask_pr_args(&nodemask));
		clear_lwk_memory(&info[0]);
		rc = atomic_read(&info->errors) ? -EINVAL : 0;
	} else
		LWKMEM_ERROR("Empty nodemask for clearing in serial path");
out:
	kfree(info);
	free_cpumask_var(cpumask);

#ifdef DEBUG_MEMORY_CLEARING
	if (!rc) {
		pr_info("Verifying cleared memory\n");
		rc = lwkmem_verify_designated();
		if (rc)
			LWKMEM_ERROR("Verification failed");
	}
#endif
	pr_info("Clearing LWK memory[%s]\n",  rc ? "FAILED" : "SUCCESS");
	return rc;
}

/*
 * mos_mem_init
 *   Offlines memory from Linux and populates the free global designated memory
 *   lists of LWKMEM. This function is called from lwkctrl.c when an LWK
 *   partition is being created with memory partitioning specified.
 *
 *   @nodes, mask that captures the requested NUMA nodes to work on.
 *   @requests, array that specifies in bytes the memory needed on a
 *              corresponding NUMA node as specified by mask @nodes.
 *   @precise,  if true, the function should return error when the requested
 *              memory can not be offlined from Linux on any NUMA node
 *              specified in @nodes mask.
 */
int mos_mem_init(nodemask_t *nodes, resource_size_t *requests, bool precise)
{
	int n;
	int rc = 0;
	resource_size_t sz, sz_req, sz_alloc, sz_dist;
	nodemask_t mask;

	sz_req = 0;
	sz_alloc = 0;

	pr_info("Initializing memory management. precise=%s\n",
		precise ? "yes" : "no");

	lwkmem_n_online_nodes = 0;
	nodes_clear(mask);
	nodes_or(mask, mask, *nodes);

	percpu_down_read(&lwkmem_gsem);
	WARN(!lwkmem_empty(), "LWK memory list is not empty\n");
	percpu_up_read(&lwkmem_gsem);

	/* Determine the number of NUMA domains. */
	for_each_online_node(n)
		if (lwkmem_n_online_nodes < (n + 1))
			lwkmem_n_online_nodes = n + 1;

	for_each_node_mask(n, *nodes) {
		node_clear(n, mask);
		/* Ignore requests of size zero */
		if (!requests[n]) {
			node_clear(n, *nodes);
			continue;
		}

		sz = allocate_memory_from_linux(n, requests[n]);

		/* Initialize designated memory counters */
		lwkmem[n].n_free_pages = bytes_to_pages(sz);
		lwkmem[n].n_resv_pages = 0;

		pr_info("Node%3d: Requested %lld MB Allocated %lld MB\n",
			n, requests[n] >> 20, sz >> 20);
		/*
		 * We could not take away requested amount of memory from Linux.
		 * If precise=yes option is specified then we error out freeing
		 * memory back to Linux. Otherwise we try to distribute the
		 * unfulfilled size of request on the current NUMA node to rest
		 * of the NUMA nodes in the request. At the end if we could not
		 * fulfill the request even in part then the function returns
		 * error.
		 */
		if (sz != requests[n]) {
			sz_dist = requests[n] - sz;
			if (precise) {
				mos_ras(MOS_LWKCTL_FAILURE,
				    "Node %d: %lld MB/%lld MB precise failed",
				    n, sz >> 20, requests[n] >> 20);
				rc = mos_mem_free();
				if (rc) {
					mos_ras(MOS_LWKCTL_FAILURE,
						"%s: Err %d returning memory",
						__func__, rc);
				}
				rc = -ENOMEM;
				goto out;
			}

			pr_info("Unallocated %lld bytes req to node(s):%*pbl\n",
				sz_dist, nodemask_pr_args(&mask));
			if (nodes_empty(mask) ||
			    lwkmem_distribute_request(sz_dist, &mask,
						      requests)) {
				mos_ras(MOS_LWKCTL_WARNING,
					"%s: Could not distribute %lld bytes.",
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

	if (sz_alloc == sz_req)
		pr_info("Requested %lld MB Allocated %lld MB\n",
			sz_req >> 20, sz_alloc >> 20);
	else {
		mos_ras(MOS_LWKCTL_WARNING,
			"%s: Allocated %lld of %lld bytes requested",
			__func__, sz_alloc, sz_req);
		rc = !sz_alloc ? -ENOMEM : 0;
	}

	if (!rc)
		lwkmem_print_list();
out:
	return rc;
}

/*
 * mOS sysfs read/write helpers for LWKMEM,
 *   lwkmem_get
 *   lwkmem_reserved_get
 *   _lwkmem_get
 *
 * Functions and corresponding helpers invoked from mos.c to show LWKMEM
 * sysfs entries. Also used for reading the amount of free memory available
 * in LWK for reservation, typically used in meminfo.
 */
static int _lwkmem_get(unsigned long *lwkm, size_t *n, int reserved)
{
	int nid;

	if (*n < lwkmem_n_online_nodes) {
		LWKMEM_ERROR(
			"%s: Insufficient array size. actual:%ld expected:%ld",
			__func__, *n, lwkmem_n_online_nodes);
		return -EINVAL;
	}

	memset(lwkm, 0, lwkmem_n_online_nodes * sizeof(unsigned long));
	percpu_down_read(&lwkmem_gsem);

	for (nid = 0; nid < *n; nid++) {
		lwkm[nid] = pages_to_bytes(lwkmem[nid].n_resv_pages);
		if (!reserved)
			lwkm[nid] += pages_to_bytes(lwkmem[nid].n_free_pages);
	}

	*n = lwkmem_n_online_nodes;
	percpu_up_read(&lwkmem_gsem);

	return 0;
}

int lwkmem_get(unsigned long *lwkm, size_t *n)
{
	return _lwkmem_get(lwkm, n, 0);
}


int lwkmem_reserved_get(unsigned long *lwkm, size_t *n)
{
	return _lwkmem_get(lwkm, n, 1);
}

/*
 * Returns total designated LWK memory in @totalram and total unreserved
 * memory in @freeram in terms of number of 4k pages. If @nid is set to a
 * valid NUMA node number then the function returns the node specific info.
 * If it is set to NUMA_NO_NODE then the function returns the accumulated
 * info of all online NUMA nodes.
 */
static void lwkmem_global_mem(unsigned long *totalram, unsigned long *freeram,
			      int nid)
{
	numa_nodes_t total;
	numa_nodes_t res;
	size_t n = MAX_NUMNODES;

	if (!totalram || !freeram)
		return;

	if (!zalloc_numa_nodes_array(&total))
		return;

	if (!zalloc_numa_nodes_array(&res)) {
		free_numa_nodes_array(total);
		return;
	}

	if (lwkmem_get(total, &n))
		goto out;

	if (lwkmem_reserved_get(res, &n))
		goto out;

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

out:
	free_numa_nodes_array(total);
	free_numa_nodes_array(res);
}

/*
 * Interface to read LWK meminfo between Linux and LWKMEM directly bypassing
 * the LWK mm interface. This functionality is not process specific and instead
 * might need to read the global LWK memory information.
 */
void lwkmem_meminfo(struct sysinfo *si, int nid)
{
	struct lwk_pma_meminfo info;
	struct lwk_mm *lwk_mm;
	bool lwkview_local = IS_MOS_VIEW(current, MOS_VIEW_LWK_LOCAL);

	if (!lwkview_local && IS_MOS_VIEW(current, MOS_VIEW_LINUX))
		return;

	if (lwkview_local || IS_MOS_VIEW(current, MOS_VIEW_LWK)) {
		if (lwkview_local) {
			if (!is_mostask()) {
				LWKMEM_ERROR("mOS view %s for non LWK pid %d",
					     MOS_VIEW_STR_LWK_LOCAL, current->tgid);
				return;
			}
			lwk_mm = curr_lwk_mm();
			lwk_mm->pm_ops->meminfo(lwk_mm->pma, nid, &info);
			si->totalram = info.total_pages;
			si->freeram = info.free_pages;
		} else
			lwkmem_global_mem(&si->totalram, &si->freeram, nid);
		si->sharedram = 0;
		si->bufferram = 0;
		si->totalswap = 0;
		si->freeswap  = 0;
		si->totalhigh = 0;
		si->freehigh  = 0;
		si->mem_unit = PAGE_SIZE;
	} else if (IS_MOS_VIEW(current, MOS_VIEW_ALL)) {
		lwkmem_global_mem(&info.total_pages, &info.free_pages, nid);
		si->totalram += info.total_pages;
		si->freeram += info.free_pages;
		si->mem_unit = PAGE_SIZE;
	}
}

/*
 * Requests/reserves LWK memory for the current process.
 *
 *   @mosp, pointer to mOS process structure of current LWK process.
 *   @req,  array that holds the requested memory size in bytes for
 *          individual NUMA nodes. Array index corresponds to a NID.
 *          A size 0 request for a NUMA node is ignored.
 *   @n,    number of elements in array @req
 */
int lwkmem_request(struct mos_process_t *mosp, unsigned long *req, size_t n)
{
	int i, rc;
	unsigned long wanted;
	struct lwkmem_granule *g;
	struct lwk_mm *lwk_mm = NULL;

	/* No designated LWKMEM, implicit lwkmem-disable case */
	if (!lwkmem_n_online_nodes)
		return 0;

	if (n > lwkmem_n_online_nodes) {
		LWKMEM_ERROR("%s: Invalid n=%ld online=%ld\n", __func__,
				n, lwkmem_n_online_nodes);
		return -EINVAL;
	}

	wanted = 0;
	for (i = 0; i < n ; i++)
		wanted += req[i];

	/* LWK process not using LWKMEM, explicit lwkmem-disable case */
	if (wanted == 0)
		return 0;

	rc = allocate_lwk_mm();
	if (rc)
		return rc;

	lwk_mm = curr_lwk_mm();
	percpu_down_write(&lwkmem_gsem);

	if (lwkmem_empty()) {
		LWKMEM_ERROR("%s: No designated LWK memory!", __func__);
		rc = -EINVAL;
		goto unlock;
	}

	for (i = 0; i < n ; i++) {
		if (req[i] == 0)
			continue;

		wanted = max_t(unsigned long, rounddown(req[i], MIN_CHUNK_SIZE),
				MIN_CHUNK_SIZE);
		while (wanted > 0) {
			g = lwkmem_find_free_granule(i);
			if (!g) {
				LWKMEM_ERROR("%s: Node%d no free LWK memory!",
						__func__, i);
				rc = -ENOMEM;
				goto unlock;
			}

			if (wanted < g->length) {
				g = lwkmem_split_granule(g, wanted);
				if (!g) {
					LWKMEM_ERROR(
						"%s: no free kernel memory!",
						__func__);
					rc = -ENOMEM;
					goto unlock;
				}
				lwkmem_insert_granule(i, g);
			}

			/* Add granule to the process reserved memory list */
			g->owner = current->pid;
			list_add_tail(&g->list_reserved, &lwk_mm->list_pmem[i]);

			/* Update per NUMA node designated memory counters */
			lwkmem[i].n_resv_pages += bytes_to_pages(g->length);
			lwkmem[i].n_free_pages -= bytes_to_pages(g->length);

			/* Continue searching with the remainder */
			wanted -= g->length;
		}
	}
	lwkmem_print_list();
 unlock:
	percpu_up_write(&lwkmem_gsem);
	return rc;
}

int lwkmem_set_mempolicy_info(const char *buff, size_t size)
{
	/* LWK process not using LWKMEM */
	if (!curr_lwk_mm())
		return 0;

	return lwk_mm_set_mempolicy_info(buff, size);
}

/*
 * Per process LWKMEM callbacks called for every LWK process.
 */
static int lwkmem_process_init(struct mos_process_t *mosp)
{
	mosp->lwk_mm = NULL;
	return 0;
}

static int lwkmem_process_start(struct mos_process_t *mosp)
{
	int rc = 0;

	/* LWK process not using LWKMEM */
	if (!curr_lwk_mm())
		return rc;

	rc = start_lwk_mm();
	if (rc)
		LWKMEM_ERROR("%s: start_lwk_mm() failed, rc=%d", __func__, rc);
	return rc;
}

static void lwkmem_process_exit(struct mos_process_t *mosp)
{
	struct lwk_mm *lwk_mm = curr_lwk_mm();
	struct lwkmem_granule *curr, *next;
	struct list_head *head;
	int n, freed, rc;

	/* LWK process not using LWKMEM */
	if (!lwk_mm)
		return;

	/* Stop per process memory manager */
	rc = exit_lwk_mm();
	if (rc) {
		LWKMEM_ERROR("%s: exit_lwk_mm() failed, rc=%d", __func__, rc);
		return;
	}

	/* Release the process reserved memory back to designated memory list */
	for (n = 0; n < MAX_NUMNODES; n++) {
		freed = 0;
		head = &lwk_mm->list_pmem[n];
		list_for_each_entry_safe(curr, next, head, list_reserved) {
			freed++;
			list_del(&curr->list_reserved);
			curr->owner = -1;

			/* Update per node designated memory counters */
			lwkmem[n].n_resv_pages -= bytes_to_pages(curr->length);
			lwkmem[n].n_free_pages += bytes_to_pages(curr->length);
		}

		if (freed)
			lwkmem_merge_free_granules(n);
	}
	/* Release per process memory manager */
	rc = free_lwk_mm();
	if (rc)
		LWKMEM_ERROR("%s: free_lwk_mm() failed, rc=%d", __func__, rc);
}

static struct mos_process_callbacks_t lwkmem_callbacks = {
	.mos_process_init = lwkmem_process_init,
	.mos_process_start = lwkmem_process_start,
	.mos_process_exit = lwkmem_process_exit,
};

/*
 * LWKMEM early initializations during kernel bootup.
 *
 *   - Initializes global lwkmem[MAX_NUMNODES] array that tracks
 *     designated LWK memory.
 *   - Registers LWK per process callbacks related to LWKMEM.
 *   - Registers LWKMEM yod options.
 */
static int __init lwkmem_early_init(void)
{
	int nid;

	pr_info("LWKMEM v2.0!\n");
	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		INIT_LIST_HEAD(&lwkmem[nid].list);
		lwkmem[nid].n_free_pages = 0;
		lwkmem[nid].n_resv_pages = 0;
	}

	mos_register_process_callbacks(&lwkmem_callbacks);
	lwkmem_yod_options_init();
	return 0;
}
subsys_initcall(lwkmem_early_init);
