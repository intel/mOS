/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright (c) 2009 Cray Inc. All Rights Reserved
 * Copyright (c) 2014      Los Alamos National Security, LLC. All rights
 *                         reserved.
 * Copyright (c) 2016      Nathan Hjelm <hjelmn@cs.unm.edu>
 */

/*
 * Cross Partition Memory (XPMEM) make segment support.
 */

#include <linux/err.h>
#include <linux/mm.h>
#include "xpmem_internal.h"
#include "xpmem_private.h"

/*
 * Create a new and unique segid.
 */
static xpmem_segid_t
xpmem_make_segid(struct xpmem_thread_group *seg_tg)
{
	struct xpmem_id segid;
	xpmem_segid_t *segid_p = (xpmem_segid_t *)&segid;
	int uniq;

	DBUG_ON(sizeof(struct xpmem_id) != sizeof(xpmem_segid_t));

	uniq = atomic_inc_return(&seg_tg->uniq_segid);
	if (uniq > XPMEM_MAX_UNIQ_ID) {
		atomic_dec(&seg_tg->uniq_segid);
		return -EBUSY;
	}

	*segid_p = 0;
	segid.tgid = seg_tg->tgid;
	segid.uniq = (unsigned long)uniq;

	DBUG_ON(*segid_p <= 0);
	return *segid_p;
}

/*
 * Make a segid and segment for the specified address segment.
 */
int
xpmem_make(u64 vaddr, size_t size, int permit_type, void *permit_value,
	   xpmem_segid_t *segid_p)
{
	xpmem_segid_t segid;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_segment *seg;

	if (permit_type != XPMEM_PERMIT_MODE ||
	    ((u64)(uintptr_t)permit_value & ~00777) || size == 0) {
		return -EINVAL;
	}

	seg_tg = xpmem_tg_ref_by_tgid(current->tgid);
	if (IS_ERR(seg_tg)) {
		DBUG_ON(PTR_ERR(seg_tg) != -ENOENT);
		return -XPMEM_ERRNO_NOPROC;
	}

	if (vaddr + size > seg_tg->addr_limit) {
		if (size != XPMEM_MAXADDR_SIZE) {
			xpmem_tg_deref(seg_tg);
			return -EINVAL;
		}
		size = seg_tg->addr_limit - vaddr;
	}

	/*
	 * The start of the segment must be page aligned and it must be a
	 * multiple of pages in size.
	 */
	if (offset_in_page(vaddr) != 0 || offset_in_page(size) != 0) {
		xpmem_tg_deref(seg_tg);
		return -EINVAL;
	}

	segid = xpmem_make_segid(seg_tg);
	if (segid < 0) {
		xpmem_tg_deref(seg_tg);
		return segid;
	}

	/* create a new struct xpmem_segment structure with a unique segid */
	seg = kzalloc(sizeof(struct xpmem_segment), GFP_KERNEL);
	if (seg == NULL) {
		xpmem_tg_deref(seg_tg);
		return -ENOMEM;
	}

	spin_lock_init(&seg->lock);
	init_rwsem(&seg->sema);
	seg->segid = segid;
	seg->vaddr = vaddr;
	seg->size = size;
	seg->permit_type = permit_type;
	seg->permit_value = permit_value;
	init_waitqueue_head(&seg->destroyed_wq);
	seg->tg = seg_tg;
	INIT_LIST_HEAD(&seg->ap_list);
	INIT_LIST_HEAD(&seg->seg_list);

	xpmem_seg_not_destroyable(seg);

	/* add seg to its tg's list of segs */
	write_lock(&seg_tg->seg_list_lock);
	list_add_tail(&seg->seg_list, &seg_tg->seg_list);
	write_unlock(&seg_tg->seg_list_lock);

	xpmem_tg_deref(seg_tg);

	*segid_p = segid;
	XPMEM_DEBUG("segid %llx vaddr %llx size %ld", segid, vaddr, size);
	return 0;
}

/*
 * Remove a segment from the system.
 */
static void
xpmem_remove_seg(struct xpmem_thread_group *seg_tg, struct xpmem_segment *seg)
{
	DBUG_ON(atomic_read(&seg->refcnt) <= 0);

	spin_lock(&seg->lock);
	if (seg->flags & XPMEM_FLAG_DESTROYING) {
		spin_unlock(&seg->lock);
		/*
		 * Force a schedule to possibly yield the cpu. Another
		 * task is destroying the segment and we want to give
		 * it a chance to run.
		 */
		schedule();
		return;
	}
	seg->flags |= XPMEM_FLAG_DESTROYING;
	spin_unlock(&seg->lock);

	xpmem_seg_down_write(seg);

	/* unpin pages and clear PTEs for each attachment to this segment */
	xpmem_clear_PTEs(seg);

	/* indicate that the segment has been destroyed */
	spin_lock(&seg->lock);
	seg->flags |= XPMEM_FLAG_DESTROYED;
	spin_unlock(&seg->lock);

	/* Remove segment structure from its tg's list of segs */
	write_lock(&seg_tg->seg_list_lock);
	list_del_init(&seg->seg_list);
	write_unlock(&seg_tg->seg_list_lock);

	xpmem_seg_up_write(seg);
	xpmem_seg_destroyable(seg);
}

/*
 * Remove all segments belonging to the specified thread group.
 */
void
xpmem_remove_segs_of_tg(struct xpmem_thread_group *seg_tg)
{
	struct xpmem_segment *seg;

	read_lock(&seg_tg->seg_list_lock);

	while (!list_empty(&seg_tg->seg_list)) {
		seg = list_entry((&seg_tg->seg_list)->next,
				 struct xpmem_segment, seg_list);
		xpmem_seg_ref(seg);
		read_unlock(&seg_tg->seg_list_lock);

		xpmem_remove_seg(seg_tg, seg);

		xpmem_seg_deref(seg);
		read_lock(&seg_tg->seg_list_lock);
	}

	read_unlock(&seg_tg->seg_list_lock);
}

/*
 * Remove a segment from the system.
 */
int
xpmem_remove(xpmem_segid_t segid)
{
	struct xpmem_thread_group *seg_tg;
	struct xpmem_segment *seg;

	if (segid <= 0)
		return -EINVAL;

	seg_tg = xpmem_tg_ref_by_segid(segid);
	if (IS_ERR(seg_tg))
		return PTR_ERR(seg_tg);

	if (current->tgid != seg_tg->tgid) {
		xpmem_tg_deref(seg_tg);
		return -EACCES;
	}

	seg = xpmem_seg_ref_by_segid(seg_tg, segid);
	if (IS_ERR(seg)) {
		xpmem_tg_deref(seg_tg);
		return PTR_ERR(seg);
	}
	DBUG_ON(seg->tg != seg_tg);

	xpmem_remove_seg(seg_tg, seg);
	xpmem_seg_deref(seg);
	xpmem_tg_deref(seg_tg);
	XPMEM_DEBUG("segid %llx", segid);
	return 0;
}
