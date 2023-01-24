/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright (c) 2016      Nathan Hjelm <hjelmn@cs.unm.edu>
 */

/*
 * Cross Partition Memory (XPMEM) get access support.
 */

#include <linux/err.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include "../../include/uapi/xpmem/xpmem_internal.h"
#include "xpmem_private.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#define uid_eq(a, b)	((a) == (b))
#endif

/*
 * This is the kernel's IPC permission checking function without calls to
 * do any extra security checks. See ipc/util.c for the original source.
 */
static int
xpmem_ipcperms(struct kern_ipc_perm *ipcp, short flag)
{
	int requested_mode, granted_mode;

	requested_mode = (flag >> 6) | (flag >> 3) | flag;
	granted_mode = ipcp->mode;
	if (uid_eq(current_euid(), ipcp->cuid) ||
	    uid_eq(current_euid(), ipcp->uid))
		granted_mode >>= 6;
	else if (in_group_p(ipcp->cgid) || in_group_p(ipcp->gid))
		granted_mode >>= 3;
	/* is there some bit set in requested_mode but not in granted_mode? */
	if ((requested_mode & ~granted_mode & 0007) && !capable(CAP_IPC_OWNER))
		return -1;

	return 0;
}

/*
 * Ensure that the user is actually allowed to access the segment.
 */
static int
xpmem_check_permit_mode(int flags, struct xpmem_segment *seg)
{
	struct kern_ipc_perm perm;
	int ret;

	DBUG_ON(seg->permit_type != XPMEM_PERMIT_MODE);

	memset(&perm, 0, sizeof(struct kern_ipc_perm));
	perm.uid = perm.cuid = seg->tg->uid;
	perm.gid = perm.cgid = seg->tg->gid;
	perm.mode = (u64)seg->permit_value;

	ret = xpmem_ipcperms(&perm, S_IRUSR);
	if (ret == 0 && (flags & XPMEM_RDWR))
		ret = xpmem_ipcperms(&perm, S_IWUSR);

	return ret;
}

/*
 * Create a new and unique apid.
 */
static xpmem_apid_t
xpmem_make_apid(struct xpmem_thread_group *ap_tg)
{
	struct xpmem_id apid;
	xpmem_apid_t *apid_p = (xpmem_apid_t *)&apid;
	int uniq;

	DBUG_ON(sizeof(struct xpmem_id) != sizeof(xpmem_apid_t));

	uniq = atomic_inc_return(&ap_tg->uniq_apid);
	if (uniq > XPMEM_MAX_UNIQ_ID) {
		atomic_dec(&ap_tg->uniq_apid);
		return -EBUSY;
	}

	*apid_p = 0;
	apid.tgid = ap_tg->tgid;
	apid.uniq = (unsigned int)uniq;
	return *apid_p;
}

/*
 * Get permission to access a specified segid.
 */
int
xpmem_get(xpmem_segid_t segid, int flags, int permit_type, void *permit_value,
	  xpmem_apid_t *apid_p)
{
	xpmem_apid_t apid;
	struct xpmem_access_permit *ap;
	struct xpmem_segment *seg;
	struct xpmem_thread_group *ap_tg, *seg_tg;
	int index;

	if (segid <= 0)
		return -EINVAL;

	if ((flags & ~(XPMEM_RDONLY | XPMEM_RDWR)) ||
	    (flags & (XPMEM_RDONLY | XPMEM_RDWR)) ==
	    (XPMEM_RDONLY | XPMEM_RDWR))
		return -EINVAL;

	if (permit_type != XPMEM_PERMIT_MODE || permit_value != NULL)
		return -EINVAL;

	seg_tg = xpmem_tg_ref_by_segid(segid);
	if (IS_ERR(seg_tg))
		return PTR_ERR(seg_tg);

	/* Attempt to get access permit to self's segment */
	if (seg_tg->tgid == current->tgid) {
		xpmem_tg_deref(seg_tg);
		return -EINVAL;
	}

	seg = xpmem_seg_ref_by_segid(seg_tg, segid);
	if (IS_ERR(seg)) {
		xpmem_tg_deref(seg_tg);
		return PTR_ERR(seg);
	}

	/* assuming XPMEM_PERMIT_MODE, do the appropriate permission check */
	if (xpmem_check_permit_mode(flags, seg) != 0) {
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return -EACCES;
	}

	/* find accessor's thread group structure */
	ap_tg = xpmem_tg_ref_by_tgid(current->tgid);
	if (IS_ERR(ap_tg)) {
		DBUG_ON(PTR_ERR(ap_tg) != -ENOENT);
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return -XPMEM_ERRNO_NOPROC;
	}

	apid = xpmem_make_apid(ap_tg);
	if (apid < 0) {
		xpmem_tg_deref(ap_tg);
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return apid;
	}

	/* create a new xpmem_access_permit structure with a unique apid */
	ap = kzalloc(sizeof(struct xpmem_access_permit), GFP_KERNEL);
	if (ap == NULL) {
		xpmem_tg_deref(ap_tg);
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return -ENOMEM;
	}

	spin_lock_init(&ap->lock);
	ap->seg = seg;
	ap->tg = ap_tg;
	ap->apid = apid;
	ap->mode = flags;
	INIT_LIST_HEAD(&ap->att_list);
	INIT_LIST_HEAD(&ap->ap_list);
	INIT_LIST_HEAD(&ap->ap_hashlist);

	xpmem_ap_not_destroyable(ap);

	/* add ap to its seg's access permit list */
	spin_lock(&seg->lock);
	list_add_tail(&ap->ap_list, &seg->ap_list);
	spin_unlock(&seg->lock);

	/* add ap to its hash list */
	index = xpmem_ap_hashtable_index(ap->apid);
	write_lock(&ap_tg->ap_hashtable[index].lock);
	list_add_tail(&ap->ap_hashlist, &ap_tg->ap_hashtable[index].list);
	write_unlock(&ap_tg->ap_hashtable[index].lock);

	xpmem_tg_deref(ap_tg);

	/*
	 * The following two derefs
	 *
	 *      xpmem_seg_deref(seg);
	 *      xpmem_tg_deref(seg_tg);
	 *
	 * aren't being done at this time in order to prevent the seg
	 * and seg_tg structures from being prematurely kfree'd as long as the
	 * potential for them to be referenced via this ap structure exists.
	 *
	 * These two derefs will be done by xpmem_release_ap() at the time
	 * this ap structure is destroyed.
	 */

	*apid_p = apid;
	XPMEM_DEBUG("segid %llx apid %llx", segid, apid);
	return 0;
}

/*
 * Release an access permit and detach all associated attaches.
 */
static void
xpmem_release_ap(struct xpmem_thread_group *ap_tg,
		  struct xpmem_access_permit *ap)
{
	int index;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_attachment *att;
	struct xpmem_segment *seg;

	spin_lock(&ap->lock);
	if (ap->flags & XPMEM_FLAG_DESTROYING) {
		spin_unlock(&ap->lock);
		/*
		 * Force a schedule to possibly yield the cpu. Another
		 * task is destroying the permit and we want to give
		 * it a chance to run.
		 */
		schedule();
		return;
	}
	ap->flags |= XPMEM_FLAG_DESTROYING;

	/* deal with all attaches first */
	while (!list_empty(&ap->att_list)) {
		att = list_entry((&ap->att_list)->next, struct xpmem_attachment,
				 att_list);
		xpmem_att_ref(att);
		spin_unlock(&ap->lock);

		xpmem_detach_att(ap, att);
		DBUG_ON(atomic_read(&att->mm->mm_count) <= 0);

		xpmem_att_deref(att);
		spin_lock(&ap->lock);
	}

	ap->flags |= XPMEM_FLAG_DESTROYED;
	spin_unlock(&ap->lock);

	/*
	 * Remove access structure from its hash list.
	 * This is done after the xpmem_detach_att to prevent any racing
	 * thread from looking up access permits for the owning thread group
	 * and not finding anything, assuming everything is clean, and
	 * freeing the mm before xpmem_detach_att has a chance to
	 * use it.
	 */
	index = xpmem_ap_hashtable_index(ap->apid);
	write_lock(&ap_tg->ap_hashtable[index].lock);
	list_del_init(&ap->ap_hashlist);
	write_unlock(&ap_tg->ap_hashtable[index].lock);

	/* the ap's seg and the seg's tg were ref'd in xpmem_get() */
	seg = ap->seg;
	seg_tg = seg->tg;

	/* remove ap from its seg's access permit list */
	spin_lock(&seg->lock);
	list_del_init(&ap->ap_list);
	spin_unlock(&seg->lock);

	xpmem_seg_deref(seg);	/* deref of xpmem_get()'s ref */
	xpmem_tg_deref(seg_tg);	/* deref of xpmem_get()'s ref */

	xpmem_ap_destroyable(ap);
}

/*
 * Release all access permits and detach all associated attaches for the given
 * thread group.
 */
void
xpmem_release_aps_of_tg(struct xpmem_thread_group *ap_tg)
{
	struct xpmem_hashlist *hashlist;
	struct xpmem_access_permit *ap;
	int index;

	for (index = 0; index < XPMEM_AP_HASHTABLE_SIZE; index++) {
		hashlist = &ap_tg->ap_hashtable[index];

		read_lock(&hashlist->lock);
		while (!list_empty(&hashlist->list)) {
			ap = list_entry((&hashlist->list)->next,
					struct xpmem_access_permit,
					ap_hashlist);
			xpmem_ap_ref(ap);
			read_unlock(&hashlist->lock);

			xpmem_release_ap(ap_tg, ap);

			xpmem_ap_deref(ap);
			read_lock(&hashlist->lock);
		}
		read_unlock(&hashlist->lock);
	}
}

/*
 * Release an access permit for a XPMEM address segment.
 */
int
xpmem_release(xpmem_apid_t apid)
{
	struct xpmem_thread_group *ap_tg;
	struct xpmem_access_permit *ap;

	if (apid <= 0)
		return -EINVAL;

	ap_tg = xpmem_tg_ref_by_apid(apid);
	if (IS_ERR(ap_tg))
		return PTR_ERR(ap_tg);

	if (current->tgid != ap_tg->tgid) {
		xpmem_tg_deref(ap_tg);
		return -EACCES;
	}

	ap = xpmem_ap_ref_by_apid(ap_tg, apid);
	if (IS_ERR(ap)) {
		xpmem_tg_deref(ap_tg);
		return PTR_ERR(ap);
	}
	DBUG_ON(ap->tg != ap_tg);

	xpmem_release_ap(ap_tg, ap);
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);
	XPMEM_DEBUG("apid  %llx", apid);
	return 0;
}
