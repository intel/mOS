/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright 2009, 2010, 2014 Cray Inc. All Rights Reserved
 * Copyright (c) 2014-2016 Los Alamos National Security, LCC. All rights
 *                         reserved.
 * Copyright 2016 ARM Inc. All Rights Reserved
 */

/*
 * Private Cross Partition Memory (XPMEM) structures and macros.
 */

#ifndef _XPMEM_PRIVATE_H
#define _XPMEM_PRIVATE_H

#include <linux/version.h>
#include <linux/bit_spinlock.h>
#include <linux/sched.h>
#include <linux/hugetlb.h>
#include <asm/signal.h>

#ifdef CONFIG_MMU_NOTIFIER
#include <linux/mmu_notifier.h>
#else
#error "Kernel needs to be configured with CONFIG_MMU_NOTIFIER"
#endif /* CONFIG_MMU_NOTIFIER */

/*
 * XPMEM_CURRENT_VERSION is used to identify functional differences
 * between various releases of XPMEM to users. XPMEM_CURRENT_VERSION_STRING
 * is printed when the kernel module is loaded and unloaded.
 *
 *   version  differences
 *
 *     1.0    initial implementation of XPMEM
 *     1.1    fetchop (AMO) pages supported
 *     1.2    GET space and write combining attaches supported
 *     1.3    Convert to build for both 2.4 and 2.6 versions of kernel
 *     1.4    add recall PFNs RPC
 *     1.5    first round of resiliency improvements
 *     1.6    make coherence domain union of sharing partitions
 *     2.0    replace 32-bit xpmem_handle_t by 64-bit xpmem_segid_t
 *            replace 32-bit xpmem_id_t by 64-bit xpmem_apid_t
 *     2.1    CRAY: remove PFNtable cache
 *     2.2    CRAY: add support for MMU notifiers
 *     2.3    LANL: remove need for non-exported kernel functions
 *            and add update for kernel 3.13
 *     2.3.1  Cherry-pick Cray changes
 *     2.4    CRAY: repair page fault mmap_lock locking
 *     2.5    CRAY: prevent infinite loop when removing segment or
 *                  access_permit
 *     2.6    CRAY: rearrange/clean-up code for easier debugging
 *     2.6.1  Merge with latest Cray version (2.4->2.6)
 *     2.6.2  Fix race in xpmem_open
 *     2.6.3  Fix bugs introduced in 2.6.2 that worked with 3.x but
 *            not 4.x kernels.
 *     2.6.4  Fix hold-and-wait deadlock on detach.
 *
 * This int constant has the following format:
 *
 *      +----+------------+----------------+
 *      |////|   major    |     minor      |
 *      +----+------------+----------------+
 *
 *       major - major revision number (12-bits)
 *       minor - minor revision number (16-bits)
 */
#define XPMEM_CURRENT_VERSION		0x00026005
#define XPMEM_CURRENT_VERSION_STRING	"2.6.5"

#define XPMEM_MODULE_NAME "xpmem"

#ifdef USE_DBUG_ON
#define DBUG_ON(condition)      BUG_ON(condition)
#else
#define DBUG_ON(condition)
#endif

extern uint32_t xpmem_debug_on;

#define XPMEM_DEBUG(format, a...)					\
	if (xpmem_debug_on)						\
		printk("[%d]%s: "format"\n", current->tgid, __func__, ##a);

#define delayed_work work_struct

/*
 * Both the xpmem_segid_t and xpmem_apid_t are of type __s64 and designed
 * to be opaque to the user. Both consist of the same underlying fields.
 *
 * The 'uniq' field is designed to give each segid or apid a unique value.
 * Each type is only unique with respect to itself.
 *
 * An ID is never less than or equal to zero.
 */
struct xpmem_id {
	pid_t tgid;		/* thread group that owns ID */
	unsigned int uniq;	/* this value makes the ID unique */
};

/* Shift INT_MAX by one so we can tell when we overflow. */
#define XPMEM_MAX_UNIQ_ID	(INT_MAX >> 1)

static inline pid_t
xpmem_segid_to_tgid(xpmem_segid_t segid)
{
	DBUG_ON(segid <= 0);
	return ((struct xpmem_id *)&segid)->tgid;
}

static inline pid_t
xpmem_apid_to_tgid(xpmem_apid_t apid)
{
	DBUG_ON(apid <= 0);
	return ((struct xpmem_id *)&apid)->tgid;
}

/*
 * Hash Tables
 *
 * XPMEM utilizes hash tables to enable faster lookups of list entries.
 * These hash tables are implemented as arrays. A simple modulus of the hash
 * key yields the appropriate array index. A hash table's array element (i.e.,
 * hash table bucket) consists of a hash list and the lock that protects it.
 *
 * XPMEM has the following two hash tables:
 *
 * table		bucket					key
 * part->tg_hashtable	list of struct xpmem_thread_group	tgid
 * tg->ap_hashtable	list of struct xpmem_access_permit	apid.uniq
 */

struct xpmem_hashlist {
	rwlock_t lock;		/* lock for hash list */
	struct list_head list;	/* hash list */
} ____cacheline_aligned;

#define XPMEM_TG_HASHTABLE_SIZE	8
#define XPMEM_AP_HASHTABLE_SIZE	8

static inline int
xpmem_tg_hashtable_index(pid_t tgid)
{
	return ((unsigned int)tgid % XPMEM_TG_HASHTABLE_SIZE);
}

static inline int
xpmem_ap_hashtable_index(xpmem_apid_t apid)
{
	DBUG_ON(apid <= 0);
	return (((struct xpmem_id *)&apid)->uniq % XPMEM_AP_HASHTABLE_SIZE);
}

/*
 * general internal driver structures
 */

struct xpmem_thread_group {
	spinlock_t lock;	/* tg lock */
	pid_t tgid;		/* tg's tgid */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	uid_t uid;		/* tg's uid */
	gid_t gid;		/* tg's gid */
#else
	kuid_t uid;		/* tg's uid */
	kgid_t gid;		/* tg's gid */
#endif
	volatile int flags;	/* tg attributes and state */
	atomic_t uniq_segid;
	atomic_t uniq_apid;
	rwlock_t seg_list_lock;
	struct list_head seg_list;	/* tg's list of segs */
	atomic_t refcnt;	/* references to tg */
	atomic_t n_pinned;	/* #of pages pinned by this tg */
	u64 addr_limit;		/* highest possible user addr */
	struct list_head tg_hashlist;	/* tg hash list */
	struct task_struct *group_leader;	/* thread group leader */
	struct mm_struct *mm;	/* tg's mm */
	atomic_t n_recall_PFNs;	/* #of recall of PFNs in progress */
	struct mutex recall_PFNs_mutex;	/* lock for serializing recall of PFNs */
	wait_queue_head_t block_recall_PFNs_wq;	/* wait to block recall of PFNs */
	wait_queue_head_t allow_recall_PFNs_wq;	/* wait to allow recall of PFNs */
	struct mmu_notifier mmu_not;	/* tg's mmu notifier struct */
	int mmu_initialized;	/* registered for mmu callbacks? */
	int mmu_unregister_called;

        struct xpmem_hashlist ap_hashtable[];	/* locks + ap hash lists */
};

struct xpmem_segment {
	spinlock_t lock;	/* seg lock */
	struct rw_semaphore sema;	/* seg sema */
	xpmem_segid_t segid;	/* unique segid */
	u64 vaddr;		/* starting address */
	size_t size;		/* size of seg */
	int permit_type;	/* permission scheme */
	void *permit_value;	/* permission data */
	volatile int flags;	/* seg attributes and state */
	atomic_t refcnt;	/* references to seg */
	wait_queue_head_t destroyed_wq;	/* wait for seg to be destroyed */
	struct xpmem_thread_group *tg;	/* creator tg */
	struct list_head ap_list;	/* local access permits of seg */
	struct list_head seg_list;	/* tg's list of segs */
};

struct xpmem_access_permit {
	spinlock_t lock;	/* access permit lock */
	xpmem_apid_t apid;	/* unique apid */
	int mode;		/* read/write mode */
	volatile int flags;	/* access permit attributes and state */
	atomic_t refcnt;	/* references to access permit */
	struct xpmem_segment *seg;	/* seg permitted to be accessed */
	struct xpmem_thread_group *tg;	/* access permit's tg */
	struct list_head att_list;	/* atts of this access permit's seg */
	struct list_head ap_list;	/* access permits linked to seg */
	struct list_head ap_hashlist;	/* access permit hash list */
};

struct xpmem_attachment {
	struct mutex mutex;	/* att lock for serialization */
	u64 vaddr;		/* starting address of seg attached */
	u64 at_vaddr;		/* address where seg is attached */
	size_t at_size;		/* size of seg attachment */
	struct vm_area_struct *at_vma;	/* vma where seg is attachment */
	volatile int flags;	/* att attributes and state */
	atomic_t refcnt;	/* references to att */
	struct xpmem_access_permit *ap;/* associated access permit */
	struct list_head att_list;	/* atts linked to access permit */
	struct mm_struct *mm;	/* mm struct attached to */
	struct mutex invalidate_mutex; /* to serialize page table invalidates */
};

struct xpmem_partition {
	/* procfs debugging */
	atomic_t n_pinned; 	/* # of pages pinned xpmem */
	atomic_t n_unpinned; 	/* # of pages unpinned by xpmem */

	struct xpmem_hashlist tg_hashtable[];	/* locks + tg hash lists */
};

/*
 * Attribute and state flags for various xpmem structures. Some values
 * are defined in xpmem_internal.h, so we reserved space here via XPMEM_DONT_USE_X
 * to prevent overlap.
 */
#define XPMEM_FLAG_DESTROYING		0x00040	/* being destroyed */
#define XPMEM_FLAG_DESTROYED		0x00080	/* 'being destroyed' finished */

#define XPMEM_FLAG_VALIDPTEs		0x00200	/* valid PTEs exist */
#define XPMEM_FLAG_RECALLINGPFNS	0x00400	/* recalling PFNs */

#define	XPMEM_DONT_USE_1		0x10000
#define	XPMEM_DONT_USE_2		0x20000
#define	XPMEM_DONT_USE_3		0x40000	/* reserved for xpmem.h */
#define	XPMEM_DONT_USE_4		0x80000	/* reserved for xpmem.h */

#define XPMEM_NODE_UNINITIALIZED	-1
#define XPMEM_CPUS_UNINITIALIZED	-1
#define XPMEM_NODE_OFFLINE		-2
#define XPMEM_CPUS_OFFLINE		-2

/* found in xpmem_make.c */
extern int xpmem_make(u64, size_t, int, void *, xpmem_segid_t *);
extern void xpmem_remove_segs_of_tg(struct xpmem_thread_group *);
extern int xpmem_remove(xpmem_segid_t);

/* found in xpmem_get.c */
extern int xpmem_get(xpmem_segid_t, int, int, void *, xpmem_apid_t *);
extern void xpmem_release_aps_of_tg(struct xpmem_thread_group *);
extern int xpmem_release(xpmem_apid_t);

/* found in xpmem_attach.c */
extern struct vm_operations_struct xpmem_vm_ops;
extern int xpmem_attach(struct file *, xpmem_apid_t, off_t, size_t, u64, int,
			int, u64 *);
extern void xpmem_clear_PTEs_range(struct xpmem_segment *, u64, u64, int);
extern void xpmem_clear_PTEs(struct xpmem_segment *);
extern int xpmem_detach(u64);
extern void xpmem_detach_att(struct xpmem_access_permit *,
			     struct xpmem_attachment *);
extern int xpmem_mmap(struct file *, struct vm_area_struct *);

/* found in xpmem_pfn.c */
extern int xpmem_ensure_valid_PFN(struct xpmem_segment *seg, u64 vaddr,
				  struct vm_area_struct **pvma);
extern u64 xpmem_vaddr_to_PFN(struct mm_struct *mm, u64 vaddr);
extern int xpmem_block_recall_PFNs(struct xpmem_thread_group *, int);
extern void xpmem_unpin_pages(struct xpmem_segment *, struct mm_struct *, u64,
				size_t);
extern void xpmem_unblock_recall_PFNs(struct xpmem_thread_group *);
extern int xpmem_fork_begin(void);
extern int xpmem_fork_end(void);
#define XPMEM_TGID_STRING_LEN	11
extern spinlock_t xpmem_unpin_procfs_lock;
extern struct proc_dir_entry *xpmem_unpin_procfs_dir;
extern struct proc_ops xpmem_unpin_procfs_ops;

/* found in xpmem_main.c */
extern struct xpmem_partition *xpmem_my_part;
void xpmem_teardown(struct xpmem_thread_group *tg);

/* found in xpmem_misc.c */
extern struct xpmem_thread_group *
__xpmem_tg_ref_by_tgid_nolock_internal(pid_t tgid, int index, int return_destroying);
static inline struct xpmem_thread_group *__xpmem_tg_ref_by_tgid(pid_t tgid, int return_destroying) {
	struct xpmem_thread_group *tg;
	int index;

	index = xpmem_tg_hashtable_index(tgid);
	read_lock(&xpmem_my_part->tg_hashtable[index].lock);
	tg = __xpmem_tg_ref_by_tgid_nolock_internal (tgid, index, return_destroying);
	read_unlock(&xpmem_my_part->tg_hashtable[index].lock);
	return tg;
}

static inline struct xpmem_thread_group *__xpmem_tg_ref_by_tgid_nolock(pid_t tgid, int return_destroying) {
	return __xpmem_tg_ref_by_tgid_nolock_internal (tgid, xpmem_tg_hashtable_index(tgid),
						       return_destroying);
}
#define xpmem_tg_ref_by_tgid(t)               __xpmem_tg_ref_by_tgid(t, 0)
#define xpmem_tg_ref_by_tgid_all(t)           __xpmem_tg_ref_by_tgid(t, 1)
#define xpmem_tg_ref_by_tgid_nolock(t)        __xpmem_tg_ref_by_tgid_nolock(t, 0)
#define xpmem_tg_ref_by_tgid_all_nolock(t)    __xpmem_tg_ref_by_tgid_nolock(t, 1)
extern struct xpmem_thread_group *xpmem_tg_ref_by_segid(xpmem_segid_t);
extern struct xpmem_thread_group *xpmem_tg_ref_by_apid(xpmem_apid_t);
extern void xpmem_tg_deref(struct xpmem_thread_group *);
extern struct xpmem_segment *xpmem_seg_ref_by_segid(struct xpmem_thread_group *,
						    xpmem_segid_t);
extern void xpmem_seg_deref(struct xpmem_segment *);
extern struct xpmem_access_permit *xpmem_ap_ref_by_apid(struct
							  xpmem_thread_group *,
							  xpmem_apid_t);
extern void xpmem_ap_deref(struct xpmem_access_permit *);
extern void xpmem_att_deref(struct xpmem_attachment *);
extern int xpmem_seg_down_read(struct xpmem_thread_group *,
			       struct xpmem_segment *, int, int);
extern int xpmem_validate_access(struct xpmem_access_permit *, off_t, size_t,
				 int, u64 *);
extern struct proc_ops xpmem_debug_printk_procfs_ops;
/* found in xpmem_mmu_notifier.c */
extern int xpmem_mmu_notifier_init(struct xpmem_thread_group *);
extern void xpmem_mmu_notifier_unlink(struct xpmem_thread_group *);

/*
 * Inlines that mark an internal driver structure as being destroyable or not.
 * The idea is to set the refcnt to 1 at structure creation time and then
 * drop that reference at the time the structure is to be destroyed.
 */
static inline void
xpmem_tg_not_destroyable(struct xpmem_thread_group *tg)
{
	atomic_set(&tg->refcnt, 1);
}

static inline void
xpmem_tg_destroyable(struct xpmem_thread_group *tg)
{
	xpmem_tg_deref(tg);
}

static inline void
xpmem_seg_not_destroyable(struct xpmem_segment *seg)
{
	atomic_set(&seg->refcnt, 1);
}

static inline void
xpmem_seg_destroyable(struct xpmem_segment *seg)
{
	xpmem_seg_deref(seg);
}

static inline void
xpmem_ap_not_destroyable(struct xpmem_access_permit *ap)
{
	atomic_set(&ap->refcnt, 1);
}

static inline void
xpmem_ap_destroyable(struct xpmem_access_permit *ap)
{
	xpmem_ap_deref(ap);
}

static inline void
xpmem_att_not_destroyable(struct xpmem_attachment *att)
{
	atomic_set(&att->refcnt, 1);
}

static inline void
xpmem_att_destroyable(struct xpmem_attachment *att)
{
	xpmem_att_deref(att);
}

/*
 * Inlines that increment the refcnt for the specified structure.
 */
static inline void
xpmem_tg_ref(struct xpmem_thread_group *tg)
{
	DBUG_ON(atomic_read(&tg->refcnt) <= 0);
	atomic_inc(&tg->refcnt);
}

static inline void
xpmem_seg_ref(struct xpmem_segment *seg)
{
	DBUG_ON(atomic_read(&seg->refcnt) <= 0);
	atomic_inc(&seg->refcnt);
}

static inline void
xpmem_ap_ref(struct xpmem_access_permit *ap)
{
	DBUG_ON(atomic_read(&ap->refcnt) <= 0);
	atomic_inc(&ap->refcnt);
}

static inline void
xpmem_att_ref(struct xpmem_attachment *att)
{
	DBUG_ON(atomic_read(&att->refcnt) <= 0);
	atomic_inc(&att->refcnt);
}

/*
 * A simple test to determine whether the specified vma corresponds to a
 * XPMEM attachment.
 */
static inline int
xpmem_is_vm_ops_set(struct vm_area_struct *vma)
{
	return (vma->vm_ops == &xpmem_vm_ops);
}

/* xpmem_seg_down_read() can be found in xpmem_misc.c */

static inline void
xpmem_seg_up_read(struct xpmem_thread_group *seg_tg,
		  struct xpmem_segment *seg, int unblock_recall_PFNs)
{
	up_read(&seg->sema);
	if (unblock_recall_PFNs)
		xpmem_unblock_recall_PFNs(seg_tg);
}

static inline void
xpmem_seg_down_write(struct xpmem_segment *seg)
{
	down_write(&seg->sema);
}

static inline void
xpmem_seg_up_write(struct xpmem_segment *seg)
{
	up_write(&seg->sema);
	wake_up(&seg->destroyed_wq);
}

static inline void
xpmem_wait_for_seg_destroyed(struct xpmem_segment *seg)
{
	wait_event(seg->destroyed_wq, ((seg->flags & XPMEM_FLAG_DESTROYED) ||
				       !(seg->flags & (XPMEM_FLAG_DESTROYING |
						       XPMEM_FLAG_RECALLINGPFNS))));
}

#endif /* _XPMEM_PRIVATE_H */
