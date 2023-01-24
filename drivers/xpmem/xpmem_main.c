/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright 2010, 2014 Cray Inc. All Rights Reserved
 * Copyright 2015-2018 Los Alamos National Security, LLC. All rights reserved.
 * Copyright 2017 ARM, Inc. All rights reserved.
 */

/*
 * Cross Partition Memory (XPMEM) support.
 *
 * This module (along with a corresponding library) provides support for
 * cross-partition shared memory between threads.
 *
 * Caveats
 *
 *   * XPMEM cannot allocate VM_IO pages on behalf of another thread group
 *     since get_user_pages() doesn't handle VM_IO pages. This is normally
 *     valid if a thread group attaches a portion of an address space and is
 *     the first to touch that portion.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include "../../include/uapi/xpmem/xpmem_internal.h"
#include "xpmem_private.h"

#include <asm/uaccess.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define proc_set_user(_pde, _uid, _gid)				\
	do {							\
		(_pde)->uid = _uid;				\
		(_pde)->gid = _gid;				\
	} while (0)
#endif

struct xpmem_partition *xpmem_my_part = NULL;  /* pointer to this partition */
static void xpmem_destroy_tg(struct xpmem_thread_group *tg);

/*
 * User open of the XPMEM driver. Called whenever /dev/xpmem is opened.
 * Create a struct xpmem_thread_group structure for the specified thread group.
 * And add the structure to the tg hash table.
 */
static int
xpmem_open(struct inode *inode, struct file *file)
{
	struct xpmem_thread_group *tg;
	int index, ret;
	struct proc_dir_entry *unpin_entry;
	char tgid_string[XPMEM_TGID_STRING_LEN];

	XPMEM_DEBUG("inode=%p file=%p", inode, file);
	/* if this has already been done, just return silently */
	tg = xpmem_tg_ref_by_tgid(current->tgid);
	if (!IS_ERR(tg)) {
		xpmem_tg_deref(tg);
		return 0;
	}

	/* create tg */
	tg = kzalloc(sizeof(struct xpmem_thread_group) +
		     sizeof(struct xpmem_hashlist) *
		     XPMEM_AP_HASHTABLE_SIZE, GFP_KERNEL);
	if (tg == NULL) {
		XPMEM_DEBUG("errno=%d", ENOMEM);
		return -ENOMEM;
	}

	spin_lock_init(&tg->lock);
	tg->tgid = current->tgid;
	tg->uid = current_uid();
	tg->gid = current_gid();
	atomic_set(&tg->uniq_segid, 0);
	atomic_set(&tg->uniq_apid, 0);
	atomic_set(&tg->n_pinned, 0);
	tg->addr_limit = TASK_SIZE;
	rwlock_init(&tg->seg_list_lock);
	INIT_LIST_HEAD(&tg->seg_list);
	INIT_LIST_HEAD(&tg->tg_hashlist);
	atomic_set(&tg->n_recall_PFNs, 0);
	mutex_init(&tg->recall_PFNs_mutex);
	init_waitqueue_head(&tg->block_recall_PFNs_wq);
	init_waitqueue_head(&tg->allow_recall_PFNs_wq);
	tg->mmu_initialized = 0;
	tg->mmu_unregister_called = 0;
	tg->mm = current->mm;

	for (index = 0; index < XPMEM_AP_HASHTABLE_SIZE; index++) {
		rwlock_init(&tg->ap_hashtable[index].lock);
		INIT_LIST_HEAD(&tg->ap_hashtable[index].list);
	}

	/* Register MMU notifier callbacks */
	ret = xpmem_mmu_notifier_init(tg);
	if (ret != 0) {
		kfree(tg);
		XPMEM_DEBUG("errno=%d", -ret);
		return ret;
	}

	snprintf(tgid_string, XPMEM_TGID_STRING_LEN, "%d", current->tgid);
	spin_lock(&xpmem_unpin_procfs_lock);
	unpin_entry = proc_create_data(tgid_string, 0644,
				       xpmem_unpin_procfs_dir,
				       &xpmem_unpin_procfs_ops,
				       (void *)(unsigned long)current->tgid);
	spin_unlock(&xpmem_unpin_procfs_lock);
	if (unpin_entry != NULL) {
		proc_set_user(unpin_entry, current_uid(), current_gid());
	}

	xpmem_tg_not_destroyable(tg);

	/* add tg to its hash list */
	index = xpmem_tg_hashtable_index(tg->tgid);
	write_lock(&xpmem_my_part->tg_hashtable[index].lock);
	list_add_tail(&tg->tg_hashlist,
		      &xpmem_my_part->tg_hashtable[index].list);
	write_unlock(&xpmem_my_part->tg_hashtable[index].lock);

	/*
	 * Increment 'usage' for the current task's thread group leader, and
	 * store the task and mm_struct addresses in the tg structure for
	 * reference without lookup in later functions.  It is OK to store
	 * the mm_struct address in the tg, since no process using XPMEM
	 * can mmput() its mm_struct until it has removed all its XPMEM data
	 * and any references to it from other processes (thanks to MMU
	 * notifiers).
	 */
	get_task_struct(current->group_leader);
	tg->group_leader = current->group_leader;
	BUG_ON(current->mm != current->group_leader->mm);

	return 0;
}

/*
 * Destroy a xpmem_thread_group.  The call to mmu_notifier_unregister()
 * ensures that all linked structures are cleaned up and no future references
 * can be made.
 */
static void
xpmem_destroy_tg(struct xpmem_thread_group *tg)
{
	XPMEM_DEBUG("tg->mm=%p", tg->mm);

	/*
	 * Calls MMU release function if exit_mmap() has not executed yet.
	 * Decrements mm_count.
	 */
	xpmem_mmu_notifier_unlink(tg);
	xpmem_tg_destroyable(tg);
	xpmem_tg_deref(tg);
}

/*
 * Remove XPMEM data structures and references for a given tg.  This is
 * called whenever an address space is destroyed or when a process closes
 * /dev/xpmem.  We always arrive here via a MMU release callout.
 */
void
xpmem_teardown(struct xpmem_thread_group *tg)
{
	XPMEM_DEBUG("tg->mm=%p", tg->mm);

	spin_lock(&tg->lock);
	DBUG_ON(tg->flags & XPMEM_FLAG_DESTROYING);
	tg->flags |= XPMEM_FLAG_DESTROYING;
	spin_unlock(&tg->lock);

	xpmem_release_aps_of_tg(tg);
	xpmem_remove_segs_of_tg(tg);

	spin_lock(&tg->lock);
	DBUG_ON(tg->flags & XPMEM_FLAG_DESTROYED);
	tg->flags |= XPMEM_FLAG_DESTROYED;
	spin_unlock(&tg->lock);

	/* We don't call xpmem_destroy_tg() here.  We can't call
	 * mmu_notifier_unregister() when the stack started with a
	 * mmu_notifier_release() callout or we'll deadlock in the kernel
	 * MMU notifier code.  xpmem_destroy_tg() will be called when the
	 * close of /dev/xpmem occurs as deadlocks are not possible then.
	 */
	xpmem_tg_deref(tg);
}

/*
 * The following function gets called whenever a thread group that has opened
 * /dev/xpmem closes it.
 */
static int
xpmem_flush(struct file *file, fl_owner_t owner)
{
	char tgid_string[XPMEM_TGID_STRING_LEN];
	struct xpmem_thread_group *tg;
	int index;

	/*
	 * During a call to fork() there is a check for whether the parent
	 * process has any pending signals. If there are pending signals, then
	 * the fork aborts, and the child process is removed before delivering
	 * the signal and starting the fork again. In that case, we can end up
	 * here, but since we're mid-fork, current is pointing to the parent's
	 * task_struct and not the child's. This would cause us to remove the
	 * parent's xpmem mappings by accident. We check here whether the owner
	 * pointer we have is the same as the current->files pointer. If it is,
	 * or if current->files is NULL, then this flush really does belong to
	 * the current process. If they don't match, then we return without
	 * doing anything since the child shouldn't have a valid
	 * xpmem_thread_group struct yet.
	 */
	if (current->files && current->files != owner)
		return 0;

	/*
	 * Two threads could have called xpmem_flush at about the same time,
	 * and thus xpmem_tg_ref_by_tgid_all could return the same tg in
	 * both threads.  Guard against this race.
	 */
	index = xpmem_tg_hashtable_index(current->tgid);
	write_lock(&xpmem_my_part->tg_hashtable[index].lock);

	/* Remove tg structure from its hash list */
	tg = xpmem_tg_ref_by_tgid_all_nolock(current->tgid);
	if (IS_ERR(tg)) {
		write_unlock(&xpmem_my_part->tg_hashtable[index].lock);
		/*
		 * xpmem_flush() can get called twice for thread groups
		 * which inherited /dev/xpmem: once for the inherited fd,
		 * once for the first explicit use of /dev/xpmem. If we
		 * don't find the tg via xpmem_tg_ref_by_tgid() we assume we
		 * are in this type of scenario and return silently.
		 */
		return 0;
	}

	list_del_init(&tg->tg_hashlist);

	write_unlock(&xpmem_my_part->tg_hashtable[index].lock);

	XPMEM_DEBUG("tg->mm=%p", tg->mm);

	/*
	 * NTH: the thread group may not be released until later so remove the
	 * proc entry now to avoid a race between another call to xpmem_open()
	 * and the distruction of the thread group object.
	 */
	snprintf(tgid_string, XPMEM_TGID_STRING_LEN, "%d", tg->tgid);
	spin_lock(&xpmem_unpin_procfs_lock);
	remove_proc_entry(tgid_string, xpmem_unpin_procfs_dir);
	spin_unlock(&xpmem_unpin_procfs_lock);

	xpmem_destroy_tg(tg);

	return 0;
}

/*
 * User ioctl to the XPMEM driver. Only 64-bit user applications are
 * supported.
 */
static long
xpmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;

	switch (cmd) {
	case XPMEM_CMD_VERSION: {
		return XPMEM_CURRENT_VERSION;
	}
	case XPMEM_CMD_MAKE: {
		struct xpmem_cmd_make make_info;
		xpmem_segid_t segid;

		if (copy_from_user(&make_info, (void __user *)arg,
				   sizeof(struct xpmem_cmd_make)))
			return -EFAULT;

		ret = xpmem_make(make_info.vaddr, make_info.size,
				 make_info.permit_type,
				 (void *)make_info.permit_value, &segid);
		if (ret != 0)
			return ret;

		if (put_user(segid,
			     &((struct xpmem_cmd_make __user *)arg)->segid)) {
			(void)xpmem_remove(segid);
			return -EFAULT;
		}
		return 0;
	}
	case XPMEM_CMD_REMOVE: {
		struct xpmem_cmd_remove remove_info;

		if (copy_from_user(&remove_info, (void __user *)arg,
				   sizeof(struct xpmem_cmd_remove)))
			return -EFAULT;

		return xpmem_remove(remove_info.segid);
	}
	case XPMEM_CMD_GET: {
		struct xpmem_cmd_get get_info;
		xpmem_apid_t apid;

		if (copy_from_user(&get_info, (void __user *)arg,
				   sizeof(struct xpmem_cmd_get)))
			return -EFAULT;

		ret = xpmem_get(get_info.segid, get_info.flags,
				get_info.permit_type,
				(void *)get_info.permit_value, &apid);
		if (ret != 0)
			return ret;

		if (put_user(apid,
			     &((struct xpmem_cmd_get __user *)arg)->apid)) {
			(void)xpmem_release(apid);
			return -EFAULT;
		}
		return 0;
	}
	case XPMEM_CMD_RELEASE: {
		struct xpmem_cmd_release release_info;

		if (copy_from_user(&release_info, (void __user *)arg,
				   sizeof(struct xpmem_cmd_release)))
			return -EFAULT;

		return xpmem_release(release_info.apid);
	}
	case XPMEM_CMD_ATTACH: {
		struct xpmem_cmd_attach attach_info;
		u64 at_vaddr;

		if (copy_from_user(&attach_info, (void __user *)arg,
				   sizeof(struct xpmem_cmd_attach)))
			return -EFAULT;

		ret = xpmem_attach(file, attach_info.apid, attach_info.offset,
				   attach_info.size, attach_info.vaddr,
				   attach_info.fd, attach_info.flags,
				   &at_vaddr);
		if (ret != 0)
			return ret;

		if (put_user(at_vaddr,
			     &((struct xpmem_cmd_attach __user *)arg)->vaddr)) {
			(void)xpmem_detach(at_vaddr);
			return -EFAULT;
		}
		return 0;
	}
	case XPMEM_CMD_DETACH: {
		struct xpmem_cmd_detach detach_info;

		if (copy_from_user(&detach_info, (void __user *)arg,
				   sizeof(struct xpmem_cmd_detach)))
			return -EFAULT;

		return xpmem_detach(detach_info.vaddr);
	}
	case XPMEM_CMD_FORK_BEGIN: {
		return xpmem_fork_begin();
	}
	case XPMEM_CMD_FORK_END: {
		return xpmem_fork_end();
	}
	default:
		break;
	}
	return -ENOIOCTLCMD;
}

static struct file_operations xpmem_fops = {
	.owner = THIS_MODULE,
	.open = xpmem_open,
	.flush = xpmem_flush,
	.unlocked_ioctl = xpmem_ioctl,
	.mmap = xpmem_mmap
};

static struct miscdevice xpmem_dev_handle = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = XPMEM_MODULE_NAME,
	.fops = &xpmem_fops
};

/*
 * Initialize the XPMEM driver.
 */
int __init
xpmem_init(void)
{
	int i, ret;
	struct proc_dir_entry *global_pages_entry;
	struct proc_dir_entry *debug_printk_entry;

	/* create and initialize struct xpmem_partition array */
	xpmem_my_part = kzalloc(sizeof(struct xpmem_partition) +
				sizeof(struct xpmem_hashlist) *
				XPMEM_TG_HASHTABLE_SIZE, GFP_KERNEL);
	if (xpmem_my_part == NULL)
		return -ENOMEM;

	for (i = 0; i < XPMEM_TG_HASHTABLE_SIZE; i++) {
		rwlock_init(&xpmem_my_part->tg_hashtable[i].lock);
		INIT_LIST_HEAD(&xpmem_my_part->tg_hashtable[i].list);
	}

	/* create the /proc interface directory (/proc/xpmem) */
	spin_lock_init(&xpmem_unpin_procfs_lock);
	xpmem_unpin_procfs_dir = proc_mkdir(XPMEM_MODULE_NAME, NULL);
	if (xpmem_unpin_procfs_dir == NULL) {
		ret = -EBUSY;
		goto out_1;
	}

	/* create the XPMEM character device (/dev/xpmem) */
	ret = misc_register(&xpmem_dev_handle);
	if (ret != 0)
		goto out_2;

	/* create debugging entries in /proc/xpmem */
	atomic_set(&xpmem_my_part->n_pinned, 0);
	atomic_set(&xpmem_my_part->n_unpinned, 0);
	global_pages_entry = proc_create_data("global_pages", 0644,
					      xpmem_unpin_procfs_dir,
					      &xpmem_unpin_procfs_ops,
					      (void *)0UL);
	if (global_pages_entry == NULL) {
		ret = -EBUSY;
		goto out_3;
	}

	/* printk debugging */
	debug_printk_entry = proc_create("debug_printk", 0644,
					 xpmem_unpin_procfs_dir,
					 &xpmem_debug_printk_procfs_ops);
	if (debug_printk_entry == NULL) {
		ret = -EBUSY;
		goto out_4;
	}

	printk("XPMEM kernel module v%s loaded\n",
	       XPMEM_CURRENT_VERSION_STRING);
	return 0;

out_4:
	remove_proc_entry("global_pages", xpmem_unpin_procfs_dir);
out_3:
	misc_deregister(&xpmem_dev_handle);
out_2:
	remove_proc_entry(XPMEM_MODULE_NAME, NULL);
out_1:
	kfree(xpmem_my_part);
	return ret;
}

/*
 * Remove the XPMEM driver from the system.
 */
void __exit
xpmem_exit(void)
{
	kfree(xpmem_my_part);

	misc_deregister(&xpmem_dev_handle);
	remove_proc_entry("global_pages", xpmem_unpin_procfs_dir);
	remove_proc_entry("debug_printk", xpmem_unpin_procfs_dir);
	remove_proc_entry(XPMEM_MODULE_NAME, NULL);

	printk("XPMEM kernel module v%s unloaded\n",
	       XPMEM_CURRENT_VERSION_STRING);
}

#ifdef EXPORT_NO_SYMBOLS
EXPORT_NO_SYMBOLS;
#endif
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Silicon Graphics, Inc.");
MODULE_INFO(supported, "external");
MODULE_DESCRIPTION("XPMEM support");
MODULE_VERSION("2.6.5");
module_init(xpmem_init);
module_exit(xpmem_exit);
