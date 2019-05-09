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
** A module to test LWK memory with Linux kernel function
** get_user_pages(). LWK memory does not use struct page, but get_user_pages()
** returns a list of struct pages. Currently, this test fails under mOS. Later,
** it can serve as a test for the solution.
**
** Rolf Riesen, November 2015, Intel
*/
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/mos.h>

#define DEVICE_NAME "gup_test"
#define CLASS_NAME "mos_test"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rolf Riesen");
MODULE_DESCRIPTION("Test get_user_pages() with LWK memory");

static int major;
static struct class *mostest;
static struct device *mosdev;

static void print_flag(char *flag, int *needs_comma)
{
	if (*needs_comma)
		pr_cont(", ");
	else
		*needs_comma = 1;
	pr_cont("%s", flag);
}

static void print_flags(struct page *pg)
{
	int needs_comma = 0;

	pr_info("  Set flags:        ");
	if (PageLocked(pg))
		print_flag("Locked", &needs_comma);
	if (PageError(pg))
		print_flag("Error", &needs_comma);
	if (PageReferenced(pg))
		print_flag("Referenced", &needs_comma);
	if (PageUptodate(pg))
		print_flag("Uptodate", &needs_comma);
	if (PageDirty(pg))
		print_flag("Dirty", &needs_comma);
	if (PageLRU(pg))
		print_flag("LRU", &needs_comma);
	if (PageActive(pg))
		print_flag("Active", &needs_comma);
	if (PageSlab(pg))
		print_flag("Slab", &needs_comma);
	if (PageOwnerPriv1(pg))
		print_flag("OwnerPriv1", &needs_comma);
	if (test_bit(PG_arch_1, &pg->flags))
		print_flag("Arch1", &needs_comma);
	if (PageReserved(pg))
		print_flag("Reserved", &needs_comma);
	if (PagePrivate(pg))
		print_flag("Private", &needs_comma);
	if (PagePrivate2(pg))
		print_flag("Private2", &needs_comma);
	if (PageWriteback(pg))
		print_flag("Writeback", &needs_comma);
#ifdef CONFIG_PAGEFLAGS_EXTENDED
	if (PageHead(pg))
		print_flag("Head", &needs_comma);
	if (PageTail(pg))
		print_flag("Tail", &needs_comma);
#else
	if (PageCompound(pg))
		print_flag("Compound", &needs_comma);
#endif
	if (PageSwapCache(pg))
		print_flag("SwapCache", &needs_comma);
	if (PageMappedToDisk(pg))
		print_flag("MappedToDisk", &needs_comma);
	if (PageReclaim(pg))
		print_flag("Reclaim", &needs_comma);
	if (PageSwapBacked(pg))
		print_flag("SwapBacked", &needs_comma);
	if (PageUnevictable(pg))
		print_flag("Unevictable", &needs_comma);
#ifdef CONFIG_MMU
	if (PageMlocked(pg))
		print_flag("Mlocked", &needs_comma);
#endif
#ifdef CONFIG_ARCH_USES_PG_UNCACHED
	if (PageUncached(pg))
		print_flag("Uncached", &needs_comma);
#endif
#ifdef CONFIG_MEMORY_FAILURE
	if (PageHWPoison(pg))
		print_flag("HWPoison", &needs_comma);
#endif

}  /* end of print_flags() */



void page_info(struct page *pg, char *title)
{
	pr_info("%s\n", title);
	pr_info("  struct page at    0x%p\n", (void *)pg);
	pr_info("  pfn               0x%16lx\n", page_to_pfn(pg));
	pr_info("  struct page size    %16ld bytes\n", sizeof(struct page));
	pr_info("  flags             0x%16lx\n", pg->flags);
	print_flags(pg);
	pr_info("  mapping/s_mem     0x%p\n", pg->mapping);
	pr_info("  index/freelist    0x%p\n", pg->freelist);
	pr_info("  active            0x%16x\n", pg->active);
	if (is_lwkpg(pg))
		pr_info("  private           0x%16lx <-- LWK mem page!\n",
			pg->private);
	else
		pr_info("  private           0x%16lx\n", pg->private);
#ifdef CONFIG_MEMCG
	pr_info("  mem_cgroup        0x%p\n", pg->mem_cgroup);
#endif
#if defined(WANT_PAGE_VIRTUAL)
	pr_info("  virtual           0x%p\n", pg->virtual);
#endif
#ifdef CONFIG_KMEMCHECK
	pr_info("  shadow            0x%p\n", pg->shadow);
#endif
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	pr_info("  _last_cpupid        %d\n", pg->_last_cpupid);
#endif
}

void vma_info(struct vm_area_struct *vm, char *title)
{
	pr_info("%s\n", title);
	pr_info("  vm_start          0x%16lx\n", vm->vm_start);
	pr_info("  vm_end            0x%16lx\n", vm->vm_end);
	pr_info("  vm_next           0x%p\n", vm->vm_next);
	pr_info("  vm_prev           0x%p\n", vm->vm_prev);
	pr_info("  vm_mm             0x%p\n", vm->vm_mm);
	pr_info("  vm_page_prot      0x%16lx\n", vm->vm_page_prot.pgprot);
	pr_info("  vm_flags          0x%16lx\n", vm->vm_flags);
	pr_info("  vm_file           0x%p\n", vm->vm_file);
	pr_info("  vm_private_data   0x%p\n", vm->vm_private_data);
}

static ssize_t dev_write(struct file *f, const char __user * buf,
			 size_t arg_struct_len, loff_t * off)
{
	int rc, ret;
	int i;
	int num_pages;
	void *src, *dst;
	struct page *src_pg, *dst_pg;
	struct page **src_pages;
	struct page **dst_pages;
	struct vm_area_struct **src_vmas;
	struct vm_area_struct **dst_vmas;

	struct {
		void *src;
		void *dst;
		unsigned long len;
		int verbose;
	} args;

	if (arg_struct_len != sizeof(args)) {
		pr_warn("Argument block size incorrect!\n");
		return -EINVAL;
	}

	rc = copy_from_user(&args, buf, arg_struct_len);
	if (rc) {
		pr_warn("Could not read args of size %lx; left %d\n",
			arg_struct_len, rc);
		return -EBADR;
	}
	*off = *off + arg_struct_len;

	if (args.len < 1) {
		pr_warn("Not doing zero-length copy\n");
		return arg_struct_len;
	}

	/*
	 ** To keep things simple, we request that src and dst are page aligned,
	 ** and len is a multiple of 4k pages.
	 */
	if (((unsigned long)args.src & (PAGE_SIZE - 1)) != 0) {
		pr_warn("Src buffer must be page aligned! args.src = 0x%p\n",
			args.src);
		return -EFAULT;
	}

	if (((unsigned long)args.dst & (PAGE_SIZE - 1)) != 0) {
		pr_warn("Dst buffer must be page aligned! args.dst = 0x%p\n",
			args.dst);
		return -EFAULT;
	}

	/* How many pages? */
	num_pages = args.len >> PAGE_SHIFT;
	if ((args.len - (num_pages * PAGE_SIZE) != 0)) {
		pr_warn("Len must be a multiple of page size! args.len = %ld\n",
			args.len);
		return -EINVAL;
	}

	if (args.verbose)
		pr_info("Copying %ld bytes (%d pages) from 0x%p to 0x%p\n",
			args.len, num_pages, args.src, args.dst);

	/* Allocate memory for our page and vma lists */
	src_pages = kmalloc_array(num_pages, sizeof(struct page *), GFP_KERNEL);
	if (src_pages == NULL) {
		ret = -ENOMEM;
		goto err0;
	}

	dst_pages = kmalloc_array(num_pages, sizeof(struct page *), GFP_KERNEL);
	if (dst_pages == NULL) {
		ret = -ENOMEM;
		goto err1;
	}

	src_vmas = kmalloc_array(num_pages, sizeof(struct vm_area_struct *),
				 GFP_KERNEL);
	if (src_pages == NULL) {
		ret = -ENOMEM;
		goto err2;
	}

	dst_vmas = kmalloc_array(num_pages, sizeof(struct vm_area_struct *),
				 GFP_KERNEL);
	if (dst_pages == NULL) {
		ret = -ENOMEM;
		goto err3;
	}

	/* Get the mmap reader/writer semaphore before we can use gup() */
	down_read(&current->mm->mmap_sem);

	/* Map the src buffer */
	rc = get_user_pages((unsigned long)args.src, num_pages, 0, src_pages,
			    src_vmas);
	if (rc != num_pages) {
		pr_warn("gup() for src returned %d instead of %d pages\n",
			rc, num_pages);
		ret = -EFAULT;
		goto err4;
	}

	/* Map the destination buffer */
	rc = get_user_pages((unsigned long)args.dst, num_pages, 1, dst_pages,
			    dst_vmas);
	if (rc != num_pages) {
		pr_warn("gup() for dst returned %d instead of %d pages\n",
			rc, num_pages);
		ret = -EFAULT;
		goto err4;
	}

	/* Copy each page */
	for (i = 0; i < num_pages; i++) {
		src_pg = src_pages[i];
		dst_pg = dst_pages[i];

		if ((args.verbose > 1) && ((i == 0) || (i == 1))) {
			page_info(src_pg, "Source page");
			page_info(dst_pg, "Destination page");
		}
		if ((args.verbose > 2) && ((i == 0) || (i == 1))) {
			vma_info(src_vmas[i], "Source page");
			vma_info(dst_vmas[i], "Destination page");
		}

		/* Get the kernel virtual addresses for these pages */
		src = kmap(src_pg);
		dst = kmap(dst_pg);

		/* do the copying */
		memcpy(dst, src, PAGE_SIZE);

		/* kunmap the two pages */
		kunmap(src_pg);
		kunmap(dst_pg);

		if (!PageReserved(dst_pg))
			SetPageDirty(dst_pg);

		put_page(src_pg);
		put_page(dst_pg);
	}

	ret = arg_struct_len;
err4:
	up_read(&current->mm->mmap_sem);
	kfree(dst_vmas);
err3:
	kfree(src_vmas);
err2:
	kfree(dst_pages);
err1:
	kfree(src_pages);
err0:

	return ret;
}

static const struct file_operations fops = {
	.write = dev_write,
};

static int __init gup_test_init(void)
{
	int ret;

	major = register_chrdev(0, DEVICE_NAME, &fops);
	if (major < 0) {
		ret = major;
		pr_info("register_chrdev failed: %d\n", ret);
		goto fail_chrdev;
	}

	mostest = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(mostest)) {
		ret = PTR_ERR(mostest);
		pr_info("class_create failed: %d\n", ret);
		goto fail_class;
	}

	mosdev = device_create(mostest, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(mosdev)) {
		ret = PTR_ERR(mosdev);
		pr_info("device_create failed: %d\n", ret);
		goto fail_dev;
	}

	return 0;

fail_dev:
	class_destroy(mostest);
fail_class:
	unregister_chrdev(major, DEVICE_NAME);
fail_chrdev:
	return ret;
}

static void __exit gup_test_cleanup(void)
{
	device_destroy(mostest, MKDEV(major, 0));
	class_unregister(mostest);
	class_destroy(mostest);
	unregister_chrdev(major, DEVICE_NAME);
}

module_init(gup_test_init);
module_exit(gup_test_cleanup);
