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
** A module to test lwkmem memory with Linux kernel functions
** copy_to/from_user().
**
** Rolf Riesen, October 2015, Intel
*/
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "lwkmem_copy_test"
#define CLASS_NAME "mos_test"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rolf Riesen");
MODULE_DESCRIPTION("Test copy_to/from_user with lwkmem");

static int major;
static struct class *mostest;
static struct device *mosdev;

/*
** Copy data from one user-space location to another. We do this up to 2M at a
** time, and return how much we actually copied.
*/
static int do_copy(const void __user * src, void __user * dst,
		   unsigned long len)
{
#define ORDER		(9)
#define MAX_COPY	((1 << ORDER) * PAGE_SIZE)	/* 2^9 pages = 2M */
	void *buf = NULL;
	unsigned long cpy_len;

	cpy_len = min(MAX_COPY, len);
	buf = vmalloc(MAX_COPY);
	if (!buf)
		return -ENOMEM;

	cpy_len = cpy_len - copy_from_user(buf, src, cpy_len);
	cpy_len = cpy_len - copy_to_user(dst, buf, cpy_len);

	vfree(buf);
	return cpy_len;
}

static ssize_t dev_write(struct file *f, const char __user * buf,
			 size_t arg_struct_len, loff_t * off)
{
	int rc;
	struct {
		void *src;
		void *dst;
		unsigned long len;
		int verbose;
	} args = { NULL, NULL, 0, 0 };

	if (arg_struct_len != sizeof(args)) {
		pr_info("Argument block size incorrect!\n");
		return -EINVAL;
	}

	rc = copy_from_user(&args, buf, arg_struct_len);
	if (rc) {
		pr_info("Could not read args of size %lx; left %d\n",
			arg_struct_len, rc);
		return -EBADR;
	}
	*off = *off + arg_struct_len;

	if (args.len < 1) {
		pr_info("Not doing zero-length copy\n");
		return arg_struct_len;
	}

	if (args.verbose)
		pr_info("Copying %ld bytes from 0x%p to 0x%p\n",
			args.len, args.src, args.dst);

	while (args.len > 0) {
		rc = do_copy(args.src, args.dst, args.len);
		if (rc <= 0) {
			pr_info("Copy failed. Error %d\n", rc);
			return rc;
		}
		args.src = args.src + rc;
		args.dst = args.dst + rc;
		args.len = args.len - rc;
	}

	return arg_struct_len;
}

static const struct file_operations fops = {
	.write = dev_write,
};

static int __init lwkmem_test_init(void)
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

static void __exit lwkmem_test_cleanup(void)
{
	device_destroy(mostest, MKDEV(major, 0));
	class_unregister(mostest);
	class_destroy(mostest);
	unregister_chrdev(major, DEVICE_NAME);
}

module_init(lwkmem_test_init);
module_exit(lwkmem_test_cleanup);
