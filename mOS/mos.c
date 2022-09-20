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

#include <linux/init.h>
#include <linux/printk.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>
#include <linux/mos.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/current.h>
#include <asm/setup.h>
#include <linux/msi.h>

#include "lwkcpu.h"
#include "lwkctrl.h"
#include "mosras.h"
#include "gpumask.h"

#ifdef CONFIG_MOS_FOR_HPC

#undef pr_fmt
#define pr_fmt(fmt)	"mOS: " fmt

#define MOS_VERSION	"1.0"

static cpumask_var_t lwkcpus_map;
static cpumask_var_t utility_cpus_map;
static cpumask_var_t lwkcpus_reserved_map;
static gpumask_t lwkgpus_map;
static gpumask_t lwkgpus_reserved_map;
static int16_t lwkgpu_usage_counter[MOS_NR_GPUS];
static int16_t lwkgpus_numa[MOS_NR_GPUS];
static char *lwkauto;
static DEFINE_MUTEX(mos_sysfs_mutex);
static LIST_HEAD(mos_process_option_callbacks);
static LIST_HEAD(mos_process_callbacks);

/*
 * Driver prefixes to be used when searching for allowed lwk interrupt vectors.
 * Last entry in the list must be a null string.
*/
static char *allowed_drivers[MOS_MAX_ALLOWED_DRIVERS + 1];

/* Memory designation precision. Default set to false for boot */
static bool lwkmem_precise;

/* NOTE: The following items are not static.  They are referenced
 *       by other LWK components in mOS.
 */

DEFINE_PER_CPU(cpumask_t, lwkcpus_mask);

struct mos_process_callbacks_elem_t {
	struct list_head list;
	struct mos_process_callbacks_t *callbacks;
};

int mos_register_process_callbacks(struct mos_process_callbacks_t *cbs)
{
	struct mos_process_callbacks_elem_t *elem;

	if (!cbs)
		return -EINVAL;

	elem = vmalloc(sizeof(struct mos_process_callbacks_elem_t));

	if (!elem)
		return -ENOMEM;

	elem->callbacks = cbs;
	list_add(&elem->list, &mos_process_callbacks);

	return 0;
}

int mos_unregister_process_callbacks(struct mos_process_callbacks_t *cbs)
{
	struct mos_process_callbacks_elem_t *elem;

	if (!cbs)
		return -EINVAL;

	list_for_each_entry(elem, &mos_process_callbacks, list) {
		if (elem->callbacks == cbs) {
			list_del(&elem->list);
			vfree(elem);
			return 0;
		}
	}

	return -EINVAL;
}

struct mos_process_option_callback_elem_t {
	struct list_head list;
	char name[64];
	int (*callback)(const char *, struct mos_process_t *);
};

int mos_register_option_callback(const char *name,
	 int (*cb)(const char *, struct mos_process_t *))
{
	struct mos_process_option_callback_elem_t *elem;

	if (!cb)
		return -EINVAL;

	if (strlen(name) >= sizeof(elem->name))
		return -EINVAL;

	elem = vmalloc(sizeof(struct mos_process_option_callback_elem_t));

	if (!elem)
		return -ENOMEM;

	strcpy(elem->name, name);
	elem->callback = cb;
	list_add(&elem->list, &mos_process_option_callbacks);

	return 0;
}

int mos_unregister_option_callback(const char *name,
		   int (*cb)(const char *, struct mos_process_t *))
{
	struct mos_process_option_callback_elem_t *elem;

	if (!cb)
		return -EINVAL;

	list_for_each_entry(elem, &mos_process_option_callbacks, list) {
		if (elem->callback == cb && strcmp(name, elem->name) == 0) {
			list_del(&elem->list);
			vfree(elem);
			return 0;
		}
	}

	return -EINVAL;
}

void get_mos_view_cpumask(struct cpumask *dst, const struct cpumask *src)
{
	if (IS_MOS_VIEW(current, MOS_VIEW_LWK_LOCAL))
		cpumask_and(dst, src, current->mos_process->lwkcpus);
	else {
		if (IS_MOS_VIEW(current, MOS_VIEW_LINUX))
			cpumask_andnot(dst, src, cpu_lwkcpus_mask);
		else if (IS_MOS_VIEW(current, MOS_VIEW_LWK))
			cpumask_and(dst, src, cpu_lwkcpus_mask);
		else
			cpumask_copy(dst, src);
	}
}

ssize_t cpumap_print_mos_view_cpumask(char *buf, const struct cpumask *mask, loff_t off, size_t count)
{
	ssize_t ret;
	cpumask_var_t mos_view_cpumask;

	if (!alloc_cpumask_var(&mos_view_cpumask, GFP_KERNEL))
		return -ENOMEM;

	get_mos_view_cpumask(mos_view_cpumask, mask);

	ret = cpumap_print_bitmask_to_buf(buf, mos_view_cpumask, off, count);
	free_cpumask_var(mos_view_cpumask);
	return ret;
}

ssize_t cpumap_print_mos_list_to_buf(char *buf, const struct cpumask *mask, loff_t off, size_t count)
{
	ssize_t ret;
	cpumask_var_t mos_view_cpumask;

	if (!alloc_cpumask_var(&mos_view_cpumask, GFP_KERNEL))
		return -ENOMEM;

	get_mos_view_cpumask(mos_view_cpumask, mask);

	ret = cpumap_print_list_to_buf(buf, mos_view_cpumask, off, count);
	free_cpumask_var(mos_view_cpumask);
	return ret;
}
bool mos_is_allowed_interrupt(struct irq_desc *desc)
{
	int i;
	int rc = false;

	if (desc->irq_common_data.msi_desc &&
	    desc->irq_common_data.msi_desc->dev &&
	    desc->irq_common_data.msi_desc->dev->driver) {
		const char *dname = desc->irq_common_data.msi_desc->dev->driver->name;

		for (i = 0; allowed_drivers[i]; i++) {
			if (!strncmp(allowed_drivers[i], dname, strlen(allowed_drivers[i]))) {
				rc = true;
				break;
			}
		}
	}
	return rc;
}

#ifdef MOS_DEBUG_PROCESS
static void _mos_debug_process(struct mos_process_t *p, const char *func,
			       const int line)
{
	if (!p) {
		pr_info("[%s:%d] NULL process", func, line);
		return;
	}
	scnprintf(cpulist_buf, sizeof(cpulist_buf), "%*pbl", cpumask_pr_args(p->lwkcpus));
	pr_info("[%s:%d] tgid=%d lwkcpu=%s alive=%d\n", func,
		line, p->tgid, cpulist_buf, atomic_read(&p->alive));
	scnprintf(cpulist_buf, sizeof(cpulist_buf), "%*pbl", cpumask_pr_args(p->utilcpus));
	pr_info("[%s:%d] tgid=%d utilcpu=%s p@=%p\n", func, line, p->tgid,
		cpulist_buf, p);
}
#else
#define _mos_debug_process(a, b, c)
#endif

/**
 * Find the MOS process associated with the current thread.
 * Create the entry if one does not already exist.
 */
static struct mos_process_t *mos_get_process(void)
{
	struct mos_process_t *process = current->mos_process;

	if (!process) {
		struct mos_process_callbacks_elem_t *elem;

		process = vmalloc(sizeof(struct mos_process_t));
		if (!process)
			return 0;
		process->tgid = current->tgid;

		if (!zalloc_cpumask_var(&process->lwkcpus, GFP_KERNEL) ||
		    !zalloc_cpumask_var(&process->utilcpus, GFP_KERNEL)) {
			mos_ras(MOS_LWK_PROCESS_ERROR_UNSTABLE_NODE,
				"CPU mask allocation failure.");
			return 0;
		}
		gpumask_clear(&process->lwkgpus);

		process->lwkcpus_sequence = 0;
		process->num_lwkcpus = 0;
		process->num_util_threads = 0;

		/* Mark current process as mOS LWK process. */
		current->mos_flags |= MOS_IS_LWK_PROCESS;

		atomic_set(&process->alive, 1); /* count the current thread */

		list_for_each_entry(elem, &mos_process_callbacks, list) {
			if (elem->callbacks->mos_process_init &&
			    elem->callbacks->mos_process_init(process)) {
				mos_ras(MOS_LWK_PROCESS_ERROR,
					"Non-zero return code from LWK process initialization callback %pf.",
					elem->callbacks->mos_process_init);
				process = 0;
				break;
			}
		}

	}

	return process;
}

void mos_exit_thread(void)
{
	struct mos_process_t *process;
	struct mos_process_callbacks_elem_t *elem;
	int gpu;

	mutex_lock(&mos_sysfs_mutex);

	process = current->mos_process;

	if (!process) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Unexpected NULL LWK process object pointer encountered in %s().",
			__func__);
		goto unlock;
	}

	_mos_debug_process(process, __func__, __LINE__);

	list_for_each_entry(elem, &mos_process_callbacks, list) {
		if (elem->callbacks->mos_thread_exit)
			elem->callbacks->mos_thread_exit(process);
	}

	/* Wait for the last thread to shut down before cleaning up. */
	if (!atomic_dec_and_test(&process->alive))
		goto unlock;

	_mos_debug_process(process, __func__, __LINE__);

	list_for_each_entry(elem, &mos_process_callbacks, list) {
		if (elem->callbacks->mos_process_exit)
			elem->callbacks->mos_process_exit(process);
	}

	/* Release the resources reserved by this process. */

	cpumask_xor(lwkcpus_reserved_map, lwkcpus_reserved_map,
		    process->lwkcpus);

	/* decrement the usage counter for each GPU and if zero, reset the
	 * corresponding bit map flag.
	 */
	for_each_gpu(gpu, &process->lwkgpus) {
		if (lwkgpu_usage_counter[gpu] <= 0) {
			mos_ras(MOS_KERNEL_WARNING,
				"Unexpected GPU usage count=%d in %s().",
				lwkgpu_usage_counter[gpu], __func__);
		} else if (--lwkgpu_usage_counter[gpu] != 0)
			gpumask_clear_gpu(gpu, &process->lwkgpus);
	}
	/* Clear reserved bits for ref counts that reached zero */
	gpumask_xor(&lwkgpus_reserved_map, &lwkgpus_reserved_map,
		    &process->lwkgpus);

	/* Free process resources. */
	free_cpumask_var(process->lwkcpus);
	free_cpumask_var(process->utilcpus);
	vfree(process->lwkcpus_sequence);
	vfree(process);

unlock:
	mutex_unlock(&mos_sysfs_mutex);
}

/**
 * An operations structure for modifying various cpumask based
 * mOS sysfs files.  This allows us to compose various types of
 * operations and file types.
 */
struct mos_sysfs_cpumask_write_op {
	int (*parser)(const char *, cpumask_var_t);
	int (*operation)(cpumask_var_t);
} mos_sysfs_cpumask_write_op;

/**
 * A parameterized write operations for mOS sysfs files.  The buf/count
 * arguments are parsed via the op->parser field.  Then the op->operation
 * is applied under the safety of the mos_sysfs_mutex.
 */

static ssize_t mos_sysfs_cpumask_write(const char *buf, size_t count,
				    struct mos_sysfs_cpumask_write_op *op)
{
	cpumask_var_t reqmask;
	int rc;

	if (!zalloc_cpumask_var(&reqmask, GFP_KERNEL))
		return -ENOMEM;

	if (op->parser(buf, reqmask)) {
		pr_info("Could not parse %s\n", buf);
		count = -EINVAL;
		goto out;
	}

	mutex_lock(&mos_sysfs_mutex);

	rc = op->operation(reqmask);

	if (rc < 0)
		count = rc;

	mutex_unlock(&mos_sysfs_mutex);

out:
	free_cpumask_var(reqmask);
	return count;

}

/**
 * _xxx_cpus_reserved = request
 * Return -EINVAL if request is not a subset of the lwkcpus.  Otherwise
 * copy the request into the target and return 0.
 */

static int _cpus_reserved_set(cpumask_var_t request, cpumask_var_t target)
{
	int rc = 0;

	if (!cpumask_empty(request) && !cpumask_subset(request, lwkcpus_map)) {
		pr_info("Non-LWK CPU was requested.\n");
		rc = -EINVAL;
		goto out;
	}

	cpumask_copy(target, request);

out:
	return rc;
}

static int _lwkcpus_reserved_set(cpumask_var_t request)
{
	return _cpus_reserved_set(request, lwkcpus_reserved_map);
}

/**
 * xxx_reserved |= request
 * Return -EINVAL if request is not a subset of the designated
 * LWK CPUs (lwkcpus_maps).  Return -EBUSY if the requested set
 * overlaps with the reserved compute CPUs.
 * Otherwise, update the target with the requested set.
 */

static int _cpus_request_set(cpumask_var_t request, cpumask_var_t target)
{
	int rc = 0;

	if (!cpumask_subset(request, lwkcpus_map)) {
		pr_info("Non-LWK CPU was requested.\n");
		rc = -EINVAL;
		goto out;
	}

	if (cpumask_intersects(request, lwkcpus_reserved_map)) {
		rc = -EBUSY;
		goto out;
	}

	cpumask_or(target, target, request);
out:
	return rc;
}

static int _lwkcpus_request_set(cpumask_var_t request)
{
	int rc;

	rc = _cpus_request_set(request, lwkcpus_reserved_map);

	if (!rc) {
		int *cpu_list, num_lwkcpus, cpu;

		current->mos_process = mos_get_process();

		if (!current->mos_process) {
			rc = -ENOMEM;
			goto out;
		}
		cpumask_or(current->mos_process->lwkcpus, request, request);

		/* Allocate the CPU sequence array */
		num_lwkcpus = cpumask_weight(current->mos_process->lwkcpus);
		cpu_list = vmalloc(sizeof(int)*(num_lwkcpus+1));
		if (!cpu_list) {
			rc = -ENOMEM;
			goto out;
		}
		current->mos_process->num_lwkcpus = num_lwkcpus;
		current->mos_process->lwkcpus_sequence = cpu_list;

		/* We use the mm pointer as a marker. It will change when yod
		** execv() into the application process. We can use this marker
		** to tell whether yod or the LWK process is calling
		** lwk_sys_brk() for example.
		*/
		current->mos_process->yod_mm = current->mm;

		/* Initialize the sequencing array based on the lwkcpus mask */
		for_each_cpu(cpu, current->mos_process->lwkcpus)
			*cpu_list++ = cpu;

		/* Set sentinel value */
		*cpu_list = -1;

		/* Create a mask within the process of all utility CPUs */
		cpumask_or(current->mos_process->utilcpus,
			   current->mos_process->utilcpus,
			   utility_cpus_map);

		_mos_debug_process(current->mos_process, __func__, __LINE__);
out:
		if (rc) {
			/* In case of error clear the CPUs that we marked reserved */
			cpumask_andnot(lwkcpus_reserved_map,
					lwkcpus_reserved_map, request);
		}
	}

	return rc;
}

static ssize_t show_cpu_list(cpumask_var_t cpus, char *buff)
{
	ssize_t n;

	n = scnprintf(buff, PAGE_SIZE, "%*pbl", cpumask_pr_args(cpus));
	if (n >= 0) {
		buff[n++] = '\n';
		buff[n] = 0;
	}
	return n;
}

static ssize_t show_cpu_mask(cpumask_var_t cpus, char *buff)
{
	ssize_t n;

	n = scnprintf(buff, PAGE_SIZE, "%*pb", cpumask_pr_args(cpus));
	if (n >= 0) {
		buff[n++] = '\n';
		buff[n] = 0;
	}
	return n;
}

struct mos_sysfs_gpumask_write_op {
	int (*parser)(const char *, gpumask_t *);
	int (*operation)(gpumask_t *);
} mos_sysfs_gpumask_write_op;


static ssize_t mos_sysfs_gpumask_write(const char *buf, size_t count,
				    struct mos_sysfs_gpumask_write_op *op)
{
	gpumask_t reqmask;
	int rc;

	if (op->parser(buf, &reqmask)) {
		pr_info("Could not parse %s\n", buf);
		count = -EINVAL;
		goto out;
	}

	mutex_lock(&mos_sysfs_mutex);

	rc = op->operation(&reqmask);

	if (rc < 0)
		count = rc;

	mutex_unlock(&mos_sysfs_mutex);

out:
	return count;

}

/**
 * _xxx_gpus_reserved = request Return -EINVAL if request is not
 * a subset of the lwkgpus.  Otherwise copy the request into the
 * target and return 0.
 */

static int _gpus_reserved_set(gpumask_t *request, gpumask_t *target)
{
	int rc = 0;

	if (!gpumask_empty(request) && !gpumask_subset(request, &lwkgpus_map)) {
		pr_info("Non-LWK GPU was requested.\n");
		rc = -EINVAL;
		goto out;
	}

	gpumask_copy(target, request);

out:
	return rc;
}

static int _lwkgpus_reserved_set(gpumask_t *request)
{
	return _gpus_reserved_set(request, &lwkgpus_reserved_map);
}

/**
 * xxx_reserved |= request
 * Return -EINVAL if request is not a subset of the designated
 * LWK GPUs (lwkgpus_maps).  Return -EBUSY if the requested set
 * overlaps with the reserved compute GPUs. Otherwise, update
 * the target with the requested set.
 */

static int _gpus_request_set(gpumask_t *request, gpumask_t *target)
{
	int rc = 0;
	int gpu;

	if (!gpumask_subset(request, &lwkgpus_map)) {
		pr_info("Non-LWK GPU was requested.\n");
		rc = -EINVAL;
		goto out;
	}

	/* We allow reserving on top of previously reserved GPUs.
	 * Update the counters for each GPU device being reserved
	 */
	for_each_gpu(gpu, request)
		lwkgpu_usage_counter[gpu]++;

	gpumask_or(target, target, request);
out:
	return rc;
}

static int _lwkgpus_request_set(gpumask_t *request)
{
	int rc;
	struct mos_process_t *process;

	rc = _gpus_request_set(request, &lwkgpus_reserved_map);

	if (!rc) {
		process = mos_get_process();

		if (!process) {
			rc = -ENOMEM;
			goto out;
		}
		gpumask_or(&process->lwkgpus, request, request);
	}

 out:
	if (rc) {
		/* In case of error clear the GPUs that we marked reserved */
		gpumask_andnot(&lwkgpus_reserved_map,
			       &lwkgpus_reserved_map, request);
	}
	return rc;
}

static int _lwkgpus_set(gpumask_t *request)
{
	gpumask_copy(&lwkgpus_map, request);

	return 0;
}

static ssize_t show_gpu_list(gpumask_t *gpus, char *buff)
{
	ssize_t n;

	n = scnprintf(buff, PAGE_SIZE, "%*pbl", gpumask_pr_args(gpus));
	if (n >= 0) {
		buff[n++] = '\n';
		buff[n] = 0;
	}
	return n;
}

static ssize_t show_gpu_mask(gpumask_t *gpus, char *buff)
{
	ssize_t n;

	n = scnprintf(buff, PAGE_SIZE, "%*pb", gpumask_pr_args(gpus));
	if (n >= 0) {
		buff[n++] = '\n';
		buff[n] = 0;
	}
	return n;
}

static ssize_t version_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	return scnprintf(buff, PAGE_SIZE, "%s\n", MOS_VERSION);
}

#define MOS_SYSFS_CPU_SHOW_LIST(name)				\
	static ssize_t name##_show(struct kobject *kobj,	\
				   struct kobj_attribute *attr,	\
				   char *buff)			\
	{							\
		return show_cpu_list(name##_map, buff);		\
	}

#define MOS_SYSFS_CPU_SHOW_MASK(name)					\
	static ssize_t name##_mask_show(struct kobject *kobj,		\
					struct kobj_attribute *attr,	\
					char *buff)			\
	{								\
		return show_cpu_mask(name##_map, buff);			\
	}

#define MOS_SYSFS_CPU_STORE_LIST(name)					\
	static struct mos_sysfs_cpumask_write_op name##_op = {		\
		.parser = cpulist_parse,				\
		.operation = _##name##_set,				\
	};								\
									\
	static ssize_t name##_store(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    const char *buf, size_t count)	\
	{								\
		return mos_sysfs_cpumask_write(buf, count, &name##_op);\
	}								\

#define MOS_SYSFS_CPU_STORE_MASK(name) \
	static struct mos_sysfs_cpumask_write_op name##_mask_op = {	\
		.parser = cpumask_parse,				\
		.operation = _##name##_set,				\
	};								\
									\
	static ssize_t name##_mask_store(struct kobject *kobj,		\
					 struct kobj_attribute *attr,	\
					 const char *buf, size_t count)	\
	{								\
		return mos_sysfs_cpumask_write(buf, count, &name##_mask_op); \
	}								\

#define MOS_SYSFS_GPU_SHOW_LIST(name)					\
	static ssize_t name##_show(struct kobject *kobj,		\
				   struct kobj_attribute *attr,		\
				   char *buff)				\
	{								\
		return show_gpu_list(&name##_map, buff);			\
	}

#define MOS_SYSFS_GPU_SHOW_MASK(name)					\
	static ssize_t name##_mask_show(struct kobject *kobj,		\
					struct kobj_attribute *attr,	\
					char *buff)			\
	{								\
		return show_gpu_mask(&name##_map, buff);			\
	}

#define MOS_SYSFS_GPU_STORE_LIST(name)					\
	static struct mos_sysfs_gpumask_write_op name##_op = {		\
		.parser = gpulist_parse,				\
		.operation = _##name##_set,				\
	};								\
									\
	static ssize_t name##_store(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    const char *buf, size_t count)	\
	{								\
		return mos_sysfs_gpumask_write(buf, count, &name##_op);\
	}								\

#define MOS_SYSFS_GPU_STORE_MASK(name) \
	static struct mos_sysfs_gpumask_write_op name##_mask_op = {	\
		.parser = gpumask_parse,				\
		.operation = _##name##_set,				\
	};								\
									\
	static ssize_t name##_mask_store(struct kobject *kobj,		\
					 struct kobj_attribute *attr,	\
					 const char *buf, size_t count)	\
	{								\
		return mos_sysfs_gpumask_write(buf, count, &name##_mask_op); \
	}								\

#define MOS_SYSFS_CPU_RO(name)				\
	MOS_SYSFS_CPU_SHOW_LIST(name)			\
	MOS_SYSFS_CPU_SHOW_MASK(name)			\
	static struct kobj_attribute name##_attr =	\
		__ATTR_RO(name);			\
	static struct kobj_attribute name##_mask_attr = \
		__ATTR_RO(name##_mask)			\

#define MOS_SYSFS_CPU_RW(name)				\
	MOS_SYSFS_CPU_SHOW_LIST(name)			\
	MOS_SYSFS_CPU_SHOW_MASK(name)			\
	MOS_SYSFS_CPU_STORE_LIST(name)			\
	MOS_SYSFS_CPU_STORE_MASK(name)			\
	static struct kobj_attribute name##_attr =	\
		__ATTR_RW(name);			\
	static struct kobj_attribute name##_mask_attr =	\
		__ATTR_RW(name##_mask)			\

#define MOS_SYSFS_CPU_WO(name)				\
	MOS_SYSFS_CPU_STORE_LIST(name)			\
	MOS_SYSFS_CPU_STORE_MASK(name)			\
	static struct kobj_attribute name##_attr =	\
		__ATTR_WO(name);			\
	static struct kobj_attribute name##_mask_attr =	\
		__ATTR_WO(name##_mask)			\

#define MOS_SYSFS_GPU_RO(name)				\
	MOS_SYSFS_GPU_SHOW_LIST(name)			\
	MOS_SYSFS_GPU_SHOW_MASK(name)			\
	static struct kobj_attribute name##_attr =	\
		__ATTR_RO(name);			\
	static struct kobj_attribute name##_mask_attr = \
		__ATTR_RO(name##_mask)			\

#define MOS_SYSFS_GPU_RW(name)				\
	MOS_SYSFS_GPU_SHOW_LIST(name)			\
	MOS_SYSFS_GPU_SHOW_MASK(name)			\
	MOS_SYSFS_GPU_STORE_LIST(name)			\
	MOS_SYSFS_GPU_STORE_MASK(name)			\
	static struct kobj_attribute name##_attr =	\
		__ATTR_RW(name);			\
	static struct kobj_attribute name##_mask_attr =	\
		__ATTR_RW(name##_mask)			\

#define MOS_SYSFS_GPU_WO(name)				\
	MOS_SYSFS_GPU_STORE_LIST(name)			\
	MOS_SYSFS_GPU_STORE_MASK(name)			\
	static struct kobj_attribute name##_attr =	\
		__ATTR_WO(name);			\
	static struct kobj_attribute name##_mask_attr =	\
		__ATTR_WO(name##_mask)			\

MOS_SYSFS_CPU_RO(lwkcpus);
MOS_SYSFS_CPU_RW(lwkcpus_reserved);
MOS_SYSFS_CPU_WO(lwkcpus_request);
MOS_SYSFS_CPU_RO(utility_cpus);

MOS_SYSFS_GPU_RW(lwkgpus);
MOS_SYSFS_GPU_RW(lwkgpus_reserved);
MOS_SYSFS_GPU_WO(lwkgpus_request);

static ssize_t _lwkmem_vec_show(char *buff, int (*getter)(unsigned long *, size_t *), unsigned long deflt)
{
	numa_nodes_t lwkm;
	size_t  i, n;
	ssize_t len;
	int rc;

	if (!zalloc_numa_nodes_array(&lwkm))
		return -ENOMEM;

	if (getter) {
		n = MAX_NUMNODES;
		rc = getter(lwkm, &n);
		if (rc) {
			free_numa_nodes_array(lwkm);
			return -EINVAL;
		}
	} else {
		lwkm[0] = deflt ? deflt : 0;
		n = 1;
	}

	len = 0;
	buff[0] = 0;

	for (i = 0; i < n; i++)
		len += scnprintf(buff + len, PAGE_SIZE - len, "%lu ", lwkm[i]);

	buff[len++] = '\n';
	free_numa_nodes_array(lwkm);
	return len;
}

static int _lwkmem_vec_parse(char *buff, unsigned long *lwkm, size_t *n, unsigned long *total)
{
	char *val, *bptr;
	size_t capacity = *n;
	int rc;

	bptr = buff;
	*total = 0;
	*n = 0;

	while ((val = strsep(&bptr, " "))) {

		if (*n == capacity) {
			mos_ras(MOS_LWK_PROCESS_ERROR,
				"Potential overflow in lwkmem_request buffer (capacity=%ld).",
				capacity);
			return -EINVAL;
		}

		rc = kstrtoul(val, 0, lwkm + *n);

		if (rc) {
			mos_ras(MOS_LWK_PROCESS_ERROR,
				"Attempted to write invalid value (%s) to lwkmem_request.",
				val);
			return -EINVAL;
		}

		*total += lwkm[*n];
		(*n)++;
	}

	return *n > 0 ? 0 : -EINVAL;
}

static ssize_t lwkmem_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buff)
{
	return _lwkmem_vec_show(buff, lwkmem_get, 0);
}

static ssize_t lwkmem_reserved_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buff)
{
	return _lwkmem_vec_show(buff, lwkmem_reserved_get, 0);
}

static ssize_t lwkmem_request_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	int rc;
	unsigned long total;
	numa_nodes_t lwkm;
	size_t n;
	char *str;
	struct mos_process_t *process;

	str = kstrdup(buff, GFP_KERNEL);

	if (!zalloc_numa_nodes_array(&lwkm) || !str) {
		rc = -ENOMEM;
		goto out;
	}

	n = MAX_NUMNODES;
	rc = _lwkmem_vec_parse(str, lwkm, &n, &total);

	if (rc)
		goto out;

	mutex_lock(&mos_sysfs_mutex);

	rc = count;
	process = mos_get_process();

	if (!process) {
		rc = -ENOMEM;
		goto unlock;
	}

	if (lwkmem_request) {
		if (lwkmem_request(process, lwkm, n)) {
			rc = -EBUSY;
			goto unlock;
		}
	}

	_mos_debug_process(process, __func__, __LINE__);

 unlock:
	mutex_unlock(&mos_sysfs_mutex);

 out:
	free_numa_nodes_array(lwkm);
	kfree(str);
	return rc;
}

static ssize_t lwk_util_threads_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buff, size_t count)
{
	struct mos_process_t *proc = current->mos_process;
	int num_util_threads;

	if (!proc) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Attempted to set the number of utility threads from non-LWK process.");
		return  -EINVAL;
	}
	if (kstrtoint(buff, 0, &num_util_threads) || (num_util_threads < 0)) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Attempted to write an invalid value (%s) to the LWK utility thread count.",
			buff);
		return -EINVAL;
	}

	proc->num_util_threads = num_util_threads;

	return count;
}

static ssize_t lwkprocesses_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buff)
{
	char *current_buff = buff;
	int remaining_buffsize = PAGE_SIZE;
	int bytes_written = 0;
	int total_bytes_written = 0;
	struct task_struct *task;

	mutex_lock(&mos_sysfs_mutex);
	read_lock(&tasklist_lock);

	for_each_process(task) {
		if (task->mos_process) {
			bytes_written = scnprintf(current_buff,
						  remaining_buffsize, "%u,",
						  task->tgid);
			remaining_buffsize -= bytes_written;
			current_buff += bytes_written;
			total_bytes_written += bytes_written;
		}
	}

	read_unlock(&tasklist_lock);
	mutex_unlock(&mos_sysfs_mutex);

	/* Replace trailing comma with newline character. the
	   scnprintf already stored the required NULL string termination */
	if (bytes_written > 0)
		*(--current_buff) = '\n';
	else /* If no processes in the list, terminate the empty string */
		*buff = '\0';

	return total_bytes_written;
}

static ssize_t lwkgpus_usage_count_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buff)
{
	char *current_buff = buff;
	int remaining_buffsize = PAGE_SIZE;
	int bytes_written = 0;
	int total_bytes_written = 0;
	int i, loop_end;

	mutex_lock(&mos_sysfs_mutex);

	loop_end = gpumask_empty(&lwkgpus_map) ?
				0 : gpumask_last(&lwkgpus_map) + 1;

	for(i = 0; i < loop_end; i++) {
		bytes_written = scnprintf(current_buff,
					  remaining_buffsize, "%u,",
					  lwkgpu_usage_counter[i]);
		remaining_buffsize -= bytes_written;
		current_buff += bytes_written;
		total_bytes_written += bytes_written;
	}

	mutex_unlock(&mos_sysfs_mutex);

	/* Replace trailing comma with newline character. the
	   scnprintf already stored the required NULL string termination */
	if (bytes_written > 0)
		*(--current_buff) = '\n';
	else
		*buff = '\0';

	return total_bytes_written;
}

static ssize_t lwkgpus_usage_count_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	unsigned usage_count;
	int16_t *usage_ptr = lwkgpu_usage_counter;
	int usage_counters_in_list = 0;
	int i;
	char *str, *str_orig = 0;
	char *val;
	size_t rc = count;

	mutex_lock(&mos_sysfs_mutex);

	str = kstrndup(buff, count, GFP_KERNEL);
	if (!str) {
		rc = -ENOMEM;
		goto out;
	}
	str_orig = str;
	while ((val = strsep(&str, ","))) {
		int kresult = kstrtouint(val, 0, &usage_count);

		if (kresult) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"Attempted to write invalid value to the LWK GPU usage counter list (rc=%d).",
				kresult);
			rc = -EINVAL;
			goto out;
		}
		/* Store usage count into the integer array */
		if (++usage_counters_in_list > MOS_NR_GPUS) {
			rc = -EINVAL;
			mos_ras(MOS_LWKCTL_FAILURE,
			    "Usage counter list exceeded number of GPU devices supported by the mOS kernel (>%d)",
			    MOS_NR_GPUS);
			goto out;
		}
		*usage_ptr++ = usage_count;
	}
	if (usage_counters_in_list < MOS_NR_GPUS) {
		/* Fill remaining entries with a zero count */
		for (i = usage_counters_in_list; i < MOS_NR_GPUS; i++)
			*usage_ptr++ = 0;
	}
out:
	kfree(str_orig);
	mutex_unlock(&mos_sysfs_mutex);
	return rc;
}

static ssize_t lwkgpus_numa_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buff)
{
	char *current_buff = buff;
	int remaining_buffsize = PAGE_SIZE;
	int bytes_written = 0;
	int total_bytes_written = 0;
	int i, loop_end;

	mutex_lock(&mos_sysfs_mutex);

	loop_end = gpumask_empty(&lwkgpus_map) ?
				0 : gpumask_last(&lwkgpus_map) + 1;

	for(i = 0; i < loop_end; i++) {
		bytes_written = scnprintf(current_buff,
					  remaining_buffsize, "%u,",
					  lwkgpus_numa[i]);
		remaining_buffsize -= bytes_written;
		current_buff += bytes_written;
		total_bytes_written += bytes_written;
	}

	mutex_unlock(&mos_sysfs_mutex);

	/* Replace trailing comma with newline character. the
	   scnprintf already stored the required NULL string termination */
	if (bytes_written > 0)
		*(--current_buff) = '\n';
	else
		*buff = '\0';

	return total_bytes_written;
}

static ssize_t lwkgpus_numa_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	unsigned nid;
	int16_t *nid_ptr = lwkgpus_numa;
	int nids_in_list = 0;
	int i;
	char *str, *str_orig = 0;
	char *val;
	size_t rc = count;

	mutex_lock(&mos_sysfs_mutex);

	str = kstrndup(buff, count, GFP_KERNEL);
	if (!str) {
		rc = -ENOMEM;
		goto out;
	}
	str_orig = str;
	while ((val = strsep(&str, ","))) {
		int kresult = kstrtouint(val, 0, &nid);

		if (kresult) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"Attempted to write invalid value to the LWK GPU NID list (rc=%d).",
				kresult);
			rc = -EINVAL;
			goto out;
		}
		/* Store NUMA id into the integer array */
		if (++nids_in_list > MOS_NR_GPUS) {
			rc = -EINVAL;
			mos_ras(MOS_LWKCTL_FAILURE,
			    "NID list exceeded number of GPU devices supported by the mOS kernel (>%d)",
			    MOS_NR_GPUS);
			goto out;
		}
		*nid_ptr++ = nid;
	}
	if (nids_in_list < MOS_NR_GPUS) {
		/* Fill remaining entries with an invalid NID value */
		for (i = nids_in_list; i < MOS_NR_GPUS; i++)
			*nid_ptr++ = -1;
	}
out:
	kfree(str_orig);
	mutex_unlock(&mos_sysfs_mutex);
	return rc;
}

static ssize_t lwk_interrupts_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buff)
{
	char *current_buff = buff;
	int remaining_buffsize = PAGE_SIZE;
	int bytes_written = 0;
	int total_bytes_written = 0;
	int i;

	mutex_lock(&mos_sysfs_mutex);

	for(i = 0; allowed_drivers[i]; i++) {
		bytes_written = scnprintf(current_buff,
					  remaining_buffsize, "%s,",
					  allowed_drivers[i]);
		remaining_buffsize -= bytes_written;
		current_buff += bytes_written;
		total_bytes_written += bytes_written;
	}

	mutex_unlock(&mos_sysfs_mutex);

	/* Replace trailing comma with newline character. the
	   scnprintf already stored the required NULL string termination */
	if (bytes_written > 0)
		*(--current_buff) = '\n';
	else
		*buff = '\0';

	return total_bytes_written;
}

static ssize_t lwk_interrupts_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	int i = 0;
	char *str, *str_orig = 0;
	char *val;
	size_t rc = count;

	mutex_lock(&mos_sysfs_mutex);

	str = kstrndup(buff, count, GFP_KERNEL);
	if (!str) {
		rc = -ENOMEM;
		goto out;
	}
	str_orig = str;
	while ((val = strsep(&str, ",")) && (i < MOS_MAX_ALLOWED_DRIVERS)) {
		/* Store string into array. Free any previous entry */
		kfree(allowed_drivers[i]);
		allowed_drivers[i++] = kstrdup(val, GFP_KERNEL);
	}
	allowed_drivers[i] = NULL; /* Sentinel */
out:
	kfree(str_orig);
	mutex_unlock(&mos_sysfs_mutex);
	return rc;
}

static ssize_t lwkcpus_sequence_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buff, size_t count)
{
	unsigned cpuid;
	int *cpu_ptr;
	int cpus_in_list = 0;
	char *str, *str_orig = 0;
	char *val;
	size_t rc = count;
	struct mos_process_t *proc = current->mos_process;

	if (!proc) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Attempted to write an LWK CPU sequence for a non-LWK process.");
		rc = -EINVAL;
		goto out;
	}
	cpu_ptr = proc->lwkcpus_sequence;
	if (!cpu_ptr) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Attempted to write an LWK CPU sequence prior to reserving LWK CPUs.");
		rc = -EINVAL;
		goto out;
	}
	str = kstrndup(buff, count, GFP_KERNEL);
	if (!str) {
		rc = -ENOMEM;
		goto out;
	}
	str_orig = str;
	while ((val = strsep(&str, ","))) {
		int kresult = kstrtouint(val, 0, &cpuid);

		if (kresult) {
			mos_ras(MOS_LWK_PROCESS_ERROR,
				"Attempted to write invalid value to the LWK CPU sequence (rc=%d).",
				kresult);
			rc = -EINVAL;
			goto out;
		}
		/* Store CPU id into the integer array */
		if (++cpus_in_list > proc->num_lwkcpus) {
			rc = -EINVAL;
			mos_ras(MOS_LWK_PROCESS_ERROR,
				"Too many CPUs were provided in an LWK sequence list.");
			goto out;
		}
		*cpu_ptr++ = cpuid;
	}
	if (cpus_in_list < proc->num_lwkcpus) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Too few CPUs were provided in an LWK sequence list.");
		rc = -EINVAL;
	}
out:
	kfree(str_orig);
	return rc;
}

static ssize_t lwk_options_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buff, size_t count)
{
	ssize_t rc = count;
	char *option = 0, *value;
	const char *name = buff;
	struct mos_process_t *mosp = current->mos_process;
	struct mos_process_option_callback_elem_t *elem;
	struct mos_process_callbacks_elem_t *cbs;
	bool not_found;

	if (!mosp) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Attempted to set LWK options for a non-LWK process.");
		rc = -EINVAL;
		goto out;
	}

	/* Options are stored in the buffer as a sequence of strings,
	 * separated by a null character.  This possibly includes a
	 * leading null character.  The end of the sequence is identified
	 * by two null characters.
	 */

	if (*name == '\0')
		name++;

	while (strlen(name)) {

		pr_debug("(*) %s: option=\"%s\"\n", __func__, name);

		option = kstrndup(name, count, GFP_KERNEL);

		if (!option) {
			rc = -ENOMEM;
			goto out;
		}

		value = strchr(option, '=');
		if (value)
			*value++ = '\0';

		not_found = true;
		list_for_each_entry(elem, &mos_process_option_callbacks, list) {
			if (strcmp(elem->name, option) == 0) {
				rc = elem->callback(value, mosp);
				if (rc) {
					mos_ras(MOS_LWK_PROCESS_ERROR,
						"Option callback %s / %pf reported an error (rc=%ld).",
						elem->name, elem->callback, rc);
					rc = -EINVAL;
					goto out;
				}
				not_found = false;
				break;
			}
		}

		if (not_found) {
			mos_ras(MOS_LWK_PROCESS_ERROR,
				"No option callback found for %s\n", option);
			rc = -EINVAL;
			goto out;
		}

		name += strlen(name) + 1;

		if (name - buff > count) {
			mos_ras(MOS_LWK_PROCESS_ERROR,
				"Overflow in options buffer.");
			rc = -EINVAL;
			goto out;
		}

		kfree(option);
		option = NULL;
	}

	list_for_each_entry(cbs, &mos_process_callbacks, list) {
		if (cbs->callbacks->mos_process_start &&
		    cbs->callbacks->mos_process_start(mosp)) {
			mos_ras(MOS_LWK_PROCESS_ERROR,
				"Non-zero return code from process start callback %pf\n",
				cbs->callbacks->mos_process_start);
			rc = -EINVAL;
			goto out;
		}
	}

	rc = count;
 out:
	kfree(option);
	return rc;
}

static ssize_t lwkmem_mempolicy_info_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	ssize_t rc = -EINVAL;
	struct mos_process_t *mosp = current->mos_process;


	if (!mosp) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Attempted to set mempolicy for a non-LWK process.");
		return -EINVAL;
	}

	if (!buff || !count) {
		mos_ras(MOS_LWK_PROCESS_ERROR,
			"Invalid buffer argument");
		return -EINVAL;
	}

	mutex_lock(&mos_sysfs_mutex);

	if (lwkmem_set_mempolicy_info) {
		rc = lwkmem_set_mempolicy_info(buff, count);
		if (rc == 0)
			rc = count;
	}

	mutex_unlock(&mos_sysfs_mutex);
	return rc;
}

static int validate_lwkcpus_spec(char *lwkcpus_parm)
{
	cpumask_var_t to, from, new_lwkcpus, new_syscallcpus;
	char *mutable_param_start, *mutable_param, *s_to, *s_from;
	int rc = -EINVAL;
	int cpu;

	mutable_param_start = mutable_param = kstrdup(lwkcpus_parm, GFP_KERNEL);
	if (!mutable_param) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"Failure duplicating CPU param_value string in %s.",
			__func__);
		return -ENOMEM;
	}
	if (!zalloc_cpumask_var(&to, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&from, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&new_syscallcpus, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&new_lwkcpus, GFP_KERNEL)) {
		mos_ras(MOS_LWKCTL_FAILURE, "Could not allocate cpumasks.");
		kfree(mutable_param_start);
		return -ENOMEM;
	}
	while ((s_to = strsep(&mutable_param, ":"))) {
		if (!(s_from = strchr(s_to, '.'))) {
			/* No syscall target defined */
			s_from = s_to;
			s_to = strchr(s_to, '\0');
		} else
			*s_from++ = '\0';
		if (cpulist_parse(s_to, to) < 0 ||
		    cpulist_parse(s_from, from) < 0) {
			mos_ras(MOS_LWKCTL_WARNING,
				"Invalid character in CPU specification.");
			goto out;
		}
		/* Maximum of one syscall target CPU allowed per LWKCPU range */
		if ((cpumask_weight(to) > 1) && !cpumask_empty(from)) {
			mos_ras(MOS_LWKCTL_WARNING,
				"More than one syscall target CPU specified.");
			goto out;
		}
		/* Build the set of lwk CPUs */
		cpumask_or(new_lwkcpus, new_lwkcpus, from);
		/* Build the set of syscall CPUs */
		cpumask_or(new_syscallcpus, new_syscallcpus, to);
	}

	if (cpumask_empty(new_lwkcpus)) {
		mos_ras(MOS_LWKCTL_WARNING,
			"No cpus specified for LWKCPU partition: %s",
			lwkcpus_parm);
		goto out;
	}
	for_each_cpu((cpu), new_lwkcpus) {
		if (!cpumask_test_cpu(cpu, cpu_online_mask)) {
			mos_ras(MOS_LWKCTL_WARNING,
					"Inline offlining requires LWK CPUs to be online, "
					"LWK CPUs: %*pbl Online CPUs: %*pbl.",
					cpumask_pr_args(new_lwkcpus),
					cpumask_pr_args(cpu_online_mask));
			goto out;
		}
	}
	if (cpumask_intersects(new_lwkcpus, new_syscallcpus)) {
		mos_ras(MOS_LWKCTL_WARNING,
			"Overlap detected. LWK CPUs: %*pbl syscall CPUs: %*pbl.",
			cpumask_pr_args(new_lwkcpus),
			cpumask_pr_args(new_syscallcpus));
		goto out;
	}
	rc = 0;
out:
	free_cpumask_var(to);
	free_cpumask_var(from);
	free_cpumask_var(new_lwkcpus);
	free_cpumask_var(new_syscallcpus);
	kfree(mutable_param_start);
	return rc;
}

/*
 * The specifed LWK CPUs should be in the Linux off-line state when called
 *
 * example input string:
 *	1.2-7,9:10.11,13,14
 *		In the above example, CPU 1 will be the syscall target
 *		for LWK CPUS 2,3,4,5,6,7,9 and CPU 10 will be the target
 *		for LWK CPUS 10,11,13,14
 */
int lwk_config_lwkcpus(char *param_value, char *profile)
{
	cpumask_var_t to;
	cpumask_var_t from;
	cpumask_var_t new_utilcpus;
	cpumask_var_t new_lwkcpus;

	unsigned cpu;
	char *s_to, *s_from;
	int rc = -EINVAL;
	bool return_cpus;
	char *mutable_param, *mutable_param_start = NULL;

	if (param_value && param_value[0] == '\0') {
		mos_ras(MOS_LWKCTL_FAILURE,
			"LWK partition without CPUs is not supported");
		return rc;
	}

	/* Is this a delete or create operation? */
	return_cpus = !param_value;

	/*
	 * Return success if we are asked to delete a partition
	 * when there is no existing LWK partition.
	 */
	if (return_cpus && cpumask_empty(lwkcpus_map))
		return 0;

	if (!zalloc_cpumask_var(&to, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&from, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&new_utilcpus, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&new_lwkcpus, GFP_KERNEL)) {
		mos_ras(MOS_LWKCTL_FAILURE, "Could not allocate cpumasks.");
		return -ENOMEM;
	}

	if (return_cpus) {
		rc = lwkcpu_partition_destroy(lwkcpus_map);

		/*
		 * No fallback necessary for delete flow as we have
		 * not yet modified global masks.
		 */
		if (rc)
			goto out;

		/*
		 * On success,
		 *
		 * At this point CPUs that were previously LWKCPUs are
		 * offlined, LWK scheduler de-activated and there are no LWK
		 * processes running. So below changes are safe.
		 *
		 *  - reset CPU hotplug state markings that we had done before
		 *    during partition creation for filtering of CPU hotplug
		 *    states.
		 *  - reset per CPU syscall migration masks from CPUs that were
		 *    previously LWK CPUs.
		 *  - reset per CPU LWK CPU mask from all CPUs.
		 */
		lwkcpu_state_deinit();

		/* Reset per CPU LWK CPU mask */
		for_each_possible_cpu(cpu)
			cpumask_clear(per_cpu_ptr(&lwkcpus_mask, cpu));
		pr_info("Returning CPUs to Linux: %*pbl\n",
			cpumask_pr_args(lwkcpus_map));
	} else {
		mutable_param = kstrdup(param_value, GFP_KERNEL);
		mutable_param_start = mutable_param;
		if (!mutable_param) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"Failure duplicating CPU string in %s.",
				__func__);
			rc = -ENOMEM;
			goto out;
		}

		/*
		 * Compute and update utility CPU masks for each
		 * LWKCPU in the new specification.
		 */
		while ((s_to = strsep(&mutable_param, ":"))) {
			if (!(s_from = strchr(s_to, '.'))) {
				/* No syscall target defined */
				s_from = s_to;
				s_to = strchr(s_to, '\0');
			} else
				*s_from++ = '\0';
			cpulist_parse(s_to, to);
			cpulist_parse(s_from, from);
			/* Build the new LWK and Utility CPUs masks */
			cpumask_or(new_lwkcpus, new_lwkcpus, from);
			cpumask_or(new_utilcpus, new_utilcpus, to);
		}
		pr_info("Configured LWK CPUs: %*pbl\n",
			cpumask_pr_args(new_lwkcpus));
		pr_info("Configured Utility CPUs: %*pbl\n",
			cpumask_pr_args(new_utilcpus));

		/* Let each CPU have its own copy of the lwkcpus mask. This gets
		 * interrogated on each system call.
		 */
		for_each_possible_cpu(cpu) {
			cpumask_copy(per_cpu_ptr(&lwkcpus_mask, cpu),
				     new_lwkcpus);
		}

		/* Set CPU hotplug state filtering for LWKCPUs if requested */
		if (profile && lwkcpu_state_init(profile)) {
			mos_ras(MOS_LWKCTL_WARNING,
				"lwkcpu_profile: %s failed, trying %s profile",
				profile, LWKCPU_PROF_NOR);
			profile = NULL;
		}

		/*
		 * Fallback to normal filtering of CPU hotplug states if
		 * setting the requested profile failed or user did not
		 * specify one.
		 */
		rc = 0;
		if (!profile) {
			rc = lwkcpu_state_init(LWKCPU_PROF_NOR);
			if (rc) {
				mos_ras(MOS_LWKCTL_FAILURE,
					"Failed to set lwkcpu_profile: %s.",
					LWKCPU_PROF_NOR);
			}
		}

		/* If we succeded in setting lwkcpu_profile proceed further */
		if (!rc) {
			rc = lwkcpu_partition_create(new_lwkcpus);
			if (rc)
				lwkcpu_state_deinit();
		}

		/*
		 * In case of failure clear the
		 * LWKCPUs mask that we had set before attempting to create
		 * LWKCPU partition. Failure could be either due to the
		 * inability to set CPU hotplug filtering or CPU partition
		 * creation itself failed. This reset of masks is safe as
		 * CPUs are still offlined and there are no active LWK tasks.
		 */
		if (rc) {
			/* Reset per cpu lwkcpus_mask */
			for_each_possible_cpu(cpu)
				cpumask_clear(per_cpu_ptr(&lwkcpus_mask, cpu));
			goto out;
		}
	}

	/*
	 * If we are here we succeded in fulfilling the user request which is
	 * either delete or create LWKCPU partition. So we do updates that are
	 * common upon these successful operations.
	 */

	/* Update the sysfs cpu masks */
	cpumask_copy(lwkcpus_map, new_lwkcpus);
	cpumask_copy(utility_cpus_map, new_utilcpus);

	/* Update LWKCPU spec gloabl strings: lwkcpus=, lwkcpu_profile=  */
	snprintf(lwkctrl_cpus_spec, LWKCTRL_CPUS_SPECSZ, "%s",
		 param_value ? param_value : "");
	snprintf(lwkctrl_cpu_profile_spec, LWKCTRL_CPU_PROFILE_SPECSZ, "%s",
		 return_cpus ? "" : profile ? profile : LWKCPU_PROF_NOR);
	/* status success */
	rc = 0;
out:
	free_cpumask_var(to);
	free_cpumask_var(from);
	free_cpumask_var(new_utilcpus);
	free_cpumask_var(new_lwkcpus);
	kfree(mutable_param_start);
	return rc;
}

int lwk_config_lwkmem(char *param_value)
{
	int rc;

	if (!param_value)
		rc = lwkmem_partition_destroy();
	else
		rc = lwkmem_partition_create(param_value, lwkmem_precise);
	return rc;
}

static int lwk_validate_auto(char *auto_s)
{
	int rc = 0;
	char *tmp_start, *tmp, *resource;

	tmp_start = tmp = kstrdup(auto_s, GFP_KERNEL);
	if (!tmp_start)
		return -1;
	while ((resource = strsep(&tmp, ","))) {
		if (strcmp(resource, "cpu") && strcmp(resource, "mem")) {
			rc = -1;
			break;
		}
	}
	kfree(tmp_start);
	return rc;
}

static ssize_t lwk_config_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buff, size_t count)
{
	ssize_t rc = -EINVAL;
	char *lwkcpus, *lwkcpu_profile, *lwkmem, *auto_config;
	char *old_lwkcpus, *old_lwkcpu_profile;
	char *tmp, *tmp_start, *s_keyword, *s_value;
	bool delete_lwkcpu, delete_lwkmem;

	lwkcpus = lwkcpu_profile = lwkmem = auto_config = NULL;
	old_lwkcpus = old_lwkcpu_profile = NULL;
	tmp = tmp_start = s_keyword = s_value = NULL;
	delete_lwkcpu = delete_lwkmem = false;

	if (!buff)
		return -EINVAL;

	mutex_lock(&mos_sysfs_mutex);

	pr_info("Kernel processing request: [%s]\n", buff);

	/* Check if its a request to delete existing LWK partition */
	if (buff[0] == '0') {
		delete_lwkcpu = strcmp(lwkctrl_cpus_spec, "") != 0;
		delete_lwkmem = strcmp(lwkmem_get_spec(), "") != 0;

		/* There is nothing to do, return success */
		if (!delete_lwkcpu && !delete_lwkmem) {
			rc = count;
			goto out;
		}

		if (!delete_lwkcpu && delete_lwkmem) {
			/*
			 * Unexpected LWK partition state found. We make an
			 * attempt to fix by proceeding to delete it. Also
			 * flag RAS failure events at the same time.
			 */
			mos_ras(MOS_LWKCTL_FAILURE,
				"Invalid state of LWK partition: only LWKMEM");
		}
	} else {
		/* Parse syntax for a create operation */
		tmp_start = tmp = kstrdup(buff, GFP_KERNEL);
		if (!tmp) {
			rc = -ENOMEM;
			goto out;
		}

		while ((s_keyword = strsep(&tmp, " "))) {
			if (strlen(s_keyword) == 0)
				continue;
			if (!(s_value = strchr(s_keyword, '='))) {
				mos_ras(MOS_LWKCTL_FAILURE,
					"Failed to find [=] for keyword: %s",
					s_keyword);
				goto out;
			}
			*s_value++ = '\0';
			if (*s_value == '\n')
				*s_value = '\0';
			if (strcmp(s_keyword, "lwkcpus") == 0) {
				strreplace(s_value, '\n', '\0');
				kfree(lwkcpus);
				lwkcpus = kstrdup(s_value, GFP_KERNEL);
				if (!lwkcpus) {
					rc = -ENOMEM;
					goto out;
				}
			} else if (!strcmp(s_keyword, "lwkcpu_profile")) {
				kfree(lwkcpu_profile);
				strreplace(s_value, '\n', '\0');
				lwkcpu_profile = kstrdup(s_value, GFP_KERNEL);
				if (!lwkcpu_profile) {
					rc = -ENOMEM;
					goto out;
				}
			} else if (!strcmp(s_keyword, "lwkmem")) {
				kfree(lwkmem);
				strreplace(s_value, '\n', '\0');
				/* Its a valid syntax to specify 'lwkmem='
				 * it means user requested an LWK partition
				 * without LWK memory. Such an LWK partition
				 * will have only LWK CPUs.
				 */
				lwkmem = kstrdup(s_value, GFP_KERNEL);
				if (!lwkmem) {
					rc = -ENOMEM;
					goto out;
				}
			} else if (!strcmp(s_keyword, "auto")) {
				kfree(auto_config);
				strreplace(s_value, '\n', '\0');
				auto_config = kstrdup(s_value, GFP_KERNEL);
				if (!auto_config) {
					rc = -ENOMEM;
					goto out;
				}
			} else if (!strcmp(s_keyword, "precise")) {
				strreplace(s_value, '\n', '\0');
				if (!strcmp(s_value, "yes"))
					lwkmem_precise = true;
				else if (!strcmp(s_value, "no"))
					lwkmem_precise = false;
				else
					goto out;
			} else {
				mos_ras(MOS_LWKCTL_WARNING,
					"Unsupported keyword: %s was ignored.",
					s_keyword);
			}
		}
		/*
		 * It is incorrect to specify anything without
		 * specifying lwkcpus for a create operation.
		 */
		if (!lwkcpus) {
			mos_ras(MOS_LWKCTL_WARNING,
				"Invalid LWK spec [%s], no lwkcpus specified",
				buff);
			goto out;
		}

		/* Catch invalid specification for create operation */
		rc = validate_lwkcpus_spec(lwkcpus);
		if (rc)
			goto out;

		/*
		 * Reset rc, error flow assumes that
		 * this is set to default error code
		 */
		rc = -EINVAL;

		/* Deny attempt to overwrite an existing LWK partition */
		if (!cpumask_empty(lwkcpus_map)) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"Unsupported: modifying LWKCPU config.");
			goto out;
		}

		if (auto_config && lwk_validate_auto(auto_config)) {
			mos_ras(MOS_LWKCTL_WARNING,
				"Unsupported auto configuration data=%s",
				auto_config);
			goto out;
		}
	}

	/*
	 * Ok by now all parsing, input validation, syntax checking,
	 * are all done, so let us get to the real thing.
	 */

	/*
	 * NOTE: on RAS messages,
	 *
	 * In the below code unless it is a kernel failure caused directly
	 * by this function we print warning level RAS messages and let the
	 * called function from here decide if the RAS level should be warning
	 * or error based on what really happened within that function.
	 */

	/* LWK partition delete operation */
	if (delete_lwkcpu || delete_lwkmem) {
		/*
		 * Save old specification just in case we need to fallback
		 * to old config later.
		 */
		old_lwkcpus = kstrdup(lwkctrl_cpus_spec, GFP_KERNEL);
		old_lwkcpu_profile = kstrdup(lwkctrl_cpu_profile_spec,
					     GFP_KERNEL);

		if (delete_lwkcpu && lwk_config_lwkcpus(NULL, NULL) < 0) {
			mos_ras(MOS_LWKCTL_WARNING,
				"Failed to delete LWKCPU partition");
			goto out;
		}

		if (delete_lwkmem && lwk_config_lwkmem(NULL) < 0) {
			mos_ras(MOS_LWKCTL_WARNING,
				"Failed to delete LWKMEM partition");

			/* Try to restore old LWKCPU partition */
			if (delete_lwkcpu && old_lwkcpus &&
			    old_lwkcpu_profile &&
			    lwk_config_lwkcpus(old_lwkcpus,
					       old_lwkcpu_profile)) {
				mos_ras(MOS_LWKCTL_FAILURE,
					"Failed to revert to lwkcpus=%s lwkcpu_profile=%s",
					old_lwkcpus, old_lwkcpu_profile);
			}
			goto out;
		}

		/* Clear auto indicator */
		kfree(lwkauto);
		lwkauto = NULL;
	} else {
		/* LWK partition create operation */
		if (lwkmem && lwk_config_lwkmem(lwkmem) < 0) {
			mos_ras(MOS_LWKCTL_WARNING,
				"Failure processing: lwkmem=%s", lwkmem);
			goto out;
		}

		if (lwkcpus &&
		    lwk_config_lwkcpus(lwkcpus, lwkcpu_profile) < 0) {
			mos_ras(MOS_LWKCTL_WARNING,
				"Failure processing: lwkcpus=%s", lwkcpus);
			if (lwkmem && strcmp(lwkmem, "") &&
			    lwk_config_lwkmem(NULL) < 0) {
				mos_ras(MOS_LWKCTL_FAILURE,
					"Failure returning LWK memory");
			}
			goto out;
		}

		/* Clear partitioned LWK memory */
		if (lwkmem && strcmp(lwkmem, "") &&
		    lwkmem_partition_clear_memory() < 0) {
			/* Return CPUs */
			if (lwkcpus && lwk_config_lwkcpus(NULL, NULL) < 0)
				mos_ras(MOS_LWKCTL_FAILURE,
					"Failed to return LWK CPUs");
			if (lwk_config_lwkmem(NULL) < 0)
				mos_ras(MOS_LWKCTL_FAILURE,
					"Failed to return LWK memory");
			goto out;
		}

		/* Set auto indicator if specififed */
		if (auto_config) {
			kfree(lwkauto);
			lwkauto = auto_config;
		}
	}
	rc = count;
out:
	if (rc == -ENOMEM)
		mos_ras(MOS_LWKCTL_FAILURE, "No free kernel memory");

	if (rc < 0)
		kfree(auto_config);
	kfree(lwkcpus);
	kfree(lwkcpu_profile);
	kfree(old_lwkcpus);
	kfree(old_lwkcpu_profile);
	kfree(lwkmem);
	kfree(tmp_start);
	pr_info("Kernel processing request: [%s] [%s]\n\n",
		buff, rc == count ? "SUCCESS" : "FAILED");
	mutex_unlock(&mos_sysfs_mutex);
	return rc;
}

static ssize_t lwk_config_show(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buff)
{
	int buffsize = PAGE_SIZE;
	int rc = -ENOMEM;
	size_t auto_ssize;
	char *cur_buff = buff;
	char *auto_s;

	mutex_lock(&mos_sysfs_mutex);

	if (!lwkauto)
		auto_s = kstrdup("", GFP_KERNEL);
	else {
		auto_ssize = strlen(lwkauto) + sizeof(" auto=");
		auto_s = kmalloc(auto_ssize, GFP_KERNEL);
		if (!auto_s)
			goto out;
		snprintf(auto_s, auto_ssize, "auto=%s", lwkauto);
	}
	rc = scnprintf(cur_buff, buffsize,
			"lwkcpus=%s lwkcpu_profile=%s lwkmem=%s %s precise=%s\n",
			lwkctrl_cpus_spec, lwkctrl_cpu_profile_spec,
			lwkmem_get_spec(), auto_s,
			lwkmem_precise ? "yes" : "no");
out:
	kfree(auto_s);
	mutex_unlock(&mos_sysfs_mutex);
	return rc;
}

static struct kobject *mos_kobj;
static struct kobj_attribute version_attr = __ATTR_RO(version);
static struct kobj_attribute lwkmem_attr = __ATTR_RO(lwkmem);
static struct kobj_attribute lwkmem_reserved_attr = __ATTR_RO(lwkmem_reserved);
static struct kobj_attribute lwkmem_request_attr = __ATTR_WO(lwkmem_request);
static struct kobj_attribute lwkprocesses_attr = __ATTR_RO(lwkprocesses);
static struct kobj_attribute lwkgpus_usage_count_attr = __ATTR_RW(lwkgpus_usage_count);
static struct kobj_attribute lwkgpus_numa_attr = __ATTR_RW(lwkgpus_numa);
static struct kobj_attribute lwk_interrupts_attr = __ATTR_RW(lwk_interrupts);
static struct kobj_attribute lwkcpus_sequence_attr =
						__ATTR_WO(lwkcpus_sequence);
static struct kobj_attribute lwk_util_threads_attr =
						__ATTR_WO(lwk_util_threads);
static struct kobj_attribute lwk_options_attr = __ATTR_WO(lwk_options);
static struct kobj_attribute lwkmem_mempolicy_info_attr =
					__ATTR_WO(lwkmem_mempolicy_info);
static struct kobj_attribute lwk_config_attr = __ATTR_RW(lwk_config);
static  struct attribute *mos_attributes[] = {
	&version_attr.attr,
	&lwkcpus_attr.attr,
	&lwkcpus_mask_attr.attr,
	&lwkcpus_reserved_attr.attr,
	&lwkcpus_reserved_mask_attr.attr,
	&lwkcpus_request_attr.attr,
	&lwkcpus_request_mask_attr.attr,
	&lwkmem_attr.attr,
	&lwkmem_reserved_attr.attr,
	&lwkmem_request_attr.attr,
	&lwkprocesses_attr.attr,
	&lwkgpus_usage_count_attr.attr,
	&lwkgpus_numa_attr.attr,
	&lwk_interrupts_attr.attr,
	&lwkcpus_sequence_attr.attr,
	&lwk_util_threads_attr.attr,
	&lwk_options_attr.attr,
	&lwkmem_mempolicy_info_attr.attr,
	&utility_cpus_attr.attr,
	&utility_cpus_mask_attr.attr,
	&lwk_config_attr.attr,
	&lwkgpus_attr.attr,
	&lwkgpus_mask_attr.attr,
	&lwkgpus_reserved_attr.attr,
	&lwkgpus_reserved_mask_attr.attr,
	&lwkgpus_request_attr.attr,
	&lwkgpus_request_mask_attr.attr,
	NULL
};

static struct attribute_group mos_attr_group = {
	.attrs = mos_attributes,
};

static int __init mos_sysfs_init(void)
{

	int ret;

	if (!zalloc_cpumask_var(&lwkcpus_map, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&utility_cpus_map, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_reserved_map, GFP_KERNEL)) {
		mos_ras(MOS_BOOT_ERROR,
			"%s: CPU mask allocation failed.", __func__);
		ret = -ENOMEM;
		goto out;
	}

	mos_kobj = kobject_create_and_add("mOS", kernel_kobj);

	if (!mos_kobj) {
		ret = -ENOMEM;
		goto out;
	}

	lwkcpus_request_attr.attr.mode |= S_IWGRP;
	lwkcpus_request_mask_attr.attr.mode |= S_IWGRP;
	lwkgpus_request_attr.attr.mode |= S_IWGRP;
	lwkgpus_request_mask_attr.attr.mode |= S_IWGRP;
	lwkmem_mempolicy_info_attr.attr.mode |= S_IWGRP;
	lwkmem_request_attr.attr.mode |= S_IWGRP;
	lwkcpus_sequence_attr.attr.mode |= S_IWGRP;
	lwk_options_attr.attr.mode |= S_IWGRP;
	lwk_util_threads_attr.attr.mode |= S_IWGRP;

	ret = sysfs_create_group(mos_kobj, &mos_attr_group);
	if (ret) {
		mos_ras(MOS_BOOT_ERROR,
			"%s: Could not create sysfs entries for mOS.",
			__func__);
		goto out;
	}

	ret = mosras_sysfs_init(mos_kobj);

	if (ret)
		goto out;

	return 0;

out:
	return ret;
}

subsys_initcall(mos_sysfs_init);

#endif /* CONFIG_MOS_FOR_HPC */
