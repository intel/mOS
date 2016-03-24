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

#ifdef CONFIG_MOS_FOR_HPC

#undef pr_fmt
#define pr_fmt(fmt)	"mOS: " fmt

#define MOS_VERSION	"0.3"

static char cpulist_buf[NR_CPUS + 1];
static cpumask_var_t lwkcpus_map;
static cpumask_var_t lwkcpus_syscall_map;
static cpumask_var_t lwkcpus_reserved_map;
static DEFINE_MUTEX(mos_sysfs_mutex);
static LIST_HEAD(mos_process_option_callbacks);
static LIST_HEAD(mos_process_callbacks);

/* NOTE: The following items are not static.  They are referenced
 *       by other LWK components in mOS.
 */

DEFINE_PER_CPU(cpumask_t, mos_syscall_mask);
DEFINE_PER_CPU(cpumask_t, lwkcpus_mask);

/* Parse the syscall CPUs list from the kernel parameters. */
static int __init lwkcpus_setup(char *str)
{
	static cpumask_t to __initdata;
	static cpumask_t from __initdata;
	static cpumask_t build_lwkcpus_mask __initdata;
	static char buf1[NR_CPUS + 1] __initdata;
	static char tmp[COMMAND_LINE_SIZE] __initdata;

	unsigned cpu;
	char *s_to, *s_from;

	BUG_ON(!str);

	/* break the argument on ';'s, then '<'s */
	str = strcpy(tmp, str);
	while ((s_to = strsep(&str, ":"))) {
		if (!(s_from = strchr(s_to, '.')))
			goto invalid;
		*(s_from++) = '\0';

		if (cpulist_parse(s_to, &to) < 0 ||
				cpulist_parse(s_from, &from) < 0)
			goto invalid;

		for_each_cpu(cpu, &from) {
			cpumask_t *mask;

			mask = per_cpu_ptr(&mos_syscall_mask, cpu);
			cpumask_or(mask, mask, &to);
			/* We only ship from LWK CPUs. Build the set */
			cpumask_or(&build_lwkcpus_mask, &build_lwkcpus_mask,
				&from);
		}
	}

	/* These are the LWK CPUS */
	scnprintf(buf1, sizeof(buf1), "%*pbl", cpumask_pr_args(&build_lwkcpus_mask));
	pr_info("lwkcpus_mask: \"%s\"\n", buf1);

	/* Let each CPU have its own copy. This gets interrogated on each
	 * system call. */
	for_each_possible_cpu(cpu)
		cpumask_copy(per_cpu_ptr(&lwkcpus_mask, cpu),
			&build_lwkcpus_mask);

	return 0;

invalid:
	pr_warn("mOS: Invalid lwkcpus cpulist\n");
	return 1;
}
__setup("lwkcpus=", lwkcpus_setup);

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
 * Find the MOS process associated with the specified thread
 * group.
 */
static struct mos_process_t *mos_find_process(pid_t tgid)
{
	struct mos_process_t *process = NULL;
	struct task_struct *task;

	rcu_read_lock();
	task = tgid ? find_task_by_vpid(tgid) : current;
	if (task) {
		get_task_struct(task);
		process = task->mos_process;
		put_task_struct(task);
	}
	rcu_read_unlock();

	return process;
}

/**
 * Find the MOS process associated with the specified thread
 * group; create the entry if one does not already exist.
 */
static struct mos_process_t *mos_get_process(pid_t tgid)
{
	struct mos_process_t *process;

	process = mos_find_process(tgid);

	if (!process) {
		struct mos_process_callbacks_elem_t *elem;

		process = vmalloc(sizeof(struct mos_process_t));
		process->tgid = tgid;

		if (!zalloc_cpumask_var(&process->lwkcpus, GFP_KERNEL) ||
		    !zalloc_cpumask_var(&process->utilcpus, GFP_KERNEL)) {
			pr_warn("CPU mask allocation failure.\n");
			return 0;
		}

		process->lwkcpus_sequence = 0;
		process->num_lwkcpus = 0;
		process->num_util_threads = 0;

		atomic_set(&process->alive, 1); /* count the current thread */

		list_for_each_entry(elem, &mos_process_callbacks, list) {
			if (elem->callbacks->mos_process_init &&
			    elem->callbacks->mos_process_init(process)) {
				pr_warn("(!) non-zero return code from process init callback %pf\n",
					elem->callbacks->mos_process_init);
				process = 0;
				break;
			}
		}

	}

	return process;
}

void mos_exit_thread(pid_t pid, pid_t tgid)
{
	struct mos_process_t *process;
	struct mos_process_callbacks_elem_t *elem;

	mutex_lock(&mos_sysfs_mutex);

	process = mos_find_process(pid);

	/* Check to see if this is a thread of some known MOS process.
	 * If not, warning. */
	if (!process) {
		process = mos_find_process(tgid);
		if (!process) {
			pr_warn("Unknown MOS process pid=%d tgid=%d ignored.\n",
				pid, tgid);
			goto unlock;
		}
	}

	/* This can go away at some point .... */
	if (current->mos_process != process)
		pr_warn("(W) process mismatch pid=%d tgid=%d curr=%p proc=%p\n",
			pid, tgid, current->mos_process, process);

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

	/* Free process resources. */
	free_cpumask_var(process->lwkcpus);
	free_cpumask_var(process->utilcpus);
	vfree(process->lwkcpus_sequence);
	vfree(process);

unlock:
	mutex_unlock(&mos_sysfs_mutex);
}

/**
 * An operations structure for modifying various mOS sysfs
 * files.  This allows us to compose various types of operations
 * and file types.
 */
struct mos_sysfs_mask_write_op {
	int (*parser)(const char *, cpumask_var_t);
	int (*operation)(cpumask_var_t);
} mos_sysfs_mask_write_op;

/**
 * A parameterized write operations for mOS sysfs files.  The buf/count
 * arguments are parsed via the op->parser field.  Then the op->operation
 * is applied under the safety of the mos_sysfs_mutex.
 */

static ssize_t mos_sysfs_mask_write(const char *buf, size_t count,
				    struct mos_sysfs_mask_write_op *op)
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

	current->mos_flags |= MOS_IS_LWK_PROCESS;
out:
	return rc;
}

static int _lwkcpus_request_set(cpumask_var_t request)
{
	int rc;

	rc = _cpus_request_set(request, lwkcpus_reserved_map);

	if (!rc) {
		int *cpu_list, num_lwkcpus, cpu;

		current->mos_process = mos_get_process(current->tgid);

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

		/* Create a mask of the shared utility CPUs based on the CPUs
		 * participating as syscall targets for all of the lwk cpus
		 * in this process
		 */
		for_each_cpu(cpu, current->mos_process->lwkcpus)
			cpumask_or(current->mos_process->utilcpus,
				   current->mos_process->utilcpus,
				   per_cpu_ptr(&mos_syscall_mask, cpu));


		_mos_debug_process(current->mos_process, __func__, __LINE__);
	}

 out:
	return rc;
}

static struct kobject *mos_kobj;

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
		return show_cpu_mask(name##_map, buff);		\
	}

#define MOS_SYSFS_CPU_STORE_LIST(name)					\
	static struct mos_sysfs_mask_write_op name##_op = {		\
		.parser = cpulist_parse,				\
		.operation = _##name##_set,				\
	};								\
									\
	static ssize_t name##_store(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    const char *buf, size_t count)	\
	{								\
		return mos_sysfs_mask_write(buf, count, &name##_op);	\
	}								\

#define MOS_SYSFS_CPU_STORE_MASK(name) \
	static struct mos_sysfs_mask_write_op name##_mask_op = {	\
		.parser = cpumask_parse,				\
		.operation = _##name##_set,				\
	};								\
									\
	static ssize_t name##_mask_store(struct kobject *kobj,		\
					 struct kobj_attribute *attr,	\
					 const char *buf, size_t count)	\
	{								\
		return mos_sysfs_mask_write(buf, count, &name##_mask_op); \
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

MOS_SYSFS_CPU_RO(lwkcpus);
MOS_SYSFS_CPU_RW(lwkcpus_reserved);
MOS_SYSFS_CPU_WO(lwkcpus_request);
MOS_SYSFS_CPU_RO(lwkcpus_syscall);

#define MAX_NIDS (1 << CONFIG_NODES_SHIFT)

static ssize_t _lwkmem_vec_show(char *buff, int (*getter)(unsigned long *, size_t *), unsigned long deflt)
{
	unsigned long lwkm[MAX_NIDS];
	size_t  i, n;
	ssize_t len;
	int rc;

	if (getter) {
		n = ARRAY_SIZE(lwkm);
		rc = getter(lwkm, &n);
		if (rc)
			return -EINVAL;
	} else {
		lwkm[0] = deflt ? deflt : 0;
		n = 1;
	}

	len = 0;
	buff[0] = 0;

	for (i = 0; i < n; i++)
		len += scnprintf(buff + len, PAGE_SIZE - len, "%lu ", lwkm[i]);

	buff[len] = '\n';
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
			pr_err("Potential overflow in lwkmem_request buffer\n");
			return -EINVAL;
		}

		rc = kstrtoul(val, 0, lwkm + *n);

		if (rc) {
			pr_warn("Attempted to write invalid value to lwkmem_request");
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
	unsigned long lwkm[MAX_NIDS], total;
	size_t n;
	char *str;
	struct mos_process_t *process;

	str = kstrdup(buff, GFP_KERNEL);

	if (!str) {
		rc = -ENOMEM;
		goto out;
	}

	n = ARRAY_SIZE(lwkm);

	rc = _lwkmem_vec_parse(str, lwkm, &n, &total);

	if (rc)
		goto out;

	mutex_lock(&mos_sysfs_mutex);

	current->mos_flags |= MOS_IS_LWK_PROCESS;

	rc = count;

	process = mos_get_process(current->tgid);

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
	kfree(str);
	return rc;
}

static ssize_t lwkmem_debug_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buff)
{
	int level;

	level = 0;
	if (lwkmem_get_debug_level)
		level = lwkmem_get_debug_level();
	return scnprintf(buff, PAGE_SIZE, "%u\n", level);
}

static ssize_t lwkmem_debug_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buff, size_t count)
{
	int level = 0;

	if (kstrtoint(buff, 0, &level)) {
		pr_warn("Attempted to write invalid valid to lwkmem_debug");
		return -EINVAL;
	}

	if (lwkmem_set_debug_level)
		lwkmem_set_debug_level(level);
	return count;
}

static ssize_t lwk_util_threads_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buff, size_t count)
{
	struct mos_process_t *proc = current->mos_process;
	int num_util_threads;

	if (!proc) {
		pr_warn("Attempt to set number of utility threads from non-mOS process\n");
		return  -EINVAL;
	}
	if (kstrtoint(buff, 0, &num_util_threads)) {
		pr_warn("Attempted to write invalid value to num_util_threads\n");
		return -EINVAL;
	}

	if (num_util_threads < 0) {
		pr_warn("Attempted to write a negative value to num_util_threads\n");
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
		pr_warn("Attempt to write cpu sequence from non-mOS process\n");
		rc = -EINVAL;
		goto out;
	}
	cpu_ptr = proc->lwkcpus_sequence;
	if (!cpu_ptr) {
		pr_warn(
		    "Attempt to write cpu sequence prior to reserving CPUs\n");
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
			pr_warn(
		    "Attempted to write invalid value to cpu sequence rc=%d\n",
				kresult);
			rc = -EINVAL;
			goto out;
		}
		/* Store CPU id into the integer array */
		if (++cpus_in_list > proc->num_lwkcpus) {
			rc = -EINVAL;
			pr_warn("Too many cpus provided in sequence list\n");
			goto out;
		}
		*cpu_ptr++ = cpuid;
	}
	if (cpus_in_list < proc->num_lwkcpus) {
		pr_warn("Too few cpus provided in sequence list\n");
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
	char *options = 0, *tok, *name, *value;
	struct mos_process_t *mosp = current->mos_process;
	struct mos_process_option_callback_elem_t *elem;
	struct mos_process_callbacks_elem_t *cbs;
	bool not_found;

	if (!mosp) {
		pr_warn("Attempt to set options for a non-mOS process\n");
		rc = -EINVAL;
		goto out;
	}

	tok = options = kstrndup(buff, count, GFP_KERNEL);

	while ((name = strsep(&tok, ","))) {

		if (strlen(name) == 0)
			continue;

		value = strchr(name, '=');
		if (value)
			*value++ = '\0';

		not_found = true;
		list_for_each_entry(elem, &mos_process_option_callbacks, list) {
			if (strcmp(elem->name, name) == 0) {
				rc = elem->callback(value, mosp);
				if (rc) {
					pr_warn("(!) error %ld invoking option callback for %s / %pf\n",
						rc, elem->name, elem->callback);
					rc = -EINVAL;
					goto out;
				}
				not_found = false;
				break;
			}
		}

		if (not_found) {
			pr_warn("(!) no option callback found for %s\n", name);
			rc = -EINVAL;
			goto out;
		}
	}

	list_for_each_entry(cbs, &mos_process_callbacks, list) {
		if (cbs->callbacks->mos_process_start &&
		    cbs->callbacks->mos_process_start(mosp)) {
			pr_warn("(!) non-zero return code from process start callback %pf\n",
				cbs->callbacks->mos_process_start);
			rc = -EINVAL;
			goto out;
		}
	}

	rc = count;
 out:
	kfree(options);
	return rc;
}

static ssize_t lwkmem_domain_info_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buff, size_t count)
{
	ssize_t rc;
	unsigned long nids[MAX_NIDS];
	size_t n;
	char *str, *typ_str, *nids_str, *nid_str;
	enum lwkmem_type_t typ;
	struct mos_process_t *mosp = current->mos_process;

	pr_debug("(>) %s buff=\"%s\" count=%ld\n", __func__, buff, count);

	mutex_lock(&mos_sysfs_mutex);

	if (!mosp) {
		pr_warn("Attempt to set domain information for a non-mOS process.\n");
		rc = -EINVAL;
		goto out;
	}

	str = kstrdup(buff, GFP_KERNEL);

	if (!str) {
		rc = -ENOMEM;
		goto out;
	}

	/* Information is passed along as a space-delimited sequence of
	 * <type>=<nid>[,<nid>...] phrases.  Each phrase is parsed, converted
	 * to an array of NIDs and lwkmem_type_t, and ultimately passed along
	 * to the memory subsystem.
	 */
	while ((typ_str = strsep(&str, " "))) {

		if (strlen(typ_str) == 0)
			continue;

		nids_str = strchr(typ_str, '=');

		if (!nids_str) {
			rc = -EINVAL;
			goto out;
		}

		*nids_str++ = '\0';

		if (strcmp(typ_str, "mcdram") == 0)
			typ = lwkmem_mcdram;
		else if (strcmp(typ_str, "dram") == 0)
			typ = lwkmem_dram;
		else {
			rc = -EINVAL;
			pr_warn("Unrecognized memory type: %s\n", typ_str);
			goto out;
		}

		n = 0;

		while ((nid_str = strsep(&nids_str, ","))) {

			if (n == MAX_NIDS) {
				pr_err("Overflow in lwkmem_domain_info buffer.\n");
				rc = -EINVAL;
				goto out;
			}

			rc = kstrtoul(nid_str, 0, nids + n);

			if (rc) {
				pr_warn("Attempted to write invalid value to lwkmem_domain_info: %s\n",
					nid_str);
				rc = -EINVAL;
				goto out;
			}

			n++;

		}

		if (lwkmem_set_domain_info) {
			rc = lwkmem_set_domain_info(mosp, typ, nids, n);
			if (rc) {
				pr_warn("Non-zero rc=%ld from lwkmem_set_domain_info.\n",
					rc);
				rc = -EINVAL;
				goto out;
			}
		}
	}

	rc = count;
 out:
	mutex_unlock(&mos_sysfs_mutex);
	kfree(str);
	return rc;
}

static struct kobj_attribute version_attr = __ATTR_RO(version);
static struct kobj_attribute lwkmem_attr = __ATTR_RO(lwkmem);
static struct kobj_attribute lwkmem_reserved_attr = __ATTR_RO(lwkmem_reserved);
static struct kobj_attribute lwkmem_request_attr = __ATTR_WO(lwkmem_request);
static struct kobj_attribute lwkmem_debug_attr = __ATTR_RW(lwkmem_debug);
static struct kobj_attribute lwkprocesses_attr = __ATTR_RO(lwkprocesses);
static struct kobj_attribute lwkcpus_sequence_attr =
						__ATTR_WO(lwkcpus_sequence);
static struct kobj_attribute lwk_util_threads_attr =
						__ATTR_WO(lwk_util_threads);
static struct kobj_attribute lwk_options_attr = __ATTR_WO(lwk_options);
static struct kobj_attribute lwkmem_domain_info_attr =
						__ATTR_WO(lwkmem_domain_info);

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
	&lwkmem_debug_attr.attr,
	&lwkprocesses_attr.attr,
	&lwkcpus_sequence_attr.attr,
	&lwk_util_threads_attr.attr,
	&lwk_options_attr.attr,
	&lwkmem_domain_info_attr.attr,
	&lwkcpus_syscall_attr.attr,
	&lwkcpus_syscall_mask_attr.attr,
	NULL
};

static struct attribute_group mos_attr_group = {
	.attrs = mos_attributes,
};

static int __init mos_sysfs_init(void)
{

	int ret;
	unsigned cpu;

	if (!zalloc_cpumask_var(&lwkcpus_map, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_syscall_map, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_reserved_map, GFP_KERNEL)) {
		pr_warn("CPU mask allocation failed.\n");
		ret = -ENOMEM;
		goto out;
	}

	for_each_possible_cpu(cpu) {
		cpumask_or(lwkcpus_map, lwkcpus_map,
			   per_cpu_ptr(&lwkcpus_mask, cpu));
		if (cpumask_test_cpu(cpu, lwkcpus_map)) {
			cpumask_or(lwkcpus_syscall_map, lwkcpus_syscall_map,
				per_cpu_ptr(&mos_syscall_mask, cpu));
		}
	}

	scnprintf(cpulist_buf, sizeof(cpulist_buf), "%*pbl",
			cpumask_pr_args(lwkcpus_map));
	pr_info("Assigned LWK CPUs: %s\n", cpulist_buf);

	mos_kobj = kobject_create_and_add("mOS", kernel_kobj);

	if (!mos_kobj) {
		ret = -ENOMEM;
		goto out;
	}

	lwkcpus_request_attr.attr.mode |= (S_IWUSR | S_IWGRP);
	lwkcpus_request_mask_attr.attr.mode |= (S_IWUSR | S_IWGRP);
	lwkmem_request_attr.attr.mode |= (S_IWUSR | S_IWGRP);
	lwkcpus_sequence_attr.attr.mode |= (S_IWUSR | S_IWGRP);
	lwk_util_threads_attr.attr.mode |= (S_IWUSR | S_IWGRP);

	ret = sysfs_create_group(mos_kobj, &mos_attr_group);
	if (ret) {
		pr_warn("mOS: could not create lwkcpus entry in sysfs\n");
		goto out;
	}
	return 0;

out:
	return ret;
}

subsys_initcall(mos_sysfs_init);

#endif /* CONFIG_MOS_FOR_HPC */
