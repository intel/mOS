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

#ifndef _LINUX_MOS_H
#define _LINUX_MOS_H


#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/cpuhotplug.h>
#include <linux/mm.h>
#include <linux/mosras.h>
#include <linux/moslwkmem.h>
#include <linux/bitmap.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>

#ifdef CONFIG_MOS_FOR_HPC
/*
 * task->mos_flags
 */
#define MOS_IS_LWK_PROCESS	1    /* bit 0 */

#define MOS_VIEW_POS		1
/* Bit 2,1                       */
/*     0, 0  --> Linux view      */
/*     0, 1  --> LWK global view */
/*     1, 0  --> LWK local  view */
/*     1, 1  --> All view        */
#define MOS_VIEW_MASK		(3UL << MOS_VIEW_POS)
#define MOS_VIEW_LINUX		(0UL << MOS_VIEW_POS)
#define MOS_VIEW_LWK		(1UL << MOS_VIEW_POS)
#define MOS_VIEW_LWK_LOCAL      (2UL << MOS_VIEW_POS)
#define MOS_VIEW_ALL		(3UL << MOS_VIEW_POS)
#define MOS_VIEW_DEFAULT	MOS_VIEW_ALL
#define MOS_VIEW_STR_LEN	20
#define MOS_VIEW_STR_LINUX	"linux"
#define MOS_VIEW_STR_LWK	"lwk"
#define MOS_VIEW_STR_LWK_LOCAL	"lwk-local"
#define MOS_VIEW_STR_ALL	"all"

#define CLR_MOS_VIEW(task) \
	((task)->mos_flags &= ~MOS_VIEW_MASK)
#define SET_MOS_VIEW(task, view) 				\
	do {							\
		CLR_MOS_VIEW(task);				\
		(task)->mos_flags |= ((view) & MOS_VIEW_MASK);	\
	} while (0)
#define IS_MOS_VIEW(task, view) \
	(((task)->mos_flags & MOS_VIEW_MASK) == ((view) & MOS_VIEW_MASK))
#define is_mostask() (current->mos_flags & MOS_IS_LWK_PROCESS)
#define is_lwk_process(task) (task->mos_flags & MOS_IS_LWK_PROCESS)
#define cpu_lwkcpus_mask this_cpu_ptr(&lwkcpus_mask)
#define cpu_islwkcpu(cpu) cpumask_test_cpu((cpu), cpu_lwkcpus_mask)
#define mos_lwkcpus_arg (&__mos_lwkcpus_arg)
#define mos_sccpus_arg (&__mos_sccpus_arg)
#define MOS_NR_GPUS 64
#define MOS_MAX_ALLOWED_DRIVERS 8

/*
 * Currently nr_gpumask_bits represents GPU devices. In the future sub-devices
 * (i.e. tiles) may be included in the mask. That is why we are not directly
 * using MOS_NR_GPUS for the specification of the gpu bit mask size.
 */
#define nr_gpumask_bits	MOS_NR_GPUS
#else
#define MOS_VIEW_LINUX		0
#define MOS_VIEW_LWK		0
#define MOS_VIEW_LWK_LOCAL	0
#define MOS_VIEW_ALL		0
#define MOS_VIEW_DEFAULT	0
#define CLR_MOS_VIEW(task)
#define SET_MOS_VIEW(task, view)
#define IS_MOS_VIEW(task, view) false
#define is_mostask() false
#define is_lwk_process(task) false
#define cpu_lwkcpus_mask NULL
#define cpu_islwkcpu(cpu) false
#define mos_lwkcpus_arg NULL
#define mos_sccpus_arg NULL
#endif

#ifdef CONFIG_MOS_FOR_HPC

/* mOS definitions */
extern cpumask_t lwkcpus_mask;
extern cpumask_t mos_syscall_mask;
extern cpumask_t __mos_lwkcpus_arg;
extern cpumask_t __mos_sccpus_arg;

extern void mos_linux_enter(void);
extern void mos_linux_leave(void);
extern void mos_sysfs_update(void);
extern void mos_exit_thread(void);
extern void get_mos_view_cpumask(struct cpumask *dst,
			const struct cpumask *src);
extern ssize_t cpumap_print_mos_bitmap_to_buf(char *buf, const struct cpumask *mask, loff_t off, size_t count);
extern ssize_t cpumap_print_mos_list_to_buf(char *buf, const struct cpumask *mask, loff_t off, size_t count);
extern ssize_t cpumap_print_mos_view_cpumask(bool list, char *buf, const struct cpumask *mask);
extern bool mos_is_allowed_interrupt(struct irq_desc *desc);

typedef struct gpumask { DECLARE_BITMAP(bits, nr_gpumask_bits); } gpumask_t;

struct mos_process_t {
	struct list_head list;
	pid_t tgid;
	atomic_t alive;
	cpumask_var_t lwkcpus;
	cpumask_var_t utilcpus;
	gpumask_t lwkgpus;

	/* Array of CPUs ordered by allocation sequence */
	int *lwkcpus_sequence;

	/* Are we still yod? */
	struct mm_struct *yod_mm;

	/* Number of LWK CPUs for this process */
	int num_lwkcpus;

	/* Number of utility threads */
	int num_util_threads;

#ifdef CONFIG_MOS_LWKMEM
	/* Memory attributes go here */
#endif

#ifdef CONFIG_MOS_SCHEDULER
	/* Scheduler attributes go here */
#endif
};

#if MAX_NUMNODES > 64
typedef unsigned long *numa_nodes_t;

static inline bool zalloc_numa_nodes_array(numa_nodes_t *node_pp)
{
	*node_pp = kzalloc(sizeof(unsigned long) * MAX_NUMNODES, GFP_KERNEL);
	return *node_pp != NULL;
}

#define free_numa_nodes_array(node_p) kfree(node_p)

#else
typedef unsigned long numa_nodes_t[MAX_NUMNODES];

static inline bool clear_numa_nodes_array(numa_nodes_t *nodes, unsigned long n)
{
	while (n)
		(*nodes)[--n] = 0;
	return true;
}

#define zalloc_numa_nodes_array(a) clear_numa_nodes_array(a, ARRAY_SIZE(*a))
#define free_numa_nodes_array(a)
#endif

extern int mos_register_option_callback(const char *name,
		int (*callback)(const char *, struct mos_process_t *));
extern int mos_unregister_option_callback(const char *name,
		  int (*callback)(const char *, struct mos_process_t *));

struct mos_process_callbacks_t {
	int (*mos_process_init)(struct mos_process_t *);
	int (*mos_process_start)(struct mos_process_t *);
	void (*mos_thread_exit)(struct mos_process_t *);
	void (*mos_process_exit)(struct mos_process_t *);
};

extern int mos_register_process_callbacks(struct mos_process_callbacks_t *);
extern int mos_unregister_process_callbacks(struct mos_process_callbacks_t *);

extern int lwkmem_get(unsigned long *mem, size_t *n) __attribute__((weak));
extern int lwkmem_reserved_get(unsigned long  *mem, size_t *n)
	__attribute__((weak));
extern int lwkmem_request(struct mos_process_t *mos_p, unsigned long *mem,
	size_t n) __attribute__((weak));
extern int lwkmem_get_debug_level(void) __attribute__((weak));
extern void lwkmem_set_debug_level(int level) __attribute__((weak));
extern void lwkmem_release(struct mos_process_t *mos_p) __attribute__((weak));
extern int lwkmem_set_mempolicy_info(const char *buff, size_t size)
	__attribute__((weak));

/* Needed by LWKCTL module to trigger the creation of default LWK partition */
extern int lwk_config_lwkcpus(char *param_value, char *profile);
extern int lwk_config_lwkmem(char *param_value);

/*
 * Function exposed by LWK control to trigger the creation of default LWK part-
 * -ition as specified in Linux command line. This function is called from
 * init/main.c during kernel bootup.
 */
extern void lwkctl_def_partition(void);

#ifdef CONFIG_MOS_SCHEDULER
/* Scheduler additions go here */
#endif

/* The definitions below are Linux definitions. They are collected here for
 * several reasons:
 * 1). They get used in several mOS files; defining them once makes sense
 * 2). This list gives a sense of how intertwined or dependent on Linux mOS is
 * 3). An early warning system for when these definitions change in future
 *         Linux kernels and the mOS code has to adjust
 * 4). Indicate when we change a static Linux definition because we need
 *         access to it from within mOS
 * Make use to include mos.h in Linux files that needed changes in 4.)
 */
extern int do_cpu_up(unsigned int cpu, enum cpuhp_state target);
extern int do_cpu_down(unsigned int cpu, enum cpuhp_state target);

#else
static inline int lwk_config_lwkcpus(char *parm_value, char *p) { return -1; }
static inline int lwk_config_lwkmem(char *parm_value) { return -1; }
static inline void lwkctl_def_partition(void) {}
static inline void get_mos_view_cpumask(struct cpumask *dst,
				const struct cpumask *src) {}
static inline ssize_t cpumap_print_mos_view_cpumask(char *buf, const struct cpumask *mask, loff_t off, size_t count) { return -1; }
static inline bool mos_is_allowed_interrupt(struct irq_desc *desc) { return true; }
#endif /* CONFIG_MOS_FOR_HPC */
#endif /* _LINUX_MOS_H */
