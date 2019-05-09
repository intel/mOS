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


#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/cpuhotplug.h>
#include <linux/mm.h>
#include <linux/mosras.h>
#include <linux/elf.h>

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

extern void mos_linux_enter(void *sys_wrap);
extern void mos_linux_leave(void);
extern void mos_sysfs_update(void);
extern void mos_exit_thread(void);
extern void get_mos_view_cpumask(struct cpumask *dst,
			const struct cpumask *src);
extern ssize_t cpumap_print_mos_view_cpumask(bool list,
			char *buf, const struct cpumask *mask);

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
enum lwkmem_kind_t {kind_4k = 0, kind_2m, kind_1g, kind_last};
#else
enum lwkmem_kind_t {kind_4k = 0, kind_4m, kind_1g, kind_last};
#endif
extern unsigned long lwk_page_shift[];
enum lwkmem_type_t {lwkmem_dram = 0, lwkmem_hbm, lwkmem_nvram, lwkmem_type_last };
enum allocate_site_t {
	lwkmem_mmap = 0,
	lwkmem_brk = 1,
	lwkmem_static = 2,
	lwkmem_stack = 3,
	lwkmem_site_last = 4
};
enum attachment_align_stats_t {
	ALIGN_ELIGIBLE = 0,
	ALIGN_NOT_ELIGIBLE,
	ALIGN_SUCCESS,
	ALIGN_SUCCESS_HP,
	ALIGN_FAIL_MAPFIXED,
	ALIGN_FAIL_LINUXVMA,
	ALIGN_FAIL_SRCPGSZ,
	ALIGN_FAIL_NOVM,
	ALIGN_FAIL_ERROR,
	ALIGN_STAT_END
};

struct mos_process_t {
	struct list_head list;
	pid_t tgid;
	atomic_t alive;
	cpumask_var_t lwkcpus;
	cpumask_var_t utilcpus;

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

        /* Amount of memory reseved for this process */
        int64_t lwkmem;

        /* Phys memory regions reserved for this process */
        struct list_head lwkmem_list;

        /* Lists of blocks of each kind partitioned for this process */
	struct list_head free_list[kind_last][MAX_NUMNODES];
	struct list_head busy_list[kind_last][MAX_NUMNODES];

        /* Number of blocks available of each kind */
        int64_t num_blks[kind_last];

	/* brk line for lwkmem heap management */
	unsigned long brk;

	/* end of heap region (minus one).  This may move beyond the
	 * brk value when backing heap with large pages and thus
	 * mapping a region that exceeds the brk line.
	 */
	unsigned long brk_end;

	/* Disable LWK-memory backed heap */
	bool lwkmem_brk_disable;

	int64_t max_page_size;
	int64_t heap_page_size;

	int domain_info[lwkmem_type_last][MAX_NUMNODES];
	int domain_info_len[lwkmem_type_last];
	int domain_order_index[lwkmem_type_last][kind_last];
	bool lwkmem_interleave_disable;
	int lwkmem_interleave;

	struct memory_preference_t {
		enum lwkmem_type_t lower_type_order[lwkmem_type_last];
		enum lwkmem_type_t upper_type_order[lwkmem_type_last];
		unsigned long threshold;
	} memory_preference[lwkmem_site_last];

	bool lwkmem_load_elf_segs;

	unsigned long lwkmem_mmap_aligned_threshold;
	unsigned long lwkmem_mmap_alignment;
	unsigned long lwkmem_next_addr;

	/* Total number of blocks used (allocated). */
	unsigned long blks_allocated[kind_last][MAX_NUMNODES];
	unsigned long blks_in_use[kind_last][MAX_NUMNODES];
	unsigned long max_allocated[MAX_NUMNODES];
	bool report_blks_allocated;

	long brk_clear_len;
	unsigned long trace_block_list_addr;
	bool trace_block_list_details;

	unsigned int lwkmem_zeroes_check;
	bool lwkmem_prot_none_delegation;

	/* XPMEM counters */
	bool report_xpmem_stats;
	unsigned long src_pgmap[kind_last][kind_last];
	unsigned long dst_pgmap[kind_last][kind_last];
	unsigned long attachment_align_stats[ALIGN_STAT_END];

#endif

#ifdef CONFIG_MOS_SCHEDULER
	/* Scheduler attributes go here */

	/* Count of threads created */
	atomic_t threads_created;
	/* Original cpus_allowed mask at launch */
	cpumask_var_t original_cpus_allowed;
	/* Correctable machine check interrupt polling */
	bool mce_modifications_active;
	/* Control migration of system calls */
	bool move_syscalls_disable;
	/* Enabled round-robin threads. Value=timeslice in ms */
	int enable_rr;
	/* Idle control fields */
	int idle_mechanism;
	int idle_boundary;
	/* Disable sched_setaffinity. Value = errno+1 */
	int disable_setaffinity;
	/* Logging verbosity for scheduler statistics */
	int sched_stats;
	/* Maximum number of lwkcpus for utility thread use */
	int max_cpus_for_util;
	/* Maximum number of util threads per lwkcpu */
	int max_util_threads_per_cpu;
	/* Overcommit behavior */
	int overcommit_behavior;
	/* One CPU or multiple CPUs allowed for a utility thread */
	int allowed_cpus_per_util;
	/* Correcable machine check interrupt enablement and threshold */
	unsigned int cmci_threshold;
	/* Correcable machine check polling enablement */
	bool correctable_mcheck_polling;
	/* List of utility threads on LWK CPUs */
	struct list_head util_list;
	/* Mutex for controlling the util_list */
	struct mutex util_list_lock;

	bool track_syscall_migrations;
	struct mutex track_syscalls_lock;
	struct {
		void *func;
		unsigned int count;
	} migrations[64];
#endif
};

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
extern int lwkmem_set_domain_info(struct mos_process_t *mos_p,
	       enum lwkmem_type_t typ, unsigned long *nids,
	       size_t n) __attribute__((weak));

/* Needed by LWKCTL module to trigger the creation of default LWK partition */
extern int lwk_config_lwkcpus(char *param_value, char *profile);
extern int lwk_config_lwkmem(char *param_value);

/*
 * Function exposed by LWK control to trigger the creation of default LWK part-
 * -ition as specified in Linux command line. This function is called from
 * init/main.c during kernel bootup.
 */
extern void lwkctl_def_partition(void);
#ifdef CONFIG_MOS_LWKMEM
/* Memory additions go here */
#include <linux/page-flags.h>

#define is_lwkmem(vma)  ((vma)->vm_flags & VM_LWK)
#define is_lwkxpmem(vma) ((vma)->vm_flags & VM_LWK_XPMEM)
#define _LWKPG          (0x4c574b4dul)
#define is_lwkpg(page)  ((((page)->private) & 0xffffffff) == _LWKPG)
#define _LWKPG_DIRTY    (0x100000000ul)
#define is_lwkpg_dirty(page) (((page)->private) & _LWKPG_DIRTY)
#define set_lwkpg_dirty(page) ((page)->private |= _LWKPG_DIRTY)
#define clear_lwkpg_dirty(page) ((page)->private &= ~_LWKPG_DIRTY)

struct vma_subregion {
	/* Start and End of the sub-region */
	unsigned long start;
	unsigned long end;
	/* Entry in the list of regions */
	struct list_head list;
};

struct vma_xpmem_private {
	void *private_data;
	struct mutex subregions_lock;
	struct list_head subregions;
};

extern struct page *lwkmem_user_to_page(struct mm_struct *mm,
					unsigned long addr,
					unsigned int *size);
extern void lwkmem_available(unsigned long *totalraam, unsigned long *freeraam);

extern unsigned long elf_map_to_lwkmem(unsigned long addr, unsigned long size,
					int prot, int type);
extern long elf_unmap_from_lwkmem(unsigned long addr, unsigned long size);
extern void unmap_lwkmem_range(struct mmu_gather *tlb,
			struct vm_area_struct *vma, unsigned long start,
			unsigned long end, struct zap_details *details);
extern void si_meminfo_node_mos(struct sysinfo *val, int nid);
/*
 * mOS memory management interfaces exported to support XPMEM
 * device driver. These interfaces work only on LWK XPMEM VMAs.
 */
extern void set_xpmem_private_data(struct vm_area_struct *vma, void *data);
extern void *get_xpmem_private_data(struct vm_area_struct *vma);
extern struct vm_area_struct *create_lwkxpmem_vma(struct mm_struct *src_mm,
					unsigned long src_start,
					unsigned long dst_start,
					unsigned long len,
					unsigned long prot,
					void *vm_private_data,
					const struct vm_operations_struct *ops);
extern int copy_lwkmem_to_lwkxpmem(struct vm_area_struct *src_vma,
			unsigned long src_start,
			struct vm_area_struct *dst_vma,
			unsigned long dst_start, unsigned long len);
extern void release_lwkxpmem_vma(struct vm_area_struct *vma);
#else
#define is_lwkmem(vma) 0
#define is_lwkxpmem(vma) 0
#define is_lwkpg(page) 0
static inline void unmap_lwkmem_range(struct mmu_gather *tlb,
			struct vm_area_struct *vma, unsigned long start,
			unsigned long end, struct zap_details *details) {}
static void si_meminfo_node_mos(struct sysinfo *val, int nid) {}
inline void set_xpmem_private_data(struct vm_area_struct *vma, void *data)
		{ if (vma) vma->vm_private_data = data; }
inline void *get_xpmem_private_data(struct vm_area_struct *vma)
		{ return  vma ? vma->vm_private_data : NULL; }
inline struct vm_area_struct *create_lwkxpmem_vma(struct mm_struct *src_mm,
					unsigned long src_start,
					unsigned long dst_start,
					unsigned long len,
					unsigned long prot,
					void *vm_private_data,
					const struct vm_operations_struct *ops)
					{ return NULL; }
inline int copy_lwkmem_to_lwkxpmem(struct vm_area_struct *src_vma,
			unsigned long src_start,
			struct vm_area_struct *dst_vma,
			unsigned long dst_start, unsigned long len)
			{ return -1; }
inline void release_lwkxpmem_vma(struct vm_area_struct *vma) { }
#endif /* CONFIG_MOS_LWKMEM */


#ifdef CONFIG_MOS_SCHEDULER
/* Scheduler additions go here */
extern void mce_lwkprocess_begin(cpumask_t *lwkcpus, unsigned int threshold,
				 bool poll_enable);
extern void mce_lwkprocess_end(cpumask_t *lwkcpus, bool reset_threshold,
				bool reenable_poll);

enum mos_match_cpu {
	mos_match_cpu_FirstAvail = 0,
	mos_match_cpu_SameCore,
	mos_match_cpu_SameL1,
	mos_match_cpu_SameL2,
	mos_match_cpu_SameL3,
	mos_match_cpu_SameDomain,
	mos_match_cpu_OtherCore,
	mos_match_cpu_OtherL1,
	mos_match_cpu_OtherL2,
	mos_match_cpu_OtherL3,
	mos_match_cpu_OtherDomain,
	mos_match_cpu_InNMask,
};
enum mos_commit_cpu_scope {
	mos_commit_cpu_scope_AllCommits = 0,
	mos_commit_cpu_scope_OnlyComputeCommits,
	mos_commit_cpu_scope_OnlyUtilityCommits,
};

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

#ifdef CONFIG_MOS_LWKMEM
extern int find_vma_links(struct mm_struct *mm, unsigned long addr,
			  unsigned long end, struct vm_area_struct **pprev,
			  struct rb_node ***rb_link, struct rb_node **rb_parent);

extern void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
		     struct vm_area_struct *prev, struct rb_node **rb_link,
		     struct rb_node *rb_parent);

extern void unmap_page_range(struct mmu_gather *tlb,
			     struct vm_area_struct *vma,
			     unsigned long addr, unsigned long end,
			     struct zap_details *details);
#endif

#else
static inline int lwk_config_lwkcpus(char *parm_value, char *p) { return -1; }
static inline int lwk_config_lwkmem(char *parm_value) { return -1; }
static inline void lwkctl_def_partition(void) {}
static inline void get_mos_view_cpumask(struct cpumask *dst,
				const struct cpumask *src) {}
static inline ssize_t cpumap_print_mos_view_cpumask(bool list,
			char *buf, const struct cpumask *mask) { return -1; }
static void si_meminfo_node_mos(struct sysinfo *val, int nid) {}
#define is_lwkmem(vma) 0
#define is_lwkxpmem(vma) 0
#define is_lwkpg(page) 0

inline void set_xpmem_private_data(struct vm_area_struct *vma, void *data)
		{ if (vma) vma->vm_private_data = data; }
inline void *get_xpmem_private_data(struct vm_area_struct *vma)
		{ return  vma ? vma->vm_private_data : NULL; }
inline struct vm_area_struct *create_lwkxpmem_vma(struct mm_struct *src_mm,
					unsigned long src_start,
					unsigned long dst_start,
					unsigned long len,
					unsigned long prot,
					void *vm_private_data,
					const struct vm_operations_struct *ops)
					{ return NULL; }
inline int copy_lwkmem_to_lwkxpmem(struct vm_area_struct *src_vma,
			unsigned long src_start,
			struct vm_area_struct *dst_vma,
			unsigned long dst_start, unsigned long len)
			{ return -1; }
inline void release_lwkxpmem_vma(struct vm_area_struct *vma) { }
#endif /* CONFIG_MOS_FOR_HPC */
#endif /* _LINUX_MOS_H */
