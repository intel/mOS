/*
 * Multi Operating System (mOS)
 * Copyright (c) 2017-2020, Intel Corporation.
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

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mos
#define TRACE_INCLUDE_FILE lwkmem

#if !defined(_TRACE_LWKMEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LWKMEM_H

#include <linux/mman.h>
#include <linux/mempolicy.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>
#include <linux/mos.h>

#define show_mmap_flags(flags) 			\
	(flags) ? __print_flags(flags, ",", 	\
	{MAP_SHARED, "shared"},			\
	{MAP_PRIVATE,  "private"},		\
	{MAP_FIXED, "fixed"},			\
	{MAP_ANONYMOUS, "anonymous"},		\
	{MAP_32BIT, "32-bit"},			\
	{MAP_GROWSDOWN, "grows-down"},		\
	{MAP_DENYWRITE, "denywrite"},		\
	{MAP_EXECUTABLE, "executable"}, 	\
	{MAP_LOCKED, "locked"},			\
	{MAP_NORESERVE, "no-reserve"},		\
	{MAP_POPULATE, "populate"},		\
	{MAP_NONBLOCK, "non-block"},		\
	{MAP_STACK, "stack"},			\
	{MAP_HUGETLB, "hugetlb"}) : "none"	\

#define show_mmap_prot(prot) \
	(prot) ? __print_flags(prot, ",", \
	{PROT_EXEC, "exec"}, \
	{PROT_READ, "read"}, \
	{PROT_WRITE, "write"}) : "none"

TRACE_EVENT(mos_mmap,

	TP_PROTO(unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flags, long ret, int tgid),

	TP_ARGS(addr, len, prot, flags, ret, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(unsigned long, prot)
		__field(unsigned long, flags)
		__field(unsigned long, ret)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->len = len;
		__entry->prot = prot;
		__entry->flags = flags;
		__entry->ret = ret;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx len=%ld prot=%s flags=%s addr_ret=%lx tgid=%d",
		__entry->addr, __entry->len, show_mmap_prot(__entry->prot),
		show_mmap_flags(__entry->flags), __entry->ret, __entry->tgid)
);

TRACE_EVENT(mos_munmap,

	TP_PROTO(unsigned long addr, unsigned long len,
		long ret, int tgid),

	TP_ARGS(addr, len, ret, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(unsigned long, ret)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->len = len;
		__entry->ret = ret;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx len=%ld addr_ret=%lx tgid=%d",
		__entry->addr, __entry->len,
		__entry->ret, __entry->tgid)
);

#define show_mremap_flags(flags) 		\
	(flags) ? __print_flags(flags, ",", 	\
	{MREMAP_MAYMOVE, "may-move"},		\
	{MREMAP_FIXED, "fixed"}) : "none"	\

TRACE_EVENT(mos_mremap,

	TP_PROTO(unsigned long addr, unsigned long old_len,
		unsigned long new_len, int flags, unsigned long new_addr,
		long ret, int tgid),

	TP_ARGS(addr, old_len, new_len, flags, new_addr, ret, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, old_len)
		__field(unsigned long, new_len)
		__field(int, flags)
		__field(unsigned long, new_addr)
		__field(long, ret)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->old_len = old_len;
		__entry->new_len = new_len;
		__entry->flags = flags;
		__entry->new_addr = new_addr;
		__entry->ret = ret;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx olen=%ld nlen=%ld flags=%s new_addr=%lx ret=%lx tgid=%d",
		__entry->addr, __entry->old_len, __entry->new_len,
		show_mremap_flags(__entry->flags),
		__entry->new_addr, __entry->ret, __entry->tgid)
);


TRACE_EVENT(mos_brk,

	TP_PROTO(unsigned long brk, unsigned long brk_end,
		unsigned long clear_len, void *clear_addr, int tgid),

	TP_ARGS(brk, brk_end, clear_len, clear_addr, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, brk)
		__field(unsigned long, brk_end)
		__field(unsigned long, clear_len)
		__field(void *, clear_addr)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->brk = brk;
		__entry->brk_end = brk_end;
		__entry->clear_len = clear_len;
		__entry->clear_addr = clear_addr;
		__entry->tgid = tgid;
	),

	TP_printk("brk=%lx brk_end=%lx clr_addr=%lx clr_len=%ld tgid=%d",
			__entry->brk,
			__entry->brk_end,
			(unsigned long)__entry->clear_addr,
			__entry->clear_len,
			__entry->tgid)
);

#ifdef CREATE_TRACE_POINTS

static char *behavior2str(int behavior)
{
	switch (behavior) {
	case MADV_NORMAL: return "normal";
	case MADV_RANDOM: return "random";
	case MADV_SEQUENTIAL: return "sequential";
	case MADV_WILLNEED: return "will-need";
	case MADV_DONTNEED: return "dont-need";
	case MADV_FREE: return "free";
	case MADV_REMOVE: return "remove";
	case MADV_DONTFORK: return "dont-fork";
	case MADV_DOFORK: return "do-fork";
	case MADV_HWPOISON: return "hw-poison";
	case MADV_SOFT_OFFLINE: return "soft-offline";
	case MADV_MERGEABLE: return "mergeable";
	case MADV_UNMERGEABLE: return "unmergable";
	case MADV_HUGEPAGE: return "hugepage";
	case MADV_NOHUGEPAGE: return "no-hugepage";
	case MADV_DONTDUMP: return "dont-dump";
	case MADV_DODUMP: return "do-dump";
	default: return "???";
	}
}

#endif

TRACE_EVENT(mos_madvise,

	TP_PROTO(unsigned long addr, unsigned long len, int behavior,
		int ret, int tgid),

	TP_ARGS(addr, len, behavior, ret, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(int, behavior)
		__field(int, ret)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->len = len;
		__entry->behavior = behavior;
		__entry->ret = ret;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx len=%ld behavior=%s ret=%d tgid=%d",
		__entry->addr,
		__entry->len,
		behavior2str(__entry->behavior),
		__entry->ret,
		__entry->tgid)
);

#ifdef CREATE_TRACE_POINTS

static char *show_mbind_policy(int mode)
{
	switch (mode) {
	case MPOL_DEFAULT: return "default";
	case MPOL_PREFERRED: return "preferred";
	case MPOL_BIND: return "bind";
	case MPOL_INTERLEAVE: return "interleave";
	case MPOL_LOCAL: return "local";
	default: return "???";
	}
}

#endif

#define show_mbind_policy_flags(mode) 			\
	(mode) ? __print_flags(mode, ",", 		\
	{MPOL_F_STATIC_NODES, "static"}, 		\
	{MPOL_F_RELATIVE_NODES, "relative"}) : "none" 	\

#define show_mbind_flags(flags) 			\
	(flags) ? __print_flags(flags, ",", 		\
	{MPOL_MF_STRICT, "strict"},			\
	{MPOL_MF_MOVE, "move"},				\
	{MPOL_MF_MOVE_ALL, "move-all"}) : "none"	\

TRACE_EVENT(mos_mbind,

	TP_PROTO(unsigned long addr, unsigned long len,
		int mode, unsigned int flags, long ret,
		int tgid),

	TP_ARGS(addr, len, mode, flags, ret, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(int, mode)
		__field(unsigned int, flags)
		__field(long, ret)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->len = len;
		__entry->mode = mode;
		__entry->flags = flags;
		__entry->ret = ret;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx len=%ld mode=%s,%s flags=%s ret=%ld tgid=%d",
		__entry->addr,
		__entry->len,
		show_mbind_policy(__entry->mode & ~MPOL_MODE_FLAGS),
		show_mbind_policy_flags(__entry->mode & MPOL_MODE_FLAGS),
		show_mbind_flags(__entry->flags),
		__entry->ret,
		__entry->tgid)
);

#define show_mprotect_prot(prot) 		\
	(prot) ? __print_flags(prot, ",", 	\
	{PROT_EXEC, "exec"}, 			\
	{PROT_READ, "read"}, 			\
	{PROT_WRITE, "write"}, 			\
	{PROT_SEM, "sem"}, 			\
	{PROT_GROWSDOWN, "grows-down"}, 	\
	{PROT_GROWSUP, "grows-up"}) : "none"	\

TRACE_EVENT(mos_mprotect,

	TP_PROTO(unsigned long addr, unsigned long len,
		int prot, long ret,
		int tgid),

	TP_ARGS(addr, len, prot, ret, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(int, prot)
		__field(long, ret)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->len = len;
		__entry->prot = prot;
		__entry->ret = ret;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx len=%ld prot=%s ret=%lx tgid=%d",
		__entry->addr,
		__entry->len,
		show_mprotect_prot(__entry->prot),
		__entry->ret,
		__entry->tgid)
);

TRACE_EVENT(mos_elf_map,

	TP_PROTO(unsigned long addr, unsigned long len,
		int prot, int type, int tgid),

	TP_ARGS(addr, len, prot, type, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(int, prot)
		__field(int, type)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->len = len;
		__entry->prot = prot;
		__entry->type = type;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx len=%ld prot=%s type=%x tgid=%d",
		__entry->addr,
		__entry->len,
		show_mmap_prot(__entry->prot),
		__entry->type,
		__entry->tgid)
);

TRACE_EVENT(mos_lwkpage_dirty_error,
	TP_PROTO(unsigned long pfn),
	TP_ARGS(pfn),
	TP_STRUCT__entry(__field(unsigned long, pfn)),
	TP_fast_assign(__entry->pfn = pfn;),
	TP_printk("pfn %ld was dirty during allocation!", __entry->pfn)
);

TRACE_EVENT(mos_build_lwkxpmem_pagetbl,

	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long vstart, unsigned long vend,
		 unsigned long pfn_start, unsigned long pfn_end,
		 unsigned long page_type, int status),

	TP_ARGS(vma_start, vma_end, vstart, vend, pfn_start, pfn_end,
		page_type, status),

	TP_STRUCT__entry(
		__field(unsigned long, vma_start)
		__field(unsigned long, vma_end)
		__field(unsigned long, vstart)
		__field(unsigned long, vend)
		__field(unsigned long, pfn_start)
		__field(unsigned long, pfn_end)
		__field(unsigned long, page_type)
		__field(int, status)
	),

	TP_fast_assign(
		__entry->vma_start = vma_start;
		__entry->vma_end = vma_end;
		__entry->vstart = vstart;
		__entry->vend = vend;
		__entry->pfn_start = pfn_start;
		__entry->pfn_end = pfn_end;
		__entry->page_type = page_type;
		__entry->status = status;
	),

	TP_printk("vma=[%lx-%lx) range=[%lx-%lx) pfn=[%ld-%ld) knd %ld rc=%d",
		__entry->vma_start,
		__entry->vma_end,
		__entry->vstart,
		__entry->vend,
		__entry->pfn_start,
		__entry->pfn_end,
		__entry->page_type,
		__entry->status)
);

TRACE_EVENT(mos_clear_lwkxpmem_pagetbl,

	TP_PROTO(unsigned long vstart, unsigned long vend),

	TP_ARGS(vstart, vend),

	TP_STRUCT__entry(
		__field(unsigned long, vstart)
		__field(unsigned long, vend)
	),

	TP_fast_assign(
		__entry->vstart = vstart;
		__entry->vend = vend;
	),

	TP_printk("range=[%lx-%lx)",
		__entry->vstart,
		__entry->vend)
);

TRACE_EVENT(mos_insert_vma_subregion,

	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long vma_sub_start, unsigned long vma_sub_end,
		 int status),

	TP_ARGS(vma_start, vma_end, vma_sub_start, vma_sub_end, status),

	TP_STRUCT__entry(
		__field(unsigned long, vma_start)
		__field(unsigned long, vma_end)
		__field(unsigned long, vma_sub_start)
		__field(unsigned long, vma_sub_end)
		__field(int, status)
	),

	TP_fast_assign(
		__entry->vma_start = vma_start;
		__entry->vma_end = vma_end;
		__entry->vma_sub_start = vma_sub_start;
		__entry->vma_sub_end = vma_sub_end;
		__entry->status = status;
	),

	TP_printk("vma=[%lx-%lx) vma_sub=[%lx-%lx) rc=%d",
		__entry->vma_start,
		__entry->vma_end,
		__entry->vma_sub_start,
		__entry->vma_sub_end,
		__entry->status)
);

DECLARE_EVENT_CLASS(mos_lwkxpmem_range,

	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long vstart, unsigned long vend,
		 unsigned long status),

	TP_ARGS(vma_start, vma_end, vstart, vend, status),

	TP_STRUCT__entry(
		__field(unsigned long, vma_start)
		__field(unsigned long, vma_end)
		__field(unsigned long, vstart)
		__field(unsigned long, vend)
		__field(int, status)
	),

	TP_fast_assign(
		__entry->vma_start = vma_start;
		__entry->vma_end = vma_end;
		__entry->vstart = vstart;
		__entry->vend = vend;
		__entry->status = status;
	),

	TP_printk("vma=[%lx-%lx) range=[%lx-%lx) rc=%d",
		__entry->vma_start,
		__entry->vma_end,
		__entry->vstart,
		__entry->vend,
		__entry->status)
);

DEFINE_EVENT(mos_lwkxpmem_range, mos_remove_vma_subregions,

	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long vstart, unsigned long vend,
		 unsigned long status),

	TP_ARGS(vma_start, vma_end, vstart, vend, status)
);

DEFINE_EVENT(mos_lwkxpmem_range, mos_unmap_lwkxpmem_range,

	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long vstart, unsigned long vend,
		 unsigned long status),

	TP_ARGS(vma_start, vma_end, vstart, vend, status)
);

TRACE_EVENT(mos_copy_lwkmem_to_lwkxpmem,

	TP_PROTO(unsigned long src_vma_start, unsigned long src_vma_end,
		 unsigned long src_start, unsigned long dst_vma_start,
		 unsigned long dst_vma_end, unsigned long dst_start,
		 unsigned long len, int status),

	TP_ARGS(src_vma_start, src_vma_end, src_start,
		dst_vma_start, dst_vma_end, dst_start,
		len, status),

	TP_STRUCT__entry(
		__field(unsigned long, src_vma_start)
		__field(unsigned long, src_vma_end)
		__field(unsigned long, src_start)
		__field(unsigned long, dst_vma_start)
		__field(unsigned long, dst_vma_end)
		__field(unsigned long, dst_start)
		__field(unsigned long, len)
		__field(int, status)
	),

	TP_fast_assign(
		__entry->src_vma_start = src_vma_start;
		__entry->src_vma_end = src_vma_end;
		__entry->src_start = src_start;
		__entry->dst_vma_start = dst_vma_start;
		__entry->dst_vma_end = dst_vma_end;
		__entry->dst_start = dst_start;
		__entry->len = len;
		__entry->status = status;
	),

	TP_printk("src vma=[%lx-%lx) range=[%lx-%lx) dst vma[%lx-%lx) range[%lx-%lx) rc=%d",
		__entry->src_vma_start,
		__entry->src_vma_end,
		__entry->src_start,
		__entry->src_start + __entry->len,
		__entry->dst_vma_start,
		__entry->dst_vma_end,
		__entry->dst_start,
		__entry->dst_start + __entry->len,
		__entry->status)
);

TRACE_EVENT(mos_create_lwkxpmem_vma,

	TP_PROTO(unsigned long src_start, unsigned long dst_start,
		 unsigned long len, unsigned long prot, void *vma_private,
		 const void *vma_ops, unsigned long vaddr),

	TP_ARGS(src_start, dst_start, len, prot, vma_private, vma_ops, vaddr),

	TP_STRUCT__entry(
		__field(unsigned long, src_start)
		__field(unsigned long, dst_start)
		__field(unsigned long, len)
		__field(unsigned long, prot)
		__field(void *, vma_private)
		__field(const void *, vma_ops)
		__field(unsigned long, vaddr)
	),

	TP_fast_assign(
		__entry->src_start = src_start;
		__entry->dst_start = dst_start;
		__entry->len = len;
		__entry->prot = prot;
		__entry->vma_private = vma_private;
		__entry->vma_ops = vma_ops;
		__entry->vaddr = vaddr;
	),

	TP_printk("src=[%lx-%lx) dst=[%lx-%lx) prot=%s private=%p ops=%p vaddr=%lx",
		__entry->src_start,
		__entry->src_start + __entry->len,
		__entry->dst_start,
		__entry->dst_start + __entry->len,
		show_mprotect_prot(__entry->prot),
		__entry->vma_private,
		__entry->vma_ops,
		__entry->vaddr)
);

TRACE_EVENT(mos_release_lwkxpmem_vma,

	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 bool is_lwkxpmem),

	TP_ARGS(vma_start, vma_end, is_lwkxpmem),

	TP_STRUCT__entry(
		__field(unsigned long, vma_start)
		__field(unsigned long, vma_end)
		__field(bool, is_lwkxpmem)
	),

	TP_fast_assign(
		__entry->vma_start = vma_start;
		__entry->vma_end = vma_end;
		__entry->is_lwkxpmem = is_lwkxpmem;
	),

	TP_printk("vma=[%lx-%lx) [%s]",
		__entry->vma_start,
		__entry->vma_end,
		__entry->is_lwkxpmem ? "LWKXPMEM" : "Linux")
);

TRACE_EVENT(mos_unmapped_region,

	TP_PROTO(unsigned long addr, unsigned long len,
		 unsigned long flags, int tgid),

	TP_ARGS(addr, len, flags, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(unsigned long, len)
		__field(unsigned long, flags)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->addr = addr;
		__entry->len = len;
		__entry->flags = flags;
		__entry->tgid = tgid;
	),

	TP_printk("addr=%lx len=%ld flags=%lx tgid=%d",
		__entry->addr, __entry->len,
		__entry->flags, __entry->tgid)
);

/*
 * LWK Buddy allocator trace events
 */
#ifdef CREATE_TRACE_POINTS

static char *lwk_pgtype(enum lwk_page_type pgtype)
{
	switch (pgtype) {
	case LWK_PG_4K: return "4k";
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
	case LWK_PG_2M: return "2m";
#else
	case LWK_PG_4M: return "4m";
#endif
	case LWK_PG_1G: return "1g";
	default: return "??";
	}
}

static char *lwk_pma_alloc_flag(enum lwk_pma_alloc_flags flags)
{
	switch (flags) {
	case PMA_ALLOC_NORMAL: return "normal";
	case PMA_ALLOC_CONTIG: return "contig";
	case PMA_ALLOC_RANDOM: return "random";
	default: return "??????";
	}
}

#endif

TRACE_EVENT(mos_buddy_list_sort,

	TP_PROTO(int order, unsigned long n),

	TP_ARGS(order, n),

	TP_STRUCT__entry(
		__field(int, order)
		__field(unsigned long, n)
	),

	TP_fast_assign(
		__entry->order = order,
		__entry->n = n
	),

	TP_printk(" order %3d list sorted %lu elements",
		__entry->order, __entry->n)
);

TRACE_EVENT(mos_buddy_search_contig_enter,

	TP_PROTO(int horder, int lorder, unsigned long n_horder,
		unsigned long n_needed),

	TP_ARGS(horder, lorder, n_horder, n_needed),

	TP_STRUCT__entry(
		__field(int, horder)
		__field(int, lorder)
		__field(unsigned long, n_horder)
		__field(unsigned long, n_needed)
	),

	TP_fast_assign(
		__entry->horder = horder;
		__entry->lorder = lorder;
		__entry->n_horder = n_horder;
		__entry->n_needed = n_needed;
	),

	TP_printk("horder %3d lorder %3d n_horder %lu n_needed %lu",
		__entry->horder,
		__entry->lorder,
		__entry->n_horder,
		__entry->n_needed)
);

TRACE_EVENT(mos_buddy_search_contig_exit,

	TP_PROTO(int horder, int lorder, unsigned long n_horder,
		unsigned long n_pages, unsigned long spfn),

	TP_ARGS(horder, lorder, n_horder, n_pages, spfn),

	TP_STRUCT__entry(
		__field(int, horder)
		__field(int, lorder)
		__field(unsigned long, n_horder)
		__field(unsigned long, n_pages)
		__field(unsigned long, spfn)
	),

	TP_fast_assign(
		__entry->horder = horder;
		__entry->lorder = lorder;
		__entry->n_horder = n_horder;
		__entry->n_pages = n_pages;
		__entry->spfn = spfn;
	),

	TP_printk(" horder %3d lorder %3d n_horder %lu n_total  %lu [ %#013lx- %#013lx )",
		__entry->horder, __entry->lorder, __entry->n_horder,
		__entry->n_pages, __entry->spfn,
		__entry->spfn + (__entry->n_pages << __entry->lorder))
);

TRACE_EVENT(mos_buddy_remove_contig,

	TP_PROTO(int horder, int lorder, unsigned long n_needed),

	TP_ARGS(horder, lorder, n_needed),

	TP_STRUCT__entry(
		__field(int, horder)
		__field(int, lorder)
		__field(unsigned long, n_needed)
	),

	TP_fast_assign(
		__entry->horder = horder;
		__entry->lorder = lorder;
		__entry->n_needed = n_needed;
	),

	TP_printk("horder %3d lorder %3d n_needed %lu",
		__entry->horder,
		__entry->lorder,
		__entry->n_needed)
);

TRACE_EVENT(mos_buddy_free_lwkpages_node,

	TP_PROTO(int nid, unsigned long spfn, unsigned long n, int order),

	TP_ARGS(nid, spfn, n, order),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(unsigned long, spfn)
		__field(unsigned long, n)
		__field(int, order)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->spfn = spfn;
		__entry->n = n;
		__entry->order = order;
	),

	TP_printk("node%3d [ %#013lx - %#013lx ) order %3d",
		__entry->nid, __entry->spfn,
		__entry->spfn + (__entry->n << __entry->order),
		__entry->order)
);

TRACE_EVENT(mos_free_lwkpages_range,

	TP_PROTO(unsigned long spfn, unsigned long n, int order),

	TP_ARGS(spfn, n, order),

	TP_STRUCT__entry(
		__field(unsigned long, spfn)
		__field(unsigned long, n)
		__field(int, order)
	),

	TP_fast_assign(
		__entry->spfn = spfn;
		__entry->n = n;
		__entry->order = order;
	),

	TP_printk("[ %#013lx - %#013lx ) order %3d",
		__entry->spfn,
		__entry->spfn + (__entry->n << __entry->order),
		__entry->order)
);

TRACE_EVENT(mos_buddy_alloc_contig,

	TP_PROTO(int order, unsigned long n_needed),

	TP_ARGS(order, n_needed),

	TP_STRUCT__entry(
		__field(int, order)
		__field(unsigned long, n_needed)
	),

	TP_fast_assign(
		__entry->order = order;
		__entry->n_needed = n_needed;
	),

	TP_printk("order %3d n_needed %lu",
		__entry->order,
		__entry->n_needed)
);

TRACE_EVENT(mos_buddy_alloc_enter,

	TP_PROTO(int nid, unsigned long n_needed, enum lwk_page_type pgtype,
		 enum lwk_pma_alloc_flags flags),

	TP_ARGS(nid, n_needed, pgtype, flags),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(unsigned long, n_needed)
		__field(enum lwk_page_type, pgtype)
		__field(enum lwk_pma_alloc_flags, flags)
		),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->n_needed = n_needed;
		__entry->pgtype = pgtype;
		__entry->flags = flags;
		),

	TP_printk("node%3d pgtype=%2s allocation=%6s needed=%lu",
		__entry->nid,
		lwk_pgtype(__entry->pgtype),
		lwk_pma_alloc_flag(__entry->flags),
		__entry->n_needed)
);

TRACE_EVENT(mos_buddy_alloc_exit,
	TP_PROTO(unsigned long n_allocated),
	TP_ARGS(n_allocated),
	TP_STRUCT__entry(__field(unsigned long, n_allocated)),
	TP_fast_assign(__entry->n_allocated = n_allocated;),
	TP_printk("n_allocated=%lu", __entry->n_allocated)
);

TRACE_EVENT(mos_buddy_setup,

	TP_PROTO(int nid, unsigned long spfn, unsigned long epfn),

	TP_ARGS(nid, spfn, epfn),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(unsigned long, spfn)
		__field(unsigned long, epfn)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->spfn = spfn;
		__entry->epfn = epfn;
	),

	TP_printk("node%3d [ %#013lx - %#013lx )",
		__entry->nid, __entry->spfn, __entry->epfn)
);

TRACE_EVENT(mos_buddy_split_page,

	TP_PROTO(enum lwk_page_type pgtype, unsigned long pfn, int nid),

	TP_ARGS(pgtype, pfn, nid),

	TP_STRUCT__entry(
		__field(enum lwk_page_type, pgtype)
		__field(unsigned long, pfn)
		__field(int, nid)
	),

	TP_fast_assign(
		__entry->pgtype = pgtype;
		__entry->pfn = pfn;
		__entry->nid = nid;
	),

	TP_printk("pfn=%#lx page_size=%s nid=%d",
		  __entry->pfn, lwk_pgtype(__entry->pgtype),
		  __entry->nid)
);

/*
 * LWK mm trace points
 */
#define lwk_vmr(flags) \
	(flags) ? __print_flags(flags, ",", \
	{VM_LWK_STACK, "stack"}, \
	{VM_LWK_TSTACK, "tstack"}, \
	{VM_LWK_ANON_PRIVATE, "anon_private"}, \
	{VM_LWK_HEAP, "heap"}, \
	{VM_LWK_DBSS, "dbss"}) : "none"

DECLARE_EVENT_CLASS(mos_mm_vma,

	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long start, unsigned long end,
		 unsigned long flags),

	TP_ARGS(vma_start, vma_end, start, end, flags),

	TP_STRUCT__entry(
		__field(unsigned long, vma_start)
		__field(unsigned long, vma_end)
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned long, flags)
	),

	TP_fast_assign(
		__entry->vma_start = vma_start;
		__entry->vma_end = vma_end;
		__entry->start = start;
		__entry->end = end;
		__entry->flags = flags;
	),

	TP_printk("vma vmr=%s vma=[%#lx, %#lx) range=[%#lx, %#lx)",
		lwk_vmr(__entry->flags), __entry->vma_start, __entry->vma_end,
		__entry->start, __entry->end)
);

DECLARE_EVENT_CLASS(mos_mm_map_vma,

	TP_PROTO(unsigned long start, unsigned long end, enum lwk_page_type t),

	TP_ARGS(start, end, t),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(enum lwk_page_type, t)
	),

	TP_fast_assign(
		__entry->start = start;
		__entry->end = end;
		__entry->t = t;
	),

	TP_printk("range=[%#lx, %#lx) pgs=%s", __entry->start, __entry->end,
		  lwk_pgtype(__entry->t))
);

DEFINE_EVENT(mos_mm_vma, mos_mm_alloc_pages_vma,
	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long start, unsigned long end,
		 unsigned long flags),
	TP_ARGS(vma_start, vma_end, start, end, flags)
);

DEFINE_EVENT(mos_mm_map_vma, mos_mm_map_aligned_range,
	TP_PROTO(unsigned long start, unsigned long end, enum lwk_page_type t),
	TP_ARGS(start, end, t)
);

DEFINE_EVENT(mos_mm_map_vma, mos_mm_pgtbl_map_pages,
	TP_PROTO(unsigned long start, unsigned long end, enum lwk_page_type t),
	TP_ARGS(start, end, t)
);

DEFINE_EVENT(mos_mm_vma, mos_mm_pgtbl_unmap_pages,
	TP_PROTO(unsigned long vma_start, unsigned long vma_end,
		 unsigned long start, unsigned long end,
		 unsigned long flags),
	TP_ARGS(vma_start, vma_end, start, end, flags)
);

TRACE_EVENT(mos_mm_page_fault,

	TP_PROTO(unsigned long vm_start, unsigned long vm_end,
		 unsigned long lwk_vm_start, unsigned long lwk_vm_end,
		 unsigned long address, unsigned long flags),

	TP_ARGS(vm_start, vm_end, lwk_vm_start, lwk_vm_end, address, flags),

	TP_STRUCT__entry(
		__field(unsigned long, vm_start)
		__field(unsigned long, vm_end)
		__field(unsigned long, lwk_vm_start)
		__field(unsigned long, lwk_vm_end)
		__field(unsigned long, address)
		__field(unsigned long, flags)
	),

	TP_fast_assign(
		__entry->vm_start = vm_start;
		__entry->vm_end = vm_end;
		__entry->lwk_vm_start = lwk_vm_start;
		__entry->lwk_vm_end = lwk_vm_end;
		__entry->address = address;
		__entry->flags = flags;
	),

	TP_printk("vma=[%#lx, %#lx) lwk_vm=[%#lx, %#lx) addr=%#lx flags=%#lx",
		  __entry->vm_start, __entry->vm_end,
		  __entry->lwk_vm_start, __entry->lwk_vm_end,
		  __entry->address, __entry->flags)
);

TRACE_EVENT(mos_mm_page_fault_pagetbl,

	TP_PROTO(unsigned long address, unsigned long flags,
		 unsigned long pud, unsigned long pmd, unsigned long pte),

	TP_ARGS(address, flags, pud, pmd, pte),

	TP_STRUCT__entry(
		__field(unsigned long, address)
		__field(unsigned long, flags)
		__field(unsigned long, pud)
		__field(unsigned long, pmd)
		__field(unsigned long, pte)
	),

	TP_fast_assign(
		__entry->address = address;
		__entry->flags = flags;
		__entry->pud = pud;
		__entry->pmd = pmd;
		__entry->pte = pte;
	),

	TP_printk("addr=%#lx flags=%#lx pud=%#lx pmd=%#lx pte=%#lx",
		  __entry->address, __entry->flags,
		  __entry->pud, __entry->pmd, __entry->pte)
);

DECLARE_EVENT_CLASS(mos_mm_pagetable,

	TP_PROTO(int level, unsigned long start, unsigned long end),

	TP_ARGS(level, start, end),

	TP_STRUCT__entry(
		__field(int, level)
		__field(unsigned long, start)
		__field(unsigned long, end)
	),

	TP_fast_assign(
		__entry->level = level;
		__entry->start = start;
		__entry->end = end;
	),

	TP_printk("range=[%#lx, %#lx) page_size=%s",
		  __entry->start, __entry->end, lwk_pgtype(__entry->level))
);

DEFINE_EVENT(mos_mm_pagetable, mos_mm_pgtbl_map,
	TP_PROTO(int level, unsigned long start, unsigned long end),
	TP_ARGS(level, start, end)
);

DEFINE_EVENT(mos_mm_pagetable, mos_mm_pgtbl_unmap,
	TP_PROTO(int level, unsigned long start, unsigned long end),
	TP_ARGS(level, start, end)
);

DECLARE_EVENT_CLASS(mos_mm_pagetable_move,

	TP_PROTO(unsigned long old_vm_start, unsigned long old_vm_end,
		 unsigned long old_start,
		 unsigned long new_vm_start, unsigned long new_vm_end,
		 unsigned long new_start,
		 unsigned long len_in, unsigned long len_out),

	TP_ARGS(old_vm_start, old_vm_end, old_start,
		new_vm_start, new_vm_end, new_start,
		len_in, len_out),

	TP_STRUCT__entry(
		__field(unsigned long, old_vm_start)
		__field(unsigned long, old_vm_end)
		__field(unsigned long, old_start)
		__field(unsigned long, new_vm_start)
		__field(unsigned long, new_vm_end)
		__field(unsigned long, new_start)
		__field(unsigned long, len_in)
		__field(unsigned long, len_out)
	),

	TP_fast_assign(
		__entry->old_vm_start = old_vm_start;
		__entry->old_vm_end = old_vm_end;
		__entry->old_start = old_start;
		__entry->new_vm_start = new_vm_start;
		__entry->new_vm_end = new_vm_end;
		__entry->new_start = new_start;
		__entry->len_in = len_in;
		__entry->len_out = len_out;
	),

	TP_printk("old_vma=[%#lx, %#lx) old_start=%#lx new_vma=[%#lx, %#lx) new_start=%#lx len_in=%lx len_out=%lx",
		  __entry->old_vm_start, __entry->old_vm_end,
		  __entry->old_start,
		  __entry->new_vm_start, __entry->new_vm_end,
		  __entry->new_start,
		  __entry->len_in,
		  __entry->len_out)
);

DEFINE_EVENT(mos_mm_pagetable_move, mos_mm_pgtbl_move_enter,

	TP_PROTO(unsigned long old_vm_start, unsigned long old_vm_end,
		 unsigned long old_start,
		 unsigned long new_vm_start, unsigned long new_vm_end,
		 unsigned long new_start,
		 unsigned long len_in, unsigned long len_out),

	TP_ARGS(old_vm_start, old_vm_end, old_start,
		new_vm_start, new_vm_end, new_start,
		len_in, len_out)
);

DEFINE_EVENT(mos_mm_pagetable_move, mos_mm_pgtbl_move_exit,

	TP_PROTO(unsigned long old_vm_start, unsigned long old_vm_end,
		 unsigned long old_start,
		 unsigned long new_vm_start, unsigned long new_vm_end,
		 unsigned long new_start,
		 unsigned long len_in, unsigned long len_out),

	TP_ARGS(old_vm_start, old_vm_end, old_start,
		new_vm_start, new_vm_end, new_start,
		len_in, len_out)
);

TRACE_EVENT(mos_mm_pgtbl_move,

	TP_PROTO(int level, unsigned long old_start, unsigned long new_start,
		 unsigned long len),

	TP_ARGS(level, old_start, new_start, len),

	TP_STRUCT__entry(
		__field(int, level)
		__field(unsigned long, old_start)
		__field(unsigned long, new_start)
		__field(unsigned long, len)
	),

	TP_fast_assign(
		__entry->level = level;
		__entry->old_start = old_start;
		__entry->new_start = new_start;
		__entry->len = len;
	),

	TP_printk("old_range=[%#lx, %#lx) new_range=[%#lx, %#lx) page_size=%s",
		  __entry->old_start, __entry->old_start + __entry->len,
		  __entry->new_start, __entry->new_start + __entry->len,
		  lwk_pgtype(__entry->level))
);

TRACE_EVENT(mos_mm_pgtbl_split,

	TP_PROTO(int level, unsigned long vm_start, unsigned long vm_end,
		 unsigned long addr),

	TP_ARGS(level, vm_start, vm_end, addr),

	TP_STRUCT__entry(
		__field(int, level)
		__field(unsigned long, vm_start)
		__field(unsigned long, vm_end)
		__field(unsigned long, addr)
	),

	TP_fast_assign(
		__entry->level = level;
		__entry->vm_start = vm_start;
		__entry->vm_end = vm_end;
		__entry->addr = addr;
	),

	TP_printk("vma=[%#lx, %#lx) addr=%#lx level=%s",
		  __entry->vm_start, __entry->vm_end, __entry->addr,
		  __entry->level == 1 ? "pmd" :
		  __entry->level == 2 ? "pud" : "unsupported")
);

#endif /* _TRACE_LWKMEM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
