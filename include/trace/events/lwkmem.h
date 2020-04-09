/*
 * Multi Operating System (mOS)
 * Copyright (c) 2017, Intel Corporation.
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

#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>

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

	TP_PROTO(unsigned long brk, unsigned long clear_len,
		void *clear_addr, int tgid),

	TP_ARGS(brk, clear_len, clear_addr, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, brk)
		__field(unsigned long, clear_len)
		__field(void *, clear_addr)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->brk = brk;
		__entry->clear_len = clear_len;
		__entry->clear_addr = clear_addr;
		__entry->tgid = tgid;
	),

	TP_printk("brk=%lx clr_addr=%lx clr_len=%ld tgid=%d",
			__entry->brk,
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

DECLARE_EVENT_CLASS(mos_mem_block_event,

	TP_PROTO(unsigned long va, unsigned long vlen,
		unsigned long pa, unsigned long plen,
		int knd, int nblks, int stride, int nid, int tgid),

	TP_ARGS(va, vlen, pa, plen, knd, nblks, stride, nid, tgid),

	TP_STRUCT__entry(
		__field(unsigned long, va)
		__field(unsigned long, vlen)
		__field(unsigned long, pa)
		__field(unsigned long, plen)
		__field(int, knd)
		__field(int, nblks)
		__field(int, stride)
		__field(int, nid)
		__field(int, tgid)
	),

	TP_fast_assign(
		__entry->va = va;
		__entry->vlen = vlen;
		__entry->pa = pa;
		__entry->plen = plen;
		__entry->knd = knd;
		__entry->nblks = nblks;
		__entry->stride = stride;
		__entry->nid = nid;
		__entry->tgid = tgid;
	),

	TP_printk("[%#018lx-%#018lx) [%#018lx-%#018lx) nid=%d num=%d knd=%s ilv=%d tgid=%d",
		__entry->va, __entry->va + __entry->vlen,
		__entry->pa, __entry->pa + __entry->plen,
		__entry->nid, __entry->nblks,
		kind_str[__entry->knd], __entry->stride,
		__entry->tgid)
);

DEFINE_EVENT(mos_mem_block_event, mos_mem_block_reserved,
	TP_PROTO(unsigned long va, unsigned long vlen,
		unsigned long pa, unsigned long plen,
		int knd, int nblks, int stride, int nid, int tgid),
	TP_ARGS(va, vlen, pa, plen, knd, nblks, stride, nid, tgid)
);

DEFINE_EVENT(mos_mem_block_event, mos_mem_block_allocated,
	TP_PROTO(unsigned long va, unsigned long vlen,
		unsigned long pa, unsigned long plen,
		int knd, int nblks, int stride, int nid, int tgid),
	TP_ARGS(va, vlen, pa, plen, knd, nblks, stride, nid, tgid)
);

DEFINE_EVENT(mos_mem_block_event, mos_mem_block_deallocated,
	TP_PROTO(unsigned long va, unsigned long vlen,
		unsigned long pa, unsigned long plen,
		int knd, int nblks, int stride, int nid, int tgid),
	TP_ARGS(va, vlen, pa, plen, knd, nblks, stride, nid, tgid)
);

DEFINE_EVENT(mos_mem_block_event, mos_mem_block_divided,
	TP_PROTO(unsigned long va, unsigned long vlen,
		unsigned long pa, unsigned long plen,
		int knd, int nblks, int stride, int nid, int tgid),
	TP_ARGS(va, vlen, pa, plen, knd, nblks, stride, nid, tgid)
);

DEFINE_EVENT(mos_mem_block_event, mos_mem_block_dump,
	TP_PROTO(unsigned long va, unsigned long vlen,
		unsigned long pa, unsigned long plen,
		int knd, int nblks, int stride, int nid, int tgid),
	TP_ARGS(va, vlen, pa, plen, knd, nblks, stride, nid, tgid)
);

DEFINE_EVENT(mos_mem_block_event, mos_mem_block_released,
	TP_PROTO(unsigned long va, unsigned long vlen,
		unsigned long pa, unsigned long plen,
		int knd, int nblks, int stride, int nid, int tgid),
	TP_ARGS(va, vlen, pa, plen, knd, nblks, stride, nid, tgid)
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

#endif /* _TRACE_LWKMEM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
