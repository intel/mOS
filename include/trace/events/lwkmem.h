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

#endif /* _TRACE_LWKMEM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
