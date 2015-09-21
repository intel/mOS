/* SPDX-License-Identifier: GPL-2.0 */
/*
 * syscall_wrapper.h - x86 specific wrappers to syscall definitions
 */

#ifndef _ASM_X86_SYSCALL_WRAPPER_H
#define _ASM_X86_SYSCALL_WRAPPER_H

struct pt_regs;

/* Mapping of registers to parameters for syscalls on x86-64 and x32 */
#define SC_X86_64_REGS_TO_ARGS(x, ...)					\
	__MAP(x,__SC_ARGS						\
		,,regs->di,,regs->si,,regs->dx				\
		,,regs->r10,,regs->r8,,regs->r9)			\

/* Mapping of registers to parameters for syscalls on i386 */
#define SC_IA32_REGS_TO_ARGS(x, ...)					\
	__MAP(x,__SC_ARGS						\
	      ,,(unsigned int)regs->bx,,(unsigned int)regs->cx		\
	      ,,(unsigned int)regs->dx,,(unsigned int)regs->si		\
	      ,,(unsigned int)regs->di,,(unsigned int)regs->bp)

#ifdef CONFIG_IA32_EMULATION
/*
 * For IA32 emulation, we need to handle "compat" syscalls *and* create
 * additional wrappers (aptly named __ia32_sys_xyzzy) which decode the
 * ia32 regs in the proper order for shared or "common" syscalls. As some
 * syscalls may not be implemented, we need to expand COND_SYSCALL in
 * kernel/sys_ni.c and SYS_NI in kernel/time/posix-stubs.c to cover this
 * case as well.
 */
#define __IA32_COMPAT_SYS_STUB0(x, name)				\
	asmlinkage long __ia32_compat_sys_##name(const struct pt_regs *regs);\
	ALLOW_ERROR_INJECTION(__ia32_compat_sys_##name, ERRNO);		\
	asmlinkage long __ia32_compat_sys_##name(const struct pt_regs *regs)\
	{								\
		return __se_compat_sys_##name();			\
	}

#define __IA32_COMPAT_SYS_STUBx(x, name, ...)				\
	asmlinkage long __ia32_compat_sys##name(const struct pt_regs *regs);\
	ALLOW_ERROR_INJECTION(__ia32_compat_sys##name, ERRNO);		\
	asmlinkage long __ia32_compat_sys##name(const struct pt_regs *regs)\
	{								\
		return __se_compat_sys##name(SC_IA32_REGS_TO_ARGS(x,__VA_ARGS__));\
	}

#define __IA32_SYS_STUBx(x, name, ...)					\
	asmlinkage long __ia32_sys##name(const struct pt_regs *regs);	\
	ALLOW_ERROR_INJECTION(__ia32_sys##name, ERRNO);			\
	asmlinkage long __ia32_sys##name(const struct pt_regs *regs)	\
	{								\
		return __se_sys##name(SC_IA32_REGS_TO_ARGS(x,__VA_ARGS__));\
	}

/*
 * To keep the naming coherent, re-define SYSCALL_DEFINE0 to create an alias
 * named __ia32_sys_*()
 */

#define SYSCALL_DEFINE0(sname)						\
	SYSCALL_METADATA(_##sname, 0);					\
	asmlinkage long __x64_sys_##sname(const struct pt_regs *__unused);\
	ALLOW_ERROR_INJECTION(__x64_sys_##sname, ERRNO);		\
	SYSCALL_ALIAS(__ia32_sys_##sname, __x64_sys_##sname);		\
	asmlinkage long __x64_sys_##sname(const struct pt_regs *__unused)

#define COND_SYSCALL(name)							\
	asmlinkage __weak long __x64_sys_##name(const struct pt_regs *__unused)	\
	{									\
		return sys_ni_syscall();					\
	}									\
	asmlinkage __weak long __ia32_sys_##name(const struct pt_regs *__unused)\
	{									\
		return sys_ni_syscall();					\
	}

#define SYS_NI(name)							\
	SYSCALL_ALIAS(__x64_sys_##name, sys_ni_posix_timers);		\
	SYSCALL_ALIAS(__ia32_sys_##name, sys_ni_posix_timers)

#else /* CONFIG_IA32_EMULATION */
#define __IA32_COMPAT_SYS_STUBx(x, name, ...)
#define __IA32_SYS_STUBx(x, fullname, name, ...)
#endif /* CONFIG_IA32_EMULATION */


#ifdef CONFIG_X86_X32
/*
 * For the x32 ABI, we need to create a stub for compat_sys_*() which is aware
 * of the x86-64-style parameter ordering of x32 syscalls. The syscalls common
 * with x86_64 obviously do not need such care.
 */
#define __X32_COMPAT_SYS_STUB0(x, name, ...)				\
	asmlinkage long __x32_compat_sys_##name(const struct pt_regs *regs);\
	ALLOW_ERROR_INJECTION(__x32_compat_sys_##name, ERRNO);		\
	asmlinkage long __x32_compat_sys_##name(const struct pt_regs *regs)\
	{								\
		return __se_compat_sys_##name();\
	}

#define __X32_COMPAT_SYS_STUBx(x, name, ...)				\
	asmlinkage long __x32_compat_sys##name(const struct pt_regs *regs);\
	ALLOW_ERROR_INJECTION(__x32_compat_sys##name, ERRNO);		\
	asmlinkage long __x32_compat_sys##name(const struct pt_regs *regs)\
	{								\
		return __se_compat_sys##name(SC_X86_64_REGS_TO_ARGS(x,__VA_ARGS__));\
	}

#else /* CONFIG_X86_X32 */
#define __X32_COMPAT_SYS_STUB0(x, name)
#define __X32_COMPAT_SYS_STUBx(x, name, ...)
#endif /* CONFIG_X86_X32 */


#ifdef CONFIG_COMPAT
/*
 * Compat means IA32_EMULATION and/or X86_X32. As they use a different
 * mapping of registers to parameters, we need to generate stubs for each
 * of them.
 */
#define COMPAT_SYSCALL_DEFINE0(name)					\
	static long __se_compat_sys_##name(void);			\
	static inline long __do_compat_sys_##name(void);		\
	__IA32_COMPAT_SYS_STUB0(x, name)				\
	__X32_COMPAT_SYS_STUB0(x, name)					\
	static long __se_compat_sys_##name(void)			\
	{								\
		return __do_compat_sys_##name();			\
	}								\
	static inline long __do_compat_sys_##name(void)

#define COMPAT_SYSCALL_DEFINEx(x, name, ...)					\
	static long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	__IA32_COMPAT_SYS_STUBx(x, name, __VA_ARGS__)				\
	__X32_COMPAT_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{									\
		return __do_compat_sys##name(__MAP(x,__SC_DELOUSE,__VA_ARGS__));\
	}									\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

/*
 * As some compat syscalls may not be implemented, we need to expand
 * COND_SYSCALL_COMPAT in kernel/sys_ni.c and COMPAT_SYS_NI in
 * kernel/time/posix-stubs.c to cover this case as well.
 */
#define COND_SYSCALL_COMPAT(name) 					\
	cond_syscall(__ia32_compat_sys_##name);				\
	cond_syscall(__x32_compat_sys_##name)

#define COMPAT_SYS_NI(name)						\
	SYSCALL_ALIAS(__ia32_compat_sys_##name, sys_ni_posix_timers);	\
	SYSCALL_ALIAS(__x32_compat_sys_##name, sys_ni_posix_timers)

#endif /* CONFIG_COMPAT */

static inline void __mos_linux_enter(void *sys_wrap);
static inline void __mos_linux_leave(void *sys_wrap);

/*
 * Instead of the generic __SYSCALL_DEFINEx() definition, this macro takes
 * struct pt_regs *regs as the only argument of the syscall stub named
 * __x64_sys_*(). It decodes just the registers it needs and passes them on to
 * the __se_sys_*() wrapper performing sign extension and then to the
 * __do_sys_*() function doing the actual job. These wrappers and functions
 * are inlined (at least in very most cases), meaning that the assembly looks
 * as follows (slightly re-ordered for better readability):
 *
 * <__x64_sys_recv>:		<-- syscall with 4 parameters
 *	callq	<__fentry__>
 *
 *	mov	0x70(%rdi),%rdi	<-- decode regs->di
 *	mov	0x68(%rdi),%rsi	<-- decode regs->si
 *	mov	0x60(%rdi),%rdx	<-- decode regs->dx
 *	mov	0x38(%rdi),%rcx	<-- decode regs->r10
 *
 *	xor	%r9d,%r9d	<-- clear %r9
 *	xor	%r8d,%r8d	<-- clear %r8
 *
 *	callq	__sys_recvfrom	<-- do the actual work in __sys_recvfrom()
 *				    which takes 6 arguments
 *
 *	cltq			<-- extend return value to 64-bit
 *	retq			<-- return
 *
 * This approach avoids leaking random user-provided register content down
 * the call chain.
 *
 * If IA32_EMULATION is enabled, this macro generates an additional wrapper
 * named __ia32_sys_*() which decodes the struct pt_regs *regs according
 * to the i386 calling convention (bx, cx, dx, si, di, bp).
 */
#define __SYSCALL_DEFINEx(x, name, ...)					\
	asmlinkage long __x64_sys##name(const struct pt_regs *regs);	\
	ALLOW_ERROR_INJECTION(__x64_sys##name, ERRNO);			\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long lwk_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__)) __attribute__((weak));;	\
	asmlinkage long __x64_sys##name(const struct pt_regs *regs)	\
	{								\
		return __se_sys##name(SC_X86_64_REGS_TO_ARGS(x,__VA_ARGS__));\
	}								\
	__IA32_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret;						\
		if (lwk_sys##name && is_mostask()) {			\
			ret = lwk_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));	\
			if (ret != -ENOSYS) goto out;			\
		}							\
		__mos_linux_enter(__x64_sys##name);				\
		ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__mos_linux_leave(__x64_sys##name);				\
out:									\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

/*
 * As the generic SYSCALL_DEFINE0() macro does not decode any parameters for
 * obvious reasons, and passing struct pt_regs *regs to it in %rdi does not
 * hurt, we only need to re-define it here to keep the naming congruent to
 * SYSCALL_DEFINEx() -- which is essential for the COND_SYSCALL() and SYS_NI()
 * macros to work correctly.
 */
#ifndef SYSCALL_DEFINE0
#define SYSCALL_DEFINE0(sname)					\
	SYSCALL_METADATA(_##sname, 0);				\
	ALLOW_ERROR_INJECTION(__x64_sys_##sname, ERRNO);	\
	static inline long __do_sys##name(void); 		\
	asmlinkage long lwk_sys##name(void) __attribute__((weak));;	\
	asmlinkage long __x64_sys_##sname(const struct pt_regs *__unused) \
	{							\
		long ret;					\
		if (lwk_sys_##sname && is_mostask()) {		\
			ret = lwk_sys_##sname();		\
			if (ret != -ENOSYS) goto out0;		\
		}						\
		__mos_linux_enter(__x64_sys_##sname);		\
		ret = __do_sys##sname();			\
		__mos_linux_leave(__x64_sys_##sname);		\
out0:								\
		return ret;					\
	}							\
	static inline long __do_sys##sname(void)
#endif


#ifndef COND_SYSCALL
#define COND_SYSCALL(name) 							\
	asmlinkage __weak long __x64_sys_##name(const struct pt_regs *__unused)	\
	{									\
		return sys_ni_syscall();					\
	}
#endif

#ifndef SYS_NI
#define SYS_NI(name) SYSCALL_ALIAS(__x64_sys_##name, sys_ni_posix_timers);
#endif


/*
 * For VSYSCALLS, we need to declare these three syscalls with the new
 * pt_regs-based calling convention for in-kernel use.
 */
asmlinkage long __x64_sys_getcpu(const struct pt_regs *regs);
asmlinkage long __x64_sys_gettimeofday(const struct pt_regs *regs);
asmlinkage long __x64_sys_time(const struct pt_regs *regs);

#include <linux/mos.h>
#ifdef CONFIG_MOS_MOVE_SYSCALLS

/* We need to declare the syscalls that will be executed locally */
asmlinkage long __x64_sys_clock_adjtime(const struct pt_regs *regs);
asmlinkage long __x64_sys_clock_settime(const struct pt_regs *regs);
asmlinkage long __x64_sys_clock_gettime(const struct pt_regs *regs);
asmlinkage long __x64_sys_clock_getres(const struct pt_regs *regs);
asmlinkage long __x64_sys_clock_nanosleep(const struct pt_regs *regs);
asmlinkage long __x64_sys_futex(const struct pt_regs *regs);
asmlinkage long __x64_sys_getitimer(const struct pt_regs *regs);
asmlinkage long __x64_sys_getpid(void);
asmlinkage long __x64_sys_getppid(void);
asmlinkage long __x64_sys_getpriority(const struct pt_regs *regs);
asmlinkage long __x64_sys_setpriority(const struct pt_regs *regs);
asmlinkage long __x64_sys_mbind(const struct pt_regs *regs);
asmlinkage long __x64_sys_mmap(const struct pt_regs *regs);
asmlinkage long __x64_sys_mmap_pgoff(const struct pt_regs *regs);
asmlinkage long __x64_sys_munmap(const struct pt_regs *regs);
asmlinkage long __x64_sys_mremap(const struct pt_regs *regs);
asmlinkage long __x64_sys_nanosleep(const struct pt_regs *regs);
asmlinkage long __x64_sys_perf_event_open(const struct pt_regs *regs);
asmlinkage long __x64_sys_process_vm_readv(const struct pt_regs *regs);
asmlinkage long __x64_sys_process_vm_writev(const struct pt_regs *regs);
asmlinkage long __x64_sys_sched_setaffinity(const struct pt_regs *regs);
asmlinkage long __x64_sys_sched_getaffinity(const struct pt_regs *regs);
asmlinkage long __x64_sys_sched_yield(void);
asmlinkage long __x64_sys_setitimer(const struct pt_regs *regs);
asmlinkage long __x64_sys_timer_create(const struct pt_regs *regs);
asmlinkage long __x64_sys_timer_gettime(const struct pt_regs *regs);
asmlinkage long __x64_sys_timer_getoverrun(const struct pt_regs *regs);
asmlinkage long __x64_sys_timer_settime(const struct pt_regs *regs);
asmlinkage long __x64_sys_timer_delete(const struct pt_regs *regs);
asmlinkage long __x64_sys_times(const struct pt_regs *regs);
asmlinkage long __x64_sys_writev(const struct pt_regs *regs);

/*
 * When 'm' is true, the optimizer can easily prove it statically--after
 * all, the same symbol appears on both sides of an equal sign; this
 * allows the compiler to elide the comparisons entirely.  When 'm' is
 * false, a static proof by the optimizer isn't possible (except perhaps
 * through type-based alias analysis, some of the time)--only the linker
 * knows whether symbols with different names have different values.
 *
 * To ensure runtime tests are avoided in both cases, ask the optimizer
 * whether a proof is possible and assume a non-match whenever it isn't.
 *
 * (Must be a macro to behave correctly, at least with GCC 4.8.3.)
 */
#define __mos_do_on_original_cpu(s)				\
	({							\
		bool m = (/* Keep these alphabetical */		\
			s == __x64_sys_clock_adjtime ||		\
			s == __x64_sys_clock_getres ||		\
			s == __x64_sys_clock_gettime ||		\
			s == __x64_sys_clock_nanosleep ||	\
			s == __x64_sys_clock_settime ||		\
			s == __x64_sys_futex ||			\
			s == __x64_sys_getitimer ||		\
			s == __x64_sys_getpid ||		\
			s == __x64_sys_getppid ||		\
			s == __x64_sys_getpriority ||		\
			s == __x64_sys_gettimeofday ||		\
			s == __x64_sys_mbind ||			\
			s == __x64_sys_mmap ||			\
			s == __x64_sys_mmap_pgoff ||		\
			s == __x64_sys_mremap ||		\
			s == __x64_sys_munmap ||		\
			s == __x64_sys_nanosleep ||		\
			s == __x64_sys_perf_event_open ||	\
			s == __x64_sys_process_vm_readv ||	\
			s == __x64_sys_process_vm_writev ||	\
			s == __x64_sys_sched_getaffinity ||	\
			s == __x64_sys_sched_setaffinity ||	\
			s == __x64_sys_sched_yield ||		\
			s == __x64_sys_setitimer ||		\
			s == __x64_sys_time ||			\
			s == __x64_sys_timer_create ||		\
			s == __x64_sys_timer_delete ||		\
			s == __x64_sys_timer_getoverrun ||	\
			s == __x64_sys_timer_gettime ||		\
			s == __x64_sys_timer_settime ||		\
			s == __x64_sys_times ||			\
			s == __x64_sys_writev ||		\
			0);					\
		__builtin_constant_p(m) ? m : false;		\
	})
#endif  /* CONFIG_MOS_MOVE_SYSCALLS */

static inline void __mos_linux_enter(void *sys_wrap)
{
#ifdef CONFIG_MOS_MOVE_SYSCALLS
	if (!__mos_do_on_original_cpu(sys_wrap))
		mos_linux_enter(sys_wrap);
#endif
}
static inline void __mos_linux_leave(void *sys_wrap)
{
#ifdef CONFIG_MOS_MOVE_SYSCALLS
	if (!__mos_do_on_original_cpu(sys_wrap))
		mos_linux_leave();
#endif
}


#endif /* _ASM_X86_SYSCALL_WRAPPER_H */
