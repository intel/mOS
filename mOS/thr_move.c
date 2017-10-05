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

#include <linux/syscalls.h>
#include <linux/mos.h>
#include <asm/setup.h>
#include <linux/mos.h>

void mos_linux_enter(void)
{
	int ret;

	BUG_ON(current->mos_nesting < 0);  /* remove me */

	if (current->mos_nesting++ > 0)
		return;
#ifdef CONFIG_MOS_SCHEDULER

	if (current->mos.move_syscalls_disable)
		return;
#endif

	if ((ret = set_cpus_allowed_ptr(current, NULL)))
		pr_warn("mOS->Linux: error %d on CPU %u\n", ret, task_cpu(current));
}

void mos_linux_leave(void)
{
	int ret;

	BUG_ON(current->mos_nesting < 1);  /* remove me */

	if (--current->mos_nesting > 0)
		return;
#ifdef CONFIG_MOS_SCHEDULER

	if (current->mos.move_syscalls_disable)
		return;
#endif

	if ((ret = set_cpus_allowed_ptr(current, &current->mos_savedmask)))
		pr_warn("mOS<-Linux: error %d on CPU %u\n", ret, task_cpu(current));
}

void mos_linux_duped(struct task_struct *p)
{
	BUG_ON(p->mos_nesting < 0);  /* remove me */

	if (!p->mos_nesting)
		return;

	cpumask_copy(&p->cpus_allowed, &p->mos_savedmask);
	p->nr_cpus_allowed = cpumask_weight(&p->mos_savedmask);

	p->mos_nesting = 0;
}
