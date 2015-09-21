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

static int __init mos_move_init(void)
{
	static cpumask_t done __initdata;
	unsigned cpu, cmp;

	/* sanitize the masks, which may be uninitialized */
	for_each_cpu_not(cpu, cpu_possible_mask)
		cpumask_clear(per_cpu_ptr(&mos_syscall_mask, cpu));

	for_each_possible_cpu(cpu) {
		cpumask_t *mask = per_cpu_ptr(&mos_syscall_mask, cpu);

		cpumask_and(mask, mask, cpu_possible_mask);
		if (cpumask_test_cpu(cpu, mask))
			pr_warn("mOS: CPU %d would forward syscalls to itself; "
				"removing\n", cpu);
		if (cpumask_test_cpu(cpu, mask) || cpumask_empty(mask))
			cpumask_set_cpu(cpu, &done);
	}

	for_each_cpu(cpu, &done)
		cpumask_copy(per_cpu_ptr(&mos_syscall_mask, cpu), &done);

	/* summarize the final configuration */

	pr_info("mOS: CPUs %*pbl will not move syscalls\n", cpumask_pr_args(&done));

	for_each_cpu_not(cpu, cpu_possible_mask)
		cpumask_set_cpu(cpu, &done);

	for_each_cpu_not(cpu, &done) {
		static cpumask_t mask __initdata;

		cpumask_clear(&mask);
		for_each_cpu_not(cmp, &done)
			if (cpumask_equal(per_cpu_ptr(&mos_syscall_mask, cpu),
			                  per_cpu_ptr(&mos_syscall_mask, cmp)))
				cpumask_set_cpu(cmp, &mask);

		pr_info("mOS: CPUs %*pbl will move syscalls onto CPUs %*pbl\n",
			cpumask_pr_args(&mask),
			cpumask_pr_args(per_cpu_ptr(&mos_syscall_mask, cpu)));

		cpumask_or(&done, &done, &mask);
	}

	pr_info("mOS: These CPUs are isolated: %*pbl\n",
		cpumask_pr_args(cpu_isolated_map));

	return 0;
}
early_initcall(mos_move_init);
