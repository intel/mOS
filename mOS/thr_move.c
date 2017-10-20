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

void mos_linux_enter(void *sysc)
{
	int ret;
	int i;
	struct mos_process_t *mosp = current->mos_process;

	BUG_ON(current->mos_nesting < 0);  /* remove me */

	if (current->mos_nesting++ > 0)
		return;

#ifdef CONFIG_MOS_SCHEDULER

	if (current->mos.move_syscalls_disable)
		return;

	/* Track system calls by function. */
	if (!mosp || !mosp->track_syscall_migrations)
		goto syscall_tracking_complete;

	if (cpumask_test_cpu(smp_processor_id(), this_cpu_ptr(&mos_syscall_mask)))
		goto syscall_tracking_complete;

	mutex_lock(&mosp->track_syscalls_lock);

	for (i = 0; i < ARRAY_SIZE(mosp->migrations); i++) {
		if (mosp->migrations[i].func == sysc) {
			mosp->migrations[i].count++;
			goto syscall_tracking_unlock;
		} else if (mosp->migrations[i].func == 0) {
			mosp->migrations[i].func = sysc;
			mosp->migrations[i].count = 1;
			goto syscall_tracking_unlock;
		}
	}

	pr_warn("(*) Could not count syscalls for %pF (out of space)\n", sysc);

 syscall_tracking_unlock:
	mutex_unlock(&mosp->track_syscalls_lock);

 syscall_tracking_complete:

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


static int thr_move_process_init(struct mos_process_t *mosp)
{
	mosp->track_syscall_migrations = false;
	return 0;
}

static int thr_move_process_start(struct mos_process_t *mosp)
{
	int i;

	if (mosp->track_syscall_migrations) {
		mutex_init(&mosp->track_syscalls_lock);
		for (i = 0; i < ARRAY_SIZE(mosp->migrations); i++)
			mosp->migrations[i].func = 0;
	}

	return 0;
}

static void thr_move_process_exit(struct mos_process_t *mosp)
{
	int i;

	if (mosp->track_syscall_migrations) {
		pr_info("(>) %s pid=%d\n", __func__, mosp->tgid);
		for (i = 0; i < ARRAY_SIZE(mosp->migrations); i++) {
			if (!mosp->migrations[i].func)
				break;
			pr_info("(*) [%2d] %pF -> %d\n",
				i, mosp->migrations[i].func,
				mosp->migrations[i].count);
		}
		pr_info("(<) %s pid=%d\n", __func__, mosp->tgid);
	}
}

static struct mos_process_callbacks_t thr_move_callbacks = {
	.mos_process_init = thr_move_process_init,
	.mos_process_start = thr_move_process_start,
	.mos_process_exit = thr_move_process_exit,
};

static int thr_move_track_syscall_migrations_cb(const char *val,
					struct mos_process_t *mosp)
{
	mosp->track_syscall_migrations = true;
	return 0;
}

static int __init _thr_move_init(void)
{
	mos_register_process_callbacks(&thr_move_callbacks);
	mos_register_option_callback("lwksched-track-syscall-migrations",
				     thr_move_track_syscall_migrations_cb);

	return 0;
}

subsys_initcall(_thr_move_init);


