#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/highuid.h>
#include <linux/getcpu.h>
#include <linux/printk.h>
#include <linux/uidgid.h>
#include <linux/mos.h>

/*
 * This is the same code as Linux' sys_getppid() For now we use it as a test
 * system call to tell which version got called -- LWK or Linux -- and which
 * CPU we were on.
 * Once we have a "real" lwk_sys* call we wont need this example anymore.
 * At that time we will list sys_getppid in the __mos_do_on_original_cpu()
 * macro to handle it locally, using the Linux code.
 */
asmlinkage long lwk_sys_getppid(void)
{
        int pid;
	int this_cpu;

        rcu_read_lock();
        pid = task_tgid_vnr(rcu_dereference(current->real_parent));
        rcu_read_unlock();
	this_cpu = get_cpu();
	put_cpu();

        printk(KERN_ALERT "mOS: LWK getppid() returning %d from CPU %d, is_mostask() is %d\n",
                pid, this_cpu, is_mostask());

        return pid;
}


/*
 * Experiment with a call that does take arguments
 */
asmlinkage long lwk_sys_getpriority(int which, int who)
{
	struct task_struct *g, *p;
	struct user_struct *user;
	const struct cred *cred = current_cred();
	long niceval, retval = -ESRCH;
	struct pid *pgrp;
	kuid_t uid;

	if (which > PRIO_USER || which < PRIO_PROCESS)
		return -EINVAL;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	switch (which) {
	case PRIO_PROCESS:
		if (who)
			p = find_task_by_vpid(who);
		else
			p = current;
		if (p) {
			niceval = nice_to_rlimit(task_nice(p));
			if (niceval > retval)
				retval = niceval;
		}
		break;
	case PRIO_PGRP:
		if (who)
			pgrp = find_vpid(who);
		else
			pgrp = task_pgrp(current);
		do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
			niceval = nice_to_rlimit(task_nice(p));
			if (niceval > retval)
				retval = niceval;
		} while_each_pid_thread(pgrp, PIDTYPE_PGID, p);
		break;
	case PRIO_USER:
		uid = make_kuid(cred->user_ns, who);
		user = cred->user;
		if (!who)
			uid = cred->uid;
		else if (!uid_eq(uid, cred->uid)) {
			user = find_user(uid);
			if (!user)
				goto out_unlock;	/* No processes for this user */
		}
		do_each_thread(g, p) {
			if (uid_eq(task_uid(p), uid)) {
				niceval = nice_to_rlimit(task_nice(p));
				if (niceval > retval)
					retval = niceval;
			}
		} while_each_thread(g, p);
		if (!uid_eq(uid, cred->uid))
			free_uid(user);		/* for find_user() */
		break;
	}
out_unlock:
	read_unlock(&tasklist_lock);
	rcu_read_unlock();
	{
	int this_cpu;
	this_cpu = get_cpu();
	put_cpu();
	printk(KERN_ALERT "mOS: LWk getpriority(which %d, who %d) returning %ld from CPU %d\n",
		which, who, retval, this_cpu);
	}

	return retval;
}
