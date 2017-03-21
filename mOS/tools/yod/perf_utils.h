#ifndef PERF_UTILS_H
#define PERF_UTILS_H
#include <unistd.h>
#include <syscall.h>
#include <linux/perf_event.h>

static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                   group_fd, flags);
    return ret;
}


#endif

