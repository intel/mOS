/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018 Intel Corporation.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <xpmem.h>
#include "xpmem_utils.h"

#define OWNER				0
#define NONOWNER			1

#define SHMEM_FILE			"/tmp/xpmem.file"
#define XPMEM_SHARE_SIZE		(((unsigned long) 4) << 30)

/* Flags to synchronize owner and non-owner accesses */
#define WAIT_OWNER_READY		1
#define WAIT_NONOWNER_READY		2
#define WAIT_OWNER_DONE			3
#define WAIT_NONOWNER_DONE		4

#define MAX_TEST_CASES			20
#define TIMEOUT				120 /* seconds */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define LOG(format, ...) \
		printf("[%-9s : pid %d] " format "\n",\
			proc_types[proc], getpid(), ##__VA_ARGS__)

/**
 * The following data is shared between processes.  Traditional Linux shared
 * memory mechanisms are used.
 */
struct shinfo_t {
	pid_t owner_pid;
	pid_t nonowner_pid;

	xpmem_segid_t segid;
	unsigned long segsize;

	int wait;
};

/* Normal owner usage, needed for all non-owner test cases */
static int owner_normal(void);
/*
 * Owner creates a share without mapping the address space, used by
 * non-owner test cases which accesses xpmem attachments without
 * any virtual memory mappings in the owner.
 */
static int owner_nomap(void);

/* Owner test cases */
static int owner_test_invalid_share(void);
static int owner_test_att_owned_share(void);

/* Non-owner test cases */
static int nonowner_test_invalid_att(void);
static int nonowner_test_invalid_att_overlap(void);
static int nonowner_test_invalid_access_map(void);
static int nonowner_test_invalid_access_owner_exited(void);

/* Test descriptions */
char *invalid_usage_tests[] = {
	"Owner creating XPMEM share of invalid address range",
	"Owner creating attachment to its own XPMEM share",
	"Non-owner creating attachment at invalid address range",
	"Non-owner creating overlapping attachments",
	"Non-owner writing to owner shared address space which is not yet mapped",
	"Non-owner writing to owner shared address space while owner has exited"
};

/*
 * Table for looking up owner/non-owner tests.
 * A test number is the index to second dimension of the table, so for a given
 * test case number there is one owner function and corresponding non-owner
 * function.
 */
static int (*method[][MAX_TEST_CASES])(void) = {
	/* Owner test cases */
	{ owner_test_invalid_share,
	  owner_test_att_owned_share,
	  owner_normal,
	  owner_normal,
	  owner_nomap,
	  owner_nomap,
	},
	/* Non-owner test cases */
	{ NULL,
	  NULL,
	  nonowner_test_invalid_att,
	  nonowner_test_invalid_att_overlap,
	  nonowner_test_invalid_access_map,
	  nonowner_test_invalid_access_owner_exited
	}
};

/* Common globals */
char *proc_types[] = { "owner", "non-owner" };
int proc;
int current_test;
struct shinfo_t *shmem;

/* SIGSEGV handling helpers */
struct sigaction segv_action;
void *segv_addr_start;
void *segv_addr_end;

static void sig_action(int sig, siginfo_t *sinfo, void *ucontext)
{
	int status = -1;
	char *sigstr;

	if (sig == SIGSEGV || sig == SIGBUS) {
		sigstr = sig == SIGSEGV ? "SIGSEGV" : "SIGBUS";

		LOG("Received %s signal, attempting to access %p",
		    sigstr, sinfo->si_addr);
		if (sinfo->si_addr >= segv_addr_start &&
		    sinfo->si_addr <= segv_addr_end) {
			if (sig == SIGSEGV && sinfo->si_code != SEGV_MAPERR) {
				LOG("Unexpected %s", sigstr);
				goto out;
			}
			LOG("Expected %s", sigstr);
			status = 0;
		} else
			LOG("Unexpected %s", sigstr);
	}
out:
	shmem->wait = WAIT_NONOWNER_DONE;
	exit(status);
}

static int install_sig_action(void)
{
	int rc =  -1;

	memset(&segv_action, 0, sizeof(segv_action));
	segv_action.sa_sigaction = sig_action;
	segv_action.sa_flags = SA_SIGINFO;
	sigemptyset(&segv_action.sa_mask);

	rc = sigaction(SIGBUS, &segv_action, NULL);
	if (rc)
		return rc;
	return sigaction(SIGSEGV, &segv_action, NULL);
}

static int parse_args(int argc, char **argv)
{
	int i;

	if (strcmp("--help", argv[1]) == 0 || argc != 4)
		goto help;

	if (strcmp("--owner", argv[1]) == 0) {
		proc = OWNER;
	} else if (strcmp("--nonowner", argv[1]) == 0) {
		proc = NONOWNER;
	} else {
		printf("(E) Specify --owner/--nonowner as first argument.\n");
		return -1;
	}

	if (strcmp("--test", argv[2]) == 0) {
		current_test = strtoul(argv[3], 0, 0);
		if (current_test < 0 ||
		    current_test > ARRAY_SIZE(invalid_usage_tests))
			goto help;
	} else {
		goto help;
	}

	shmem = create_shared_mem(SHMEM_FILE, sizeof(struct shinfo_t),
			  proc == OWNER ? O_CREAT : 0);
	if (!shmem) {
		printf("Failed to open shared memory\n");
		return -1;
	}

	if (proc == OWNER) {
		/* Just make sure. */
		shmem->wait = 0;
		shmem->owner_pid = getpid();
		shmem->segid = -1;
		shmem->segsize = 0;
	} else
		shmem->nonowner_pid = getpid();
	return 0;

help:
	printf("Usage:  %s {--owner|--nonowner} --test <N>\n", argv[0]);
    printf("\nTotal test cases: %ld\n", ARRAY_SIZE(invalid_usage_tests));
	printf("<N> Test number\n");
	for (i = 0; i < ARRAY_SIZE(invalid_usage_tests); i++)
		printf(" %d - %s\n", i, invalid_usage_tests[i]);
	printf("\n");
	return -1;
}

static int is_running(pid_t pid)
{
	FILE *pstatus = NULL;
	size_t size = 128;
	int rc = 0;
	char procfs_path[size];
	char *buffer = NULL;
	char *line;

	if (snprintf(procfs_path, size, "/proc/%d/status", pid) >= size) {
		printf("ERROR: Truncated procfs path: %s\n", procfs_path);
		return rc;
	}

	pstatus = fopen(procfs_path, "r");

	if (pstatus) {
		while (getline(&buffer, &size, pstatus) > 0) {
			line = strstr(buffer, "State");
			if (line) {
				strsep(&line, ":");
				if (line)
					line++;
				while (line && (*line == ' '))
					line++;
				if (line) {
					if (*line == 'Z' || *line == 'X' ||
					    *line == 'T')
						rc = 0;
					else
						rc = 1;
					if (!rc)
						printf("pstat(pid %d): %s\n",
							pid, line);
				} else
					printf("ERROR: Procfs status\n");
				break;
			}
			memset(buffer, 0, size);
		}
		fclose(pstatus);
		if (buffer)
			free(buffer);
	}
	return rc;
}

static int wait_for_pid(pid_t pid)
{
	int timeout = 120; // secs

	while (is_running(pid) && timeout--)
		sleep(1);
	if (timeout < 0)
		LOG("Timeout in %s()", __func__);
	return timeout > 0;
}

/*
 * Owner tests
 */
static int owner_normal(void)
{
	void *owner_vm;
	int timeout = TIMEOUT;
	int status = -1;

	LOG("%s(): enter", __func__);
	LOG("Creating XPMEM share of size %ld", XPMEM_SHARE_SIZE);
	/* Create a valid XPMEM share */
	owner_vm = create_private_mem(NULL, XPMEM_SHARE_SIZE);
	if (owner_vm) {
		shmem->segsize = XPMEM_SHARE_SIZE;
		shmem->segid = xpmem_make(owner_vm,
					  XPMEM_SHARE_SIZE,
					  XPMEM_PERMIT_MODE,
					  (void *)0666);
		if (shmem->segid < 0) {
			perror("xpmem_make");
			goto out;
		}
		shmem->wait = WAIT_OWNER_READY;

		/* Wait till non-owner is done */
		while (shmem->wait != WAIT_NONOWNER_DONE && timeout--)
			sleep(1);
		if (timeout < 0) {
			LOG("Timeout in %s()", __func__);
			goto out;
		}
		status = 0;
	}
out:
	if (shmem->segid >= 0) {
		if (xpmem_remove(shmem->segid)) {
			perror("xpmem_remove");
			status = -1;
		}
	}
	if (owner_vm) {
		if (munmap(owner_vm, XPMEM_SHARE_SIZE)) {
			perror("munmap");
			status = -1;
		}
	}
	LOG("%s(): exiting", __func__);
	return status;
}

static int owner_nomap(void)
{
	void *owner_vm;
	int timeout = TIMEOUT;
	int status = -1;

	LOG("%s(): enter", __func__);
	LOG("Creating XPMEM share of size %ld", XPMEM_SHARE_SIZE);
	/* Create a valid XPMEM share without virtual memory mappings */
	owner_vm = create_private_mem(NULL, XPMEM_SHARE_SIZE);

	if (owner_vm) {
		/* Now unmap virtual memory backing */
		if (munmap(owner_vm, XPMEM_SHARE_SIZE)) {
			perror("munmap");
			owner_vm = NULL;
			goto out;
		}
		LOG("Unmapped %p - %p", owner_vm, owner_vm + XPMEM_SHARE_SIZE);

		/* Create XPMEM share*/
		shmem->segsize = XPMEM_SHARE_SIZE;
		shmem->segid = xpmem_make(owner_vm,
					  XPMEM_SHARE_SIZE,
					  XPMEM_PERMIT_MODE,
					  (void *)0666);
		owner_vm = NULL;
		if (shmem->segid < 0) {
			perror("xpmem_make");
			goto out;
		}

		/* Let non-owner proceed, good luck! */
		shmem->wait = WAIT_OWNER_READY;

		/* Wait till non-owner is done */
		while (shmem->wait != WAIT_NONOWNER_DONE && timeout--)
			sleep(1);
		if (timeout < 0) {
			LOG("Timeout in %s()", __func__);
			goto out;
		}
		status = 0;
	}
out:
	if (shmem->segid >= 0) {
		if (xpmem_remove(shmem->segid)) {
			perror("xpmem_remove");
			status = -1;
		}
	}
	if (owner_vm) {
		if (munmap(owner_vm, XPMEM_SHARE_SIZE)) {
			perror("munmap");
			status = -1;
		}
	}
	LOG("%s(): exiting", __func__);
	return status;
}

static int owner_test_invalid_share(void)
{
	void *owner_vm;
	int status = -1;

	LOG("%s(): enter", __func__);
	/* Attempt to create an XPMEM share over an invalid address range */
	owner_vm = create_private_mem(NULL, XPMEM_SHARE_SIZE);
	if (owner_vm) {
		shmem->segsize = XPMEM_SHARE_SIZE;
		shmem->segid = xpmem_make(owner_vm,
					  (unsigned long)-1, /* max size */
					  XPMEM_PERMIT_MODE,
					  (void *)0666);
		if (shmem->segid > 0) {
			LOG("ERROR: Created an XPMEM share with invalid size");
			/* This could fail, give it a try anyway */
			xpmem_remove(shmem->segid);
		} else {
			LOG("Attempt to create a share of invalid size failed");
			status = 0;
		}

		if (munmap(owner_vm, XPMEM_SHARE_SIZE)) {
			perror("munmap");
			status = -1;
		}
	}
	LOG("%s(): exiting", __func__);
	return status;
}

static int owner_test_att_owned_share(void)
{
	struct xpmem_addr addr;
	void *owner_vm;
	int status = -1;

	LOG("%s(): enter", __func__);
	/* Create a valid XPMEM share and try to attach to its own segment */
	owner_vm = create_private_mem(NULL, XPMEM_SHARE_SIZE);
	if (!owner_vm)
		return -1;

	shmem->segsize = XPMEM_SHARE_SIZE;
	shmem->segid = xpmem_make(owner_vm,
				  XPMEM_SHARE_SIZE,
				  XPMEM_PERMIT_MODE,
				  (void *)0666);
	if (shmem->segid < 0) {
		perror("xpmem_make");
		goto out;
	}

	addr.apid = xpmem_get(shmem->segid, XPMEM_RDWR,
			XPMEM_PERMIT_MODE, (void *)0666);
	if (addr.apid < 0) {
		LOG("Attempt to get apid to its own share failed");
		status = 0;
	} else {
		LOG("Created an apid to its own share!");
		if (xpmem_release(addr.apid))
			perror("xpmem_release");
	}
out:
	if (shmem->segid >= 0) {
		if (xpmem_remove(shmem->segid)) {
			perror("xpmem_remove");
			status = -1;
		}
	}
	if (munmap(owner_vm, XPMEM_SHARE_SIZE)) {
		perror("munmap");
		status = -1;
	}
	LOG("%s(): exiting", __func__);
	return status;
}

/*
 * Non-owner tests
 */
static int nonowner_test_invalid_att(void)
{
	struct xpmem_addr addr;
	void *attachment;
	int timeout = TIMEOUT;
	int status = -1;

	LOG("%s(): enter", __func__);

	while (shmem->wait != WAIT_OWNER_READY && timeout--)
		sleep(1);

	if (timeout < 0) {
		LOG("ERROR: Timeout in %s()!", __func__);
		goto out;
	}

	/* Try to create an attachment of invalid size */
	addr.apid = xpmem_get(shmem->segid, XPMEM_RDWR,
			XPMEM_PERMIT_MODE, (void *)0666);
	if (addr.apid < 0) {
		perror("xpmem_get");
		goto out;
	}

	addr.offset = 0;
	attachment = xpmem_attach(addr, (unsigned long)-1, 0);
	if (attachment != (void *)-1) {
		LOG("ERROR: Could create attachment of invalid addr range!");
		/* This could fail, give it a try anyway */
		if (xpmem_detach(attachment))
			perror("xpmem_detach");
	} else {
		status = 0;
		LOG("Attempt to create attachment over invalid range failed");
	}

	if (xpmem_release(addr.apid)) {
		perror("xpmem_release");
		status = -1;
	}
out:
	shmem->wait = WAIT_NONOWNER_DONE;
	LOG("%s(): exiting", __func__);
	return status;
}

static int nonowner_test_invalid_att_overlap(void)
{
	struct xpmem_addr addr;
	void *attachment, *ovl_attachment;
	int timeout = TIMEOUT;
	int status = -1;

	LOG("%s(): enter", __func__);
	addr.apid = -1;
	while (shmem->wait != WAIT_OWNER_READY && timeout--)
		sleep(1);

	if (timeout < 0) {
		LOG("ERROR: Timeout in %s()!", __func__);
		goto out;
	}

	/* Try to create overlapping attachments */
	addr.apid = xpmem_get(shmem->segid, XPMEM_RDWR,
			XPMEM_PERMIT_MODE, (void *)0666);
	if (addr.apid < 0) {
		perror("xpmem_get");
		goto out;
	}

	addr.offset = 0;
	attachment = xpmem_attach(addr, (unsigned long)shmem->segsize, 0);
	if (attachment == (void *)-1) {
		perror("xpmem_attach");
		goto out;
	}

	addr.offset = 0;
	ovl_attachment = xpmem_attach(addr, (unsigned long)shmem->segsize,
				attachment);
	if (ovl_attachment != (void *)-1) {
		LOG("ERROR: Could create overlapping attachments!");
		/* Try to cleanup, may not succeed */
		if (xpmem_detach(ovl_attachment))
			perror("xpmem_detach");
	} else {
		status = 0;
		LOG("Attempt to create overlapping attachments failed");
	}

	if (xpmem_detach(attachment)) {
		perror("xpmem_detach");
		status = -1;
	}
out:
	if (addr.apid >= 0) {
		if (xpmem_release(addr.apid)) {
			perror("xpmem_release");
			status = -1;
		}
	}
	shmem->wait = WAIT_NONOWNER_DONE;
	LOG("%s(): exiting", __func__);
	return status;
}

static int nonowner_test_write(int chk_segv, int write_after_owner_exits)
{
	struct xpmem_addr addr;
	void *attachment = NULL;
	int timeout = TIMEOUT;
	int status = -1;

	LOG("%s(): enter", __func__);
	addr.apid = -1;
	while (shmem->wait != WAIT_OWNER_READY && timeout--)
		sleep(1);

	if (timeout < 0) {
		LOG("ERROR: Timeout in %s()!", __func__);
		goto out;
	}

	addr.apid = xpmem_get(shmem->segid, XPMEM_RDWR,
			XPMEM_PERMIT_MODE, (void *)0666);
	if (addr.apid < 0) {
		perror("xpmem_get");
		goto out;
	}

	addr.offset = 0;
	attachment = xpmem_attach(addr, (unsigned long)shmem->segsize, 0);
	if (attachment == (void *)-1) {
		perror("xpmem_attach");
		goto out;
	}

	if (write_after_owner_exits) {
		shmem->wait = WAIT_NONOWNER_DONE;
		if (!wait_for_pid(shmem->owner_pid))
			goto out;
		LOG("Owner has exited by now");
	}

	if (chk_segv) {
		segv_addr_start = attachment;
		segv_addr_end = attachment + shmem->segsize - 1;
		LOG("XPMEM attachment: %p - %p",
		    segv_addr_start, segv_addr_end);
	}

	/* Fill with 0xaa */
	memset(attachment, 0xaa, shmem->segsize);

	if (!chk_segv)
		status = 0;
out:
	if (attachment) {
		if (xpmem_detach(attachment)) {
			perror("xpmem_detach");
			status = -1;
		}
	}
	if (addr.apid >= 0) {
		if (xpmem_release(addr.apid)) {
			perror("xpmem_release");
			status = -1;
		}
	}
	shmem->wait = WAIT_NONOWNER_DONE;
	LOG("%s(): exiting", __func__);
	return status;
}

static int nonowner_test_invalid_access_map(void)
{
	int status;

	LOG("%s(): enter", __func__);
	install_sig_action();
	status = nonowner_test_write(1, 0);
	LOG("%s(): exiting", __func__);
	return status;
}

static int nonowner_test_invalid_access_owner_exited(void)
{
	int status;

	LOG("%s(): enter", __func__);
	install_sig_action();
	status = nonowner_test_write(1, 1);
	LOG("%s(): exiting", __func__);
	return status;
}

int main(int argc, char **argv)
{
	unsigned int version = 0;

	if (parse_args(argc, argv))
		return -1;

	version = xpmem_version();
	LOG("XPMEM version %d.%x", version >> 16, version & ~(~0 << 16));

	if (method[proc][current_test]) {
		LOG("Running test - %s", invalid_usage_tests[current_test]);
		return method[proc][current_test]();
	}
	/*
	 * If there is no registered method then simply return success since
	 * no action is expected out of that process for the input test case.
	 */
	return 0;
}
