/*
 * Multi Operating System (mOS)
 * Copyright (c) 2019, Intel Corporation.
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
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "lwkctl.h"

#define CHAR_BUFFER_SIZE 4096

/* Systemd commands and formats */
#define GET_IRQBALANCE_STATUS "systemctl -q is-active irqbalance"
#define SYSTEMCTL_SET_ENV_FORMAT "systemctl set-environment %s=%s"
#define SYSTEMCTL_UNSET_ENV_FORMAT "systemctl unset-environment %s"
#define START_IRQBALANCE "service irqbalance restart 2>/dev/null"
#define STOP_IRQBALANCE "service irqbalance stop 2>/dev/null"

/*
 * Executes a command on shell and returns an error code
 *
 * Returns,
 *     0 on success
 *     EINVAL if command is NULL,
 *            if shell could not be executed,
 *            if command executed on shell returned non-zero exit status
 *     +ve error codes if system() could not create a child process
 */
static int system_common(char *command)
{
	int rc = EINVAL;

	if (!command)
		return rc;

	rc = system(command);
	if (rc != 0) {
		if (rc < 0)
			rc = errno;
		else {
			rc = EINVAL;
			if (WIFEXITED(rc)) {
				LC_LOG(LC_WARN, "command [%s] exited [%d]",
				       command, WEXITSTATUS(rc));
			}
		}
	}
	return rc;
}

/*
 * Checks if the irqbalance daemon is active or not
 *
 * Returns,
 *      false if irqbalance daemon is inactive
 *      true  if irqbalance daemon is active
 */
bool is_irqbalance_active(void)
{
	return system_common(GET_IRQBALANCE_STATUS) ? false : true;
}

/*
 * Start irqbalance daemon, lwk_created flag indicates
 * if the LWK partition was created before starting the
 * daemon. In that case environment variables of the
 * irqbalance is set to ignore the LWKCPUs for balancing
 * irqs. If the daemon is started after deleting an LWK
 * partition then the previously set environment variable
 * is cleared.
 *
 * Returns,
 *     0 on success
 *     +ve error code on failure
 */
int start_irqbalance(void)
{
	int rc;

	rc = system_common(START_IRQBALANCE);

	return rc;
}

/*
 * Stop irqbalance daemon
 *
 * Returns,
 *      0 on success
 *      +ve error code on failure
 */
int stop_irqbalance(void)
{
	return system_common(STOP_IRQBALANCE);
}
