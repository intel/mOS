/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018, Intel Corporation.
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
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <getopt.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <mos.h>
#include "lwksched.h"

static void usage(void);
static void *accelerator(void *);
static unsigned long monitored_field;

/**
 * The accelerator function models an accelerator executing for
 * a period of time and then providing a completion response.
 * @return The overall status of this thread.
 */
static void *accelerator(void *arg)
{
	long rc = 0;
	unsigned long response_time = (unsigned long)arg;

	log_msg(LOG_DEBUG,
	    "Simulate %s running for %d milliseconds...\n", __func__,
	    response_time);

	/* signal complete after accelerator 'runs' for the time period */
	usleep(response_time * 1000);

	log_msg(LOG_DEBUG, "Modifying the monitored memory location=%p\n",
	    &monitored_field);
	monitored_field += 1;

	return (void *)rc;
}

int main(int argc, char **argv)
{
	int rc = 0;
	int rc_local;
	unsigned int i = 0;
	pthread_t mythread;
	void *retval = 0;
	unsigned long previous_value;
	unsigned long new_value;
	int test_num = 0;
	unsigned long accelerator_time;
	unsigned long mwait_timeout;

	struct option options[] = {
	 /* Enable additional debug output */
	 { "debug", no_argument, 0, 'd' },
	 { "help", no_argument, 0, 'h' },
	};

	setlocale(LC_ALL, "");
	while (1) {
		int c;
		int opt_index;

		c = getopt_long(argc, argv, "dh", options,
				&opt_index);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			logging_level++;
			break;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return -1;
		}
	}
	/*
	 * TEST 1: Expected response from accelerator, no timeout
	 */
	test_num++;
	rc_local = 0;
	accelerator_time = 20; /* 'run' for 20 msecs before responding */
	mwait_timeout = accelerator_time*5;
	previous_value = monitored_field;
	log_msg(LOG_INFO, "Starting test %d", test_num);

	/* Spawn a pthread */
	if (pthread_create(&mythread, 0, accelerator, (void *)accelerator_time))
		log_msg(LOG_FATAL, "Could not spawn: %s", strerror(errno));

	log_msg(LOG_DEBUG, "Thread spawned. Calling mos_mwait API");

	if (mos_mwait(mos_mwait_sleep_deep, &monitored_field,
					previous_value, mwait_timeout) < 0) {
		if (errno == EBUSY)
			log_msg(LOG_ERR, " Timeout detected: %s",
						strerror(errno));
		else
			log_msg(LOG_ERR, " Could not mwait: %s",
						strerror(errno));
		rc_local = -1;
	}
	log_msg(LOG_DEBUG, "Woke from API");

	new_value = monitored_field;

	if (new_value != previous_value + 1) {
		log_msg(LOG_ERR,
			" Unexpected new value.  Old value=%ld New value=%ld",
		    previous_value, new_value);
		rc_local = -1;
	} else
		log_msg(LOG_DEBUG,
			"Returned from mos_mwait. Old value=%ld New value=%ld",
		    previous_value, new_value);

	pthread_join(mythread, &retval);

	log_msg(LOG_DEBUG, "Thread join completed");

	if (retval != 0) {
		log_msg(LOG_WARN, " Non-zero return (%p) from thread %d",
			retval, i);
	}
	log_msg(LOG_DEBUG, "Exiting test %d", test_num);

	if (rc_local) {
		log_msg(LOG_ERR, "Test %d failed.", test_num);
		rc = -1;
	}
	/*
	 * TEST 2: Expected timeout
	 */
	test_num++;
	rc_local = 0;
	accelerator_time = 200; /* 'run' 200 msecs before responding */
	mwait_timeout = accelerator_time/2;
	previous_value = monitored_field;
	log_msg(LOG_INFO, "Starting test %d", test_num);

	/* Spawn a pthread */
	if (pthread_create(&mythread, 0, accelerator, (void *)accelerator_time))
		log_msg(LOG_FATAL, "Could not spawn: %s", strerror(errno));

	log_msg(LOG_DEBUG, "Thread spawned. Calling mos_mwait API");

	if (mos_mwait(mos_mwait_sleep_deep, &monitored_field,
					previous_value, mwait_timeout) < 0) {
		if (errno == EBUSY)
			log_msg(LOG_DEBUG, " Expected timeout detected: %s",
						strerror(errno));
		else {
			log_msg(LOG_ERR, " Could not mwait: %s",
						strerror(errno));
			rc_local = -1;
		}
	}
	log_msg(LOG_DEBUG, "Woke from API");
	new_value = monitored_field;

	if (new_value != previous_value) {
		log_msg(LOG_ERR,
			" Unexpected new value.  Old value=%ld New value=%ld",
		    previous_value, new_value);
		rc_local = -1;
	} else
		log_msg(LOG_DEBUG,
			"Returned from mos_mwait. Old value=%ld New value=%ld",
		    previous_value, new_value);

	pthread_join(mythread, &retval);

	log_msg(LOG_DEBUG, "Thread join completed");

	if (retval != 0) {
		log_msg(LOG_WARN, " Non-zero return (%p) from thread %d",
			retval, i);
	}

	 log_msg(LOG_DEBUG, "Exiting test %d", test_num);

	if (rc_local) {
		log_msg(LOG_ERR, "Test %d failed.", test_num);
		rc = -1;
	}
	log_msg(LOG_DEBUG, "Exiting %s", __func__);
	return rc;
}

static void usage(void)
{
	printf("[--debug]..  [--help]\n");
}
