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
#include <sys/types.h>
#include <sys/mman.h>
#include <xpmem.h>
#include "xpmem_utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (4096)
#endif

/**
 * The following data is shared between processes.  Traditional Linux shared
 * memory mechanisms are used.
 */
struct shinfo_t {
	/* The XpMem segment id communicated from producer to consumer */
	xpmem_segid_t segment_id;

	/* Assorted configuration and program arguments.  These are stored
	 * by the producer and shared with the consumer.
	 */
	unsigned long num_messages;
	unsigned long message_size;
	unsigned long message_granularity;
	int shutdown_style;

	/* Counts of messages sent and received.  The producer increments
	 * the sent count whereas the consumer increments the received
	 * count.
	 */
	volatile unsigned long messages_sent;
	volatile unsigned long messages_received;

	/* An indicator to shutdown. */
	volatile int shutdown;

	/* Sequencing flags */
	volatile int ok_to_remove;
	volatile int ok_to_detach_and_release;
	volatile int early_term_type;

	pid_t p_pid, c_pid;

	/* A text message provided from the consumer to the producer. */
	char message[256];
};

#define PRODUCER 1
#define CONSUMER 2

const char *PROCT = "?PC?";
unsigned int do_munmap_test;

#define SHMEM_FILE "/tmp/xpmem.file"

#define SD_CANONICAL 0
#define SD_INVERTED 1
#define SD_RACE 2
#define SD_ETERM_P_C_ALIVE 3
#define SD_ETERM_P_C_DEAD 4
#define SD_ETERM_C_P_ALIVE 5
#define SD_ETERM_C_P_DEAD 6

static int parse_args(int argc, char **argv, struct shinfo_t **shinfo_ptr, int *proc_type)
{
	int i, j;
	struct shinfo_t *shinfo = 0;

	struct shutdown_style_t {
		int style;
		const char *mnemonic;
		const char *help;
	} SHUTDOWN[] = {
		{ SD_CANONICAL, "canonical", "Shut down in the standard order. (default)" },
		{ SD_INVERTED, "inverted", "The producer removes segments before the consumer detaches." },
		{ SD_RACE, "race", "Shut down order is left to chance." },
		{ SD_ETERM_P_C_ALIVE, "eterm-p-c-alive", "Early terminate producer without cleaning up XPMEM resources while consumer is alive." },
		{ SD_ETERM_P_C_DEAD, "eterm-p-c-dead", "Early terminate producer without cleaning up XPMEM resources while consumer is dead." },
		{ SD_ETERM_C_P_ALIVE, "eterm-c-p-alive", "Early terminate consumer without cleaning up XPMEM resources while producer is alive." },
		{ SD_ETERM_C_P_DEAD, "eterm-c-p-dead", "Early terminate consumer without cleaning up XPMEM resources while producer is dead." },
	};

	/*
	 * The first argument must be --version, --help or either
	 * --producer/--consumer
	 */

	if (strcmp("--version", argv[1]) == 0) {
		printf("XpMem Version %x\n", xpmem_version());
		return -1;
	}

	if (strcmp("--help", argv[1]) == 0)
		goto help;

	if (strcmp("--producer", argv[1]) == 0) {
		*proc_type = PRODUCER;
	} else if (strcmp("--consumer", argv[1]) == 0) {
		*proc_type = CONSUMER;
	} else {
		printf("(E) You must specify either --producer or --consumer as the first argument.\n");
		return -1;
	}

	*shinfo_ptr = shinfo =
		create_shared_mem(SHMEM_FILE, sizeof(struct shinfo_t),
			  *proc_type == PRODUCER ? O_CREAT : 0);

	if (*proc_type == PRODUCER) {
		shinfo->num_messages = 1;
		shinfo->message_size = 0x1000;
		shinfo->message_granularity = 1;
		shinfo->shutdown_style = SD_CANONICAL;
		shinfo->early_term_type = -1;
	}

#define PRODUCER_ARG_CHECK() do { if (*proc_type != PRODUCER) goto help; } while (0)

	for (i = 2; i < argc; i++) {

		if (strcmp("--size", argv[i]) == 0) {
			PRODUCER_ARG_CHECK();
			shinfo->message_size = strtoul(argv[++i], 0, 0);
		} else if (strcmp("--num", argv[i]) == 0) {
			PRODUCER_ARG_CHECK();
			shinfo->num_messages = strtoul(argv[++i], 0, 0);
		} else if (strcmp("--granularity", argv[i]) == 0) {
			PRODUCER_ARG_CHECK();
			shinfo->message_granularity = strtoul(argv[++i], 0, 0);
		} else if (strcmp("--shutdown", argv[i]) == 0) {
			PRODUCER_ARG_CHECK();
			i++;
			for (j = 0; j < ARRAY_SIZE(SHUTDOWN); j++) {
				if (strcmp(SHUTDOWN[j].mnemonic, argv[i]) == 0) {
					shinfo->shutdown_style = SHUTDOWN[j].style;
					goto nextarg;
				}
			}

			printf("(E) Invalid value for --shutdown \"%s\"\n", argv[i]);
			return -1;
		} else if (strcmp("--munmap", argv[i]) == 0) {
			do_munmap_test = 1;
		} else {
			goto help;
		}

nextarg:
		;
	}

	return 0;

help:
	printf("Usage:  %s {--producer|--consumer} [options]\n", argv[0]);
	printf("  Common Options:\n");
	printf("    --munmap   : Enable munmap test of XPMEM memory\n");
	printf("  Producer Options:\n");
	printf("    --num <N>  : specify the number of messages to be passed. (default=1)\n");
	printf("    --size <N> : specify the size of the messages to be passed. (default=4k)\n");
	printf("    --granularity <N> : print after every N messages are sent. (default=1).\n");
	printf("    --shutdown <S> :  One of the following:\n");
	for (j = 0; j < ARRAY_SIZE(SHUTDOWN); j++)
		printf("        %s : %s\n", SHUTDOWN[j].mnemonic, SHUTDOWN[j].help);
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
		printf("Error: Truncated procfs path: %s\n", procfs_path);
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
					printf("Error: Procfs status\n");
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

static void wait_for_pid(pid_t pid, struct shinfo_t *shinfo)
{
	pid_t current = getpid();
	int is_producer = current == shinfo->p_pid;
	int timeout = 60 * 100; /* 60 seconds at 10ms intervals */

	while (is_running(pid) && timeout--)
		usleep(10000);
	if (timeout < 0) {
		printf("Error: %c (%d) timeout reached waiting for %c (%d)\n",
			is_producer ? 'P' : 'C', current,
			pid == shinfo->p_pid ? 'P' : 'C', pid);
	}
}

static void early_terminate(struct shinfo_t *shinfo)
{
	pid_t current = getpid();

	if (current == shinfo->p_pid) {
		if (shinfo->early_term_type == SD_ETERM_P_C_DEAD) {
			wait_for_pid(shinfo->c_pid, shinfo);
			goto early_exit;
		} else if (shinfo->early_term_type == SD_ETERM_P_C_ALIVE)
			goto early_exit;
		else if (shinfo->early_term_type == SD_ETERM_C_P_ALIVE)
			wait_for_pid(shinfo->c_pid, shinfo);
	} else if (current == shinfo->c_pid) {
		if (shinfo->early_term_type == SD_ETERM_C_P_DEAD) {
			wait_for_pid(shinfo->p_pid, shinfo);
			goto early_exit;
		} else if (shinfo->early_term_type == SD_ETERM_C_P_ALIVE)
			goto early_exit;
		else if (shinfo->early_term_type == SD_ETERM_P_C_ALIVE)
			wait_for_pid(shinfo->p_pid, shinfo);
	} else
		printf("Error: current pid %d doesn't match P(%d) or C(%d)\n",
			current, shinfo->p_pid, shinfo->c_pid);

	return;

early_exit:
	printf("(%c) Exiting without cleaning up XPMEM resources\n",
		current == shinfo->p_pid ? 'P' : 'C');
	exit(0);
}

int main(int argc, char **argv)
{

	unsigned long i, j, N, stride;
	int proc_type = 0;
	struct shinfo_t *shinfo = 0;
	unsigned long *message_buffer = 0;

	if (parse_args(argc, argv, &shinfo, &proc_type))
		return -1;

	printf("(%c) pid=%d size=%ld num=%ld XpMem Version %x\n",
	       PROCT[proc_type], getpid(), shinfo->message_size,
	       shinfo->num_messages, xpmem_version());

	switch (proc_type) {
	case PRODUCER: {

		/*
		 * The producer process does the following:
		 *   - creates a region and makes it shareable in the xpmem sense.
		 *   - sends N messages by scribbling into the shared memory
		 *     region and updated a shared counter.  After each message
		 *     is sent, waits for the receiver's indication that the
		 *     message has been processed.
		 *   - waits for the shutdown signal from the receiver.
		 *   - removes the shared region.
		 */

		message_buffer = create_private_mem(NULL, shinfo->message_size);

		shinfo->p_pid = getpid();
		shinfo->segment_id = xpmem_make(message_buffer,
						shinfo->message_size,
						XPMEM_PERMIT_MODE,
						(void *)0666);
		shinfo->message[0] = 0;
		shinfo->shutdown = 0;
		shinfo->messages_sent = shinfo->messages_received = 0;

		if (shinfo->segment_id < 0) {
			perror("xpmem_make");
			return -1;
		}

		switch (shinfo->shutdown_style) {
		case SD_CANONICAL:
			shinfo->ok_to_remove = 0;
			shinfo->ok_to_detach_and_release = 1;
			break;
		case SD_INVERTED:
			shinfo->ok_to_remove = 1;
			shinfo->ok_to_detach_and_release = 0;
			break;
		case SD_RACE:
			shinfo->ok_to_remove = 1;
			shinfo->ok_to_detach_and_release = 1;
			break;
		case SD_ETERM_P_C_ALIVE:
		case SD_ETERM_P_C_DEAD:
		case SD_ETERM_C_P_ALIVE:
		case SD_ETERM_C_P_DEAD:
			shinfo->early_term_type = shinfo->shutdown_style;
			shinfo->ok_to_remove = 1;
			shinfo->ok_to_detach_and_release = 1;
			break;
		default:
			printf("(E) Unsupported shutdown style\n");
			return -1;
		}

		for (i = 0; i < shinfo->num_messages && !shinfo->shutdown; i++) {

			int j;
			unsigned long *buffer;

			N = shinfo->message_size / sizeof(unsigned long);
			stride = PAGE_SIZE / sizeof(unsigned long);

			for (j = 0; j < N; j += stride)
				message_buffer[j] = i;

			shinfo->messages_sent++;

			if (i % shinfo->message_granularity == 0) {
				printf("(%c) Sent message %ld/%ld.\n",
				       PROCT[proc_type], shinfo->messages_sent,
				       shinfo->num_messages);
				fflush(stdout);
			}

			while (shinfo->messages_sent > shinfo->messages_received && !shinfo->shutdown)
				;

			if (do_munmap_test) {
				buffer = recreate_private_mem(message_buffer,
						shinfo->message_size);
				if (buffer != message_buffer) {
					printf("(%c) recreate buffer failed\n",
						PROCT[proc_type]);
					break;
				}
				if (i % shinfo->message_granularity == 0) {
					printf("(%c) Recreated buffer\n",
						PROCT[proc_type]);
					fflush(stdout);
				}
			}
		}

		while (!shinfo->shutdown);
		printf("(%c) Shutdown message: %s\n", PROCT[proc_type],
		       shinfo->message);

		early_terminate(shinfo);
		while (!shinfo->ok_to_remove)
			;

		if (xpmem_remove(shinfo->segment_id)) {
			perror("xpmem_remove");
			return -1;
		}
		printf("(%c) XpMem segment removed.\n", PROCT[proc_type]);

		shinfo->ok_to_detach_and_release = 1;

		if (remove(SHMEM_FILE))
			perror("Could not clean up.");
		break;
	}

	case CONSUMER: {

		/*
		 * The consumer process does the following:
		 *
		 *   - gains access to the shared segment of the producer.
		 *   - attaches to the shared segment.
		 *   - receives messages from the producer as they become
		 *     available.
		 *   - detaches and releases the shared memory segment.
		 */

		struct xpmem_addr xpmaddr;

		printf("(%c) segment id: %ld\n", PROCT[proc_type],
		       (long)shinfo->segment_id);

		shinfo->c_pid = getpid();
		xpmaddr.apid = xpmem_get(shinfo->segment_id, XPMEM_RDWR,
					 XPMEM_PERMIT_MODE, (void *)0666);

		if (xpmaddr.apid < 0) {
			perror("xpmem_get");
			strcpy(shinfo->message, "xpmem_get failed!");
			goto done;
		}

		xpmaddr.offset = 0;
		message_buffer = xpmem_attach(xpmaddr, shinfo->message_size, 0);

		if (message_buffer == (unsigned long *)-1) {
			perror("xpmem_attach");
			strcpy(shinfo->message, "xpmem_attach failed!");
			goto done;
		}

		for (i = 0; i < shinfo->num_messages; i++) {

			while (shinfo->messages_sent == shinfo->messages_received)
				;

			N = shinfo->message_size / sizeof(unsigned long);
			stride = PAGE_SIZE / sizeof(unsigned long);

			for (j = 0; j < N; j += stride) {
				if (message_buffer[j] != i) {
					printf("(%c) (ERROR) corruption in message %ld at offset %ld: (expected) %ld vs. %ld (actual)\n",
					       PROCT[proc_type], i, j, i,
					       message_buffer[j]);
					strcpy(shinfo->message, "BAD MESSAGE");
					goto done;
				}
			}

			shinfo->messages_received++;
			if (i % shinfo->message_granularity == 0) {
				printf("(%c) Received message %ld/%ld.\n",
				       PROCT[proc_type],
				       shinfo->messages_received,
				       shinfo->num_messages);
				fflush(stdout);
			}
		}


		strcpy(shinfo->message, "Goodnight!");

done:
		shinfo->shutdown = 1;
		early_terminate(shinfo);

		while (!shinfo->ok_to_detach_and_release);

		if (do_munmap_test) {
			printf("(%c) unmaping the XPMEM attachment\n",
				PROCT[proc_type]);
			fflush(stdout);
			/* Attempting to unmap XPMEM attachment using munmap.
			 * This is an invalid usage of XPMEM mappings and the
			 * kernel implementation kills the non-owner process
			 * making such an attempt without breaking the kernel.
			 */
			if (munmap(message_buffer, shinfo->message_size)) {
				printf("(%c) ERROR munmap failed\n",
					PROCT[proc_type]);
				perror("(C) munmap error");
			} else {
				printf("(%c) unmaped the XPMEM attachment!\n",
					PROCT[proc_type]);
				exit(-1);
			}
		}

		if (message_buffer && xpmem_detach(message_buffer))
			perror("xpmem_detach failed!");

		if (xpmem_release(xpmaddr.apid))
			perror("xpmem_release failed!");

		printf("(%c) XpMem segment detached and released.\n",
		       PROCT[proc_type]);

		shinfo->ok_to_remove = 1;

		break;
	}

	default: {
		printf("(E) You must specify either --producer or --consumer\n");
		return -1;
	}
	}

	return 0;
}
