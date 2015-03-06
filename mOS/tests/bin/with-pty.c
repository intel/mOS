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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <pty.h>
#include <string.h>
#include <locale.h>
#include <errno.h>
#include <sys/wait.h>

#define die() do { perror(arg0); abort(); } while (0)

static char *arg0;

enum {
	NORMAL = 0,
	IN_VT100,
};

static int strip_vt100(int state, char c)
{
	switch (state) {
	case NORMAL:
		if (c == '\x1b')
			return IN_VT100;
		if (c != '\n' && iscntrl(c))
			return NORMAL;
		putchar(c);
		return NORMAL;

	case IN_VT100:
		if (isalpha(c))
			return NORMAL;
		return IN_VT100;

	default:
		abort();
	}
}

static int hexdump(int state, char c)
{
	switch (state) {
	case NORMAL:
		if (c != '\n' && iscntrl(c))
			printf("\\x%02x", c);
		else {
			if (c == '\\')
				putchar('\\');
			putchar(c);
		}
		break;

	default:
		abort();
	}

	return state;
}

static void observe(int tty, int (*machine)(int, char))
{
	int state = NORMAL;
	fd_set rfds;
	struct timeval tv;
	char buf[512];
	int r;
	ssize_t s, i;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(tty, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = 100000;

		if ((r = select(tty + 1, &rfds, NULL, NULL, &tv)) < 0)
			die();
		if (!r) {
			state = NORMAL;
			fflush(stdout);
		}

		if ((s = read(tty, buf, sizeof(buf))) < 1) {
			if (errno == EINTR)
				continue;
			putchar('\n');
			return;
		}

		for (i = 0; i < s; i++)
			state = machine(state, buf[i]);
	}
}

int main(int argc, char **argv)
{
	static const char usage[] =
	"Usage: %s [-xfln] [--] command...\n"
	"  -x   translate control characters to C-style escapes\n"
	"  -f   fully buffered\n"
	"  -l   line buffered (default)\n"
	"  -n   unbuffered\n";

	int opt, hex = 0, buf = _IOLBF;
	int tty;
	struct termios termp = {0};
	struct winsize winp = {0};
	pid_t child;
	int status;

	if (argc > 0)
		arg0 = argv[0];

	while ((opt = getopt(argc, argv, "xfln")) != -1) {
		switch (opt) {
		case 'x':
			hex = 1;
			break;
		case 'f':
			buf = _IOFBF;
			break;
		case 'l':
			buf = _IOLBF;
			break;
		case 'n':
			buf = _IONBF;
			break;
		default:
			fprintf(stderr, usage, arg0);
			return 1;
		}
	}

	if (argc <= optind) {
		fprintf(stderr, "%s: no command specified\n", arg0);
		return 1;
	}

	setlocale(LC_ALL, "C");

	if (setvbuf(stdout, NULL, buf, BUFSIZ) != 0)
		die();

	termp.c_cflag = CS8;
	termp.c_cc[VMIN] = 0;
	termp.c_cc[VTIME] = 8;
	winp.ws_col = 80;
	winp.ws_row = 24;

	if ((child = forkpty(&tty, NULL, &termp, &winp)) == 0) {
		if (setenv("TERM", "vt100", 1))
			die();
		execvp(argv[optind], &argv[optind]);
		die();
	}

	observe(tty, hex ? hexdump : strip_vt100);

	if (close(tty) == -1)
		die();
	if (wait(&status) != child)
		die();
	return WEXITSTATUS(status);
}
