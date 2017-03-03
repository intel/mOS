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

/*
** Measure call overhead for timing functions. Make sure they are handled
** locally and not exported to a Linxu CPU.
**
** Rolf Riesen, December 2015, Intel
*/
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>

#define CALL_THRESHOLD	(1500)
#define LOOP_COUNT	(3000000)

/*
** We use CPU ticks to measure everything
*/

static inline uint64_t getticks_start(void)
{
	uint64_t high, low, maxfunc;

	__asm__ __volatile__ ("cpuid"		/* serialize */
		: "=a"(maxfunc) : "a"(0)
		: "rbx", "rcx", "rdx", "memory");

	__asm__ __volatile__ ("rdtsc"		/* read timestamp counter */
		: "=a"(low), "=d"(high) :
		: "memory");

	return (high << 32) | low;
}

static inline uint64_t getticks_end(void)
{
	uint64_t high, low;

	__asm__ __volatile__ ("rdtscp"		/* read timestamp counter */
		: "=a"(low), "=d"(high) :
		: "memory");

	return (high << 32) | low;
}

/*
** Measure call overhead
*/

#define high_overhead(func, ...) \
({ \
	uint64_t start, end, ret; \
	int i; \
	start = getticks_start(); \
	for (i = 0; i < LOOP_COUNT; i++) \
		func(__VA_ARGS__); \
	end = getticks_end(); \
	ret = (end - start) / LOOP_COUNT; \
	printf("  %-17s %6lu ticks\n", #func "()", ret); \
	ret > CALL_THRESHOLD; \
})

int main(void)
{
	struct timespec tm;
	struct tms t;
	struct timeval tv;
	int fail = 0;

	printf("Call overhead of the various functions\n");

	fail += high_overhead(clock_gettime, CLOCK_MONOTONIC_RAW, &tm);
	fail += high_overhead(clock);
	fail += high_overhead(time, NULL);
	fail += high_overhead(times, &t);
	fail += high_overhead(gettimeofday, &tv, NULL);

	printf("\n");

	if (fail == 0) {
		printf("PASS\n");
		return 0;
	}
	printf("FAIL: overhead too high for %d timer call(s)\n", fail);
	return 1;
}
