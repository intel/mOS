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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sched.h>
#include "../../../include/generated/autoconf.h"
#include "yod.h"
#include "yod_debug.h"

static int _yod_max_cpus = -1;

int yod_max_cpus(void)
{
	if (_yod_max_cpus == -1) {
		if (getenv("YOD_MAX_CPUS"))
			_yod_max_cpus = atoi(getenv("YOD_MAX_CPUS"));
		else
			_yod_max_cpus = CONFIG_NR_CPUS;
	}

	return _yod_max_cpus;
}

size_t yod_setsize(void)
{
	return CPU_ALLOC_SIZE(yod_max_cpus());
}

static unsigned int yod_nbits(void)
{
	return yod_setsize() * 8;
}

yod_cpuset_t *yod_cpuset_alloc()
{
	yod_cpuset_t *set;

	set = (yod_cpuset_t *)malloc(sizeof(yod_cpuset_t));
	if (!set)
		yod_abort(-1, "Could not allocate a yod_cpuset");

	set->cpuset = CPU_ALLOC(yod_max_cpus());

	CPU_ZERO_S(yod_setsize(), set->cpuset);
	return set;
}

void yod_cpuset_free(yod_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);

	CPU_FREE(set->cpuset);
	free(set);
}


char *yod_cpuset_to_list(yod_cpuset_t *s)
{
	if (!s)
		return "NULL";
	else {
		int i, N;
		size_t setsz = yod_setsize();
		char *p = s->_buffer;
		int len = sizeof(s->_buffer); /* capacity */

		s->_buffer[0] = '\0';

		/* Iterate through the entire list of CPUs.  If a CPU is found,
		 * then count the adjacent CPUs (n) and use "m-n" format if
		 * possible to compress the resulting string.
		 */

		for (i = 0, N = yod_nbits(); i < N; i++) {
			if (CPU_ISSET_S(i, setsz, s->cpuset)) {
				int n, l;

				for (n = i + 1;
				     n < N && CPU_ISSET_S(n, setsz, s->cpuset);
				     n++)
					;

				if (n == i+1)
					l = snprintf(p, len, "%d,", i);
				else {
					l = snprintf(p, len, "%d-%d,", i, n-1);
					i = n;
				}

				if (l < 0 || l >= len)
					yod_abort(-ENOMEM,
						  "Insufficient buffer space");

				len -= l;
				p += l;
			}
		}

		/* Eliminate the trailing ',' */
		if (s->_buffer[0])
			*p = '\0';

		return s->_buffer;
	}
}

char *yod_cpuset_to_mask(yod_cpuset_t *set)
{

	if (!set)
		return "NULL";
	else {
		int i;
		char *ptr = set->_buffer;
		size_t setsz = yod_setsize();

		assert(set);
		assert(sizeof(set->_buffer) > yod_nbits()/4);

		for (i = yod_nbits() - 4; i >= 0; i -= 4, ptr++) {
			int j, val;

			for (j = 0, val = 0; j < 4; j++)
				if (CPU_ISSET_S(i + j, setsz, set->cpuset))
					val |= (1 << j);
			if (val < 10)
				*ptr++ = '0' + val;
			else
				*ptr++ = 'a' + val;
		}
		*ptr = '\0';
		return set->_buffer;
	}
}

static long int yod_parse_cpu_num(const char *cpustr)
{
	long int result;

	if (yodopt_parse_integer(cpustr, &result, 0, yod_max_cpus() + 1))
		yod_abort(-EINVAL, "Invalid CPU identifier: %s", cpustr);

	return result;
}

int yod_parse_cpulist(const char *list, yod_cpuset_t *set)
{
	char *p, *dup;
	char *tok, *left_s, *right_s, *stride_s;
	long int i, left, right, stride;
	size_t setsz = yod_setsize();

	assert(set != NULL && set->cpuset != NULL);
	assert(list != NULL);

	CPU_XOR_S(setsz, set->cpuset, set->cpuset, set->cpuset);

	p = dup = strdup(list);

	if (!dup)
		yod_abort(-ENOMEM, "Could not allocate memory.");

	while (isspace(p[strlen(p) - 1]))
		p[strlen(p) - 1] = '\0';

	while (*p != '\0') {
		if (!isspace(*p))
			goto parse;
		p++;
	}

	/* If we got here, the string is all white space, so
	 * return the empty set.
	 */

	free(dup);
	return 0;

 parse:

	while ((tok = strsep(&p, ","))) {

		if (strlen(tok) == 0)
			break;

		stride_s = tok;
		tok = strsep(&stride_s, ":");
		right_s = tok;
		left_s = strsep(&right_s, "-");

		left = yod_parse_cpu_num(left_s);
		right = right_s ? yod_parse_cpu_num(right_s) : left;
		stride = stride_s ? yod_parse_cpu_num(stride_s) : 1;

		for (i = left; i <= right; i += stride)
			CPU_SET_S(i, setsz, set->cpuset);

	}

	free(dup);
	return 0;
}

int yod_parse_cpumask(const char *mask, yod_cpuset_t *set)
{
	char *p, *dup;
	int i, cpu;
	size_t setsz = yod_setsize();

	assert(set != NULL && set->cpuset != NULL);

	p = dup = strdup(mask);

	if (!dup)
		yod_abort(-ENOMEM, "Could not allocate memory.");

	if (strlen(p) > 1 && p[0] == '0' && tolower(p[1]) == 'x')
		p += 2;

	CPU_XOR_S(setsz, set->cpuset, set->cpuset, set->cpuset);

	for (i = strlen(p) - 1, cpu = 0; i >= 0; i--, cpu += 4) {

		int j, nibble;

		if (!isxdigit(p[i]))
			yod_abort(-EINVAL, "Invalid CPU mask: %s", mask);

		nibble = isdigit(p[i]) ? p[i] - '0' : tolower(p[i]) - 'a' + 10;

		for (j = 0; j < 4; j++)
			if (nibble & (1 << j))
				CPU_SET_S(cpu + j, setsz, set->cpuset);
	}

	free(dup);

	return 0;
}

void yod_cpuset_set(int cpu, yod_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);
	assert(cpu <= yod_max_cpus());
	CPU_SET_S(cpu, yod_setsize(), set->cpuset);
}

void yod_cpuset_xor(yod_cpuset_t *dest, yod_cpuset_t *a, yod_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);
	assert(dest != NULL && dest->cpuset != NULL);

	CPU_XOR_S(yod_setsize(), dest->cpuset, a->cpuset, b->cpuset);
}

void yod_cpuset_or(yod_cpuset_t *dest, yod_cpuset_t *a, yod_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);
	assert(dest != NULL && dest->cpuset != NULL);

	CPU_OR_S(yod_setsize(), dest->cpuset, a->cpuset, b->cpuset);
}


void yod_cpuset_and(yod_cpuset_t *dest, yod_cpuset_t *a, yod_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);
	assert(dest != NULL && dest->cpuset != NULL);

	CPU_AND_S(yod_setsize(), dest->cpuset, a->cpuset, b->cpuset);
}

int yod_cpuset_equal(yod_cpuset_t *a, yod_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);

	return CPU_EQUAL_S(yod_setsize(), a->cpuset, b->cpuset);
}

int yod_cpuset_is_empty(yod_cpuset_t *set)
{
	int i, N;

	assert(set != NULL && set->cpuset != NULL);

	for (i = 0, N = yod_nbits(); i < N; i++) {
		if (CPU_ISSET_S(i, yod_setsize(), set->cpuset))
			return 0;
	}
	return 1;
}

int yod_cpuset_is_set(int cpu, yod_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);
	return CPU_ISSET_S(cpu, yod_setsize(), set->cpuset) != 0;
}

int yod_cpuset_biggest(yod_cpuset_t *set)
{
	int i;

	assert(set != NULL && set->cpuset != NULL);

	for (i = yod_nbits(); i >= 0; i--) {
		if (CPU_ISSET_S(i, yod_setsize(), set->cpuset))
			return i;
	}

	return -1;
}

int yod_cpuset_cardinality(yod_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);
	return CPU_COUNT_S(yod_setsize(), set->cpuset);
}

int yod_cpuset_is_subset(yod_cpuset_t *sub, yod_cpuset_t *sup)
{
	int result;
	yod_cpuset_t *tmp;

	assert(sub != NULL && sup->cpuset != NULL);
	assert(sup != NULL && sup->cpuset != NULL);

	tmp = yod_cpuset_alloc();
	
	yod_cpuset_xor(tmp, sub, sup);
	yod_cpuset_and(tmp, tmp, sub);

	result = yod_cpuset_is_empty(tmp);

	yod_cpuset_free(tmp);
	
	return result;
}

void yod_cpuset_not(yod_cpuset_t *dest, yod_cpuset_t *src)
{

	/* NOTE: use a temporary in case source and dest are the same */

	int i, N;
	yod_cpuset_t *tmp;

	assert(dest && dest->cpuset && src && src->cpuset);

	tmp = yod_cpuset_alloc();

	yod_cpuset_xor(tmp, tmp, tmp);

	for (i = 0, N = yod_nbits(); i < N; i++) {
		if (!CPU_ISSET_S(i, yod_setsize(), src->cpuset))
			CPU_SET_S(i, yod_setsize(), tmp->cpuset);
	}
	
	yod_cpuset_or(dest, tmp, tmp);
	
	yod_cpuset_free(tmp);
}


yod_cpuset_t *yod_cpuset_clone(yod_cpuset_t *s)
{
	yod_cpuset_t *clone;

	if (s == NULL)
		return NULL;

	clone = yod_cpuset_alloc();
	yod_cpuset_or(clone, s, s);
	return clone;
}

int yod_cpuset_nth_cpu(int n, yod_cpuset_t *s)
{
	int i, N;

	assert(s && s->cpuset);
	assert(n > 0);

	for (i = 0, N = yod_nbits(); i < N; i++) {
		if (CPU_ISSET_S(i, yod_setsize(), s->cpuset)) {
			n--;
			if (n == 0)
				return i;
		}
	}

	return -1;
}
