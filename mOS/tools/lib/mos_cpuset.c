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
#include <limits.h>
#include "../../../include/generated/autoconf.h"
#include "mos_cpuset.h"
#include "mos_debug.h"

#define MOD_NAME	"mos_cpuset"

static int _mos_max_cpus = -1;

int mos_max_cpus(void)
{
	if (_mos_max_cpus == -1) {
		_mos_max_cpus = CONFIG_NR_CPUS;
		if (getenv("YOD_MAX_CPUS")) {
			int user_max = atoi(getenv("YOD_MAX_CPUS"));

			if (user_max > 0 && user_max < INT_MAX)
				_mos_max_cpus = user_max;
		}
	}

	return _mos_max_cpus;
}

size_t mos_setsize(void)
{
	return CPU_ALLOC_SIZE(mos_max_cpus());
}

static unsigned int mos_nbits(void)
{
	return mos_setsize() * 8;
}

mos_cpuset_t *mos_cpuset_alloc()
{
	mos_cpuset_t *set;

	set = (mos_cpuset_t *)malloc(sizeof(mos_cpuset_t));
	if (!set) {
		MOS_ERR(MOD_NAME, "Could not allocate a mos_cpuset");
		return NULL;
	}

	set->cpuset = CPU_ALLOC(mos_max_cpus());

	CPU_ZERO_S(mos_setsize(), set->cpuset);
	return set;
}

void mos_cpuset_free(mos_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);

	CPU_FREE(set->cpuset);
	free(set);
}


char *mos_cpuset_to_list(mos_cpuset_t *s)
{
	if (!s)
		return "NULL";
	else {
		int i, N;
		size_t setsz = mos_setsize();
		char *p = s->_buffer;
		int len = sizeof(s->_buffer); /* capacity */

		s->_buffer[0] = '\0';

		/* Iterate through the entire list of CPUs.  If a CPU is found,
		 * then count the adjacent CPUs (n) and use "m-n" format if
		 * possible to compress the resulting string.
		 */

		for (i = 0, N = mos_nbits(); i < N; i++) {
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

				if (l < 0 || l >= len) {
					MOS_ERR(MOD_NAME,
						"Insufficient buffer space");
					return NULL;
				}

				len -= l;
				p += l;
			}
		}

		/* Eliminate the trailing ',' */
		if (s->_buffer[0]) {
			if (*--p == ',')
				*p = '\0';
		}

		return s->_buffer;
	}
}

char *mos_cpuset_to_mask(mos_cpuset_t *set)
{

	if (!set)
		return "NULL";
	else {
		int i;
		char *ptr = set->_buffer;
		size_t setsz = mos_setsize();

		assert(sizeof(set->_buffer) > mos_nbits()/4);

		for (i = mos_nbits() - 4; i >= 0; i -= 4, ptr++) {
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

static long int mos_parse_cpu_num(const char *cpustr)
{
	long int val;
	char *remainder;

	errno = 0;
	val = strtol(cpustr, &remainder, 0);

	if (errno == ERANGE)
		goto out;

	if (remainder == cpustr)
		/* Nothing found */
		goto out;

	if (*remainder != '\0')
		/* Extraneous characters */
		goto out;

	if ((errno != 0) && (val == 0))
		/* Other cases (see strtol man page) */
		goto out;

	if ((val < 0) || (val > (mos_max_cpus() + 1)))
		goto out;

	return val;
out:
	return -1;
}

int mos_parse_cpulist(const char *list, mos_cpuset_t *set)
{
	char *p, *dup;
	char *tok, *left_s, *right_s, *stride_s;
	long int i, left, right, stride;
	size_t setsz = mos_setsize();

	assert(set != NULL && set->cpuset != NULL);
	assert(list != NULL);

	CPU_XOR_S(setsz, set->cpuset, set->cpuset, set->cpuset);

	p = dup = strdup(list);

	if (!dup) {
		MOS_ERR(MOD_NAME, "Could not allocate memory.");
		return -1;
	}

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

		left = mos_parse_cpu_num(left_s);
		right = right_s ? mos_parse_cpu_num(right_s) : left;
		stride = stride_s ? mos_parse_cpu_num(stride_s) : 1;

		if ((left < 0) || (right < 0) || (stride < 0)) {
			MOS_ERR(MOD_NAME, "Invalid CPU format: %s", list);
			free(dup);
			return -1;
		}
		for (i = left; i <= right; i += stride)
			CPU_SET_S(i, setsz, set->cpuset);

	}

	free(dup);
	return 0;
}

int mos_parse_cpumask(const char *mask, mos_cpuset_t *set)
{
	char *p, *dup;
	int i, cpu;
	size_t setsz = mos_setsize();

	assert(set != NULL && set->cpuset != NULL);

	p = dup = strdup(mask);

	if (!dup) {
		MOS_ERR(MOD_NAME, "Could not allocate memory.");
		return -1;
	}

	if (strlen(p) > 1 && p[0] == '0' && tolower(p[1]) == 'x')
		p += 2;

	CPU_XOR_S(setsz, set->cpuset, set->cpuset, set->cpuset);

	for (i = strlen(p) - 1, cpu = 0; i >= 0; i--, cpu += 4) {

		int j, nibble;

		if (!isxdigit(p[i])) {
			MOS_ERR(MOD_NAME, "Invalid CPU mask %s", mask);
			free(dup);
			return -1;
		}

		nibble = isdigit(p[i]) ? p[i] - '0' : tolower(p[i]) - 'a' + 10;

		for (j = 0; j < 4; j++)
			if (nibble & (1 << j))
				CPU_SET_S(cpu + j, setsz, set->cpuset);
	}

	free(dup);

	return 0;
}

void mos_cpuset_set(int cpu, mos_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);
	assert(cpu <= mos_max_cpus());
	CPU_SET_S(cpu, mos_setsize(), set->cpuset);
}

void mos_cpuset_clr(int cpu, mos_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);
	assert(cpu <= mos_max_cpus());
	CPU_CLR_S(cpu, mos_setsize(), set->cpuset);
}

void mos_cpuset_xor(mos_cpuset_t *dest, mos_cpuset_t *a, mos_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);
	assert(dest != NULL && dest->cpuset != NULL);

	CPU_XOR_S(mos_setsize(), dest->cpuset, a->cpuset, b->cpuset);
}

void mos_cpuset_or(mos_cpuset_t *dest, mos_cpuset_t *a, mos_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);
	assert(dest != NULL && dest->cpuset != NULL);

	CPU_OR_S(mos_setsize(), dest->cpuset, a->cpuset, b->cpuset);
}


void mos_cpuset_and(mos_cpuset_t *dest, mos_cpuset_t *a, mos_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);
	assert(dest != NULL && dest->cpuset != NULL);

	CPU_AND_S(mos_setsize(), dest->cpuset, a->cpuset, b->cpuset);
}

int mos_cpuset_equal(mos_cpuset_t *a, mos_cpuset_t *b)
{
	assert(a != NULL && a->cpuset != NULL);
	assert(b != NULL && b->cpuset != NULL);

	return CPU_EQUAL_S(mos_setsize(), a->cpuset, b->cpuset);
}

int mos_cpuset_is_empty(mos_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);

	return CPU_COUNT_S(mos_setsize(), set->cpuset) == 0;
}

int mos_cpuset_is_set(int cpu, mos_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);
	return CPU_ISSET_S(cpu, mos_setsize(), set->cpuset) != 0;
}

int mos_cpuset_biggest(mos_cpuset_t *set)
{
	int i;

	assert(set != NULL && set->cpuset != NULL);

	for (i = mos_nbits(); i >= 0; i--) {
		if (CPU_ISSET_S(i, mos_setsize(), set->cpuset))
			return i;
	}

	return -1;
}

int mos_cpuset_cardinality(mos_cpuset_t *set)
{
	assert(set != NULL && set->cpuset != NULL);
	return CPU_COUNT_S(mos_setsize(), set->cpuset);
}

int mos_cpuset_is_subset(mos_cpuset_t *sub, mos_cpuset_t *sup)
{
	int result;
	mos_cpuset_t *tmp;

	assert(sub != NULL && sup->cpuset != NULL);
	assert(sup != NULL && sup->cpuset != NULL);

	tmp = mos_cpuset_alloc();

	mos_cpuset_xor(tmp, sub, sup);
	mos_cpuset_and(tmp, tmp, sub);

	result = mos_cpuset_is_empty(tmp);

	mos_cpuset_free(tmp);

	return result;
}

void mos_cpuset_not(mos_cpuset_t *dest, mos_cpuset_t *src)
{

	/* NOTE: use a temporary in case source and dest are the same */

	int i, N;
	mos_cpuset_t *tmp;

	assert(dest && dest->cpuset && src && src->cpuset);

	tmp = mos_cpuset_alloc();

	mos_cpuset_xor(tmp, tmp, tmp);

	for (i = 0, N = mos_nbits(); i < N; i++) {
		if (!CPU_ISSET_S(i, mos_setsize(), src->cpuset))
			CPU_SET_S(i, mos_setsize(), tmp->cpuset);
	}

	mos_cpuset_or(dest, tmp, tmp);
	mos_cpuset_free(tmp);
}


mos_cpuset_t *mos_cpuset_clone(mos_cpuset_t *s)
{
	mos_cpuset_t *clone;

	if (s == NULL)
		return NULL;

	clone = mos_cpuset_alloc();
	mos_cpuset_or(clone, s, s);
	return clone;
}

int mos_cpuset_nth_cpu(int n, mos_cpuset_t *s)
{
	int i, N;

	assert(s && s->cpuset);
	assert(n > 0);

	for (i = 0, N = mos_nbits(); i < N; i++) {
		if (CPU_ISSET_S(i, mos_setsize(), s->cpuset)) {
			n--;
			if (n == 0)
				return i;
		}
	}

	return -1;
}
