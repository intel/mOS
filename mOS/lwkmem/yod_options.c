/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2020 Intel Corporation.
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

#include <linux/mos.h>

/* Private headers */
#include "lwk_mm_private.h"

/*
 * Sets all LWKMEM related yod options to their default values
 * for the current LWK process. This function is called from
 * allocate_lwk_mm() which is called
 */
void lwkmem_yod_options_set_default(void)
{
	struct lwk_mm *lwk_mm = curr_lwk_mm();
	enum lwk_vmr_type vmr;
	enum lwk_page_type pt, pt_max = LWK_MAX_NUMPGTYPES - 1;

	if (lwk_mm) {
		lwk_mm->pma_type = LWK_BUDDY_ALLOCATOR;
		lwk_mm->report_level = 0;
		lwk_mm->brk_clear_len = PAGE_SIZE;
		for (vmr = 0; vmr < LWK_MAX_NUMVMRTYPES; vmr++)
			lwk_mm->policy[vmr].disabled = false;
		for_each_lwkpage_type(pt)
			lwk_mm->pma_cache_limits[pt] = pt < pt_max ? 512 : 4;
	}
}

static int check_lwkmem_yodargs(struct mos_process_t *mosp, const char *val,
				bool check_val)
{
	if (!mosp || !is_mostask()) {
		LWKMEM_ERROR("%s: Err, pid %d is not an LWK process", __func__,
				current->pid);
		return -EINVAL;
	}

	if (check_val && !val) {
		LWKMEM_ERROR("%s: Illegal value (%s) detected.", __func__, val);
		return -EINVAL;
	}
	return 0;
}

static int lwkmem_pma(const char *val, struct mos_process_t *mosp)
{
	struct lwk_mm *lwk_mm = curr_lwk_mm();
	enum lwk_pma_type pma_type;

	pr_debug("(*) %s val=%s\n", __func__, val);
	if (check_lwkmem_yodargs(mosp, val, true))
		return -EINVAL;
	/* Is LWKMEM usage disabled */
	if (!lwk_mm)
		return 0;

	for (pma_type = 0; pma_type < LWK_PMA_MAX; pma_type++) {
		if (!strcasecmp(lwk_pmas_name[pma_type], val))
			break;
	}

	if (pma_type >= LWK_PMA_MAX)
		return -EINVAL;

	lwk_mm->pma_type = pma_type;
	pr_debug("(*) %s pma_type=%d\n", __func__, lwk_mm->pma_type);
	return 0;
}

static int lwkmem_report(const char *val, struct mos_process_t *mosp)
{
	struct lwk_mm *lwk_mm = curr_lwk_mm();
	unsigned long level;

	pr_debug("(*) %s val=%s\n", __func__, val);
	if (check_lwkmem_yodargs(mosp, val, true))
		return -EINVAL;
	/* Is LWKMEM usage disabled */
	if (!lwk_mm)
		return 0;
	if (kstrtoul(val, 0, &level))
		return -EINVAL;
	lwk_mm->report_level = level;

	pr_debug("(*) %s report_level=%ld\n", __func__, lwk_mm->report_level);
	return 0;
}

static int lwkmem_vmr_disable(const char *val, struct mos_process_t *mosp)
{
	struct lwk_mm *lwk_mm = curr_lwk_mm();
	enum lwk_vmr_type vmr;
	char *args, *args_start, *vmr_str;

	pr_debug("(*) %s val=%s\n", __func__, val);
	if (check_lwkmem_yodargs(mosp, val, true))
		return -EINVAL;

	/* Is LWKMEM usage disabled */
	if (!lwk_mm)
		return 0;

	args = kstrdup(val, GFP_KERNEL);
	if (!args)
		return -ENOMEM;

	args_start = args;
	while ((vmr_str = strsep(&args, ",")) != NULL) {
		if (strlen(vmr_str) == 0)
			continue;

		for (vmr = 0; vmr < LWK_MAX_NUMVMRTYPES; vmr++) {
			if (strcasecmp(lwk_vmrs_name[vmr], vmr_str) == 0) {
				lwk_mm->policy[vmr].disabled = true;
				pr_debug("(*) %s vmr=%s disabled\n",
					 __func__, vmr_str);
				break;
			}
		}

		if (vmr == LWK_MAX_NUMVMRTYPES) {
			LWKMEM_ERROR("Invalid vmr to disable=[%s], ignoring..",
				     vmr_str);
		}
	}
	kfree(args_start);
	return 0;
}

static int lwkmem_brk_clear_len(const char *val, struct mos_process_t *mosp)
{
	int rc;
	long len;
	struct lwk_mm *lwk_mm = curr_lwk_mm();

	pr_debug("(*) %s val=%s\n", __func__, val);
	if (check_lwkmem_yodargs(mosp, val, true))
		return -EINVAL;

	/* Is LWKMEM usage disabled */
	if (!lwk_mm)
		return 0;

	rc = kstrtol(val, 0, &len);
	if (rc)
		return rc;
	lwk_mm->brk_clear_len = len < 0 ?  -1 : len;
	return 0;
}

static int lwkmem_pma_cache(const char *val, struct mos_process_t *mosp)
{
	unsigned long nr_pages;
	enum lwk_page_type pt;
	struct lwk_mm *lwk_mm = curr_lwk_mm();
	char *args, *args_start, *str_tok, *str_val;

	pr_debug("(*) %s val=%s\n", __func__, val);
	if (check_lwkmem_yodargs(mosp, val, true))
		return -EINVAL;

	/* Is LWKMEM usage disabled */
	if (!lwk_mm)
		return 0;

	args = kstrdup(val, GFP_KERNEL);
	if (!args)
		return -ENOMEM;

	args_start = args;
	while ((str_tok = strsep(&args, ",")) != NULL) {
		if (strlen(str_tok) == 0)
			continue;

		str_val = str_tok;
		str_tok = strsep(&str_val, ":");

		if (!str_val || kstrtoul(str_val, 0, &nr_pages)) {
			LWKMEM_WARN("Invalild value [%s] for [%s], ingnoring",
				    str_val, str_tok);
			continue;
		}

		if (!strcasecmp(str_tok, "all")) {
			for_each_lwkpage_type(pt)
				lwk_mm->pma_cache_limits[pt] = nr_pages;

		} else {
			for_each_lwkpage_type(pt) {
				if (!strcasecmp(str_tok, lwkpage_desc(pt))) {
					lwk_mm->pma_cache_limits[pt] = nr_pages;
					break;
				}
			}

			if (pt == LWK_MAX_NUMPGTYPES)
				LWKMEM_WARN("Invalid token [%s], ingnoring",
					    str_tok);
		}
	}
	kfree(args_start);
	return 0;
}

static struct {
	const char *desc;
	int (*cb)(const char *val, struct mos_process_t *mosp);
} yod_option[] = {
	{ "lwkmem-pma",			lwkmem_pma },
	{ "lwkmem-report",		lwkmem_report },
	{ "lwkmem-vmr-disable",		lwkmem_vmr_disable },
	{ "lwkmem-brk-clear-len",	lwkmem_brk_clear_len },
	{ "lwkmem-pma-cache",		lwkmem_pma_cache },
};

void lwkmem_yod_options_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(yod_option); i++) {
		mos_register_option_callback(yod_option[i].desc,
					     yod_option[i].cb);
	}
}
