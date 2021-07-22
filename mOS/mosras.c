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

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/mos.h>

#include "mosras.h"

#ifdef CONFIG_MOS_FOR_HPC

#undef pr_fmt
#define pr_fmt(fmt)	"mOS-ras: " fmt

typedef int (*mosras_formatter_t)(const char *, const char *, const char *,
				  const char *);

static int mosras_default_formatter(const char *evtid,
				    const char *location,
				    const char *jobid,
				    const char *msg);

static int mosras_ucs_formatter(const char *evtid,
				const char *location,
				const char *jobid,
				const char *msg);

static char mosras_config[32] = "default";
static char mosras_location[128];
static char mosras_jobid[64];
static mosras_formatter_t mosras_formatter = mosras_default_formatter;

static char *_rstrip(char *attr)
{
	int n = strlen(attr);

	while (n > 0 && isspace(attr[n-1]))
		attr[--n] = 0;

	return attr;
}

#define MOSRAS_SYSFS_SHOW_ATTR(name)				\
	static ssize_t name##_show(struct kobject *kobj,	\
				   struct kobj_attribute *attr,	\
				   char *buff)			\
	{							\
		return scnprintf(buff,				\
				 sizeof(mosras_##name) + 1,	\
				 "%s\n", mosras_##name);	\
	}

#define MOSRAS_SYSFS_STORE_ATTR(name)					\
	static ssize_t name##_store(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    const char *buf, size_t count)	\
	{								\
		if (count < sizeof(mosras_##name)) {			\
			strncpy(mosras_##name, buf, count);		\
			mosras_##name[count] = '\0';			\
			_rstrip(mosras_##name);				\
			return count;					\
		}							\
									\
		pr_err("Could not set " # name 				\
			" (\"%s\" is too long)\n", 			\
			buf);						\
		return -EINVAL;						\
	}

static int mosras_configure(const char *cfg)
{
	int i, found = 0, ret = 0;
	static struct {
		const char *name;
		mosras_formatter_t formatter;
	} _CFGS[] = {
		{ "default", mosras_default_formatter, },
		{ "ucs", mosras_ucs_formatter, },
	};

	for (i = 0; i < ARRAY_SIZE(_CFGS) && !found; i++)
		if (strncmp(_CFGS[i].name, cfg, strlen(_CFGS[i].name)) == 0) {
			mosras_formatter = _CFGS[i].formatter;
			mosras_config[sizeof(mosras_config)-1] = '\0';
			strncpy(mosras_config, _CFGS[i].name, sizeof(mosras_config)-1);
			_rstrip(mosras_config);
			found = 1;
		}

	if (!found) {
		pr_warn("\"%s\" is not a recognized configuration.\n", cfg);
		ret = -EINVAL;
	}

	pr_debug("(<) %s cfg=\"%s\" ret=%d\n",
		 __func__, cfg, ret);

	return ret;
}

static ssize_t config_store(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    const char *buff, size_t count)
{
	int rc = mosras_configure(buff);

	return (rc == 0) ? count : rc;
}

static ssize_t inject_store(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    const char *buff, size_t count)
{
	char *dup, *msg;
	ssize_t ret;
	char *event_id;

	dup = msg = kmalloc(count + 1, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(msg, buff, count);
	msg[count] = '\0';
	event_id = strsep(&msg, " ");

	if (!event_id || !msg) {
		ret = -EINVAL;
		goto out;
	}

	ret = mos_ras(event_id, _rstrip(msg));

	if (ret == 0)
		ret = count;

 out:
	kfree(dup);
	return ret;
}

MOSRAS_SYSFS_SHOW_ATTR(config)
MOSRAS_SYSFS_SHOW_ATTR(location)
MOSRAS_SYSFS_STORE_ATTR(location)
MOSRAS_SYSFS_SHOW_ATTR(jobid)
MOSRAS_SYSFS_STORE_ATTR(jobid)

static struct kobj_attribute location_attr = __ATTR_RW(location);
static struct kobj_attribute jobid_attr = __ATTR_RW(jobid);
static struct kobj_attribute config_attr = __ATTR_RW(config);
static struct kobj_attribute inject_attr = __ATTR_WO(inject);

static  struct attribute *mosras_attributes[] = {
	&location_attr.attr,
	&jobid_attr.attr,
	&config_attr.attr,
	&inject_attr.attr,
	NULL
};

static struct attribute_group mosras_attr_group = {
	.attrs = mosras_attributes,
};

int mosras_sysfs_init(struct kobject *mos_kobj)
{
	int ret = 0;
	struct kobject *mosras_kobj;

	mosras_kobj = kobject_create_and_add("ras", mos_kobj);

	if (!mos_kobj) {
		ret = -ENOMEM;
		goto out;
	}

	location_attr.attr.mode |= S_IWGRP;
	jobid_attr.attr.mode |= S_IWGRP;
	config_attr.attr.mode |= S_IWGRP;
	inject_attr.attr.mode |= S_IWGRP;

	ret = sysfs_create_group(mosras_kobj, &mosras_attr_group);
	if (ret) {
		pr_warn("Could not create ras entries in sysfs\n");
		goto out;
	}

 out:
	return ret;
}

static int __init _mosras_location_setup(char *str)
{
	mosras_location[sizeof(mosras_location)-1] = '\0';
	strncpy(mosras_location, str, sizeof(mosras_location)-1);
	return 0;
}
__setup("mosras_location=", _mosras_location_setup);


static int __init _mosras_config_setup(char *str)
{
	return mosras_configure(str);
}
__setup("mosras_config=", _mosras_config_setup);


#define MOSRAS_MSG_SIZE 4096

int mos_ras(const char *event_id, const char *fmt, ...)
{

	va_list argptr;
	size_t n;
	char *msg;

	msg = kmalloc(MOSRAS_MSG_SIZE, GFP_KERNEL);

	if (!msg)
		return -ENOMEM;

	va_start(argptr, fmt);
	n = vsnprintf(msg, MOSRAS_MSG_SIZE, fmt, argptr);

	if (n > MOSRAS_MSG_SIZE)
		pr_warn("RAS message was truncated.\n");

	mosras_formatter(event_id, mosras_location, mosras_jobid, msg);

	va_end(argptr);
	kfree(msg);
	return 0;
}

static int mosras_default_formatter(const char *evtid,
				    const char *location,
				    const char *jobid,
				    const char *msg)
{
	pr_crit("msg=\"%s\" id=%s location=%s jobid=%s\n",
		msg, evtid, location, jobid);
	return 0;
}

static int mosras_ucs_formatter(const char *evtid,
				const char *location,
				const char *jobid,
				const char *msg)
{
#undef pr_fmt
#define pr_fmt(fmt) fmt

	pr_crit("UcsRasEvent "
		"\"Event\": \"%s\", "
		"\"Lctn\": \"%s\", "
		"\"JobId\": \"%s\", "
		"\"Data\": \"%s\" "
		"\n",
		evtid, location, jobid, msg);

	return 0;

#undef pr_fmt
}

#endif
