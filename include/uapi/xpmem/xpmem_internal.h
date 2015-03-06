/* -*- Mode: C; indent-tabs-mode:nil -*- */
/*
 * Cross Partition Memory user-facing API (internal bits)
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright © 2016      Nathan Hjelm <hjelmn@cs.unm.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * version 2.1 of the License. See the "COPYING.LESSER" file in
 * the main directory of this archive for more details.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#if !defined(XPMEM_INTERNAL_H)
#define XPMEM_INTERNAL_H

#include "xpmem.h"
#include <asm/ioctl.h>

/* ioctl()'s used to communicate with the xpmem kernel module */
#define XPMEM_CMD_VERSION    _IO('x', 0)

/** ioctl to make an xpmem segment */
#define XPMEM_CMD_MAKE       _IO('x', 1)

/**
 * Structure to pass data for XPMEM_CMD_MAKE ioctl
 */
struct xpmem_cmd_make {
  /** Base of virtual address range of new xpmem segment */
  __u64 vaddr;
  /** Size of xpmem segment */
  size_t size;
  /** Permit type */
  int permit_type;
  /** Permit value (permissions) */
  __u64 permit_value;
  /** New segment identifier (out) */
  xpmem_segid_t segid;
};
typedef struct xpmem_cmd_make xpmem_cmd_make_t;

/** ioctl to remove an xpmem segment */
#define XPMEM_CMD_REMOVE     _IO('x', 2)

/**
 * Structure to pass data for XPMEM_CMD_REMOVE ioctl
 */
struct xpmem_cmd_remove {
  /** xpmem segment identifier of segment to remove */
  xpmem_segid_t segid;
};
typedef struct xpmem_cmd_remove xpmem_cmd_remove_t;

/** ioctl to get an xpmem access permit */
#define XPMEM_CMD_GET        _IO('x', 3)

/**
 * Structure to pass data for XPMEM_CMD_GET ioctl
 */
struct xpmem_cmd_get {
  /** xpmem segment identifier of segment to request access */
  xpmem_segid_t segid;
  /** xpmem access flags */
  int flags;
  /** Access permit type (must be XPMEM_PERMIT_MODE) */
  int permit_type;
  /** Access permit value (unix permissions with mask 0777) */
  __u64 permit_value;
  /** New xpmem access permit (out) */
  xpmem_apid_t apid;
};
typedef struct xpmem_cmd_get xpmem_cmd_get_t;

/** ioctl to release an access permit */
#define XPMEM_CMD_RELEASE    _IO('x', 4)

/**
 * Structure to pass data for XPMEM_CMD_RELEASE ioctl
 */
struct xpmem_cmd_release {
  /** Access permit to release */
  xpmem_apid_t apid;
};
typedef struct xpmem_cmd_release xpmem_cmd_release_t;

/** ioctl to attach to a region */
#define XPMEM_CMD_ATTACH     _IO('x', 5)

/**
 * Structure to pass data for XPMEM_CMD_ATTACH ioctl
 */
struct xpmem_cmd_attach {
  /** Access permit */
  xpmem_apid_t apid;
  /** Offset in xpmem segment */
  off_t offset;
  /** Size of region */
  size_t size;
  /** Local address of remote memory region (out) */
  __u64 vaddr;
  /** File descriptor (not used). For compatibility with Cray XPMEM. */
  int fd;
  /** Attach flags (not used). For compatibility with Cray XPMEM. */
  int flags;
};
typedef struct xpmem_cmd_attach xpmem_cmd_attach_t;

/** ioctl to detach a region */
#define XPMEM_CMD_DETACH     _IO('x', 6)

/**
 * Structure to pass data for XPMEM_CMD_DETACH ioctl
 */
struct xpmem_cmd_detach {
  /** Local address of memory region to detach */
  __u64 vaddr;
};
typedef struct xpmem_cmd_detach xpmem_cmd_detach_t;

#define XPMEM_CMD_FORK_BEGIN _IO('x', 7)
#define XPMEM_CMD_FORK_END   _IO('x', 8)

/*
 * path to XPMEM device
 */
#define XPMEM_DEV_PATH  "/dev/xpmem"

#endif /* !defined(XPMEM_INTERNAL_H) */
