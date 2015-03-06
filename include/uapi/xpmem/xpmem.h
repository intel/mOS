/*
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License.  See the file "COPYING.LESSER" in the main directory of
 * this archive for more details. The underlying library is subject to the
 * terms and conditions of the GNU Lesser General Public License.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright (c) 2016      Nathan Hjelm. All rights reserved.
 */

/*
 * Cross Partition Memory (XPMEM) structures and macros.
 */

#ifndef XPMEM_H
#define XPMEM_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif

/*
 * basic argument type definitions
 */
/**
 * segid returned from xpmem_make()
 */
typedef __s64 xpmem_segid_t;

/**
 * apid returned from xpmem_get()
 */
typedef __s64 xpmem_apid_t;

/**
 * Structure used by xpmem_attach().
 */
struct xpmem_addr {
        /** apid that represents memory */
        xpmem_apid_t apid;
        /** offset into apid's memory region */
	off_t offset;
};

/**
 * Maximum address size for xpmem_make. Keep in mind that there may
 * be platform-dependant restrictions beyond this size. Attempting
 * to attach to an address range that goes outside the additional
 * restriction will return an error. A new define may be added in
 * the future to indicate the largest address that can be attached.
 */
#define XPMEM_MAXADDR_SIZE	(size_t)(-1L)

/*
 * The following are the possible XPMEM related errors.
 */
/** Unknown thread due to fork() */
#define XPMEM_ERRNO_NOPROC	2004

/*
 * Flags for segment permissions
 */
#define XPMEM_RDONLY	0x1
#define XPMEM_RDWR	0x2

/*
 * Valid permit_type values for xpmem_make().
 */
enum {
  /** Permit value are unix-style permissions with mask 0777. Any bit
   * set outside this range is an error. This is the only valid permit
   * mode at this time. */
  XPMEM_PERMIT_MODE = 0x1,
};

#if !defined(__KERNEL__)

/**
 * xpmem_version - get the XPMEM version
 *
 * Return Value:
 *	Success: XPMEM version number
 *	Failure: -1
 */
int xpmem_version (void);

/**
 * xpmem_make - share a memory block
 * @vaddr: IN: starting address of region to share
 * @size: IN: number of bytes to share
 * @permit_type: IN: only XPMEM_PERMIT_MODE currently defined
 * @permit_value: IN: permissions mode expressed as an octal value
 * Description:
 *	xpmem_make() shares a memory block by invoking the XPMEM driver.
 * Context:
 *	Called by the source process to obtain a segment ID to share with other
 *	processes. It is common to call this function with vadder = NULL and
 *      size = XPMEM_MAXADDR_SIZE. This will share the entire address space of
 *      the calling process.
 * Return Value:
 *	Success: 64-bit segment ID (xpmem_segid_t)
 *	Failure: -1
 */
xpmem_segid_t xpmem_make (void *vaddr, size_t size, int permit_type, void *permit_value);

/**
 * xpmem_remove - revoke access to a shared memory block
 * @segid: IN: 64-bit segment ID of the region to stop sharing
 * Description:
 *	The opposite of xpmem_make(), this function deletes the mapping for a
 *	specified segid that was created from a previous xpmem_make() call.
 * Context:
 *	Optionally called by the source process, otherwise automatically called
 *	by the driver when the source process exits.
 * Return Value:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_remove (xpmem_segid_t segid);

/**
 * xpmem_get - obtain permission to attach memory
 * @segid: IN: segment ID returned from a previous xpmem_make() call
 * @flags: IN: read-write (XPMEM_RDWR) or read-only (XPMEM_RDONLY)
 * @permit_type: IN: only XPMEM_PERMIT_MODE currently defined
 * @permit_value: IN: permissions mode expressed as an octal value
 * Description:
 *	xpmem_get() attempts to get access to a shared memory block.
 * Context:
 *	Called by the consumer process to get permission to attach memory from
 *	the source virtual address space associated with this segid. If access
 *	is granted, an apid will be returned to pass to xpmem_attach().
 * Return Value:
 *	Success: 64-bit access permit ID (xpmem_apid_t)
 *	Failure: -1
 */
xpmem_apid_t xpmem_get (xpmem_segid_t segid, int flags, int permit_type,
                        void *permit_value);

/**
 * xpmem_release - give up access to the segment
 * @apid: IN: 64-bit access permit ID to release
 * Description:
 *	The opposite of xpmem_get(), this function deletes any mappings in the
 *	consumer's address space.
 * Context:
 *	Optionally called by the consumer process, otherwise automatically
 *	called by the driver when the consumer process exits.
 * Return Value:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_release (xpmem_apid_t apid);

/**
 * xpmem_attach - map a source address to own address space
 * @addr: IN: a structure consisting of a xpmem_apid_t apid and an off_t offset
 * 	addr.apid: access permit ID returned from a previous xpmem_get() call
 * 	addr.offset: offset into the source memory to begin the mapping
 * @size: IN: number of bytes to map
 * @vaddr: IN: address at which the mapping should be created, or NULL if the
 *		kernel should choose
 * Description:
 *	Attaches a virtual address space range from the source process.
 * Context:
 *	Called by the consumer to get a mapping between the shared source
 *	address and an address in the consumer process' own address space. If
 *	the mapping is successful, then the consumer process can now begin
 *	accessing the shared memory.
 * Return Value:
 *	Success: virtual address at which the mapping was created
 *	Failure: -1
 */
void *xpmem_attach (struct xpmem_addr addr, size_t size, void *vaddr);

/**
 * xpmem_detach - remove a mapping between consumer and source
 * @vaddr: IN: virtual address within an XPMEM mapping in the consumer's
 *		address space
 * Description:
 *	Detach from the virtual address space of the source process.
 * Context:
 *	Optionally called by the consumer process, otherwise automatically
 *	called by the driver when the consumer process exits.
 * Return Value:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_detach (void *vaddr);

#endif /* !defined(__KERNEL__) */

#endif /* XPMEM_H */
