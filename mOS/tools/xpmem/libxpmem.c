/*
 * Copyright (c) 2009 Cray, Inc.
 * Copyright (c) 2016 Nathan Hjelm <hjelmn@cs.unm.edu>
 *
 * This file is subject to the terms and conditions of the GNU Lesser General Public
 * License.  See the file "COPYING.LESSER" in the main directory of this archive
 * for more details.
 */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "../../../include/uapi/xpmem/xpmem_internal.h"

static int xpmem_fd = -1;

/**
 * xpmem_init - Creates an XPMEM file descriptor
 * Description:
 *	Opens XPMEM device file and sets the Close On Exec flag. The device file
 *	descriptor is stored internally for later use with xpmem_ioctl().
 * Context:
 *	xpmem_init() is called by xpmem_ioctl(). This is an internal call--the
 *	user should not need to call this manually.
 * Return Values:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_init(void)
{
	struct stat stb;

	if (stat(XPMEM_DEV_PATH, &stb) != 0 ||
	    !S_ISCHR(stb.st_mode) ||
	    (xpmem_fd = open(XPMEM_DEV_PATH, O_RDWR)) == -1 ||
	    fcntl(xpmem_fd, F_SETFD, FD_CLOEXEC) == -1) {
		return -1;
	}
	return 0;

}

/**
 * xpmem_ioctl - wrapper for ioctl()
 * @cmd: IN: The command to pass to ioctl()
 * @arg: IN: The argument to pass to ioctl()
 * Description:
 *	Creates an xpmem file descriptor if not present, or use the one
 *	created previously as an argument to ioctl().
 * Context:
 *	xpmem_ioctl() replaces all ioctl() calls in this library. This is an
 *	internal call--the user should not need to call this function manually.
 * Return Values:
 *	Success: not -1
 *	Failure: -1
 */
int xpmem_ioctl(int cmd, void *arg)
{
	int ret;
	if (xpmem_fd == -1 && xpmem_init() != 0)
		return -1;
	ret = ioctl(xpmem_fd, cmd, arg);
	/**
	 * A child process that never opened the XPMEM device, but inherits
	 * xpmem_fd from its parent will have -XPMEM_ERRNO_NOPROC returned. So
	 * simply open the device and retry the ioctl.
	 */
	if (ret == -1 && errno == XPMEM_ERRNO_NOPROC) {
		if ((xpmem_fd = open(XPMEM_DEV_PATH, O_RDWR)) == -1)
			return -1;
		ret = ioctl(xpmem_fd, cmd, arg);
	}
	return ret;
}

xpmem_segid_t xpmem_make(void *vaddr, size_t size, int permit_type,
			 void *permit_value)
{
	struct xpmem_cmd_make make_info;

	make_info.vaddr = (__u64)vaddr;
	make_info.size  = size;
	make_info.permit_type  = permit_type;
	make_info.permit_value = (__u64)permit_value;
	if (xpmem_ioctl(XPMEM_CMD_MAKE, &make_info) < 0 || !make_info.segid)
		return -1;
	return make_info.segid;
}

int xpmem_remove(xpmem_segid_t segid)
{
	struct xpmem_cmd_remove	remove_info;

	remove_info.segid = segid;
	if (xpmem_ioctl(XPMEM_CMD_REMOVE, &remove_info) == -1)
		return -1;
	return 0;
}

xpmem_apid_t xpmem_get(xpmem_segid_t segid, int flags, int permit_type,
			void *permit_value)
{
	struct xpmem_cmd_get get_info;

	get_info.segid = segid;
	get_info.flags = flags;
	get_info.permit_type = permit_type;
	get_info.permit_value = (__u64)NULL;
	if (xpmem_ioctl(XPMEM_CMD_GET, &get_info) == -1 || !get_info.apid)
		return -1;
	return get_info.apid;
}

int xpmem_release(xpmem_apid_t apid)
{
	struct xpmem_cmd_release release_info;

	release_info.apid = apid;
	if (xpmem_ioctl(XPMEM_CMD_RELEASE, &release_info) == -1)
		return -1;
	return 0;
}

void *xpmem_attach(struct xpmem_addr addr, size_t size, void *vaddr)
{
	struct xpmem_cmd_attach attach_info;

	attach_info.apid = addr.apid;
	attach_info.offset = addr.offset;
	attach_info.size = size;
	attach_info.vaddr = (__u64)vaddr;
	attach_info.fd = xpmem_fd;
	attach_info.flags = 0;
	if (xpmem_ioctl(XPMEM_CMD_ATTACH, &attach_info) == -1)
		return (void *)-1;
	return (void *)attach_info.vaddr;
}

int xpmem_detach(void *vaddr)
{
	struct xpmem_cmd_detach detach_info;

	detach_info.vaddr = (__u64)vaddr;
	if (xpmem_ioctl(XPMEM_CMD_DETACH, &detach_info) == -1)
		return -1;
	return 0;
}

int xpmem_version(void)
{
	return xpmem_ioctl(XPMEM_CMD_VERSION, NULL);
}
