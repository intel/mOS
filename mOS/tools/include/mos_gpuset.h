/*
 * Multi Operating System (mOS)
 * Copyright (c) 2021, Intel Corporation.
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

#ifndef __MOS_GPUSET__
#define __MOS_GPUSET__

#define _GNU_SOURCE
/*
 * Define the maximum supported number of GPU devices and tiles within those
 * GPU devices. The total number of tiles cannot exceed 64 since the GPU bit
 * mask is currently fixed at 64 bits in the mOS kernel. Any combination of
 * MAX_GPU_DEVICES and MAX_TILES_PER_GPU can be support as long as the product
 * of the two are less than or equal to 64.
 */
#define MOS_MAX_GPU_TILES 64
#define MOS_MAX_GPU_DEVICES 16
#define MOS_MAX_TILES_PER_GPU 4

#endif
