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
#ifndef __MOS_GPUMASK_H
#define __MOS_GPUMASK_H

/*
 * Gpumasks provide a bitmap suitable for representing the
 * set of GPU's in a system, One bit position per GPU device.
 */
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/mos.h>

/**
 * gpumask_bits - get the bits in a gpumask
 * @maskp: the struct gpumask *
 *
 */

#define gpumask_bits(maskp) ((maskp)->bits)

/**
 * gpumask_pr_args - printf args to output a gpumask
 * @maskp: gpumask to be printed
 *
 * Can be used to provide arguments for '%*pb[l]' when printing
 * a gpumask.
 */


#define gpumask_pr_args(maskp)		nr_gpumask_bits, gpumask_bits(maskp)

static inline void gpu_max_bits_warn(unsigned int gpu, unsigned int bits)
{
#ifdef MOS_DEBUG_GPU_MAP
	WARN_ON_ONCE(gpu >= bits);
#endif /* MOS_DEBUG_GPU_MAP */

}

/* verify gpu argument to gpumask_* operators */
static inline unsigned int gpumask_check(unsigned int gpu)
{
	gpu_max_bits_warn(gpu, nr_gpumask_bits);
	return gpu;
}

/**
 * gpumask_first - get the first gpu in a gpumask
 * @srcp: the gpumask pointer
 *
 * Returns >= nr_gpumask_bits if no gpus set.
 */
static inline unsigned int gpumask_first(const struct gpumask *srcp)
{
	return find_first_bit(gpumask_bits(srcp), nr_gpumask_bits);
}

/**
 * gpumask_last - get the last gpu in a gpumask
 * @srcp:	- the gpumask pointer
 *
 * Returns	>= nr_gpumask_bits if no GPUs set.
 */
static inline unsigned int gpumask_last(const struct gpumask *srcp)
{
	return find_last_bit(gpumask_bits(srcp), nr_gpumask_bits);
}

/**
 * gumask_next - get the next gpu in a gpumask
 * @n: the gpu prior to the place to search (ie. return will be
 *   > @n)
 * @srcp: the gpumask pointer
 *
 * Returns >= nr_gpumask_bits if no further gpus set.
 */
static inline int gpumask_next(int n, const struct gpumask *srcp)
{
	/* -1 is a legal arg here. */
	if (n != -1)
		gpumask_check(n);
	return find_next_bit(gpumask_bits(srcp), nr_gpumask_bits, n + 1);
}


/**
 * gpumask_next_zero - get the next unset gpu in a gpumask
 * @n: the gpu prior to the place to search (ie. return will be
 *   > @n)
 * @srcp: the gpumask pointer
 *
 * Returns >= nr_gpumask_bits if no further gpus unset.
 */
static inline unsigned int gpumask_next_zero(int n, const struct gpumask *srcp)
{
	/* -1 is a legal arg here. */
	if (n != -1)
		gpumask_check(n);
	return find_next_zero_bit(gpumask_bits(srcp), nr_gpumask_bits, n+1);
}

/**
 * for_each_gpu - iterate over every gpu in a mask
 * @gpu: the (optionally unsigned) integer iterator
 * @mask: the gpumask pointer
 *
 * After the loop, gpu is >= nr_gpumask_bits.
 */
#define for_each_gpu(gpu, mask)				\
	for ((gpu) = -1;				\
		(gpu) = gpumask_next((gpu), (mask)),	\
		(gpu) < nr_gpumask_bits;)


/**
 * gpumask_set_gpu - set a gpu in a gpumask
 * @gpu: gpu number (< nr_gpumask_bits)
 * @dstp: the gpumask pointer
 */
static inline void gpumask_set_gpu(unsigned int gpu, struct gpumask *dstp)
{
	set_bit(gpumask_check(gpu), gpumask_bits(dstp));
}

static inline void __gpumask_set_gpu(unsigned int gpu, struct gpumask *dstp)
{
	__set_bit(gpumask_check(gpu), gpumask_bits(dstp));
}


/**
 * gpumask_clear_gpu - clear a gpu in a gpumask
 * @gpu: gpu number (< nr_gpumask_bits)
 * @dstp: the gpumask pointer
 */
static inline void gpumask_clear_gpu(int gpu, struct gpumask *dstp)
{
	clear_bit(gpumask_check(gpu), gpumask_bits(dstp));
}

static inline void __gpumask_clear_gpu(int gpu, struct gpumask *dstp)
{
	__clear_bit(gpumask_check(gpu), gpumask_bits(dstp));
}

/**
 * gpumask_test_gpu - test for a gpu in a gpumask
 * @gpu: gpu number (< nr_gpumask_bits)
 * @gpumask: the gpumask pointer
 *
 * Returns 1 if @gpu is set in @gpumask, else returns 0
 */
static inline int gpumask_test_gpu(int gpu, const struct gpumask *gpumask)
{
	return test_bit(gpumask_check(gpu), gpumask_bits((gpumask)));
}

/**
 * gpumask_test_and_set_gpu - atomically test and set a gpu in a
 * gpumask
 * @gpu: gpu number (< nr_gpumask_bits)
 * @gpumask: the gpumask pointer
 *
 * Returns 1 if @gpu is set in old bitmap of @gpumask, else
 * returns 0
 *
 * test_and_set_bit wrapper for gpumasks.
 */
static inline int gpumask_test_and_set_gpu(int gpu, struct gpumask *gpumask)
{
	return test_and_set_bit(gpumask_check(gpu), gpumask_bits(gpumask));
}

/**
 * gpumask_test_and_clear_gpu - atomically test and clear a gpu
 * in a gpumask
 * @gpu: gpu number (< nr_gpumask_bits)
 * @gpumask: the gpumask pointer
 *
 * Returns 1 if @gpu is set in old bitmap of @gpumask, else
 * returns 0
 *
 * test_and_clear_bit wrapper for gpumasks.
 */
static inline int gpumask_test_and_clear_gpu(int gpu, struct gpumask *gpumask)
{
	return test_and_clear_bit(gpumask_check(gpu), gpumask_bits(gpumask));
}

/**
 * gpumask_setall - set all gpus (< nr_gpumask_bits) in a pumask
 * @dstp: the gpumask pointer
 */
static inline void gpumask_setall(struct gpumask *dstp)
{
	bitmap_fill(gpumask_bits(dstp), nr_gpumask_bits);
}

/**
 * gpumask_clear - clear all gpus (< nr_gpumask_bits) in a
 * gpumask
 * @dstp: the gpumask pointer
 */
static inline void gpumask_clear(struct gpumask *dstp)
{
	bitmap_zero(gpumask_bits(dstp), nr_gpumask_bits);
}

/**
 * gpumask_and - *dstp = *src1p & *src2p
 * @dstp: the gpumask result
 * @src1p: the first input
 * @src2p: the second input
 *
 * If *@dstp is empty, returns 0, else returns 1
 */
static inline int gpumask_and(struct gpumask *dstp,
			       const struct gpumask *src1p,
			       const struct gpumask *src2p)
{
	return bitmap_and(gpumask_bits(dstp), gpumask_bits(src1p),
				       gpumask_bits(src2p), nr_gpumask_bits);
}

/**
 * gpumask_or - *dstp = *src1p | *src2p
 * @dstp: the gpumask result
 * @src1p: the first input
 * @src2p: the second input
 */
static inline void gpumask_or(struct gpumask *dstp, const struct gpumask *src1p,
			      const struct gpumask *src2p)
{
	bitmap_or(gpumask_bits(dstp), gpumask_bits(src1p),
				      gpumask_bits(src2p), nr_gpumask_bits);
}

/**
 * gpumask_xor - *dstp = *src1p ^ *src2p
 * @dstp: the gpumask result
 * @src1p: the first input
 * @src2p: the second input
 */
static inline void gpumask_xor(struct gpumask *dstp,
			       const struct gpumask *src1p,
			       const struct gpumask *src2p)
{
	bitmap_xor(gpumask_bits(dstp), gpumask_bits(src1p),
				       gpumask_bits(src2p), nr_gpumask_bits);
}

/**
 * Gpumask_andnot - *dstp = *src1p & ~*src2p
 * @dstp: the gpumask result
 * @src1p: the first input
 * @src2p: the second input
 *
 * If *@dstp is empty, returns 0, else returns 1
 */
static inline int gpumask_andnot(struct gpumask *dstp,
				  const struct gpumask *src1p,
				  const struct gpumask *src2p)
{
	return bitmap_andnot(gpumask_bits(dstp), gpumask_bits(src1p),
					  gpumask_bits(src2p), nr_gpumask_bits);
}

/**
 * gpumask_complement - *dstp = ~*srcp
 * @dstp: the gpumask result
 * @srcp: the input to invert
 */
static inline void gpumask_complement(struct gpumask *dstp,
				      const struct gpumask *srcp)
{
	bitmap_complement(gpumask_bits(dstp), gpumask_bits(srcp),
					      nr_gpumask_bits);
}

/**
 * gpumask_equal - *src1p == *src2p
 * @src1p: the first input
 * @src2p: the second input
 */
static inline bool gpumask_equal(const struct gpumask *src1p,
				const struct gpumask *src2p)
{
	return bitmap_equal(gpumask_bits(src1p), gpumask_bits(src2p),
						 nr_gpumask_bits);
}

/**
 * gpumask_or_equal - *src1p | *src2p == *src3p
 * @src1p: the first input
 * @src2p: the second input
 * @src3p: the third input
 */
static inline bool gpumask_or_equal(const struct gpumask *src1p,
				    const struct gpumask *src2p,
				    const struct gpumask *src3p)
{
	return bitmap_or_equal(gpumask_bits(src1p), gpumask_bits(src2p),
			       gpumask_bits(src3p), nr_gpumask_bits);
}

/**
 * gpumask_intersects - (*src1p & *src2p) != 0
 * @src1p: the first input
 * @src2p: the second input
 */
static inline bool gpumask_intersects(const struct gpumask *src1p,
				     const struct gpumask *src2p)
{
	return bitmap_intersects(gpumask_bits(src1p), gpumask_bits(src2p),
						      nr_gpumask_bits);
}

/**
 * gpumask_subset - (*src1p & ~*src2p) == 0
 * @src1p: the first input
 * @src2p: the second input
 *
 * Returns 1 if *@src1p is a subset of *@src2p, else returns 0
 */
static inline int gpumask_subset(const struct gpumask *src1p,
				 const struct gpumask *src2p)
{
	return bitmap_subset(gpumask_bits(src1p), gpumask_bits(src2p),
						  nr_gpumask_bits);
}

/**
 * gpumask_empty - *srcp == 0
 * @srcp: the gpumask to that all gpus < nr_gpu_ids are clear.
 */
static inline bool gpumask_empty(const struct gpumask *srcp)
{
	return bitmap_empty(gpumask_bits(srcp), nr_gpumask_bits);
}

/**
 * gpumask_full - *srcp == 0xFFFFFFFF...
 * @srcp: the gpumask to that all gpus < nr_gpu_ids are set.
 */
static inline bool gpumask_full(const struct gpumask *srcp)
{
	return bitmap_full(gpumask_bits(srcp), nr_gpumask_bits);
}

/**
 * gpumask_weight - Count of bits in *srcp
 * @srcp: the gpumask to count bits (< nr_gpu_ids) in.
 */
static inline unsigned int gpumask_weight(const struct gpumask *srcp)
{
	return bitmap_weight(gpumask_bits(srcp), nr_gpumask_bits);
}

/**
 * gpumask_shift_right - *dstp = *srcp >> n
 * @dstp: the gpumask result
 * @srcp: the input to shift
 * @n: the number of bits to shift by
 */
static inline void gpumask_shift_right(struct gpumask *dstp,
				       const struct gpumask *srcp, int n)
{
	bitmap_shift_right(gpumask_bits(dstp), gpumask_bits(srcp), n,
					       nr_gpumask_bits);
}

/**
 * gpumask_shift_left - *dstp = *srcp << n
 * @dstp: the gpumask result
 * @srcp: the input to shift
 * @n: the number of bits to shift by
 */
static inline void gpumask_shift_left(struct gpumask *dstp,
				      const struct gpumask *srcp, int n)
{
	bitmap_shift_left(gpumask_bits(dstp), gpumask_bits(srcp), n,
					      nr_gpumask_bits);
}

/**
 * gpumask_copy - *dstp = *srcp
 * @dstp: the result
 * @srcp: the input gpumask
 */
static inline void gpumask_copy(struct gpumask *dstp,
				const struct gpumask *srcp)
{
	bitmap_copy(gpumask_bits(dstp), gpumask_bits(srcp), nr_gpumask_bits);
}

/**
 * gpumask_any - pick a "random" gpu from *srcp
 * @srcp: the input gpumask
 *
 * Returns >= nr_gpu_ids if no gpus set.
 */
#define gpumask_any(srcp) gpumask_first(srcp)

/**
 * gpumask_first_and - return the first gpu from *srcp1 & *srcp2
 * @src1p: the first input
 * @src2p: the second input
 *
 * Returns >= nr_gpu_ids if no gpus set in both.  See also gpumask_next_and().
 */
#define gpumask_first_and(src1p, src2p) gpumask_next_and(-1, (src1p), (src2p))

/**
 * gpumask_any_and - pick a "random" gpu from *mask1 & *mask2
 * @mask1: the first input gpumask
 * @mask2: the second input gpumask
 *
 * Returns >= nr_gpu_ids if no gpus set.
 */
#define gpumask_any_and(mask1, mask2) gpumask_first_and((mask1), (mask2))

/**
 * gpumask_of - the gpumask containing just a given gpu
 * @gpu: the gpu (<= nr_gpu_ids)
 */
#define gpumask_of(gpu) (get_gpu_mask(gpu))

/**
 * gpumask_parse_user - extract a gpumask from a user string
 * @buf: the buffer to extract from
 * @len: the length of the buffer
 * @dstp: the gpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int gpumask_parse_user(const char __user *buf, int len,
				     struct gpumask *dstp)
{
	return bitmap_parse_user(buf, len, gpumask_bits(dstp), nr_gpumask_bits);
}

/**
 * gpumask_parselist_user - extract a gpumask from a user string
 * @buf: the buffer to extract from
 * @len: the length of the buffer
 * @dstp: the gpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int gpumask_parselist_user(const char __user *buf, int len,
				     struct gpumask *dstp)
{
	return bitmap_parselist_user(buf, len, gpumask_bits(dstp),
				     nr_gpumask_bits);
}

/**
 * gpumask_parse - extract a gpumask from a string
 * @buf: the buffer to extract from
 * @dstp: the gpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int gpumask_parse(const char *buf, struct gpumask *dstp)
{
	unsigned int len = strchrnul(buf, '\n') - buf;

	return bitmap_parse(buf, len, gpumask_bits(dstp), nr_gpumask_bits);
}

/**
 * gpulist_parse - extract a gpumask from a user string of ranges
 * @buf: the buffer to extract from
 * @dstp: the gpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int gpulist_parse(const char *buf, struct gpumask *dstp)
{
	return bitmap_parselist(buf, gpumask_bits(dstp), nr_gpumask_bits);
}

/**
 * gpumask_size - size to allocate for a 'struct gpumask' in bytes
 */
static inline unsigned int gpumask_size(void)
{
	return BITS_TO_LONGS(nr_gpumask_bits) * sizeof(long);
}

/**
 * gpumap_print_to_pagebuf  - copies the gpumask into the
 *      buffer either as comma-separated list of gpus or hex
 *      values of gpumask
 * @list: indicates whether the gpumap must be list
 * @mask: the gpumask to copy
 * @buf: the buffer to copy into
 *
 * Returns the length of the (null-terminated) @buf string, zero if
 * nothing is copied.
 */
static inline ssize_t
gpumap_print_to_pagebuf(bool list, char *buf, const struct gpumask *mask)
{
	return bitmap_print_to_pagebuf(list, buf, gpumask_bits(mask),
				      nr_gpumask_bits);
}

#endif
