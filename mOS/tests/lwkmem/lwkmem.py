# Multi Operating System (mOS)
# Copyright (c) 2016, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

from mostests import *
import re
import random

logger = logging.getLogger()

GiB = 1024**3
MiB = 1024**2
KiB = 1024**1

sysfs_path = '/sys/kernel/mOS'
lwkmem_path = sysfs_path + '/lwkmem'
lwkmem_reserved_path = lwkmem_path + '_reserved'
lwkcpus_path = sysfs_path + '/lwkcpus'
lwkcpus_reserved_path = lwkcpus_path + '_reserved'

def zerovec(seq):
    return [0] * len(seq)

def memstr_to_int(s):
    logging.debug('> (%r)', s)
    i = s.replace(' ', '') or '0'  # NOTENOTE

    i, unit = re.match(r'([0-9]+)(G|M|K)?$', i, re.I).groups()
    unit = {
        'g': GiB,
        'm': MiB,
        'k': KiB,
        '':  1,
        }[(unit or '').lower()]
    i = int(i) * unit

    logging.debug('< (%r) = %d', s, i)
    return i

def get_file_as_vector(path):
    logging.debug('> (%r)', path)

    txt = get_file(path)
    vec = [memstr_to_int(s) for s in txt.split()]

    logging.debug('< (%r) = %r', path, vec)
    return vec

def get_cpus_domains():
    cpus = set()
    fname = '/sys/devices/system/node/has_cpu'
    with open(fname) as nodes:
        for line in nodes:
            for phrase in line.strip().split(','):
                toks = phrase.split('-')
                if len(toks) == 1:
                    cpus.add(int(toks[0]))
                elif len(toks) == 2:
                    for n in range(int(toks[0]), int(toks[1]) + 1):
                        cpus.add(n)
                else:
                    logging.error('Unrecognized format in {}: "{}"'.format(fname, line.strip()))
                    return -1

    return len(cpus)

class Base(TestCase):
    require = [lwkmem_path]

    def update_lwk_state(self):
        def assert_idle(path, func, assertion):
            value = func(path)
            if not assertion(value):
                self.skipTest('test assumes system is idle, but {} -> {!r}',
                              path, value)
            return value

        self.lwkmem = get_file_as_vector(lwkmem_path)
        self.lwkcpus = get_file(lwkcpus_path)

        a = lambda v: v == zerovec(self.lwkmem)
        self.lwkmem_reserved = assert_idle(lwkmem_reserved_path,
                                           get_file_as_vector, a)

        a = lambda v: len(v) == 0
        self.lwkcpus_reserved = assert_idle(lwkcpus_reserved_path,
                                            get_file, a)

class Basics(Base):
    def test_lwkmem(self):
        # Check if there is any designated LWK memory.
        self.update_lwk_state()
        self.assertNotEqual(self.lwkmem, zerovec(self.lwkmem),
                         'could not find designated LWK memory')

    def test_lwkmem_request(self):
        # Launch a task on all designated CPUs and memory.
        self.update_lwk_state()
        run(self, './lwkprocess', '--lwkcpus', self.lwkcpus,
            '--lwkmem', strseq(self.lwkmem, ','))

    def test_lwkmem_oversubscription_request(self):
        # For each node with LWK memory, launch a task that requests
        # more than is available and verify that this fails.
        self.update_lwk_state()
        for nid, size in enumerate(self.lwkmem):
            with self.subTest(nid=nid, size=size):
                request = zerovec(self.lwkmem)
                request[nid] = size + (2 * MiB)
                run(self, './lwkprocess', '--lwkcpus', self.lwkcpus,
                    '--lwkmem', strseq(request, ','),
                    assertion=False)

class Yod(Base):
    require = [YOD]

    def test_heap(self):
        # Launch a heap-manipulating test app and verify the heap works
        def subtest(n, size):
            with self.subTest(n=n, size=size):
                yod(self, './maptest', '--verbose', '--type', 'heap',
                    '--num', n, '--size', size)
        for size in [10, 100, 1000, 10000, 100000]:
            subtest((32 * MiB) // size, size)
        for i in range(10):
            subtest(1000, 'random')

    def test_lwkmem_exhaustion(self):
        # Verify we can allocate the full amount of designated memory
        def subtest(reserved, size):
            with self.subTest(reserved=reserved, size=size):
                yod(self, '-M', reserved, '-C', 'all', '--mosview', 'lwk-local', './maptest', '--verbose',
                    '--type', 'anonymous', '--num', -1, '--size', size)
        self.update_lwk_state()
        # first test allocation sizes that hit the TLB sizes
        combos = [(sum(self.lwkmem), 1 * GiB),
                  (3 * GiB, 2 * MiB),
                  (3 * MiB, 4 * KiB)]
        for reserved, size in combos:
            reserved = min(reserved, sum(self.lwkmem))
            subtest(reserved, size)

        # do some random reservation and allocation sizes
        for i in range(10 - len(combos)):
            # constrain size so test doesn't take too long
            reserved = random.randint(2 * MiB, sum(self.lwkmem))
            size = random.randint(max(4096, reserved // 512), reserved)
            size = round(size / 4096) * 4096
            subtest(reserved, size)

    def test_munmap(self):
        self.update_lwk_state()
        designated = sum(self.lwkmem)
        size = designated // 4 // 4096 * 4096

        # Mmap approximately half of designated memory 3 times, unmapping in
        # between.  Pick sizes that cover all three TLB sizes; but minimize
        # the overall number of mmap / munmap calls by using a size that
        # is the difference of the two TLB sizes.  For example, to stress
        # 4K TLBs use a size of 2MiB - 4KiB.  Note that the number of mmaps
        # is capped at 4K for large memory configurations in order to keep
        # run times reasonable.

        def subtest(designated, size):
            num = min(designated // size // 2, 4*KiB)
            if num > 0:
                with self.subTest(size=size, num=num):
                    yod(self, './maptest', '--type', 'anonymous', '--num', num, '--size', size, '--iterations', 3)

        sizes = [4 * KiB, 2 * MiB, 1 * GiB, 2 * GiB]
        for i in range(1,len(sizes)):
            subtest(designated, sizes[i] - sizes[i-1])

    def test_heap_zero(self):
        # Launch a heap-manipulating test app and verify that the heap
        # expansions are zeroed
        def subtest(clrlen=None):
            with self.subTest():
                if clrlen is not None:
                    yod(self, '--opt', 'lwkmem-brk-clear-len={}'.format(clrlen), './heaptest', '--clear-len', clrlen)
                else:
                    yod(self, './heaptest')
        subtest()
        subtest(clrlen=-1)
        for n in range(4):
            subtest(clrlen = (n + 1) * 0x1000)

    def test_aligned_mmap(self):
        # Launch an mmap alignment test
        def subtest(size, alignment):
            with self.subTest(size=size, alignment=alignment):
                yod(self, '--aligned-mmap', '{}:{}'.format(size, alignment), './alignmenttest', '--verbose', '--size', size, '--alignment', alignment, '--iterations', 3)
        for size in [1, 4*KiB, 256*KiB, 2*MiB, 64*MiB]:
            for alignment in [8*KiB, 256*KiB, 2*MiB, 1*GiB]:
                subtest(size, alignment)

    def test_aligned_mmap_default(self):
        # Launch an mmap alignment test without yod options to
        # validate the default behavior
        with self.subTest():
            yod(self, './alignmenttest', '--verbose', '--size', 2*MiB, '--alignment', 1*GiB, '--iterations', 3)

    def test_get_addr(self):
         with self.subTest():
            yod(self, './get_addr_test')

    def _test_munmap_segments(self, page_sizes=[4*KiB, 2*MiB], extra_yod_args=''):

        self.update_lwk_state()

        n_domains = get_cpus_domains()

        for page_size in page_sizes:

            # Iterate over a range of mapped region sizes.
            # Note that we need at least 3 pages in the mapped region
            # in order to be able to unmap left, center and right
            # segments.  An in order to internally exercise the
            # interleaving allocator, we would like to test at least up
            # to 3 pages per domain.  For pragmatic reasons, we will
            # want to test at least up to 8 page allocations and at
            # most 12.

            upper = min([max([3 * n_domains, 8]), 12])

            for map_size in list(s * page_size for s in range(3, upper + 1)):

                # Iterate over every possible size of sub-regions to
                # unmap:

                for unmap_size in list(u * page_size for u in range(1, map_size//page_size)):

                    # Slide the unmapped region from left to right
                    # through every possible situation.  This covers
                    # unmapping left, right and center.

                    for offset in list(o * page_size for o in range((map_size - unmap_size)//page_size + 1)):

                        # Test both "all resources" and "1/N" resources, which
                        # will cover both of the current allocation schemes:
                        for scale in [1, n_domains]:
                            with self.subTest():
                                cmd = '-R 1/{} {} ./munmap --map-size {} --unmap-size {} --offset {} --page-size {}'.format(scale, extra_yod_args, map_size, unmap_size, offset, page_size)
                                yod(self, *cmd.split())

    def test_munmap_segments(self):
        self._test_munmap_segments(extra_yod_args='')

    def test_mmap_map_fixed(self):
        for map_size in [4*KiB, 8*KiB, 64*KiB, 2*MiB, 8*MiB, 64*MiB, 1*GiB, 2*GiB, 4*GiB, 8*GiB]:
            for page_size in [4*KiB, 2*MiB, 1*GiB]:
                if map_size >= page_size:
                    yod(self, '--aligned-mmap', '0', './mapfixed', '-s', map_size, '-p', page_size)
                    yod(self, './mapfixed', '-s', map_size, '-p', page_size)
                    for alignment in [8*KiB, 256*KiB, 2*MiB, 1*GiB]:
                        if alignment >= map_size:
                            yod(self, '--aligned-mmap', '{}:{}'.format(map_size, alignment), './mapfixed', '-s', map_size, '-p', page_size)

    # These other variants of unmap_segments are interesting but probably
    # not worth running all the time.  We annotate them as such.
    @unittest.skipUnless(ARGS.all_tests, 'Level 2 test.')
    def test_munmap_segments_forced_mmap_alignment(self):
        self._test_munmap_segments(extra_yod_args='--aligned-mmap 1')

    @unittest.skipUnless(ARGS.all_tests, 'Level 2 test.')
    def test_munmap_segments_4k_interleave(self):
        self._test_munmap_segments(extra_yod_args='-o lwkmem-interleave=4k', page_sizes=[2*MiB])

    def test_mmap_reclamation(self):
        with self.subTest('default'):
            yod(self, './protnone', '-v')
        with self.subTest('enabled'):
            yod(self, '-o', 'lwkmem-prot-none-delegation-enable', './protnone', '-v')

class Options(Base):
    require = [YOD, 'options']
    page_sizes = ['4k', '4K', '2m', '2M', '1g', '1G']

    def _test_with_options(self, options, extra_args=None):
        opts = []
        for o in options:
            opts += ['-o', o]
        if extra_args:
            opts += extra_args
        opts += ['./options']
        yod(self, *opts)

    def test_brk_disable(self):
        self._test_with_options(['lwkmem-brk-disable'])

    def test_max_page_size(self):
        for sz in self.page_sizes:
            self._test_with_options(['lwkmem-max-page-size={}'.format(sz)])

    def test_heap_page_size(self):
        for sz in self.page_sizes:
            self._test_with_options(['lwkmem-heap-page-size={}'.format(sz)])

    def test_blocks_allocated(self):
        self._test_with_options(['lwkmem-blocks-allocated'])

    def test_load_elf_disable(self):
        self._test_with_options(['lwkmem-load-elf-disable'])

    def test_interleave_disable(self):
        self._test_with_options(['lwkmem-interleave-disable'])

    def test_interleave(self):
        for sz in self.page_sizes + ['0']:
            self._test_with_options(['lwkmem-interleave={}'.format(sz)])

    def test_trace_block_lists(self):
        for addr in ['-1', '0x8000000']:
            for suffix in [None, 'details', 'summary']:
                self._test_with_options(['lwkmem-trace-block-list={}{}'.format(addr, ':{}'.format(suffix) if suffix else '')])

    def test_zero_check(self):
        # Test different combinations of checks and 'fix'.
        # The resources are constrained to a single core and
        # a modest amount of memory so that it doesn't
        # take too long to run.
        for check in ['free', 'alloc', 'release', 'all']:
            for fix in [None, 'fix']:
                zcheck = '{},{}'.format(check, fix) if fix else check
                self._test_with_options(['lwkmem-zeroes-check={}'.format(zcheck)], extra_args=['-C', '1', '-M', '64m'])
