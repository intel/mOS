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
        # Compare the actual lwkmem sysfs attribute against what is
        # found in the kernel boot argument.
        self.update_lwk_state()
        cmdline = zerovec(self.lwkmem)
        for arg in CMDLINE.get('lwkmem', '0:0').split(','):  # NOTENOTE
            # if no nid or an illegal nid, spread evenly across domains
            distribute_evenly = False
            if ':' in arg:
                nid, size = arg.split(':')
                nid = int(nid)
                if nid < 0 or nid >= len(self.lwkmem):
                    distribute_evenly = True
                else:
                    cmdline[nid] = memstr_to_int(size)
            else:
                size = arg
                distribute_evenly = True

            if distribute_evenly:
                per_nid = memstr_to_int(size) // len(self.lwkmem)
                for nid in range(len(self.lwkmem)):
                    cmdline[nid] += per_nid
        logging.debug('kernel cmdline -> {}'.format(cmdline))
        self.assertEqual(self.lwkmem, cmdline,
                         'sysfs and kernel boot arg should match')

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
                yod(self, '-M', reserved, '-C', 'all', './maptest', '--verbose',
                    '--type', 'anonymous', '--num', -1, '--size', size)
        self.update_lwk_state()
        # first test allocation sizes that hit the TLB sizes
        combos = [(31 * GiB, 1 * GiB),
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
