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
import yod
from itertools import permutations
import math
import copy

logger = logging.getLogger()

EBUSY = 240
EINVAL = 234

class HelloWorld(yod.YodTestCase):
    def test_hello(self):

        if self.get_designated_lwkcpus().countCpus() < 1:
            self.skipTest('Test requires at least one designated CPU.')

        # "Hello world" for yod.
        cmd = ['%HELLO%', 'from yod']
        self.expand_and_run(cmd, 0)

class Resources(yod.YodTestCase):
    @property
    def total_lwkmem(self):
        return sum(self.lwkmem)

    def test_all(self):
        # Test "yod -R all foo".

        self.lwkcpus_request = self.get_designated_lwkcpus()
        self.compute_lwkmem_request(fraction=1.0)

        cmd = ['%RESOURCES%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', str(self.lwkcpus_request), '--lwkmem_reserved', str(self.total_lwkmem)]
        self.expand_and_run(cmd, 0)

    def test_fraction(self):

        n_cores = self.get_designated_lwkcpus().countBy(self.topology.cores)

        if n_cores < 2:
            self.skipTest('This test requires at least 2 designated cores.')

        for frac in ['.5', '0.5', '1/2']:
            for alg in ['*', 'numa', 'simple']:

                cmd = ['%RESOURCES%', frac]

                if alg == '*':
                    self.lwkcpus_request = self.get_n_cores(n_cores // 2)
                else:
                    cmd += ['--resource_algorithm', alg]
                    self.lwkcpus_request = self.get_n_cores(n_cores // 2, algorithm=alg)

                self.compute_lwkmem_request(fraction=0.5)

                cmd += ['%AFFINITY_TEST%', '--lwkcpus_reserved', self.lwkcpus_request, '--lwkmem_reserved', self.total_lwkmem // 2]
                self.expand_and_run(cmd, 0)


class Cores(yod.YodTestCase):
    def test_all(self):
        # Test "yod -C all foo" variations.

        # Take one CPU out of the designated CPUs, just to make things
        # more interesting.  Adjust the expected affinity to acount
        # for this missing CPU and other CPUs in the same core.

        designated = self.get_designated_lwkcpus()
        designated -=  designated.nthCpu(1)
        self.var['I_LWKCPUS'] = str(designated)
        self.lwkcpus_request = self.get_designated_cores()
        self.compute_lwkmem_request(fraction=1.0)

        if self.lwkcpus_request.isEmpty():
            self.skipTest('Not enough cores for this test.')

        cmd = ['%CORES%', 'all', '%MEM%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', str(self.lwkcpus_request) ]

        self.expand_and_run(cmd, 0)

    def test_all_partial(self):
        # Test "yod -C all foo" when something is already reserved.

        # Grab one CPU and remove it from the designated list.  Then
        # grab another and pre-reserve it.  The expected affinity
        # mask needs to account for both of these CPUs, modulo complete
        # cores.  The lwkcpus_reserved state is the expected affinity
        # mask plus the one pre-reserved CPU.

        first = self.get_designated_lwkcpus().nthCpu(1)
        designated = self.get_designated_lwkcpus() - first
        second = designated.nthCpu(1)

        self.var['I_LWKCPUS'] = str(designated)
        self.var['I_LWKCPUS_RESERVED'] = str(second)

        self.lwkcpus_request = (designated - second).filterBy(self.topology.cores)
        self.compute_lwkmem_request(fraction=1.0)

        if self.lwkcpus_request.isEmpty():
            self.skipTest('Not enough cores for this test.')

        cmd = ['%CORES%', 'all', '%MEM%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', str(self.lwkcpus_request + second) ]
        self.expand_and_run(cmd, 0)

    def test_all_none_available(self):
        # Test "yod -C all foo" when no cores are available.

        # Grab one CPU from every core and pre-reserve it.  Then launch all
        # cores, which will, of course, fail.

        rsvd = yod.CpuSet(0)
        for c in self.topology.cores:
            rsvd += c.nthCpu(1)

        self.var['I_LWKCPUS_RESERVED'] = str(rsvd)

        cmd = ['%CORES%', 'all', '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EBUSY)

    def test_one(self):
        # Test "yod -C 1 foo".

        # Eliminate one CPU from the designated list.  Then test the selection
        # of one core using various algorithms.

        first = self.get_designated_lwkcpus().nthCpu(1)
        designated = self.get_designated_lwkcpus() - first
        self.var['I_LWKCPUS'] = str(designated)

        for alg in ['*', 'numa', 'simple']:
            cmd = ['%CORES%', 1]
            if alg == '*':
                self.lwkcpus_request = self.get_n_cores(1)
            else:
                self.lwkcpus_request = self.get_n_cores(1, algorithm=alg)
                cmd += ['--resource_algorithm', alg]

            cmd += ['%MEM%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', self.lwkcpus_request]

            if self.lwkcpus_request.isEmpty():
                self.skipTest('Test requires at least one designated core.')

            self.compute_lwkmem_request(fraction=1.0)
            self.expand_and_run(cmd, 0)

    def test_many(self):
        # Test 'yod -C <N> foo' where N is the maximum number of cores possible.

        first = self.get_designated_lwkcpus().nthCpu(1)
        designated = self.get_designated_lwkcpus() - first
        n_cores = designated.countBy(self.topology.cores)
        self.lwkcpus_request = designated.filterBy(self.topology.cores)

        if n_cores == 0:
            self.skipTest('Test requires at least one designated core.')

        self.var['I_LWKCPUS'] = str(designated)
        cmd = ['%CORES%', str(n_cores), '%MEM%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', str(self.lwkcpus_request)]
        self.compute_lwkmem_request(fraction=1.0)
        self.expand_and_run(cmd, 0)

    def test_too_few_designated(self):
        # Test "yod -C <N> foo" where <N> is larger than the number of designated
        # LWK cores.  This is an invalid request.

        n_cores = self.get_designated_cores().countBy(self.topology.cores)

        cmd = ['%CORES%', str(n_cores + 1), '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

    def test_too_few_available(self):
        # Test "yod -C <N> foo" where <N> is larger than the number of available
        # LWK cores.  This is a legal request but cannot complete because resources
        # are busy.

        # Grab one CPU and remove it from the designated list.  Then
        # grab another and pre-reserve it.  The expected affinity
        # mask needs to account for both of these CPUs, module complete
        # cores.

        first = self.get_designated_lwkcpus().nthCpu(1)
        designated = self.get_designated_lwkcpus() - first
        second = designated.nthCpu(1)
        remaining = (designated - second).filterBy(self.topology.cores)
        n_cores = remaining.countBy(self.topology.cores)
        cmd = ['%CORES%', str(n_cores+1), '%MEM%', 'all', '%HELLO%', 'should not get here']

        self.var['I_LWKCPUS'] = str(designated)
        self.var['I_LWKCPUS_RESERVED'] = str(second)

        self.expand_and_run(cmd, EBUSY)

    def test_frac(self):
        # Test "yod -C <frac> foo", i.e. the factional core specifier.

        designated = self.get_designated_lwkcpus()
        n_cores = designated.countBy(self.topology.cores)

        if n_cores < 2:
            self.skipTest('This test requires at least 2 designated cores.')

        for frac in ['.5', '0.5', '1/2']:
            for alg in ['*', 'numa', 'simple']:
                for spec, extra in [('%CORES%', ['%MEM%', '.5']), ('%RESOURCES%', None)]:
                    cmd = [spec] + [frac]

                    if extra is not None:
                        cmd += extra

                    if alg == '*':
                        self.lwkcpus_request = self.get_n_cores(n_cores // 2)
                    else:
                        cmd += ['--resource_algorithm', alg]
                        self.lwkcpus_request = self.get_n_cores(n_cores // 2, algorithm=alg)

                    self.compute_lwkmem_request(fraction=0.5)

                    cmd += ['%AFFINITY_TEST%', '--lwkcpus_reserved', self.lwkcpus_request]
                    self.expand_and_run(cmd, 0)


    def test_frac_zero(self):
        # Test "yod -C <frac> foo", where <frac> translates to zero cores (error).

        n_designated_cores = self.get_designated_cores().countBy(self.topology.cores)
        frac = 1.0
        n_cores = n_designated_cores

        # Produce a fraction that translates to zero cores
        while (n_cores > 0):
            frac *= .5
            n_cores = int(frac * n_designated_cores)

        cmd = ['%CORES%', str(frac), '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

        cmd = ['%CORES%', '{}/{}'.format(1, n_designated_cores+1), '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

    def test_invalid_specifiers(self):
        # Test "yod -C <invalid> foo", where <invalid> is one of various
        # invalid specifiers for the -C/--cores option.

        my_bads = ['al',       # typo
                   '" "',      # empty
                   '0',        # must be > 0
                   '-1',       # must be > 0
                   '1-9',      # it isnt a list
                   '-.5',      # fractions must be in [0., 1.]
                   '-0.5',     # fractions must be in [0., 1.]
                   '1.0001',   # fractions must be in [0., 1.]
                   'NAN',      # fractions must be in [0., 1.]
                   'INF',      # fractions must be in [0., 1.]
                   '-INF',     # fractions must be in [0., 1.]
                   '0/1',      # must be > 0
                   '1/0',      # divide by zero
                   '9/8',      # must be less than or equal to 1.0
                   '1.0/2.0',  # must be integers
                   '1x/2',     # extraneous chars in the numerator
                   '1/2x',     # extraneous chars in the denominator
        ]

        for bad in my_bads:
            cmd = ['%CORES%'] + [bad] + ['%MEM%', 'all', '%HELLO%', 'should not get here']
            self.expand_and_run(cmd, EINVAL)

class Cpus(yod.YodTestCase):

    def test_all(self):
        # Test "yod --cpus all foo", which is also the default.
        self.lwkcpus_request = self.get_designated_lwkcpus()
        self.compute_lwkmem_request(fraction=1.0)
        cmds = [[], ['%CPUS%', 'all', '%MEM%', 'all']]
        for cmd in cmds:
            cmd += ['%AFFINITY_TEST%', '--lwkcpus_reserved', self.lwkcpus_request]
            self.expand_and_run(cmd, 0)

    def test_all_with_reserved(self):
        # Test "yod -c all foo", with an existing reservation.

        # We will reserve the second and next to last CPUs.  So let's
        # say we need at least four CPUs.

        n_cpus = self.get_designated_lwkcpus().countCpus()

        if n_cpus < 4:
            self.skipTest("Need at least 4 designated LWK CPUs.")

        m1 = self.get_designated_lwkcpus().nthCpu(2)
        m2 = self.get_designated_lwkcpus().nthCpu(n_cpus-1)
        self.lwkcpus_request = self.get_designated_lwkcpus() - m1 - m2
        self.compute_lwkmem_request(fraction=1.0)
        cmds = [[], ['%CPUS%', 'all', '%MEM%', 'all']]

        self.var['I_LWKCPUS_RESERVED'] = str(m1 + m2)

        for cmd in cmds:
            cmd += ['%AFFINITY_TEST%', '--lwkcpus_reserved', self.var['ALLCPUS']]
            self.expand_and_run(cmd, 0)

    def test_all_with_all_reserved(self):
        # Test "yod -c all foo" when there are no available LWK CPUs.

        self.var['I_LWKCPUS_RESERVED'] = self.var['ALLCPUS']

        cmds = [[], ['%CPUS%', 'all', '%MEM%', 'all']]

        for cmd in cmds:
            cmd += ['%HELLO%', 'should not get here']
            self.expand_and_run(cmd, EBUSY)

    def test_list(self):
        # Launch using "yod -c <list> foo".

        # Construct a list using every third CPU.

        n_cpus = self.get_designated_lwkcpus().countCpus()
        self.lwkcpus_request = yod.CpuSet(0)
        for n in range(1, n_cpus, 3):
            self.lwkcpus_request += yod.CpuSet(1 << n)

        self.compute_lwkmem_request(fraction=1.0)

        # Use both simple and stride forms of the list:
        masks = [str(self.lwkcpus_request), '1-' + str(n_cpus-1) + ':3']
        for m in masks:
            cmd = ['%CPUS%'] + [m] + ['%MEM%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', self.lwkcpus_request]
            self.expand_and_run(cmd, 0)

    def test_list_busy(self):
        # Launch using "yod -c <list> foo" where list contains a busy CPU

        first = self.get_designated_lwkcpus().nthCpu(1)

        # Reserve all CPUs and attempt to launch using one:

        self.var['I_LWKCPUS_RESERVED'] = self.var['ALLCPUS']
        cmd = ['%CPUS%', str(first), '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EBUSY)

        # Now invert it .... reserve one CPU and attempt to launch all:

        self.var['I_LWKCPUS_RESERVED'] = str(first)
        cmd = ['%CPUS%', self.var['ALLCPUS'], '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EBUSY)

    def test_list_overreach(self):
        # Launch using "yod -c <list> foo" where list contains a non-designated CPU

        # Remove the first CPU from the designated list.

        all_but_one = self.get_designated_lwkcpus() - self.get_designated_lwkcpus().nthCpu(1)

        self.var['I_LWKCPUS'] = str(all_but_one)

        cmd = ['%CPUS%', self.var['ALLCPUS'], '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

    def test_list_bad_forms(self):
        # Launch using "yod -c <list> foo" where list is bogus.

        bads = ['" "', '-1', '0-', ':2']

        for bad in bads:
            cmd = ['%CPUS%'] + [bad] + ['%HELLO%', 'should not get here']
            self.expand_and_run(cmd, EINVAL)

class Mem(yod.YodTestCase):
    @property
    def total_lwkmem(self):
        return sum(self.lwkmem)

    def test_all(self):
        # Test "yod -M all foo".

        forms = [
            ['%MEM%', 'all', '%CORES%', 'all'],  # explicit use of 'all'
            ['%MEM%', 'all', '%CPUS%', 'all'], # implicitly, by requesting all CPUs
            [], # yod with no arguments -- implicitly reserves all memory
        ]

        self.lwkcpus_request = self.get_designated_lwkcpus()
        self.compute_lwkmem_request(fraction=1.0)

        for f in forms:
            cmd = f + ['%AFFINITY_TEST%', '--lwkcpus_reserved', self.lwkcpus_request, '--lwkmem_reserved', str(self.total_lwkmem)]
            self.expand_and_run(cmd, 0)

    def test_size(self):
        # Test "yod -M <size> foo".

        # There are different forms of 1 GB

        forms = [
            ['%MEM%', '1G'],
            ['%MEM%', '1024M'],
            ['%MEM%', '1048576k'],
            ['%MEM%', '1073741824'],
            ['%MEM%', '0x40000000'],
        ]

        self.lwkcpus_request = self.get_designated_lwkcpus()
        self.compute_lwkmem_request(size=1024 * 1024 * 1024, lwkcores_request=self.get_designated_lwkcpus())

        for f in forms:
            cmd = f + ['%CORES%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', self.var['ALLCPUS'], '--lwkmem_reserved', '0x40000000']
            self.expand_and_run(cmd, 0)

    def test_fraction(self):
        # Test "yod -M <fraction> foo".

        forms = [
            ['%MEM%', '0.5'],
            ['%MEM%', '.5'],
            ['%MEM%', '+0.5'],
            ['%MEM%', '+.5'],
            ['%MEM%', '1/2'],
        ]

        x = self.total_lwkmem // 2
        self.lwkcpus_request = self.get_designated_lwkcpus()
        self.compute_lwkmem_request(fraction=0.5, lwkcores_request=self.get_designated_lwkcpus())

        for f in forms:
            cmd = f + ['%CORES%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', self.var['ALLCPUS'], '--lwkmem_reserved', str(self.total_lwkmem // 2)]
            self.expand_and_run(cmd, 0)

    def test_too_big(self):
        # Test "yod -M <size> foo" where <size> is more than what was designated.

        cmd = ['%MEM%', str(self.total_lwkmem + 1), '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

    def test_busy(self):
        # Test "yod -M <size> foo" where <size> is more than what was is
        # currently available.

        self.lwkmem_reserved[0] = 1

        cmd = ['%MEM%', str(self.total_lwkmem), '%CORES%', '1', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EBUSY)

    def test_invalid(self):
        # Launch using "yod -M <X> foo" where X is illegal.

        forms = [
            # ['1.01'] -- this is actually legal and is interpreted to be 1 byte
            ['-0.5'],
            ['-.5'],
            ['-1.'],
            ['-1'],
            ['+INF'],
            ['-INF'],
            ['NAN'],
            ['4096t'],
            ['2.5q'],
            ['foo'],
            ['-1/2'],
            ['0/1'],
            ['1/0'],
            ['9/8'],
            ['1x/8'],
            ['1/8x'],
        ]

        for f in forms:
            cmd = ['%MEM%']+ f + ['%HELLO%', 'should not get here']
            self.expand_and_run(cmd, EINVAL)

    def test_mem_sizes_with_cores(self):
        # Test combinations of -M x and -"compute" y, ensuring that the explicit
        # memory specification is not affected by the number of CPUs requested.

        mem_designated = sum(self.lwkmem)

        lwkcpus_designated = self.get_designated_lwkcpus()
        n_cores = lwkcpus_designated.countBy(self.topology.cores)
        second_cpu = self.get_designated_lwkcpus().nthCpu(2)
        all_cores = self.get_n_cores(n_cores)
        half_cores = self.get_n_cores(n_cores // 2)
        one_core = self.get_n_cores(1)

        mems = [('all', mem_designated),
                (.5,  mem_designated // 2),
                ('2M', 2 * 1024**2)]

        cpus = [('%CORES%', 'all', all_cores),
                ('%CORES%', .5, half_cores),
                ('%CORES%', 1, one_core),
                ('%CPUS%', 'all', lwkcpus_designated),
                ('%CPUS%', second_cpu, second_cpu),
                ('%CPUS%', hex(second_cpu.mask), second_cpu),
        ]

        for memarg, memval in mems:
            for cpuspec, cpuarg, requested in cpus:

                mem_cmd = ['%MEM%', memarg]
                cpu_cmd = [cpuspec, cpuarg]
                rest_of_the_cmd = ['%AFFINITY_TEST%', '--lwkmem_reserved', memval]

                self.lwkcpus_request = requested

                # Test both ordering of memory & CPU.  The amount of memory
                # reserved should *always* equal the explicit amount
                # requested (memval).

                cmd = mem_cmd + cpu_cmd + rest_of_the_cmd
                self.expand_and_run(cmd, 0)

                cmd = cpu_cmd + mem_cmd + rest_of_the_cmd
                self.expand_and_run(cmd, 0)

    def test_aligned_mmap(self):
        for size in [1, 4096, '4k', 2*1024*1024, '2m', 1024*1024*1024, '1g']:
            for alignment in [None, 8*1024, '8K', 2*1024*1024, '2m', 1024*1024*1024, '1G']:
                self.lwkcpus_request = self.get_designated_lwkcpus()
                alopt = '{}'.format(size) if alignment is None else '{}:{}'.format(size, alignment)
                cmd = ['--aligned-mmap', alopt, '%HELLO%']
                self.expand_and_run(cmd, 0)

    def test_invalid_aligned_mmap(self):
        for opt in [None, '1:', '-1', '-1:1G', 'foo', '1q', '1mq', '1:bar', '1:1', '1:4096', '1:4k', '1:8kx', '1:-8k', '1:q', '1:8kk']:
            cmd = ['--aligned-mmap'] + ([opt] if opt is not None else []) + ['%HELLO%']
            self.expand_and_run(cmd, EINVAL)

    def test_brk_clear_length(self):
        for size in [-1, 0, 1, 4096, '4k', '2m', '2.1M', '1g']:
            self.lwkcpus_request = self.get_designated_lwkcpus()
            cmd = ['--brk-clear-length', size, '%HELLO%']
            self.expand_and_run(cmd, 0)

    def test_invalid_brk_clear_length(self):
        for illegal in ['x', '1:']:
            cmd = ['--brk-clear-length', illegal, '%HELLO%']
            self.expand_and_run(cmd, EINVAL)

    def test_mem_preferences(self):

        patterns = [
            (['all:dram'], '/mmap:dram,hbm,nvram,/stack:dram,hbm,nvram,/static:dram,hbm,nvram,/brk:dram,hbm,nvram,'),
            (['stack:dram'], '/mmap:hbm,dram,nvram,/stack:dram,hbm,nvram,/static:hbm,dram,nvram,/brk:hbm,dram,nvram,'),
            (['stack:1:dram'], '/mmap:hbm,dram,nvram,/stack:dram,hbm,nvram,/static:hbm,dram,nvram,/brk:hbm,dram,nvram,'),
            (['stack:1000:dram'], '/mmap:hbm,dram,nvram,/stack:hbm,dram,nvram,/stack:1000:dram,hbm,nvram,/static:hbm,dram,nvram,/brk:hbm,dram,nvram,'),
            (['stack:0x1000:dram'], '/mmap:hbm,dram,nvram,/stack:hbm,dram,nvram,/stack:4096:dram,hbm,nvram,/static:hbm,dram,nvram,/brk:hbm,dram,nvram,'),
            (['/mmap:2:nvram/stack:3:dram,nvram/static:4:hbm,nvram/brk:5:dram/'], '/mmap:hbm,dram,nvram,/mmap:2:nvram,hbm,dram,/stack:hbm,dram,nvram,/stack:3:dram,nvram,hbm,/static:hbm,dram,nvram,/static:4:hbm,nvram,dram,/brk:hbm,dram,nvram,/brk:5:dram,hbm,nvram,'),
            (['/mmap:2:nvram', '/stack:3:dram,nvram', 'static:4:hbm,nvram', 'brk:5:dram/'], '/mmap:hbm,dram,nvram,/mmap:2:nvram,hbm,dram,/stack:hbm,dram,nvram,/stack:3:dram,nvram,hbm,/static:hbm,dram,nvram,/static:4:hbm,nvram,dram,/brk:hbm,dram,nvram,/brk:5:dram,hbm,nvram,'),
        ]

        for prefs, result in patterns:

            self.lwkcpus_request = self.get_designated_lwkcpus()

            cmd = []
            for p in prefs:
                cmd += ['%MEMPREFS%', p]

            cmd += ['%HELLO%', 'options!']
            self.expand_and_run(cmd, 0)

            options = self.get_options()
            self.assertTrue('lwkmem-memory-preferences={}'.format(result) in options)

    def test_invalid_mem_preferences(self):
        invalid = [
            'bad',
            'stack:bad',
            'stack:-1:dram',
            'stack:1junk:dram',
            'stack:1:bad',
            'stack:1:dram,bad',
            'stack:1:dram,dram',
            'stack:1:dram:bad',
            'stack:dram:bad',
            'stack:1:dram:bad',
        ]

        for bad in invalid:
            cmd = ['%MEMPREFS%', bad, '%HELLO%']
            self.expand_and_run(cmd, EINVAL)

class CpuAlgorithm(yod.YodTestCase):
    def test_random(self):
        # Exercise the random CPU assignment algorithm.

        # We will reserve 3 cores at random.
        if self.get_designated_lwkcpus().countBy(self.topology.cores) < 3:
            self.skipTest('This test requires at least 3 cores.')

        # Note that we cannot really pre-determine what the affinity mask will be ....
        # so simply exercise yod.
        cmd = ['%CORES%', '3', '%MEM%', 'all', '--resource_algorithm', 'random', '%AFFINITY_TEST%', '--echo']
        self.expand_and_run(cmd, 0)


    def test_illegal(self):
        # Test for a bad specifier for the --resource_algorithm option.

        cmd = ['--resource_algorithm', 'bogus', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

class Mask(yod.YodTestCase):
    def test_cmask(self):
        # Test the options to specify compute CPUs via mask.

        mask = 0xfedc

        if not yod.CpuSet(mask).isSubsetOf(self.get_designated_lwkcpus()):
            self.skipTest('This test requires that {} be LWK CPUs.'.format(hex(mask)))

        self.lwkcpus_request = yod.CpuSet(mask)
        self.compute_lwkmem_request(fraction=1.0)

        cmd = ['%CPUS%', hex(mask), '%MEM%', 'all', '%AFFINITY_TEST%', '--lwkcpus_reserved', hex(mask)]
        self.expand_and_run(cmd, 0)


    def test_cmask_non_lwkcpu(self):
        # Attempt to reserve a CPU that is not designated for LWK use.

        # Remove the first CPU from the designated list:
        first = self.get_designated_lwkcpus().nthCpu(1)
        desig = self.get_designated_lwkcpus() - first
        self.var['I_LWKCPUS'] = str(desig)
        cmd = ['%CPUS%', hex(int(first)), '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

    def test_cmask_bad_specifiers(self):
        # Assorted bad input for the --cmask option.

        bads = ['" "', '0x0', '0xNotALegalValue']

        for bad in bads:
            cmd = ['%CPUS%'] + [bad] + ['%MEM%', 'all', '%HELLO%', 'should not get here']
            self.expand_and_run(cmd, EINVAL)

class Duplicate(yod.YodTestCase):
    def test_lwkcpu(self):
        # Test "yod -<X> -<Y> foo" where <X> and <Y> are two different
        # forms of specifying LWK CPUs/cores.

        lwkcpu_opts = [('-C', '1'), ('--cores', '1'), ('-c', '1'),
                       ('--cpus', '1')]

        for opt1, arg1  in lwkcpu_opts:
            for opt2, arg2 in lwkcpu_opts:
                cmd = [opt1, arg1, opt2, arg2, '%HELLO%', 'should not get here']
                self.expand_and_run(cmd, EINVAL)

    def test_resources(self):
        # Test illegal combinations of --resources and specifying CPUs and/or
        # memory

        resource_opts = [('%RESOURCES%', '.5'), ('%RESOURCES%', 'all')]
        cpu_and_mem_opts = [('%CPUS%', '1'), ('%CPUS%', 'all'), ('%CORES%', '1'), ('%CORES%', '.5'), ('%CORES%', 'all'), ('%MEM%', 'all'), ('%MEM%', '.5')]

        for opt1, arg1  in resource_opts:
            for opt2, arg2 in cpu_and_mem_opts:
                cmd = [opt1, arg1, opt2, arg2, '%HELLO%', 'should not get here']
                self.expand_and_run(cmd, EINVAL)
                cmd = [opt2, arg2, opt1, arg1, '%HELLO%', 'should not get here']
                self.expand_and_run(cmd, EINVAL)

class UtilityThread(yod.YodTestCase):

    def test_utility_threads(self):
        # Test typical valid specifications for --utility_thread".
        util_thread_opts = [('%UTIL_THREADS%', '0'), ('%UTIL_THREADS%', '2')]
        for opt, arg in util_thread_opts:
            self.lwkcpus_request = self.get_n_cores(1)
            cmd = [opt, arg, '-C', '1', '-M', 'all', '%HELLO%', 'from', 'yod']
            self.expand_and_run(cmd, 0)

    def test_utility_thread_neg(self):
        # Test negative value specified for utility thread".
        cmd = ['%UTIL_THREADS%', '-2', '-C', '1', '-M', 'all', '%HELLO%', 'from', 'yod']
        self.expand_and_run(cmd, EINVAL)

    def test_utility_thread_invalid(self):
        # Test invalid value specified for utility thread".
        cmd = ['%UTIL_THREADS%', 'bad', '-C', '1', '-M', 'all', '%HELLO%', 'from', 'yod']
        self.expand_and_run(cmd, EINVAL)


class Options(yod.YodTestCase):
    option_patterns = [
        ['foo'],
        ['foo=bar'],
        ['foo=bar', 'fum'],
    ]

    def _check_options(self, options):
        actual = self.get_options()
        for o in options:
            logger.debug('Checking for {}'.format(o))
            self.assertTrue(o in actual)

    def test_options(self):
        for options in self.option_patterns:
            self.lwkcpus_request = self.get_designated_lwkcpus()
            cmd = []
            for option in options:
                cmd += ['%OPT%', option]
            cmd += ['%HELLO%', 'options!']
            self.expand_and_run(cmd, 0)

            self._check_options(options)

    def test_env_options(self):
        for options in self.option_patterns:
            self.lwkcpus_request = self.get_designated_lwkcpus()
            env = {'YOD_OPTIONS': ' '.join(options)} # separate options with spaces
            cmd = ['%HELLO%', 'options!']

            self.expand_and_run(cmd, 0, env=env)

            self._check_options(options)

    def test_interleave_default(self):
        self.lwkcpus_request = self.get_designated_lwkcpus()
        cmd = ['%HELLO%', 'options!']
        self.expand_and_run(cmd, 0)
        options = self.get_options()
        self.assertTrue('lwkmem-interleave=2m' in options)

    def test_interleave_override(self):
        self.lwkcpus_request = self.get_designated_lwkcpus()
        cmd = ['%OPT%', 'lwkmem-interleave=4k', '%HELLO%', 'options!']
        self.expand_and_run(cmd, 0)
        options = self.get_options()
        self.assertTrue('lwkmem-interleave=4k' in options)
        self.assertFalse('lwkmem-interleave=2m' in options)

    def test_interleaving_not_possible_i(self):

        # Change the designated memory such that only domain N has
        # LWK memory.  Then launch yod and confirm that interleaving
        # was not enabled implicitly.

        lwkmem = copy.copy(self.lwkmem)
        for i in range(len(self.lwkmem)):
            self.lwkmem = list(lwkmem[j] if j == i else 0 for j in range(len(lwkmem)))
            cmd = ['%HELLO%', 'there']
            additional_args = [
                None,
                '%CORES% 1 %MEM% all'.split(),
                '--resource_algorithm simple'.split(),
            ]

            for addtl in additional_args:
                full_cmd = addtl + cmd if addtl else cmd
                self.expand_and_run(full_cmd, 0)
                options = ' '.join(self.get_options())
                logger.debug('Options: "{}"'.format(options))
                self.assertFalse('lwkmem-interleave=' in options)

    def test_interleaving_not_possible_ii(self):

        # Pre-reserve memory such that only domain 0 has any
        # remaining memory.  Then launch yod and confirm that
        # interleaving was not enabled implicitly.

        #lwkmem = copy.copy(self.lwkmem)
        for i in range(len(self.lwkmem)):
            #self.lwkmem = list(lwkmem[j] if j == i else 0 for j in range(len(lwkmem)))
            self.lwkmem_reserved = list(self.lwkmem[j] if j != i else 0 for j in range(len(self.lwkmem)))
            cmd = ['%HELLO%', 'there']
            additional_args = [
                None,
                '%CORES% 1 %MEM% all'.split(),
                '--resource_algorithm simple'.split(),
            ]

            for addtl in additional_args:
                full_cmd = addtl + cmd if addtl else cmd
                self.expand_and_run(full_cmd, 0)
                options = ' '.join(self.get_options())
                logger.debug('Options: "{}"'.format(options))
                #self.assertFalse('lwkmem-interleave=' in options)


class Assorted(yod.YodTestCase):
    def test_no_args(self):
        # Test "yod" (with no arguments).  This is an error.
        cmd = []
        self.expand_and_run(cmd, EINVAL)

    def test_dry_run(self):
        # Dry-run a command that will fail if actually executed
        cmd = ['--dry-run', '%AFFINITY_TEST%']
        self.expand_and_run(cmd, 0)

    def test_verbose_option(self):
        # Test "yod --verbose=9 foo".
        cmd = ['--verbose=9', '-C', '1', '-M', 'all', '%HELLO%', 'from', 'yod']
        self.lwkcpus_request = self.get_n_cores(1)
        self.expand_and_run(cmd, 0)

    def test_rank_layout_option(self):
        # Test "yod --rank-layout <x> foo".

        self.lwkcpus_request = self.get_n_cores(1)

        options = ['compact', 'scatter', 'scatter:1', 'disable']
        for o in options:
            cmd = ['-C', '1', '-M', 'all', '--rank-layout', o, '%HELLO%', 'from', 'yod']
            self.expand_and_run(cmd, 0)

    def test_invalid_rank_layout_option(self):
        # Test "yod --rank-layout <x> foo" where <x> is invalid.

        options = [None, 'compact:1', 'scatter:1x', 'disable:1', 'fred']
        for o in options:
            cmd = ['-C', '1', '-M', 'all', '--rank-layout'] + ([o] if o is not None else []) + ['%HELLO%', 'from', 'yod']
            self.expand_and_run(cmd, EINVAL)

class Layout(yod.YodTestCase):

    def test_layouts(self):
        # Exercise the various layouts
        layouts = ['scatter', 'compact']
        for perm in permutations(['cpu', 'core', 'tile', 'node'], 4):
            layouts.append(','.join(list(perm)))

        for layout in layouts:
            cmd = ['--layout', layout, '%HELLO%', 'from', 'yod']
            self.expand_and_run(cmd, 0)

            # Add a ":1" to the first term of all of each layout
            terms = layout.split(',', maxsplit=1)
            if len(terms) == 2:
                cmd = ['--layout', terms[0] + ':1,' + terms[1], '%HELLO%', 'from', 'yod']
                self.expand_and_run(cmd, 0)

    def test_invalid_layouts(self):

        layouts = [
            'core,tile,cpu',            # Need to specify all four kinds
            'cpu,core,tile,tile,node',  # No duplicates
            'cpu,core,tile,foo',        # invalid dimension
        ]
        for invalid in layouts:
            cmd = ['--layout', invalid, '%HELLO%', 'from', 'yod']
            self.expand_and_run(cmd, EINVAL)

        boundaries = {
            'cpu'  : math.ceil(self.get_designated_lwkcpus().countCpus() / len(self.topology.cores)), # CPUs per core
            'core' : math.ceil(len(self.topology.cores) / len(self.topology.tiles)),          # cores per tile
            'tile' : math.ceil(len(self.topology.tiles) / len(self.topology.nodes)),          # tiles per node
            'node' : len(self.topology.nodes)                                                 # nodes per system
        }

        # For every slot in every permutation, test the following illegal
        # scenarios:
        #   - a non-integer count
        #   - a zero count
        #   - a (just slightly) large, invalid count

        for perm in permutations(list(boundaries.keys())):
            for i, el in enumerate(perm):

                invalid = list(perm[0:i]) + ['{}:1x'.format(el)] + list(perm[i+1:])
                cmd = ['--layout', ','.join(invalid), '%HELLO%', 'from', 'yod']
                self.expand_and_run(cmd, EINVAL)

                invalid = list(perm[0:i]) + ['{}:0'.format(el)] + list(perm[i+1:])
                cmd = ['--layout', ','.join(invalid), '%HELLO%', 'from', 'yod']
                self.expand_and_run(cmd, EINVAL)

                invalid = list(perm[0:i]) + ['{}:{}'.format(el, boundaries[el] + 1)] + list(perm[i+1:])
                cmd = ['--layout', ','.join(invalid), '%HELLO%', 'from', 'yod']
                self.expand_and_run(cmd, EINVAL)
