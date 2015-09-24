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

logger = logging.getLogger()

EBUSY = 240
EINVAL = 234

class HelloWorld(yod.YodTestCase):
    @unittest.skipIf(len(LWK_CPUS) < 1,
                     'test requires at least 1 LWK CPU')
    def test_hello(self):
        # "Hello world" for yod.
        cmd = ['%HELLO%', 'from yod']
        self.expand_and_run(cmd, 0)

class Resources(yod.YodTestCase):
    @property
    def total_lwkmem(self):
        return sum(int(x) for x in self.var['I_LWKMEM'].split())

    def test_all(self):
        # Test "yod -R all foo".

        cmd = ['%RESOURCES%', 'all', '%AFFINITY_TEST%', '--affinity', self.var['ALLCPUS'], '--lwkmem_reserved', str(self.total_lwkmem)]
        self.expand_and_run(cmd, 0)

    def test_fraction(self):
        designated = self.get_designated_lwkcpus()
        n_cores = designated.countBy(self.topology.cores)

        if n_cores < 2:
            self.skipTest('This test requires at least 2 designated cores.')

        n_cores //= 2

        mask = yod.CpuSet(0)
        for n in range(n_cores):
            mask += self.topology.allcpus.selectNthBy(n+1, self.topology.cores)

        for frac in ['.5', '0.5', '1/2']:
            for alg in ['*', 'numa', 'simple']:

                cmd = ['%RESOURCES%', frac]

                if alg == '*':
                    mask = self.get_n_cores(n_cores, fromcpus=designated)
                else:
                    cmd += ['--resource_algorithm', alg]
                    mask = self.get_n_cores(n_cores, fromcpus=designated, algorithm=alg)

                cmd += ['%AFFINITY_TEST%', '--affinity', mask, '--lwkcpus_reserved', mask, '--lwkmem_reserved', self.total_lwkmem // 2]
                self.expand_and_run(cmd, 0)


class Cores(yod.YodTestCase):
    def test_all(self):
        # Test "yod -C all foo" variations.

        # Take one CPU out of the designated CPUs, just to make things
        # more interesting.  Adjust the expected affinity to acount
        # for this missing CPU and other CPUs in the same core.

        first = self.topology.allcpus.nthCpu(1)
        desig = self.topology.allcpus - first
        self.var['I_LWKCPUS'] = str(desig)
        allcores = desig.filterBy(self.topology.cores)

        if allcores.isEmpty():
            self.skipTest('Not enough cores for this test.')

        cmd = ['%CORES%', 'all', '%MEM%', 'all', '%AFFINITY_TEST%', '--affinity', str(allcores), '--lwkcpus_reserved', str(allcores) ]
        self.expand_and_run(cmd, 0)

    def test_all_partial(self):
        # Test "yod -C all foo" when something is already reserved.

        # Grab one CPU and remove it from the designated list.  Then
        # grab another and pre-reserve it.  The expected affinity
        # mask needs to account for both of these CPUs, modulo complete
        # cores.  The lwkcpus_reserved state is the expected affinity
        # mask plus the one pre-reserved CPU.

        first = self.topology.allcpus.nthCpu(1)
        desig = self.topology.allcpus - first
        second = desig.nthCpu(1)

        self.var['I_LWKCPUS'] = str(desig)
        self.var['I_LWKCPUS_RESERVED'] = str(second)

        mask = (desig - second).filterBy(self.topology.cores)

        if mask.isEmpty():
            self.skipTest('Not enough cores for this test.')

        cmd = ['%CORES%', 'all', '%MEM%', 'all', '%AFFINITY_TEST%', '--affinity', str(mask), '--lwkcpus_reserved', str(mask + second) ]
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

        first = self.topology.allcpus.nthCpu(1)
        desig = self.topology.allcpus - first
        self.var['I_LWKCPUS'] = str(desig)

        for alg in ['*', 'numa', 'simple']:
            cmd = ['%CORES%', 1]
            if alg == '*':
                first_core = self.get_n_cores(1, fromcpus=desig)
            else:
                first_core = self.get_n_cores(1, fromcpus=desig, algorithm=alg)
                cmd += ['--resource_algorithm', alg]

            cmd += ['%MEM%', 'all', '%AFFINITY_TEST%', '--affinity', first_core,
                    '--lwkcpus_reserved', first_core]

            if first_core.isEmpty():
                self.skipTest('Test requires at least one designated core.')

            self.expand_and_run(cmd, 0)

    def test_many(self):
        # Test 'yod -C <N> foo' where N is the maximum number of cores possible.

        first = self.topology.allcpus.nthCpu(1)
        desig = self.topology.allcpus - first
        ncores = desig.countBy(self.topology.cores)
        mask = desig.filterBy(self.topology.cores)

        if ncores == 0:
            self.skipTest('Test requires at least one designated core.')

        self.var['I_LWKCPUS'] = str(desig)
        cmd = ['%CORES%', str(ncores), '%MEM%', 'all', '%AFFINITY_TEST%', '--affinity', str(mask), '--lwkcpus_reserved', str(mask)]
        self.expand_and_run(cmd, 0)

    def test_too_few_designated(self):
        # Test "yod -C <N> foo" where <N> is larger than the number of designated
        # LWK cores.  This is an invalid request.

        ncores = self.topology.allcpus.countBy(self.topology.cores)

        cmd = ['%CORES%', str(ncores + 1), '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

    def test_too_few_available(self):
        # Test "yod -C <N> foo" where <N> is larger than the number of available
        # LWK cores.  This is a legal request but cannot complete because resources
        # are busy.

        # Grab one CPU and remove it from the designated list.  Then
        # grab another and pre-reserve it.  The expected affinity
        # mask needs to account for both of these CPUs, module complete
        # cores.

        first = self.topology.allcpus.nthCpu(1)
        desig = self.topology.allcpus - first
        second = desig.nthCpu(1)
        remaining = (desig - second).filterBy(self.topology.cores)
        ncores = remaining.countBy(self.topology.cores)
        cmd = ['%CORES%', str(ncores+1), '%MEM%', 'all', '%HELLO%', 'should not get here']

        self.var['I_LWKCPUS'] = str(desig)
        self.var['I_LWKCPUS_RESERVED'] = str(second)

        self.expand_and_run(cmd, EBUSY)

    def test_frac(self):
        # Test "yod -C <frac> foo", i.e. the factional core specifier.

        designated = self.get_designated_lwkcpus()
        ncores = designated.countBy(self.topology.cores)

        if ncores < 2:
            self.skipTest('This test requires at least 2 designated cores.')

        ncores //= 2

        mask = yod.CpuSet(0)
        for n in range(ncores):
            mask += self.topology.allcpus.selectNthBy(n+1, self.topology.cores)

        for frac in ['.5', '0.5', '1/2']:
            for alg in ['*', 'numa', 'simple']:
                for spec, extra in [('%CORES%', ['%MEM%', '.5']), ('%RESOURCES%', None)]:
                    cmd = [spec] + [frac]

                    if extra is not None:
                        cmd += extra

                    if alg == '*':
                        mask = self.get_n_cores(ncores, fromcpus=designated)
                    else:
                        cmd += ['--resource_algorithm', alg]
                        mask = self.get_n_cores(ncores, fromcpus=designated, algorithm=alg)

                    cmd += ['%AFFINITY_TEST%', '--affinity', mask,
                        '--lwkcpus_reserved', mask]
                    self.expand_and_run(cmd, 0)


    def test_frac_zero(self):
        # Test "yod -C <frac> foo", where <frac> translates to zero cores (error).

        designated_cores = self.topology.allcpus.countBy(self.topology.cores)
        frac = 1.0
        ncores = designated_cores

        # Produce a fraction that translates to zero cores
        while (ncores > 0):
            frac *= .5
            ncores = int(frac * designated_cores)

        cmd = ['%CORES%', str(frac), '%MEM%', 'all', '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

        cmd = ['%CORES%', '{}/{}'.format(1, designated_cores+1), '%HELLO%', 'should not get here']
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
        allcpus = self.topology.allcpus
        cmds = [[], ['%CPUS%', 'all', '%MEM%', 'all']]
        for cmd in cmds:
            cmd += ['%AFFINITY_TEST%', '--affinity', str(allcpus), '--lwkcpus_reserved', str(allcpus)]
            self.expand_and_run(cmd, 0)

    def test_all_with_reserved(self):
        # Test "yod -c all foo", with an existing reservation.

        # We will reserve the second and next to last CPUs.  So let's
        # say we need at least four CPUs.

        ncpus = self.topology.allcpus.countCpus()

        if ncpus < 4:
            self.skipTest("Need at least 4 designated LWK CPUs.")

        m1 = self.topology.allcpus.nthCpu(2)
        m2 = self.topology.allcpus.nthCpu(ncpus-1)
        mask = self.topology.allcpus - m1 - m2
        cmds = [[], ['%CPUS%', 'all', '%MEM%', 'all']]

        self.var['I_LWKCPUS_RESERVED'] = str(m1 + m2)

        for cmd in cmds:
            cmd += ['%AFFINITY_TEST%', '--affinity', str(mask), '--lwkcpus_reserved', self.var['ALLCPUS']]
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

        ncpus = self.topology.allcpus.countCpus()
        mask = yod.CpuSet(0)
        for n in range(1, ncpus, 3):
            mask += yod.CpuSet(1 << n)

        # Use both simple and stride forms of the list:
        masks = [str(mask), '1-' + str(ncpus-1) + ':3']
        for m in masks:
            cmd = ['%CPUS%'] + [m] + ['%MEM%', 'all', '%AFFINITY_TEST%', '--affinity', str(mask), '--lwkcpus_reserved', str(mask)]
            self.expand_and_run(cmd, 0)

    def test_list_busy(self):
        # Launch using "yod -c <list> foo" where list contains a busy CPU

        first = self.topology.allcpus.nthCpu(1)

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

        all_but_one = self.topology.allcpus - self.topology.allcpus.nthCpu(1)

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
        return sum(int(x) for x in self.var['I_LWKMEM'].split())

    def test_all(self):
        # Test "yod -M all foo".

        forms = [
            ['%MEM%', 'all', '%CORES%', 'all'],  # explicit use of 'all'
            ['%MEM%', 'all', '%CPUS%', 'all'], # implicitly, by requesting all CPUs
            [], # yod with no arguments -- implicitly reserves all memory
        ]

        for f in forms:
            cmd = f + ['%AFFINITY_TEST%', '--affinity', self.var['ALLCPUS'], '--lwkmem_reserved', str(self.total_lwkmem)]
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

        for f in forms:
            cmd = f + ['%CORES%', 'all', '%AFFINITY_TEST%', '--affinity', self.var['ALLCPUS'], '--lwkmem_reserved', '0x40000000']
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

        for f in forms:
            cmd = f + ['%CORES%', 'all', '%AFFINITY_TEST%', '--affinity', self.var['ALLCPUS'], '--lwkmem_reserved', str(self.total_lwkmem // 2)]
            self.expand_and_run(cmd, 0)

    def test_too_big(self):
        # Test "yod -M <size> foo" where <size> is more than what was designated.

        cmd = ['%MEM%', str(self.total_lwkmem + 1), '%HELLO%', 'should not get here']
        self.expand_and_run(cmd, EINVAL)

    def test_busy(self):
        # Test "yod -M <size> foo" where <size> is more than what was is
        # currently available.

        if ARGS.test_yod_scalar:
            self.var['I_LWKMEM_RESERVED'] = '1'
        else:
            self.var['I_LWKMEM_RESERVED'] = '1 0'

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

        mem_designated = sum(intlist(self.var['I_LWKMEM']))
        second_cpu = self.topology.allcpus.nthCpu(2)

        mems = [('all', mem_designated),
                (.5,  mem_designated // 2),
                ('2M', 2 * 1024**2)]

        cpus = [('%CORES%', 'all'),
                ('%CORES%', .5),
                ('%CORES%', 1),
                ('%CPUS%', 'all'),
                ('%CPUS%', second_cpu),
                ('%CPUS%', hex(second_cpu.mask)),
        ]

        for memarg, memval in mems:
            for cpuspec, cpuarg in cpus:

                mem_cmd = ['%MEM%', memarg]
                cpu_cmd = [cpuspec, cpuarg]
                rest_of_the_cmd = ['%AFFINITY_TEST%', '--lwkmem_reserved', memval]

                # Test both ordering of memory & CPU.  The amount of memory
                # reserved should *always* equal the explicit amount
                # requested (memval).

                cmd = mem_cmd + cpu_cmd + rest_of_the_cmd
                self.expand_and_run(cmd, 0)

                cmd = cpu_cmd + mem_cmd + rest_of_the_cmd
                self.expand_and_run(cmd, 0)

class CpuAlgorithm(yod.YodTestCase):
    def test_random(self):
        # Exercise the random CPU assignment algorithm.

        # We will reserve 3 cores at random.
        if self.topology.allcpus.countBy(self.topology.cores) < 3:
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

        if not yod.CpuSet(mask).isSubsetOf(self.topology.allcpus):
            self.skipTest('This test requires that {} be LWK CPUs.'.format(hex(mask)))

        cmd = ['%CPUS%', hex(mask), '%MEM%', 'all', '%AFFINITY_TEST%', '--affinity', hex(mask), '--lwkcpus_reserved', hex(mask)]
        self.expand_and_run(cmd, 0)


    def test_cmask_non_lwkcpu(self):
        # Attempt to reserve a CPU that is not designated for LWK use.

        # Remove the first CPU from the designated list:
        first = self.topology.allcpus.nthCpu(1)
        desig = self.topology.allcpus - first
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

    def test_options(self):
        for options in self.option_patterns:
            cmd = []
            for option in options:
                cmd += ['%OPT%', option]
            cmd += ['%HELLO%', 'options!']
            self.expand_and_run(cmd, 0)

            with open(self.var['FS_LWK_OPTIONS']) as f:
                self.assertEqual(','.join(options), f.read().strip('\0'))

    def test_env_options(self):
        for options in self.option_patterns:
            options = ','.join(options)

            env = {'YOD_OPTIONS': options}
            cmd = ['%HELLO%', 'options!']
            self.expand_and_run(cmd, 0, env=env)

            with open(self.var['FS_LWK_OPTIONS']) as f:
                self.assertEqual(options, f.read().strip('\0'))

class Assorted(yod.YodTestCase):
    def test_no_args(self):
        # Test "yod" (with no arguments).  This is an error.
        cmd = []
        self.expand_and_run(cmd, EINVAL)

    def test_dry_run(self):
        # Dry-run a command that will fail if actually executed
        cmd = ['--dry-run', '%AFFINITY_TEST%', '--affinity', 'GARBAGE']
        self.expand_and_run(cmd, 0)

    def test_verbose_option(self):
        # Test "yod --verbose=9 foo".
        cmd = ['--verbose=9', '-C', '1', '-M', 'all', '%HELLO%', 'from', 'yod']
        self.expand_and_run(cmd, 0)
