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

logger = logging.getLogger()

class Basics(TestCase):
    require = [
        YOD,
        'aff_scan',
        'fork_process',
        'thread_placement',
        'timer_preemption',
        'thread_priority',
        ]

    def test_affinity_scan(self):
        # Single thread that sequentially affinitizes to all CPUs in
        # the starting mask.  Optionally check that syscall migration
        # returns to calling CPU.  Optionally check for migration off
        # of legal cpu on multi-bit setaffinity.
        v = ['-v'] if ARGS.test_debug else []
        yod(self, '-u', 0, './aff_scan', '-efm', *v)

    def test_placement_and_policy(self):
        # Fork a process and inspect its: affinity mask, the CPU it
        # is currently running on, and it's scheduling policy for
        # correctness.
        v = ['--debug']*2 if ARGS.test_debug else []
        yod(self, '-u', 0, './fork_process', *v)

    def test_compute_threads(self):
        # For every N in [0, ..., num_lwk_cpus-1], launch a process that
        # spawns N pthreads.  The number of utility threads is fixed at
        # zero, so each thread should land on a LWK compute CPU.
        v = ['--debug']*2 if ARGS.test_debug else []
        rng = range(len(LWK_CPUS)-1) if len(LWK_CPUS) <= 72 else list(range(66)) + list(range(len(LWK_CPUS)-6,len(LWK_CPUS)-1))
        for n in rng:
            with self.subTest(utils=0, threads=n):
                yod(self, '-u', 0, './thread_placement', '--lwkcpus', len(LWK_CPUS), '--threads', n,
                    '--spin', ARGS.test_spin, '--uthreads', 0, *v)

    def test_util_threads(self):
        # For every N in [0, ..., num_lwk_cpus-1], launch a process that
        # spawns N+1 pthreads.  The number of utility threads is set
        # to N, so N threads should land on utility CPUs and 1 thread
        # should land on a compute CPU.
        v = ['--debug'] if ARGS.test_debug else []
        rng = range(len(LWK_CPUS)-1) if len(LWK_CPUS) <= 72 else list(range(66)) + list(range(len(LWK_CPUS)-6,len(LWK_CPUS)-2))
        for n in rng:
            with self.subTest(utils=n, threads=n+1):
                yod(self, '-u', n, './thread_placement', '--lwkcpus', len(LWK_CPUS), '--threads', n+1,
                    '--spin', ARGS.test_spin, '--uthreads', n, *v)

    def test_util_shared_threads(self):
        # Fill the LWKCPUs with a mix of worker threads and utility
        # threads and create additional worker threads to validate that
        # the utility threads running on LWKCPUs are pushed to the shared
        # utility (Linux) CPUs.
        v = ['--debug'] if ARGS.test_debug else []
        rng = range(10)
        for n in rng:
            with self.subTest(utils=n, threads=len(LWK_CPUS) + n//2):
                yod(self, '-u', n,
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', len(LWK_CPUS) + n//2,
                    '--spin', ARGS.test_spin, '--uthreads', n, *v)
        for n in rng:
            with self.subTest(utils=n, threads=len(LWK_CPUS) + n//2):
                yod(self, '-u', n, '-o', 'one-cpu-per-util',
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', len(LWK_CPUS) + n//2,
                    '--spin', ARGS.test_spin,
                    '--one_cpu_per_util',
                    '--uthreads', n, *v)

    def test_util_max_cpus_enforced(self):
        # Create number of utility threads greater than the max number of
        # allowed utility CPUs. Verify that the extra utility threads
        # are placed on the utility CPUs and we do not exceed the
        # max number of LWK CPUs for utility thread usage.
        v = ['--debug'] if ARGS.test_debug else []
        rng = range(1,8)
        for maxutilcpus in rng:
            with self.subTest(utils=2*maxutilcpus, threads=2*maxutilcpus + maxutilcpus):
                yod(self,
                    '-u', 2*maxutilcpus,
                    '-o',
                    'util-threshold=' + str(maxutilcpus) + ":1",
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', 2*maxutilcpus + maxutilcpus,
                    '--spin', ARGS.test_spin,
                    '--uthreads', 2*maxutilcpus,
                    '--maxutilcpus', maxutilcpus,
                    '--maxutilspercpu', 1,
                    *v)
        for maxutilcpus in rng:
            with self.subTest(utils=2*maxutilcpus, threads=2*maxutilcpus + maxutilcpus):
                yod(self,
                    '-u', 2*maxutilcpus,
                    '-o',
                    'util-threshold=' + str(maxutilcpus) + ":1",
                    '-o', 'one-cpu-per-util',
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', 2*maxutilcpus + maxutilcpus,
                    '--spin', ARGS.test_spin,
                    '--uthreads', 2*maxutilcpus,
                    '--maxutilcpus', maxutilcpus,
                    '--maxutilspercpu', 1,
                    '--one_cpu_per_util',
                    *v)



    def test_util_overcommit_honored(self):
        # Place worker and utility threads on LWK CPUs allowing overcommit of
        # utility threads. Verify that that overcommittment occurs.
        v = ['--debug'] if ARGS.test_debug else []
        rng = range(1,8)
        for maxutilcpus in rng:
            with self.subTest(utils=2*maxutilcpus, threads=2*maxutilcpus + maxutilcpus):
                yod(self,
                    '-u', 2*maxutilcpus,
                    '-o',
                    'util-threshold=' + str(maxutilcpus) + ":2",
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', 2*maxutilcpus + maxutilcpus,
                    '--spin', ARGS.test_spin,
                    '--uthreads', 2*maxutilcpus,
                    '--maxutilcpus', maxutilcpus,
                    '--maxutilspercpu', 2,
                    *v)
        for maxutilcpus in rng:
            with self.subTest(utils=2*maxutilcpus, threads=2*maxutilcpus + maxutilcpus):
                yod(self,
                    '-u', 2*maxutilcpus,
                    '-o',
                    'util-threshold=' + str(maxutilcpus) + ":2",
                    '-o', 'one-cpu-per-util',
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', 2*maxutilcpus + maxutilcpus,
                    '--spin', ARGS.test_spin,
                    '--uthreads', 2*maxutilcpus,
                    '--maxutilcpus', maxutilcpus,
                    '--maxutilspercpu', 2,
                    '--one_cpu_per_util',
                    *v)


    def test_util_overcommit_push(self):
        # Place worker and utility threads on LWK CPUs allowing overcommit of
        # utility threads. Verify that that overcommittment
        # occurs. Create additional worker threads to push utility threads
        # to the utility cpus. Verify that the push occurs.
        v = ['--debug'] if ARGS.test_debug else []
        rng = range(1,8)
        for maxutilcpus in rng:
            with self.subTest(utils=3*maxutilcpus, threads=len(LWK_CPUS) + 3*maxutilcpus):
                yod(self,
                    '-u', 3*maxutilcpus,
                    '-o',
                    'util-threshold=' + str(maxutilcpus) + ":3",
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', len(LWK_CPUS) + 3*maxutilcpus,
                    '--spin', ARGS.test_spin,
                    '--uthreads', 3*maxutilcpus,
                    '--maxutilcpus', maxutilcpus,
                    '--maxutilspercpu', 3,
                    *v)

        for maxutilcpus in rng:
            with self.subTest(utils=3*maxutilcpus, threads=len(LWK_CPUS) + 3*maxutilcpus):
                yod(self,
                    '-u', 3*maxutilcpus,
                    '-o',
                    'util-threshold=' + str(maxutilcpus) + ":3",
                    '-o', 'one-cpu-per-util',
                    './thread_placement',
                    '--lwkcpus', len(LWK_CPUS),
                    '--threads', len(LWK_CPUS) + 3*maxutilcpus,
                    '--spin', ARGS.test_spin,
                    '--uthreads', 3*maxutilcpus,
                    '--maxutilcpus', maxutilcpus,
                    '--maxutilspercpu', 3,
                    '--one_cpu_per_util',
                    *v)



    def test_util_force_all_shared(self):
        # Set the maxutilcpus value to zero and verify that
        # no utility threads end up on an LWK CPU
        v = ['--debug'] if ARGS.test_debug else []
        rng = range(4)
        for n in rng:
            rng2 = range(1,3)
            for x in rng2:
                with self.subTest(utils=n, threads=len(LWK_CPUS) - 2 + n):
                    yod(self,
                        '-u', n,
                        '-o',
                        'util-threshold=' + "0:" + str(x),
                        './thread_placement',
                        '--lwkcpus', len(LWK_CPUS),
                        '--threads', len(LWK_CPUS) - 2 + n,
                        '--spin', ARGS.test_spin,
                        '--uthreads', n,
                        '--maxutilcpus', 0,
                        '--maxutilspercpu', x,
                        *v)
        for n in rng:
            rng2 = range(1,3)
            for x in rng2:
                with self.subTest(utils=n, threads=len(LWK_CPUS) - 2 + n):
                    yod(self,
                        '-u', n,
                        '-o',
                        'util-threshold=' + "0:" + str(x),
                        '-o', 'one-cpu-per-util',
                        './thread_placement',
                        '--lwkcpus', len(LWK_CPUS),
                        '--threads', len(LWK_CPUS) - 2 + n,
                        '--spin', ARGS.test_spin,
                        '--uthreads', n,
                        '--maxutilcpus', 0,
                        '--maxutilspercpu', x,
                        '--one_cpu_per_util',
                        *v)

    def test_preemption(self):
        # Verify that no timer-based preemption occurs in default
        # environment and verify that balanced round-robin preemptions
        # and progress occurs when a round-robin time quantum is
        # specified.
        v = ['--debug'] if ARGS.test_debug else []
        yod(self, '-u', 0, '-C', '2', '-M', 'all', './timer_preemption', '-t', 4, '-w', 6, *v)
        yod(self, '-u', 0, '-C', '2', '-M', 'all', '-o', 'lwksched-enable-rr=100',
            './timer_preemption', '--threads', 4, '-w', 6, '-q', 100, *v)

    def test_thread_priority(self):
        # Verify that no timer-based preemption occurs in default
        # environment and verify that balanced round-robin preemptions
        # and progress occurs when a round-robin time quantum is
        # specified.
        v = ['--debug'] if ARGS.test_debug else []
        yod(self, '-u', 0, '-C', '2', '-M', 'all', './thread_priority', *v)

    def test_yield(self):
        # Verify that the yield system call will round robin LWK threads of
        # equal priority
        v = ['--debug'] if ARGS.test_debug else []
        yod(self, '-u', 0, '-C', '2', '-M', 'all', './timer_preemption', '-t', 4, '-w', 6,
            '-y', 10000, *v)
    def test_concurrent_thread_creates(self):
        v = ['--debug'] if ARGS.test_debug else []
        # Test creating threads in parallel
        yod(self, './concurrent_placement', *v)



class Syscalls(TestCase):
    require = [
        YOD,
        'set_clone_attr',
        'mwait_api',
        ]

    def test_set_clone_attr(self):
        v = ['--debug'] if ARGS.test_debug else []
        # Syscall parameter validation is working correctly
        yod(self, '-C', '1', '-M', 'all', './set_clone_attr', *v)
        # Verify correct clone behavior
        #

    def test_mos_mwait(self):
        v = ['--debug'] if ARGS.test_debug else []
        # mos_mwait syscall validation
        yod(self, './mwait_api', *v)

class APIs(TestCase):
    require = [
            YOD,
            'uti_placement',
            ]
    def test_uti_api_1(self):
        v = ['--debug'] if ARGS.test_debug else []
        # UTI API validation
        yod(self, './uti_macros', *v)
        yod(self, './uti_placement', *v)

    def test_uti_api_2(self):
        v = ['--debug'] if ARGS.test_debug else []
        # UTI API validation specifying overcommit behavior = 0
        yod(self, '-o', 'overcommit-behavior=0', './uti_placement', '-b', 0, *v)
        yod(self, '-o', 'overcommit-behavior=0', '-o', 'one-cpu-per-util',
            './uti_placement', '-b', 0, *v)

    def test_uti_api_3(self):
        v = ['--debug'] if ARGS.test_debug else []
        # UTI API validation specifying overcommit behavior = 1
        yod(self, '-o', 'overcommit-behavior=1', './uti_placement', '-b', 1, *v)
        yod(self, '-o', 'overcommit-behavior=1', '-o', 'one-cpu-per-util',
            './uti_placement', '-b', 1, *v)

    def test_uti_api_4(self):
        v = ['--debug'] if ARGS.test_debug else []
        # UTI API validation specifying overcommit behavior = 2
        yod(self, '-o', 'overcommit-behavior=2', './uti_placement', '-b', 2, *v)
        yod(self, '-o', 'overcommit-behavior=2', '-o', 'one-cpu-per-util',
            './uti_placement', '-b', 2, *v)
