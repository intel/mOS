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

    def test_shared_util_threads(self):
        # Fill the LWKCPUs with a mix of worker threads and utility
        # threads and create additional worker threads to validate that
        # the utility threads running on LWKCPUs are pushed to the shared
        # utility (Linux) CPUs.
        v = ['--debug'] if ARGS.test_debug else []
        rng = range(10)
        for n in rng:
            with self.subTest(utils=n, threads=len(LWK_CPUS) + n//2):
                yod(self, '-u', n, './thread_placement', '--lwkcpus', len(LWK_CPUS),
                        '--threads', len(LWK_CPUS) + n//2,
                        '--spin', ARGS.test_spin, '--uthreads', n, *v)

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

