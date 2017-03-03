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
check_trace = import_from_file('check-trace.py')

logger = logging.getLogger()

STAP_KO = 'record_trace_stap.ko'

class Syscalls(TestCase):
    require = ['timer_call_overhead']

    def test_timing_overhead(self):
        yod(self, './timer_call_overhead')

class Motion(TestCase):
    require = [
        'stap-shim',
        'test0',
        'test2',
        STAP_KO,
        STAPRUN,
        ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not EVANESCENCE_MAP:
            cls.skipClass('requires syscall motion to be enabled')
        for dst, src in reversed(EVANESCENCE_MAP):
            if len(dst) == 1:
                break
        else:
            cls.skipClass('requires CPUs that offload to exactly one target')
        cls.same, cls.src, cls.dst = min(NORMAL_CPUS), min(src), min(dst)

    def trace(self, n, test, s=None, t='', c=None):
        log = 'trace.{}.txt'.format(n)
        cmd = './stap-shim {} ./{} {}'.format(s, test, t)
        run(self, 'staprun', STAP_KO, '-v', '-o', log, '-c', cmd)
        logpath = os.path.join(path_of(self), log)
        self.assertEqual(check_trace.main(logpath, *map(str, c)), 0,
                         'trace should pass analysis')

    def test_0(self):
        # On normal cores, syscalls should run on the core on which
        # they start.
        self.trace(0, 'test0', s=self.same,
                   c=['motion', self.same, self.same])

    def test_1(self):
        # On evanescing cores, syscalls should run on the corresponding
        # syscall core.
        self.trace(1, 'test0', s=self.src,
                   c=['motion', self.src, self.dst])

    def test_2(self):
        # External taskset should land on indicated core
        # (case 1: start on normal core).
        self.trace(2, 'test2', s=self.same, t=self.src,
                   c=['taskset', self.same, self.same, self.src, self.dst])

    def test_3(self):
        # External taskset should land on indicated core
        # (case 2: start on evanescing core).
        self.trace(3, 'test2', s=self.src, t=self.same,
                   c=['taskset', self.src, self.dst, self.same, self.same])
