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
import functools

logger = logging.getLogger()

def check_for_lwkmem_leak(func):
    # Verify that test did not increase reserved LWK memory
    @functools.wraps(func)
    def wrapper(self, *args, **kws):
        before = intlist(get_file('/sys/kernel/mOS/lwkmem_reserved'))
        r = func(self, *args, **kws)
        after = intlist(get_file('/sys/kernel/mOS/lwkmem_reserved'))
        self.assertEqual(before, after, 'lwkmem_reserved leaked by test')
        return r
    return wrapper

class Basics(TestCase):
    require = [YOD, 'fork_test']

    @unittest.skipIf(len(LWK_CPUS) < 1, 'at least one LWK CPU required')
    @check_for_lwkmem_leak
    def test_forking(self):
        # Determine which CPU can be used by this test.  We choose an
        # available CPU that isn't already reserved.
        avail = LWK_CPUS - cpulist(get_file('/sys/kernel/mOS/lwkcpus_reserved'))
        if not avail:
            self.skipTest('at least one unreserved LWK CPU required')
        lwkcpu = min(avail)

        # Test fork with various size buffers.  Ensure that we exercise
        # all three kinds of LWK memory (4K, 2M, 1G).
        def subtest():
            pids = []

            # Launch fork_test on the unused CPU
            with yod(self, '-c', lwkcpu, '-u', 0, './fork_test', nprocs,
                     bufsize, 'wait', bg=True, pipe='io') as ft:
                # Read list of PIDs from stdout
                for line in ft.stdout:
                    if line.strip() == 'ready':
                        break
                    pids.append(line)
                pids = set(intlist(''.join(pids)))
                self.assertEqual(nprocs, len(pids))

                # Get list of LWK processes (only the parent)
                lwks = set(intlist(get_file('/sys/kernel/mOS/lwkprocesses'), ','))

                # The CPU on which we launched fork_test should be reserved
                resvd = cpulist(get_file('/sys/kernel/mOS/lwkcpus_reserved'))
                self.assertIn(lwkcpu, resvd, 'CPU should be in use')

                # The PIDs reported by fork_test should NOT be LWK processes
                self.assertEqual(pids & lwks, {ft.pid},
                                 'there are LWK children')

            # Verify the fork_test processes terminated
            lwks = set(intlist(get_file('/sys/kernel/mOS/lwkprocesses'), ','))
            self.assertEqual(pids & lwks, set(), 'there are zombie LWK procs')
            r, o, e = run(self, 'ps', '-e', '--format', 'pid=,comm=', pipe='o')
            for line in o.splitlines():
                pid, line = line.split(None, 1)
                pid = int(pid)
                if pid in pids and 'fork_test' in line:
                    self.assertNotIn(pid, pids, 'fork_test zombie')

            # The CPU on which we launched should be free again
            resvd = cpulist(get_file('/sys/kernel/mOS/lwkcpus_reserved'))
            self.assertNotIn(lwkcpu, resvd, 'CPU should be free')

        nprocs = 3
        for bufsize in [500, 10000, 1000000]:
            with self.subTest(nprocs=nprocs, bufsize=bufsize):
                subtest()
