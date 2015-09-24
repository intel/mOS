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
from mostests import yod as _yod
import contextlib
import yod

logger = logging.getLogger()

class NoPlugin(yod.YodTestCase):
    yod_plugin = None
    yod_lscpu = None

    def test_multilaunch(self):
        lwkcpus_mask = int(LWK_CPUS)
        lwkcpus = yod.CpuSet(lwkcpus_mask)
        n_lwk_cores = lwkcpus.countBy(self.topology.cores)

        @contextlib.contextmanager
        def process(i):
            with _yod(self, '-C', 1, '-u', 0, '-M', '4M', '--resource_algorithm', 'simple',
                      './affinity_test', 'wait', i,
                      env=self.test_env, bg=True, pipe='io') as p:
                # wait for it to get started
                o = p.stdout.readline()
                self.assertEqual(o.strip(), 'ready')
                yield
                # wait for it to terminate
                p.stdin.write('done')

        for n in range(1, n_lwk_cores+1):
            with contextlib.ExitStack() as stack:
                stack.enter_context(self.subTest(concurrent=n))
                # launch n processes waiting on stdin
                expected = yod.CpuSet(0)
                for i in range(1, n+1):
                    stack.enter_context(process(i))
                    expected += lwkcpus.selectNthBy(i, self.topology.cores)
                # compare expected and actual reserved CPUs
                actual = cpulist(get_file('/sys/kernel/mOS/lwkcpus_reserved'))
                self.assertEqual(int(actual), int(expected))
