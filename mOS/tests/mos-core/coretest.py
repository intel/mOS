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

class NoPlugin(yod.YodTestCase):
    yod_plugin = None
    yod_lscpu = None

    def test_cores(self):
        lwkcpus_mask = int(LWK_CPUS)
        lwkcpus = yod.CpuSet(lwkcpus_mask)
        n_lwk_cores = lwkcpus.countBy(self.topology.cores)
        ncores = len(self.topology.cores) + 1

        mask = yod.CpuSet(0)
        for n in range(-1, ncores+1):
            with self.subTest(n=n):
                should_work = 1 <= n <= n_lwk_cores
                mask += lwkcpus.selectNthBy(n, self.topology.cores)
                cmd = ['-C', n, '-u', 0, '-M', 'all', '--resource_algorithm', 'simple',
                       './affinity_test', '--affinity', str(mask)]
                out, rc = yod.launch(self, cmd, self.test_env)
                self.assertCommand(rc, should_work)
