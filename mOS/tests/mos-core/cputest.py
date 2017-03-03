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

    def test_cpus(self):
        lwkcpus = int(LWK_CPUS)

        for cpu in range(MAX_CPUS):
            with self.subTest(cpu=cpu):
                cmd = ['-c', str(cpu), '-u', '0', '-M', 'all',
                       './affinity_test', '--affinity', str(cpu)]
                out, rc = yod.launch(self, cmd, self.test_env)
                self.assertCommand(rc, lwkcpus & 2**cpu)
