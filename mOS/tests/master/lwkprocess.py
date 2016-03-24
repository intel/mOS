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

ncpus = notNone(ARGS.test_ncpus, CONFIG_NR_CPUS + 5)
mask_desc = {True: 'mask', False: 'list'}

# Mix of CPUs that are online, offline, and nonsensical
TEST_CPUS = ONLINE_CPUS.OR([(POSSIBLE_CPUS - ONLINE_CPUS)[:10],
                            range(CONFIG_NR_CPUS + 5)[-10:],
                            range(5)])
logger.debug('TEST_CPUS: %s', TEST_CPUS)

@unittest.skipUnless(IS_MOS, 'tests require mOS')
class Basics(TestCase):
    require = ['lwkprocess']

    def launch(self, assertion=True, **kw):
        args = []
        for k, v in kw.items():
            args.extend(('--' + k, v))
        if logger.getEffectiveLevel() <= logging.DEBUG:
            args.append('--debug')
        run(self, './lwkprocess', *args, assertion=assertion)

    def test_each_lwkcpu(self):
        # For each CPU, launch an LWK task on it (up to ncpus times);
        # expect success for LWK CPUs and failure otherwise.
        for count, cpu in enumerate(TEST_CPUS):
            if count >= ncpus:
                break
            for mask in (False, True):
                with self.subTest(mask_desc[mask], n=count, cpu=cpu):
                    lwk = cpulist([cpu])
                    lwk = '0x'+lwk.mask() if mask else str(lwk)
                    self.launch(assertion=cpu in LWK_CPUS, lwkcpus=lwk)

    def test_all_lwkcpus(self):
        # Launch an LWK task bound to all LWK CPUs.
        for mask in (False, True):
            with self.subTest(mask_desc[mask]):
                lwk = LWK_CPUS
                lwk = '0x'+lwk.mask() if mask else str(lwk)
                self.launch(assertion=True, lwkcpus=lwk)

