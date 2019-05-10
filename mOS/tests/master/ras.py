# Multi Operating System (mOS)
# Copyright (c) 2019, Intel Corporation.
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
from mosunit import run
import time

logger = logging.getLogger()


class Basics(TestCase):
    sysfs = '/sys/kernel/mOS/ras'

    def _write_to_ras_file(self, fil, content):
        fname = '/'.join([self.sysfs, fil])
        with open(fname, 'w') as sysfile:
            n = sysfile.write(content)
            self.assertEqual(n, len(content), 'Error writing to {}, rc={} but expected {}'.format(fname, n, len(content)))
            logging.debug('Wrote "{}" to {} successfully.'.format(content, fname))

    def _inject(self, msg):
        self._write_to_ras_file('inject', msg)


    def _test_inject(self, message_id, instance_data, job_id, location, config, expected):

        self._write_to_ras_file('config', config)
        self._write_to_ras_file('jobid', job_id)
        self._write_to_ras_file('location', location)
        self._inject('{} {}'.format(message_id, instance_data))

        out, rc = run(['dmesg'], requiresRoot=True)


        dmesg = out.split('\n')
        passed = False
        for n in range(-1, -10, -1):
            if expected in dmesg[n]:
                passed = True
                logging.debug('Found:  "{}"'.format(dmesg[n]))
                break

        self.assertTrue(passed, 'Could not find "{}" in dmesg log.'.format(expected))

        self._write_to_ras_file('config', 'default')
        self._write_to_ras_file('jobid', ' ')
        self._write_to_ras_file('location', ' ')

    def test_inject_default(self):

        message_id = '00010001'
        instance_data = 'Testing the default configuration.'
        job_id = str(int(time.monotonic() * 100))
        location='R1-CH2-N03'
        expected = 'mOS-ras: msg="{}" id={} location={} jobid={}'.format(instance_data, message_id, location, job_id)

        self._test_inject(message_id, instance_data, job_id, location, 'default', expected)

    def test_inject_ucs(self):

        message_id = '00010002'
        instance_data = 'Testing the UCS configuration.'
        job_id = str(int(time.monotonic() * 100))
        location='R1-CH2-N04'
        expected = 'UcsRasEvent "Event": "{}", "Lctn": "{}", "JobId": "{}", "Data": "{}"'.format(message_id, location, job_id, instance_data)

        self._test_inject(message_id, instance_data, job_id, location, 'ucs', expected)

