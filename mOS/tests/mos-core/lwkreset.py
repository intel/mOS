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

class Basic(TestCase):

    def test_lwkreset_existence(self):
        out, rc = run(['lwkreset', '-h'])
        self.assertTrue(rc == 0, 'Could not locate lwkreset.')
