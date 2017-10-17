# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import os
import re
import threading
import unittest

import ptracer

import logging
logging.basicConfig(level=logging.DEBUG)


class TestPtracer(unittest.TestCase):
    def test_ptracer_basic(self):
        syscalls = []

        with ptracer.context(syscalls.append):
            f = open('/dev/zero', 'r')
            f.close()

        self.assertGreater(len(syscalls), 0)

    def test_ptracer_filter_01(self):
        syscalls = []

        def _trace(pattern):
            syscalls[:] = []

            with ptracer.context(syscalls.append, filter=pattern):
                f = open('/dev/null', 'w')
                f.close()
                f = open('/dev/zero', 'r')
                f.close()
                try:
                    open('/dev/nonexistent', 'r')
                except IOError:
                    pass

        _trace([
            ptracer.SysCallPattern(name='open')
        ])

        self.assertEqual(len(syscalls), 3)

        _trace([
            ptracer.SysCallPattern(
                name='open',
                args=[
                    b'/dev/null'
                ]
            )
        ])

        self.assertEqual(len(syscalls), 1)

        _trace([
            ptracer.SysCallPattern(
                name=re.compile('op.*'),
                args=[
                    b'/dev/null'
                ]
            )
        ])

        self.assertEqual(len(syscalls), 1)

        _trace([
            ptracer.SysCallPattern(
                name=re.compile('op.*'),
                args=[
                    None,
                    lambda arg: arg.value & os.O_WRONLY
                ]
            )
        ])

        self.assertEqual(len(syscalls), 1)

        _trace([
            ptracer.SysCallPattern(
                name=re.compile('op.*'),
                result=lambda res: res.value < 0
            )
        ])

        self.assertEqual(len(syscalls), 1)

    def test_ptracer_threading(self):
        syscalls = []

        def _thread():
            f = open('/dev/zero', 'r')
            f.close()

        flt = ptracer.SysCallPattern(
            name='open', args=[b'/dev/zero'])

        with ptracer.context(syscalls.append, filter=flt):
            thread = threading.Thread(target=_thread)
            thread.start()
            thread.join()

        self.assertEqual(len(syscalls), 1)
