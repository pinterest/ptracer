# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import errno
import os
import re
import threading
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

import ptracer


eperm_mock = mock.Mock(
    side_effect=OSError(errno.EPERM, 'Operation not permitted'))


class TestPtracer(unittest.TestCase):
    @mock.patch('ptracer.ptrace.attach_and_wait', eperm_mock)
    def test_ptracer__fail_01(self):
        with self.assertRaisesRegexp(ptracer.PtracerError,
                                     'Operation not permitted'):
            with ptracer.context(lambda s: None):
                f = open('/dev/zero', 'r')
                f.close()

    @mock.patch('ptracer.ptrace.syscall', eperm_mock)
    def test_ptracer__fail_02(self):
        with self.assertRaisesRegexp(ptracer.PtracerError,
                                     'Operation not permitted'):
            with ptracer.context(lambda s: None):
                f = open('/dev/zero', 'r')
                f.close()

    @mock.patch('ptracer.ptrace.syscall_exit', eperm_mock)
    def test_ptracer__fail_03(self):
        with self.assertRaisesRegexp(ptracer.PtracerError,
                                     'Operation not permitted'):
            with ptracer.context(lambda s: None):
                f = open('/dev/zero', 'r')
                f.close()

    @mock.patch('ptracer.ptrace.ptrace.getsiginfo', eperm_mock)
    def test_ptracer__fail_04(self):
        with self.assertRaisesRegexp(ptracer.PtracerError,
                                     'Operation not permitted'):
            with ptracer.context(lambda s: None):
                f = open('/dev/zero', 'r')
                f.close()

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
            ptracer.SysCallPattern(name=re.compile('op.*'))
        ])

        self.assertEqual(len(syscalls), 3)

        _trace([
            ptracer.SysCallPattern(
                name=re.compile('openat'),
                args=[
                    None,
                    b'/dev/null'
                ]
            )
        ])

        self.assertEqual(len(syscalls), 1)

        _trace([
            ptracer.SysCallPattern(
                name=re.compile('openat'),
                args=[
                    None,
                    b'/dev/null'
                ]
            )
        ])

        self.assertEqual(len(syscalls), 1)

        _trace([
            ptracer.SysCallPattern(
                name=re.compile('openat'),
                args=[
                    None,
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
            name='openat',
            args=[
                None,
                b'/dev/zero'
            ]
        )

        with ptracer.context(syscalls.append, filter=flt):
            thread = threading.Thread(target=_thread)
            thread.start()
            thread.join()

        self.assertEqual(len(syscalls), 1)
