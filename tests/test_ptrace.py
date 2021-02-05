# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import errno
import multiprocessing
import os
import signal
import time
import unittest

from ptracer import ptrace


class TestPtrace(unittest.TestCase):
    def test_ptrace_syscalls(self):
        def process_func():
            ptrace.traceme()
            os.kill(os.getpid(), signal.SIGSTOP)

            with open('/dev/null', 'w') as f:
                f.write('foo')

            rd, wr = os.pipe()
            os.close(rd)
            os.close(wr)

        try:
            process = multiprocessing.Process(target=process_func)
            process.start()

            pid, status = os.waitpid(process.pid, 0)

            self.assertTrue(os.WIFSTOPPED(status))
            stopsig = os.WSTOPSIG(status)
            self.assertEqual(stopsig, signal.SIGSTOP)

            ptrace.setoptions(process.pid, ptrace.PTRACE_O_TRACESYSGOOD)

            syscalls = []
            in_syscall = None

            while True:
                ptrace.syscall(process.pid)
                pid, status = os.waitpid(process.pid, 0)

                if os.WIFEXITED(status):
                    break

                self.assertTrue(os.WIFSTOPPED(status))

                stopsig = os.WSTOPSIG(status)
                self.assertTrue(stopsig & 0x80)
                self.assertEqual(stopsig & 0x7F, signal.SIGTRAP)

                regs = ptrace.getregs(process.pid)
                if not in_syscall:
                    syscall = ptrace.syscall_enter(process.pid, regs)
                    syscalls.append(syscall)
                    in_syscall = syscall
                else:
                    ptrace.syscall_exit(in_syscall, regs)
                    in_syscall = None

        finally:
            try:
                os.kill(process.pid, signal.SIGKILL)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    pass
                else:
                    raise

        syscalls = [
            s for s in syscalls if s.name
            in {'open', 'openat', 'write', 'close'}
        ]

        self.assertEqual(len(syscalls), 5)

        open_call, write_call, close_call = syscalls[:3]

        if open_call.name == 'openat':
            self.assertEqual(open_call.args[1].value, b'/dev/null')
        else:
            self.assertEqual(open_call.args[0].value, b'/dev/null')

        fno = open_call.result.value
        self.assertGreater(fno, 0)

        self.assertIsNotNone(open_call.result.type)

        self.assertEqual(write_call.args[0].value, fno)
        self.assertEqual(write_call.args[2].value, 3)
        self.assertEqual(write_call.result.value, 3)

        self.assertEqual(close_call.args[0].value, fno)

    def test_ptrace_attach(self):
        def process_func():
            time.sleep(0.1)

        try:
            process = multiprocessing.Process(target=process_func)
            process.start()

            ptrace.attach_and_wait(process.pid)
            ptrace.cont(process.pid)

        finally:
            try:
                os.kill(process.pid, signal.SIGKILL)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    pass
                else:
                    raise

    def test_ptrace_procmem(self):
        def process_func():
            ptrace.traceme()
            os.kill(os.getpid(), signal.SIGSTOP)

            with open('/dev/null', 'w') as f:
                f.write('foo')

            rd, wr = os.pipe()
            os.close(rd)
            os.close(wr)

        try:
            process = multiprocessing.Process(target=process_func)
            process.start()

            pid, status = os.waitpid(process.pid, 0)
            ptrace.setoptions(process.pid, ptrace.PTRACE_O_TRACESYSGOOD)

            syscalls = []
            in_syscall = None

            mem_fd = os.open('/proc/{}/mem'.format(pid), os.O_RDONLY)

            while True:
                ptrace.syscall(process.pid)
                pid, status = ptrace.wait(process.pid)

                if os.WIFEXITED(status):
                    break

                regs = ptrace.getregs(process.pid)
                if not in_syscall:
                    syscall = ptrace.syscall_enter(process.pid, regs, mem_fd)
                    syscalls.append(syscall)
                    in_syscall = syscall
                else:
                    ptrace.syscall_exit(in_syscall, regs, mem_fd)
                    in_syscall = None

        finally:
            os.close(mem_fd)

            try:
                os.kill(process.pid, signal.SIGKILL)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    pass
                else:
                    raise

        syscalls = [
            s for s in syscalls if s.name
            in {'open', 'openat', 'write', 'close'}
        ]

        self.assertEqual(len(syscalls), 5)

        open_call, write_call, close_call = syscalls[:3]

        if open_call.name == 'openat':
            self.assertEqual(open_call.args[1].value, b'/dev/null')
        else:
            self.assertEqual(open_call.args[0].value, b'/dev/null')
        fno = open_call.result.value
        self.assertGreater(fno, 0)

        self.assertEqual(write_call.args[0].value, fno)
        self.assertEqual(write_call.args[2].value, 3)
        self.assertEqual(write_call.result.value, 3)

        self.assertEqual(close_call.args[0].value, fno)
