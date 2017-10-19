# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import ctypes
import errno
import os
import signal

from .defs import *  # noqa

from . import defs
from ._ptrace import ptrace as _ptrace
try:
    from ._ptrace import set_ptracer  # noqa
except ImportError:
    pass


def traceme():
    return _ptrace(defs.PTRACE_TRACEME, 0, 0, 0)


def peektext(pid, addr):
    return _ptrace(defs.PTRACE_PEEKTEXT, pid, addr, 0)


def peekdata(pid, addr):
    return _ptrace(defs.PTRACE_PEEKDATA, pid, addr, 0)


def peekuser(pid, addr):
    return _ptrace(defs.PTRACE_PEEKUSER, pid, addr, 0)


def poketext(pid, addr, data):
    return _ptrace(defs.PTRACE_POKETEXT, pid, addr, data)


def pokedata(pid, addr, data):
    return _ptrace(defs.PTRACE_POKEDATA, pid, addr, data)


def pokeuser(pid, addr, data):
    return _ptrace(defs.PTRACE_POKEUSER, pid, addr, data)


def getregs(pid):
    regs = defs.user_regs_struct()
    _ptrace(defs.PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def getfpregs(pid):
    regs = defs.user_fpregs_struct()
    _ptrace(defs.PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def getsiginfo(pid):
    siginfo = defs.siginfo_t()
    _ptrace(defs.PTRACE_GETSIGINFO, pid, 0, ctypes.addressof(siginfo))
    return siginfo


def setoptions(pid, options):
    return _ptrace(defs.PTRACE_SETOPTIONS, pid, 0, options)


def geteventmsg(pid):
    data = ctypes.c_ulong()
    _ptrace(defs.PTRACE_GETEVENTMSG, pid, 0, ctypes.addressof(data))
    return data.value


def cont(pid, signum=0):
    return _ptrace(defs.PTRACE_CONT, pid, 0, signum)


def syscall(pid, signum=0):
    return _ptrace(defs.PTRACE_SYSCALL, pid, 0, signum)


def kill(pid):
    return _ptrace(defs.PTRACE_KILL, pid, 0, 0)


def attach(pid):
    return _ptrace(defs.PTRACE_ATTACH, pid, 0, 0)


def attach_and_wait(pid, options=0):
    attach(pid)
    wait_for_trace_stop(pid)
    options |= defs.PTRACE_O_TRACESYSGOOD
    setoptions(pid, options)


def wait_for_trace_stop(pid):
    try:
        _wait_for_trace_stop(pid)
    except BaseException:
        try:
            # If _wait_for_trace_stop fails for any reason,
            # we must try to detach from the tracee to avoid
            # leaving it blocked.
            detach(pid)
        except BaseException:
            pass

        raise


def _wait_for_trace_stop(pid):
    try:
        # First, check if the tracee is already stopped.
        siginfo = getsiginfo(pid)
    except OSError as e:
        if e.errno == errno.ESRCH:
            # The tracee is still running, so we'll wait
            pass
        else:
            raise
    else:
        # Normally, PTRACE_ATTACH will send a SIGSTOP to the tracee,
        # which we will see here.  However, on some kernels the actual
        # signal may sometimes be SIGTRAP, and that seems to happen
        # when the previous tracer had died without calling PTRACE_DETACH
        # on this process first.  In this case, we need to restart the process
        # and wait for the real SIGSTOP.
        if siginfo.si_signo == signal.SIGTRAP:
            cont(pid, siginfo.si_signo)
        elif is_stop_signal(siginfo.si_signo):
            return
        else:
            raise OSError('traced process has stopped with an unexpected '
                          'signal {}'.format(siginfo.si_signo))

    pid, status = wait(pid)

    if os.WIFEXITED(status):
        raise OSError('traced process {} has exited with exit code {}'.format(
            pid, os.WEXITSTATUS(status)))

    elif os.WIFSIGNALED(status):
        raise OSError('traced process {} has been killed by '
                      'the {} signal {}'.format(pid, os.WTERMSIG(status)))

    if not os.WIFSTOPPED(status):
        raise OSError('waitpid({}) returned an unexpected status {}'.format(
            pid, hex(status)))

    stopsig = os.WSTOPSIG(status)
    if stopsig != signal.SIGSTOP:
        raise OSError('waitpid({}) returned an unexpected status {}'.format(
            pid, hex(status)))


def wait(pid, options=0):
    options |= defs.WALL
    return os.waitpid(pid, options)


def detach(pid, signum=0):
    return _ptrace(defs.PTRACE_DETACH, pid, 0, signum)


def is_stop_signal(signum):
    return signum in (signal.SIGSTOP, signal.SIGTSTP,
                      signal.SIGTTIN, signal.SIGTTOU)
