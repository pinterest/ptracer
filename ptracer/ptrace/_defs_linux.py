# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import ctypes
import os
import signal

from . import platform
from . import syscalldef

if platform.BITS == 64:
    from ._defs_linux_64 import *  # noqa
else:
    raise RuntimeError('unsupported platform: {} ({} bit)'.format(
        platform.PLATFORM, platform.BITS))

from ._gen_defs_linux_64 import SYSCALLS


WALL = 0x40000000


# Must not intepret the fifth arg of futext() as a pointer
# because it might be a value:
#     int futex(int *uaddr, int futex_op, int val,
#               const struct timespec *timeout,   /* or: uint32_t val2 */
#               int *uaddr2, int val3);
SYSCALLS['futex'].params[3] = syscalldef.SysCallParamSig(
    name='val2', type=syscalldef.CType(['uint32_t'], ctypes.c_uint32, 0))
SYSCALLS['futex'].params[4] = syscalldef.SysCallParamSig(
    name='uaddr2', type=syscalldef.CType(['void', '*'], ctypes.c_void_p, 0))


class c_int_Array_2(ctypes.Array):
    _length_ = 2
    _type_ = ctypes.c_int


SYSCALLS['pipe'].params[0] = syscalldef.SysCallParamSig(
    name='pipefd', type=syscalldef.CType(['int', '[2]'], c_int_Array_2, 0))
SYSCALLS['pipe2'].params[0] = syscalldef.SysCallParamSig(
    name='pipefd', type=syscalldef.CType(['int', '[2]'], c_int_Array_2, 0))


def WPTRACEEVENT(status):
    if os.WIFSTOPPED(status):
        stopsig = os.WSTOPSIG(status)
        if stopsig == signal.SIGTRAP:
            return status >> 16

    return 0
