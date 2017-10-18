# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import ctypes

from . import defs
from . import memory
from . import syscalldef


_ulong_t = syscalldef.CType(
    names=['unsigned', 'long'], ctype=ctypes.c_ulong, ptr_indirection=0)

_unknown_syscall = syscalldef.SysCallSig(
    name='unknown',
    params=[
        syscalldef.SysCallParamSig(
            name='param{}'.format(i),
            type=_ulong_t
        ) for i in range(len(defs.ARGS_REGS))
    ],
    result=_ulong_t
)


def syscall_enter(pid, regs, mem_fd=None):
    syscall_num = getattr(regs, defs.FUNCTION_REG)
    syscall_name = defs.SYSCALL_NUMBERS.get(
        syscall_num, '<{}>'.format(syscall_num))

    signature = defs.SYSCALLS.get(syscall_name, _unknown_syscall)

    args = []

    for i, param in enumerate(signature.params):
        raw_value = getattr(regs, defs.ARGS_REGS[i])
        ptype = param.type

        if ptype.ptr_indirection or issubclass(ptype.ctype, ctypes.Array):
            if raw_value != 0:
                value = memory.read_c_type_ptr(
                    pid, raw_value, ptype.ctype, ptype.ptr_indirection, mem_fd)
            else:
                value = None
        else:
            value = ptype.ctype(raw_value).value

        arg = syscalldef.SysCallArg(name=param.name, type=param.type,
                                    raw_value=raw_value, value=value)

        args.append(arg)

    syscall = syscalldef.SysCall(
        name=syscall_name, args=args, result=None, pid=pid)

    return syscall


def syscall_exit(syscall, regs, mem_fd=None):
    signature = defs.SYSCALLS.get(syscall.name, _unknown_syscall)

    for i, param in enumerate(signature.params):
        ptype = param.type
        if (not ptype.ptr_indirection and
                not issubclass(ptype.ctype, ctypes.Array)):
            continue

        raw_value = getattr(regs, defs.ARGS_REGS[i])
        if raw_value != 0:
            value = memory.read_c_type_ptr(
                syscall.pid, raw_value, ptype.ctype,
                ptype.ptr_indirection, mem_fd)
        else:
            value = None

        arg = syscall.args[i]
        arg.raw_value = raw_value
        arg.value = value

    restype = signature.result
    raw_result = getattr(regs, defs.RETURN_REG)

    if restype.ptr_indirection:
        if raw_result != 0:
            value = memory.read_c_type_ptr(syscall.pid, raw_result, restype,
                                           restype.ptr_indirection)
        else:
            value = None
    else:
        value = signature.result.ctype(raw_result).value

    syscall.result = syscalldef.SysCallResult(restype, raw_result, value)

    return syscall
