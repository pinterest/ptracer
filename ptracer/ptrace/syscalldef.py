# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


class CType(object):
    __slots__ = ('names', 'ctype', 'ptr_indirection')

    def __init__(self, names, ctype, ptr_indirection):
        self.names = names
        self.ctype = ctype
        self.ptr_indirection = ptr_indirection

    def __repr__(self):
        return '<CType {}>'.format(' '.join(self.names))


class SysCallParamSig(object):
    __slots__ = ('name', 'type')

    def __init__(self, name, type):
        self.name = name
        self.type = type

    def __repr__(self):
        return '<SysCallParamSig {} {}>'.format(self.type, self.name)


class SysCallSig(object):
    __slots__ = ('name', 'params', 'result')

    def __init__(self, name, params, result):
        self.name = name
        self.params = params
        self.result = result


class SysCallArg(object):
    def __init__(self, name, type, raw_value, value):
        self.name = name
        self.type = type
        self.raw_value = raw_value
        self.value = value

    def __repr__(self):
        return '<SysCallArg {}={!r}>'.format(self.name, self.value)


class SysCallResult(object):
    def __init__(self, type, raw_value, value):
        self.type = type
        self.raw_value = raw_value
        self.value = value

    def __repr__(self):
        return '<SysCallResult {!r}>'.format(self.value)


class SysCall(object):
    def __init__(self, name, args, result, pid, traceback=None):
        self.name = name
        self._name = SysCallArg(None, None, self.name, self.name)
        self.pid = pid
        self.args = args
        self.result = result
        self.traceback = traceback

    def __repr__(self):
        return '<SysCall {!s}>'.format(self.name)
