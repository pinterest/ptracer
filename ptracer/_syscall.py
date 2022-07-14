# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import functools
import operator


def _maybe_format(value):
    if isinstance(value, (bytes, bytearray, str)):
        return value
    return '{}'.format(value)


class SysCallPattern(object):
    def __init__(self, name=None, args=None, result=None):
        self.name = name
        self.args = args
        self.result = result

        self.matcher = []

        if name is not None:
            self.matcher.append(self._get_comparator(
                operator.attrgetter('_name'), name))

        if result is not None:
            self.matcher.append(self._get_comparator(
                operator.attrgetter('result'), result))

        if args:
            def arg_getter(call, argno):
                return call.args[argno]

            for i, arg in enumerate(args):
                if arg is None:
                    continue

                indirection = functools.partial(arg_getter, argno=i)
                self.matcher.append(self._get_comparator(indirection, arg))

    def _get_comparator(self, indirection, value):
        if callable(value):
            checker = value
            getter = indirection
        elif hasattr(value, 'match'):
            checker = value.match
            getter = lambda sc: _maybe_format(indirection(sc).value)
        else:
            checker = lambda v: v == value
            getter = lambda sc: indirection(sc).value

        return getter, checker

    def match(self, syscall):
        return all(m[1](m[0](syscall)) for m in self.matcher)
