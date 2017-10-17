# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


__version__ = '0.5'
__all__ = ['context', 'enable', 'disable', 'SysCallPattern']


import threading

from . import _ptracer
from ._syscall import SysCallPattern  # NOQA
from . import _lltraceback


class TracingContext(object):
    def __init__(self):
        self.enabled = False

    def enable(self, handler_cb, filter=None):
        if self.enabled:
            raise RuntimeError('tracing context is already enabled')

        self.enabled = True
        self.thread_stop_event = threading.Event()

        debugger_start_event = threading.Event()

        if isinstance(filter, SysCallPattern):
            filter = [filter]

        self.ptrace_thread = threading.Thread(
            target=_ptracer._tracing_thread,
            args=(handler_cb, self.thread_stop_event, debugger_start_event,
                  {_lltraceback.gettid(): threading.current_thread().ident},
                  filter))

        self.ptrace_thread.start()
        self.ptrace_thread_join = self.ptrace_thread.join

        # Wait for debugger to start
        debugger_start_event.wait()

        try:
            # Perform a magic syscall to enable syscall callback invocation.
            open(b'\x01\x02\x03', 'r')
        except IOError:
            pass

    def disable(self):
        if not self.enabled:
            return
        self.thread_stop_event.set()
        self.thread_stop_event = None
        self.ptrace_thread_join()
        self.ptrace_thread = None
        self.enabled = False


class context(object):
    """Tracing context manager."""

    def __init__(self, handler_cb, filter=None):
        self.handler_cb = handler_cb
        self.filter = filter

    def __enter__(self):
        _context.enable(self.handler_cb, filter=self.filter)

    def __exit__(self, exc_type, exc_value, exc_tb):
        _context.disable()


_context = TracingContext()
enable = _context.enable
disable = _context.disable
