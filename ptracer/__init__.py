# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


__version__ = '0.6.1'
__all__ = ['context', 'enable', 'disable', 'SysCallPattern']


try:
    import Queue as queue
except ImportError:
    import queue
import multiprocessing
import threading

from . import _ptracer
from ._ptracer import PtracerError  # NOQA
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

        # Debugger error queue.
        self.error_queue = multiprocessing.Queue()

        if isinstance(filter, SysCallPattern):
            filter = [filter]

        self.ptrace_thread = threading.Thread(
            target=_ptracer._tracing_thread,
            args=(handler_cb, self.thread_stop_event, debugger_start_event,
                  {_lltraceback.gettid(): threading.current_thread().ident},
                  filter, self.error_queue))

        self.ptrace_thread.start()

        # Wait for debugger to start
        if not debugger_start_event.wait(1):
            try:
                self.disable()
            except Exception:
                raise
            else:
                raise PtracerError('Unhandled exception in ptrace process')
        else:
            try:
                # Perform a magic syscall to enable
                # syscall callback invocation.
                open(b'\x01\x02\x03', 'r')
            except IOError:
                pass

    def disable(self):
        if not self.enabled:
            return

        try:
            # Notify the debugger we're not tracing anymore.
            open(b'\x03\x02\x01', 'r')
        except IOError:
            pass

        self.enabled = False
        self.thread_stop_event.set()
        self.thread_stop_event = None
        self.ptrace_thread.join()
        self.ptrace_thread = None

        try:
            error = self.error_queue.get_nowait()
        except queue.Empty:
            error = None

        self.error_queue.close()
        self.error_queue = None

        if error is not None:
            raise error


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
