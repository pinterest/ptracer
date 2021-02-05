# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


from __future__ import print_function

import errno
import fcntl
import linecache
import logging
import multiprocessing
import os
try:
    import Queue as queue
except ImportError:
    import queue
import select
import signal
import struct
import threading
import time
import traceback

from ptracer import _lltraceback
from ptracer import ptrace


logger = logging.getLogger('ptracer')


class PtracerError(Exception):
    def __init__(self, msg, orig_exc=None):
        super(PtracerError, self).__init__(msg)
        self.orig_exc = orig_exc

    def __str__(self):
        if self.orig_exc is not None:
            return '{}\n{}'.format(self.args[0], self.orig_exc)
        else:
            return self.args[0]


# The tracing thread is run parallel to the traced thread,
# the syscall callback will be called in this thread.
def _tracing_thread(handler_cb, thread_stop_event, debugger_start_event,
                    thread_map, syscall_filter, error_queue):

    # The main syscall queue.
    syscall_queue = multiprocessing.Queue()

    # Pipes for communication with lltraceback helper.
    stack_response_read, stack_response_write = os.pipe()
    stack_request_read, stack_request_write = os.pipe()

    # Debugger process start request event.
    dbgproc_start = multiprocessing.Event()
    # Debugger process stop request event.
    dbgproc_stop = multiprocessing.Event()
    # Debugger process started response event.
    dbgproc_started = multiprocessing.Event()

    # The actual tracing is done by a subprocess.
    # It is necessary because of the GIL, as a ptrace-stopped thread
    # holding the GIL would block the tracer thread as well.
    ptrace_process = multiprocessing.Process(
        target=_tracing_process,
        args=(os.getpid(), dbgproc_started, dbgproc_start, dbgproc_stop,
              stack_request_write, stack_response_read,
              syscall_queue, syscall_filter, error_queue))

    ptrace_process.start()

    if hasattr(ptrace, 'set_ptracer'):
        # On systems with Yama LSM enabled in mode 1 (e.g. Ubuntu Trusty),
        # PTRACE_ATTACH will fail with EPERM unless we call PR_SET_PTRACER
        # with the PID of the tracing process.
        try:
            ptrace.set_ptracer(ptrace_process.pid)
        except OSError as e:
            pass

    dbgproc_start.set()

    # The lltraceback thread is a low-level GIL-independent thread
    # that is used to dump the current call stack in a given Python thread.
    _lltraceback.start_thread(
        stack_request_read, stack_response_write, thread_map)

    try:
        # Wait for debugger to start
        if not dbgproc_started.wait(1):
            # If the debugger has not started in 1 second, assume
            # it died and bail out.
            return

        # Notify the main thread that we're ready.
        debugger_start_event.set()

        while True:
            if thread_stop_event.is_set() or not ptrace_process.is_alive():
                # The tracing context has exited, stop the debugger.
                dbgproc_stop.set()

                while True:
                    # Drain the syscall queue.
                    try:
                        syscall = syscall_queue.get(timeout=0.1)
                    except queue.Empty:
                        break
                    else:
                        handler_cb(syscall)
                break

            try:
                event = syscall_queue.get_nowait()
            except queue.Empty:
                time.sleep(0.05)
                continue

            try:
                handler_cb(event)
            except Exception as e:
                logger.exception('EXCEPTION IN SYSCALL CALLBACK')
    finally:
        dbgproc_stop.set()
        _lltraceback.stop_thread()
        ptrace_process.join(1)
        if ptrace_process.exitcode is None:
            ptrace_process.terminate()
            ptrace_process.join(1)
            if ptrace_process.exitcode is None:
                os.kill(ptrace_process.pid, signal.SIGKILL)

        os.close(stack_response_read)
        os.close(stack_response_write)
        os.close(stack_request_read)
        os.close(stack_request_write)


def _tracing_process(pid, dbgproc_started, dbgproc_start, dbgproc_stop,
                     stack_request_pipe, stack_response_pipe,
                     syscall_queue, syscall_filter, error_queue):
    # The tracing process consists of two threads:
    # the first reads the call stacks from the tracee, and the second
    # does the actual tracing.

    if not dbgproc_start.wait(1):
        # The parent failed to continue the startup.
        err = PtracerError('Debugger startup handshake failed')
        error_queue.put_nowait(err)
        return

    stack_queue = queue.Queue()

    dbgthread_stop = threading.Event()

    debugger_thread = threading.Thread(
        target=_debugger_thread,
        args=(pid, dbgproc_started, dbgthread_stop,
              stack_request_pipe, stack_queue,
              syscall_queue, syscall_filter, error_queue),
        name='pytracer-debugger')

    debugger_thread.daemon = True
    debugger_thread.start()

    try:
        _read_callstacks(stack_response_pipe, stack_queue, debugger_thread,
                         dbgproc_stop)

    except Exception:
        logger.debug('Unhandled exception in ptrace process', exc_info=True)
        err = PtracerError('Unhandled exception in ptrace process',
                           orig_exc=traceback.format_exc())
        error_queue.put_nowait(err)

    finally:
        syscall_queue.close()

        if debugger_thread.is_alive():
            # Unblock the debugger if it is waiting on the stack queue
            stack_queue.put_nowait(None)
            dbgthread_stop.set()
            debugger_thread.join()


def _read_callstacks(stack_response_pipe, stack_queue, debugger_thread,
                     dbgproc_stop):
    buf = b''
    stacklen = -1
    tuplesize = 0
    elemlen = -1
    required_len = 4
    stack = []
    entry = []

    fcntl.fcntl(stack_response_pipe, fcntl.F_SETFL, os.O_NONBLOCK)

    # The call stack format is as follows:
    #     stack_length:uint32_t
    #     entry_tuple_len:uint32_t
    #     (
    #            (item_length:uint32_t
    #             item_data:char[item_length]) * entry_tuple_len
    #     ) * stack_length
    while True:
        ready, _, _ = select.select([stack_response_pipe], [], [], 1.0)

        if ready:
            try:
                buf += os.read(stack_response_pipe, 4096)
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    pass
                else:
                    raise
            else:
                while len(buf) >= required_len:
                    if stacklen == -1:
                        stacklen = struct.unpack('!i', buf[:4])[0]
                        buf = buf[4:]
                        if stacklen == 0:
                            # No stack could be extracted.
                            stack_queue.put_nowait([])
                            stacklen = -1

                    elif tuplesize == 0:
                        tuplesize = struct.unpack('!i', buf[:4])[0]
                        buf = buf[4:]

                    elif elemlen == -1:
                        elemlen = struct.unpack('!i', buf[:4])[0]
                        buf = buf[4:]
                        required_len = elemlen

                    else:
                        elem = buf[:elemlen]
                        buf = buf[elemlen:]

                        if len(entry) == 1:
                            elem = int(elem)
                        else:
                            elem = elem.decode('utf-8')
                        entry.append(elem)
                        if len(entry) == tuplesize:
                            if tuplesize == 3:
                                entry.append(
                                    linecache.getline(entry[0], entry[1]))

                            stack.append(tuple(entry))
                            entry = []
                            if len(stack) == stacklen:
                                stack_queue.put_nowait(list(reversed(stack)))
                                stack = []
                                stacklen = -1
                                tuplesize = 0

                        elemlen = -1
                        required_len = 4

        if not debugger_thread.is_alive():
            # The debugger thread has stopped.
            break

        if dbgproc_stop.is_set():
            # We were asked to stop by the traced process.
            break


def _debugger_thread(main_pid, dbgproc_started, dbgthread_stop,
                     stack_request_pipe, stack_queue,
                     syscall_queue, syscall_filter, error_queue):
    try:
        _debugger_thread_inner(main_pid, dbgproc_started, dbgthread_stop,
                               stack_request_pipe, stack_queue, syscall_queue,
                               syscall_filter)
    except Exception:
        logger.debug('Unhandled exception in ptrace process', exc_info=True)
        err = PtracerError('Unhandled exception in ptrace process',
                           orig_exc=traceback.format_exc())
        error_queue.put_nowait(err)


def _debugger_thread_inner(main_pid, dbgproc_started, dbgthread_stop,
                           stack_request_pipe, stack_queue,
                           syscall_queue, syscall_filter):
    ptrace_options = ptrace.PTRACE_O_TRACECLONE
    # Attach to the tracee and wait for it to stop.
    ptrace.attach_and_wait(main_pid, ptrace_options)

    if syscall_filter is not None:
        filter_ = lambda sc: any(m.match(sc) for m in syscall_filter)
    else:
        filter_ = None

    syscall_trap = signal.SIGTRAP | 0x80
    enabled = False
    signum = 0
    syscall_state = {}
    sigstop_received = set()

    processes = {main_pid}
    mem_fds = {}
    mem_fds[main_pid] = _open_procmem(main_pid)

    # Notify the parent that we are ready to start tracing.
    dbgproc_started.set()

    try:
        # Restart the tracee and enter the tracing loop.
        ptrace.syscall(main_pid)

        while True:
            if dbgthread_stop.is_set():
                break

            pid, status = ptrace.wait(-1)

            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                # Traced thread has died.
                processes.discard(pid)
                mem_fd = mem_fds.get(pid)
                if mem_fd is not None:
                    try:
                        os.close(mem_fd)
                    except IOError:
                        pass
                if not processes:
                    break
                else:
                    continue

            elif os.WIFSTOPPED(status):
                ptrace_event = ptrace.WPTRACEEVENT(status)
                if ptrace_event == ptrace.PTRACE_EVENT_CLONE:
                    # A new thread has been created.
                    new_pid = ptrace.geteventmsg(pid)
                    # See the comment below for the explanation of this check.
                    if new_pid not in sigstop_received:
                        ptrace.wait_for_trace_stop(new_pid)
                        try:
                            ptrace.syscall(new_pid)
                        except OSError as e:
                            if e.errno != errno.ESRCH:
                                # The new thread might have already died.
                                raise
                    else:
                        sigstop_received.discard(new_pid)

                    mem_fds[new_pid] = _open_procmem(new_pid)

                    processes.add(new_pid)
                    ptrace.syscall(pid)
                    continue

                stopsig = os.WSTOPSIG(status)
                if stopsig != syscall_trap:
                    # Signal-delivery-stop.

                    # The special condition below is for cases when we
                    # receive a SIGSTOP for a newly created thread _before_
                    # receiving the PTRACE_EVENT_CLONE event for its parent.
                    # In this case we must not forward the signal, but
                    # must record its receipt so that once we _do_ receive
                    # PTRACE_EVENT_CLONE for the parent, we don't wait for
                    # SIGSTOP in the child again.
                    if (stopsig != signal.SIGSTOP or
                            pid in processes or
                            all(syscall.name != 'clone'
                                for syscall in syscall_state.values()
                                if syscall is not None)):
                        # forward the signal
                        signum = stopsig
                    else:
                        sigstop_received.add(pid)
                else:
                    # Syscall-stop.
                    syscall = syscall_state.get(pid)
                    regs = ptrace.getregs(pid)
                    mem_fd = mem_fds.get(pid)

                    if syscall is None:
                        # Syscall-enter-stop.
                        syscall_state[pid] = ptrace.syscall_enter(
                            pid, regs, mem_fd)
                    else:
                        # Syscall-exit-stop.
                        ptrace.syscall_exit(syscall, regs, mem_fd)

                        if enabled:
                            # Stop tracing once the tracee executes
                            # the magic open() in ptracer.disable().
                            stop_tracing = (
                                syscall.name == 'open' and
                                syscall.args[0].value == b'\x03\x02\x01'
                            ) or (
                                syscall.name == 'openat' and
                                syscall.args[1].value == b'\x03\x02\x01'
                            )

                            if stop_tracing:
                                break
                            elif filter_ is None or filter_(syscall):
                                # Wait for the traceback to arrive.
                                os.write(stack_request_pipe,
                                         struct.pack('!Q', pid))
                                stack = stack_queue.get()
                                if stack is None:
                                    ptrace.cont(pid)
                                    break

                                syscall.traceback = stack
                                syscall_queue.put_nowait(syscall)

                        elif not enabled:
                            # Start tracing once the tracee executes
                            # the magic open() in ptracer.enable().
                            start_tracing = (
                                syscall.name == 'open' and
                                syscall.args[0].value == b'\x01\x02\x03'
                            ) or (
                                syscall.name == 'openat' and
                                syscall.args[1].value == b'\x01\x02\x03'
                            )

                            if start_tracing:
                                enabled = True

                        syscall_state[pid] = None
            else:
                logger.error('unexpected status of traced process %s: %s',
                             pid, status)

            # Continue until next syscall.
            ptrace.syscall(pid, signum)
            signum = 0
    finally:
        for process in processes:
            try:
                ptrace.detach(process)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    pass
                else:
                    raise

        for fd in mem_fds.values():
            try:
                os.close(fd)
            except (OSError, IOError):
                pass


def _open_procmem(pid):
    try:
        mem_fd = os.open('/proc/{}/mem'.format(pid), os.O_RDONLY)
    except IOError as e:
        if e.errno == errno.EACCESS:
            logger.debug('cannot access /proc/{}/mem'.format(pid),
                         exc_info=True)
            return None
        else:
            raise
    else:
        return mem_fd
