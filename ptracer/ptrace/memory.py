# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import ctypes
import os
import struct

from . import defs
from . import ptrace


_CONTAINER_TYPES = (ctypes.Array, ctypes.Structure, ctypes.Union)


def _ptrace_read_word(pid, address):
    word = ptrace.peektext(pid, address)
    return struct.pack('q', word)


def ptrace_read(pid, address, bytecount):
    # PTRACE_PEEK reads must be aligned on the word boundary.
    lpad = address % defs.WORD_SIZE
    rpad = (bytecount + lpad) % defs.WORD_SIZE
    if rpad:
        rpad = defs.WORD_SIZE - rpad

    data = bytearray(bytecount)
    offset = 0

    if lpad:
        word = _ptrace_read_word(pid, address - lpad)
        chunk = word[lpad:]
        chunk_len = len(chunk)
        data[offset:offset + chunk_len] = word[lpad:]
        offset += chunk_len
        bytecount -= chunk_len

    wordcount = (bytecount + rpad) // defs.WORD_SIZE
    for _ in range(wordcount - 1):
        word = _ptrace_read_word(pid, address + offset)
        data[offset:offset + defs.WORD_SIZE] = word
        offset += defs.WORD_SIZE

    if wordcount:
        word = _ptrace_read_word(pid, address - lpad)
        if rpad:
            data[offset:offset + defs.WORD_SIZE - rpad] = word[:-rpad]
        else:
            data[offset:offset + defs.WORD_SIZE] = word

    return data


def procmem_read(fd, address, bytecount):
    os.lseek(fd, address, os.SEEK_SET)
    return bytearray(os.read(fd, bytecount))


def read_c_type_ptr(pid, address, c_type, indirection=1, mem_fd=None):
    if indirection > 1:
        address = read_c_type_ptr(pid, address, ctypes.c_void_p,
                                  indirection - 1)

    if issubclass(c_type, ctypes.c_char):
        if mem_fd is not None:
            try:
                return procmem_read_c_string(mem_fd, address)
            except IOError:
                return ptrace_read_c_string(pid, address)
        else:
            return ptrace_read_c_string(pid, address)
    else:
        bytecount = ctypes.sizeof(c_type)
        if mem_fd is not None:
            try:
                data = procmem_read(mem_fd, address, bytecount)
            except IOError:
                data = ptrace_read(pid, address, bytecount)
        else:
            data = ptrace_read(pid, address, bytecount)

        c_value = c_type.from_buffer(data)

        if not issubclass(c_type, _CONTAINER_TYPES):
            value = c_value.value
        elif issubclass(c_type, ctypes.Array):
            value = tuple(c_value)
        else:
            value = c_value

        return value


def ptrace_read_c_string(pid, address, max_size=1024):
    # PTRACE_PEEK reads must be aligned on the word boundary.
    bytecount = max_size
    lpad = address % defs.WORD_SIZE
    rpad = (bytecount + lpad) % defs.WORD_SIZE
    if rpad:
        bytecount += defs.WORD_SIZE - rpad

    data = bytearray(bytecount)
    offset = 0

    if lpad:
        word = _ptrace_read_word(pid, address - lpad)
        chunk = word[lpad:]
        nulpos = chunk.find(b'\x00')
        if nulpos != -1:
            return chunk[:nulpos]

        chunk_len = len(chunk)
        data[offset:offset + chunk_len] = word[lpad:]
        offset += chunk_len
        bytecount -= chunk_len

    wordcount = (bytecount + rpad) // defs.WORD_SIZE
    for _ in range(wordcount):
        word = _ptrace_read_word(pid, address + offset)
        nulpos = word.find(b'\x00')
        if nulpos != -1:
            data[offset:offset + nulpos] = word[:nulpos]
            return bytes(data[:offset + nulpos])
        else:
            chunk_len = defs.WORD_SIZE

        data[offset:offset + defs.WORD_SIZE] = word
        offset += defs.WORD_SIZE

    return bytes(data)


def procmem_read_c_string(fd, address, max_size=1024):
    data = procmem_read(fd, address, max_size)
    nulpos = data.find(b'\x00')
    if nulpos != -1:
        return data[:nulpos]
    else:
        return data
