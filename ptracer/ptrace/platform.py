import ctypes
import sys


PLATFORM = None
WORD_SIZE = ctypes.sizeof(ctypes.c_void_p)
BITS = WORD_SIZE * 8

if sys.platform.startswith('linux'):
    PLATFORM = 'linux'

if PLATFORM is None or BITS != 64:
    raise RuntimeError('unsupported platform: {} ({} bit)'.format(
        sys.platform, BITS))
