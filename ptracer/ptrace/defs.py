from . import platform
from .platform import *  # noqa


if platform.PLATFORM == 'linux':
    from ._defs_linux import *  # noqa
