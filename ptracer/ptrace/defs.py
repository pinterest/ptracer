# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


from . import platform
from .platform import *  # noqa


if platform.PLATFORM == 'linux':
    from ._defs_linux import *  # noqa
