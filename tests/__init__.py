# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import unittest


def suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('.', pattern='test_*.py')
    return test_suite
