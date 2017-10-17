# Copyright (C) 2017-present Pinterest Inc.
#
# This module is part of ptracer and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import linecache
import os
import struct
import unittest

import ptracer._lltraceback


class TestLLTraceback(unittest.TestCase):
    def test_lltraceback(self):
        control_read, control_write = os.pipe()
        output_read, output_write = os.pipe()

        thread_id = ptracer._lltraceback.gettid()
        ptracer._lltraceback.start_thread(control_read, output_write)
        os.write(control_write, struct.pack('!Q', thread_id))

        stack_depth = struct.unpack('!L', os.read(output_read, 4))[0]
        tuple_length = struct.unpack('!L', os.read(output_read, 4))[0]

        stack = []

        for i in range(stack_depth):
            entry = []
            for j in range(tuple_length):
                item_len = struct.unpack('!L', os.read(output_read, 4))[0]
                item_data = os.read(output_read, item_len)
                if j == 1:
                    lineno = int(item_data)
                    entry.append(lineno)
                else:
                    entry.append(item_data.decode('utf8'))

            if len(entry) < 4:
                entry.append(linecache.getline(entry[0], entry[1]))

            stack.append(entry)

        ptracer._lltraceback.stop_thread()

        self.assertGreater(len(stack), 0)
