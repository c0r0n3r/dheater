# -*- coding: utf-8 -*-

import io
import os
import sys

import unittest

from dheater.__main__ import main


class TestMain(unittest.TestCase):
    _NO_DHE_SUPPORT_ERROR_PREFIX = 'Diffie-Hellman ephemeral (DHE) key exchange not supported by the server; '

    def _test_runtime_error(self, arguments, error_msg):
        with unittest.mock.patch.object(sys, 'stdout', new_callable=io.StringIO) as stdout, \
                unittest.mock.patch.object(sys, 'argv', ['dheater', ] + arguments):

            main()
            self.assertEqual(stdout.getvalue().split(os.linesep)[0], error_msg)

    def test_tls_no_dhe_support(self):

        self._test_runtime_error(
            ['--protocol', 'tls', 'ecc256.badssl.com'],
            self._NO_DHE_SUPPORT_ERROR_PREFIX + 'uri="ecc256.badssl.com", protocol="tls"'
        )
