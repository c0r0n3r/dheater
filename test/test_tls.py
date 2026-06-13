# -*- coding: utf-8 -*-

import io
import os
import sys

import unittest
import unittest.mock

from dheater.__main__ import DHEnforcerThreadTLS, main


class TestMain(unittest.TestCase):
    _NO_DHE_SUPPORT_ERROR_PREFIX = (
        'Diffie-Hellman ephemeral (DHE) key exchange (with the given key size) not supported by the server; '
    )

    def _test_runtime_error(self, arguments, error_msg):
        with unittest.mock.patch.object(sys, 'stdout', new_callable=io.StringIO) as stdout, \
                unittest.mock.patch.object(sys, 'argv', ['dheater', ] + arguments):

            main()
            self.assertEqual(stdout.getvalue().split(os.linesep)[0], error_msg)

    @unittest.mock.patch.object(DHEnforcerThreadTLS, '_pre_check', side_effect=NotImplementedError)
    def test_tls_no_dhe_support(self, _pre_check):
        self._test_runtime_error(
            ['--protocol', 'tls', 'cloudflare.com'],
            self._NO_DHE_SUPPORT_ERROR_PREFIX + 'uri="cloudflare.com", protocol="tls"'
        )
