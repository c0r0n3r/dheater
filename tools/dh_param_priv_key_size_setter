#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DH parameter file recommended private length value getter/setter
"""

import argparse
import sys

import asn1crypto.algos
import asn1crypto.pem


def get_agruments():
    parser = argparse.ArgumentParser(description='Diffie-Hellman parameter private key size setter')
    parser.add_argument(
        '--private-key-size', dest='key_size', default=0, type=int,
        help='suggested private key size in bits (default: %(default)s bit)'
    )
    parser.add_argument(
        metavar='DHParamFile', dest='dh_param_file_path', type=str,
        help='Path tp the DH parameter file'
    )

    return parser.parse_args()


def main():
    dh_param = None
    args = get_agruments()

    with open(args.dh_param_file_path, 'rb') as dh_param_file:
        dh_param_data = dh_param_file.read()
        if asn1crypto.pem.detect(dh_param_data):
            _, _, dh_param_data = asn1crypto.pem.unarmor(dh_param_data)

        try:
            dh_param = asn1crypto.algos.DHParameters.load(dh_param_data)
        except ValueError:
            pass

    private_value_length = dh_param['private_value_length'].native
    print(f'Original private key size: {private_value_length}', file=sys.stderr)

    if args.key_size == 0:
        del dh_param['private_value_length']
    else:
        dh_param['private_value_length'] = args.key_size

    private_value_length = dh_param['private_value_length'].native
    print(f'Set private key size: {private_value_length}', file=sys.stderr)

    print(asn1crypto.pem.armor('DH PARAMETERS', dh_param.dump()).decode('ascii'))


if __name__ == '__main__':
    main()
