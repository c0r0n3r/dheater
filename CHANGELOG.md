# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-06-13

### Changed

- Migrated packaging from `setup.py` to `pyproject.toml` (PEP 621).
- Followed CryptoLyzer changes up to its version 1.0.0.
- Raised the minimum supported Python version to 3.9.

## [0.4.3] - 2023-12-28

### Changed

- Followed CryptoLyzer changes up to its version 0.12.1.

## [0.4.2] - 2023-11-14

### Changed

- Followed CryptoLyzer changes up to its version 0.11.0.

## [0.4.1] - 2023-10-02

### Changed

- Followed CryptoLyzer changes up to its version 0.10.0.

## [0.4.0] - 2023-05-04

### Added

- `--key-size` parameter to enforce a specific key size (#13).
- `dh_param_priv_key_size_setter` tool to set the suggested private key size in DH parameter files.
- Well-known DH parameter files, with and without an OpenSSL-specific private key size.

### Changed

- Updated to work with the latest cryptoparser version (#15).

## [0.3.2] - 2022-02-03

### Changed

- Followed CryptoLyzer changes up to its version 0.8.0 (#10).

### Fixed

- Added a workaround for wrong dependency requirements (#11).

## [0.3.1] - 2022-02-02

### Fixed

- Removed an undefined name on the TLS 1.3 precheck path (#9).

## [0.3.0] - 2022-01-28

### Added

- TLS 1.3 support (#7).
- Protocol version printed as part of the precheck result (#7).

### Fixed

- Did not use the given timeout value during the precheck to avoid failures.

## [0.2.5] - 2021-12-06

### Added

- Float timeout values, so values below one second are possible.

### Changed

- Waited for the server message confirming the DH public key has been calculated (#6).
- Used a supported TLS version in the client hello instead of a hard-coded one.

## [0.2.4] - 2021-11-22

### Added

- Version number to the output.
- Key size and algorithm name to the summary.

### Changed

- Used the official software name and version in the SSH protocol message.

### Removed

- Statistics from the output, as they can be inaccurate.

### Fixed

- Handled the case when the server does not support DHE in TLS.
- Ensured waiting for the server-side computation to finish in SSH.

## [0.2.3] - 2021-11-13

### Changed

- Re-added the minimal signature algorithms extension in TLS.

## [0.2.2] - 2021-11-12

### Changed

- Sent only one cipher suite in TLS and one algorithm in SSH instead of all known ones.
- Stopped sending the signature algorithms extension in TLS.

### Fixed

- Handled the case when only key exchange or only group exchange is supported by the server (#2).
- Waited for key generation to start on the server side.
- Separated thread stopping and joining to make shutdown faster.

## [0.2.1] - 2021-10-07

### Fixed

- Handled network errors during the precheck.

## [0.2.0] - 2021-10-07

### Added

- SSH key exchange support.
- SSH group exchange support.
- TLS precheck deciding whether the server supports DHE key exchange.

## [0.1.0] - 2021-10-06

### Added

- Initial release: proof-of-concept implementation of the D(HE)at attack (CVE-2002-20001).
- Statistics at the end of the heating run.
