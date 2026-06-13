# D(HE)ater

D(HE)ater is the proof-of-concept implementation of the D(HE)at attack ([CVE-2002-20001](
https://nvd.nist.gov/vuln/detail/CVE-2002-20001)). For further information about the attack visit the
[project page](https://dheatattack.com/dheater) or read the [full technical paper](
https://ieeexplore.ieee.org/document/10374117) on [IEEE Access](https://ieeeaccess.ieee.org/).

## Usage

D(HE)ater is a command-line tool. The `--protocol` option and the target `uri` are mandatory:

```shell
# enforce DHE key exchange against a TLS service
dheat --protocol tls example.com:443

# enforce DHE key exchange against an SSH service
dheat --protocol ssh example.com:22
```

Optional arguments:

| Option | Default | Description |
| --- | --- | --- |
| `--timeout` | `5` | socket timeout in seconds |
| `--thread-num` | `1` | number of threads to run |
| `--key-size` | none | key size to enforce |

```shell
# 16 threads, 10 second timeout
dheat --protocol tls --thread-num 16 --timeout 10 example.com:443
```

## Requirements

D(HE)ater requires Python 3.9 or newer and depends on [CryptoLyzer](https://gitlab.com/coroner/cryptolyzer)
to check DHE support and generate the necessary traffic. The dependency is installed automatically with the
methods described below.

## Installation

Install the latest release from PyPI:

```shell
pip install dheater
```

To install the current development version directly from the source repository:

```shell
pip install git+https://gitlab.com/dheatattack/dheater.git
```

## License

The code is available under the terms of Apache License Version 2.0. 
A non-comprehensive, but straightforward description and also the full license text can be found at 
[Choose an open source license](https://choosealicense.com/licenses/apache-2.0/) website.

## Credits

D(HE)ater uses [CryptoLyzer](https://gitlab.com/coroner/cryptolyzer) to check DHE support of TLS/SSH
services and also to generate the traffic necessary to perform D(HE)at attack.
