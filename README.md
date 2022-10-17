# D(HE)ater

D(HE)ater is an attacking tool based on CPU heating in that it forces the ephemeral variant of
[Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) (DHE) in given
cryptography protocols (e.g. TLS, SSH). It is performed without calculating a cryptographically correct ephemeral key on
the client-side, but with a significant amount of calculation on the server-side. Based on this,
a [denial-of-service (DoS) attack](https://en.wikipedia.org/wiki/Denial-of-service_attack) can be initiated,
called [D(HE)at attack](https://dheatattack.com)
([CVE-2002-20001](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-20001)).

## Quick start

D(HE)ater can be installed directly via [pip](https://pip.pypa.io/en/stable/) from
[PyPi](https://pypi.org/project/dheater/)

```console
pip install dheater
dheat --protocol tls ecc256.badssl.com
dheat --protocol ssh ecc256.badssl.com
```

or can be used via [Docker](https://www.docker.com/) from
[Docker Hub](https://hub.docker.com/repository/docker/balasys/dheater)

```console
docker pull balasys/dheater
docker run --tty --rm balasys/dheater --protocol tls ecc256.badssl.com
docker run --tty --rm balasys/dheater --protocol ssh ecc256.badssl.com
```

You can increase load by string extra threads.

```console
dheat --thread-num 4 --protocol tls ecc256.badssl.com
docker run --tty --rm balasys/dheater --thread-num 4 --protocol tls ecc256.badssl.com
docker run --tty --rm balasys/dheater --thread-num 4 --protocol ssh ecc256.badssl.com
```

## Check

Without attacking a server or accessing its configuration it is still possible
to determine whether Diffie-Hellman (DH) key exchange is enabled and if so what
DH parameters (prime, genrator, key size) are used.  Command line tools such as
[CryptoLyzer](https://gitlab.com/coroner/cryptolyzer) (TLS, SSH KEX/GEX),
[testssl.sh](https://testssl.sh) (TLS only), or
[ssh-audit](https://github.com/jtesta/ssh-audit) (SSH KEX only) can do that work.

### TLS

```
cryptolyze tls1_2 dhparams example.com
cryptolyze tls1_3 dhparams example.com

testssl.sh --fs example.com
```

### SSH

```
cryptolyze ssh2 dhparams example.com

ssh-audit example.com
```

## Mitigation

### Configuration

Diffie-Hellman (DHE) key exchange should be disabled if no other mitigation mechanism can be used and either 
elliptic-curve variant of Diffie-Hellman (ECDHE) or RSA key exchange is supported by the clients. The fact that RSA key
exchange is not forward secret should be considered.

#### TLS

Elliptic-curve (named group) setting is necessary only if the underlying cryptographic library supports negotiation
Diffie-Hellman groups by implementing [RFC7919](https://www.rfc-editor.org/info/rfc7919) in TLS 1.2 or supporting the
[Finite Field Diffie-Hellman parameter groups](https://www.rfc-editor.org/rfc/rfc8446#section-7.4.1) named groups in
TLS 1.3.

| Library | Version | FFDHE goups<br>in TLS 1.2 | FFDHE groups<br>in TLS 1.3 |
| ------- |:-------:|:---:|:---:|
| OpenSSL | < 3.0   | no  | no  |
| OpenSSL | ≥ 3.0   | no  | yes |
| GnuTLS  | ≥ 3.5.6 | yes | no  |
| GnuTLS  | ≥ 3.6.3 | yes | yes |

##### Apache

```
SSLCipherSuite ...:!kDHE
SSLOpenSSLConfCmd Groups x25519:secp256r1:x448:secp521r1:secp384r1
```

##### NGINX

```
ssl_ciphers ...:!kDHE;
ssl_ecdh_curve x25519:secp256r1:x448:secp521r1:secp384r1;
```

##### Postfix


1. Diffie-Hellman key exchange algorithms can be removed by setting the [tls_medium_cipherlist](http://www.postfix.org/postconf.5.html#tls_medium_cipherlist) configuration option.

    `tls_medium_cipherlist ...:!kDHE`

1. Maximal number of new TLS sessions that a remote SMTP client is allowed to negotiate can be controlled by configuration option [smtpd_client_new_tls_session_rate_limit](http://www.postfix.org/postconf.5.html#smtpd_client_new_tls_session_rate_limit) configuration option.

    `smtpd_client_new_tls_session_rate_limit 100`

##### Others

See [moz://a SSL Configuration Generator](https://ssl-config.mozilla.org/) for configuration syntax.

##### DH parameter files

If DH key exchange need to be supported recommended private key length value
should be set to ensure the best performance of DH key exchange this option
value should be set appropriately to achieve the best performance without a
security risk.

You can check whether you DH parameter file contains the recommended private
key value by the following command:

```
tools/dh_param_priv_key_size_setter /path/to/dh/parameter/file.pem
```

The result looks like the following. If the original private key size is
`None` it some cryptographic libraries use the public size for private key
size unless the application server overrides this behaviour. This will cause
much lower performance than small private keys would be used.

```
Original private key size: None
Set private key size: None
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----

```

To set the recommended private key size in a DH parameter file use the
following commmand:

```
tools/dh_param_priv_key_size_setter --private-key-size KEY_SIZE /path/to/dh/parameter/file.pem
```

For appropriately private key sizes see Table 2 of
[NIST SP 800-57 Part 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf).
Alternatively you can download the well-know DH parameters where the recommended
private key size is set according to OpenSSL default values from
[data](https://github.com/Balasys/dheater/tree/master/data) directory.

### SSH

##### OpenSSH

1. Diffie-Hellman key exchange algorithms can be removed by setting the [KexAlgorithms](https://man.openbsd.org/sshd_config#KexAlgorithms) configuration option.

    `KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group1-sha256,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group15-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha256,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha512`
1. Maximum number of concurrent unauthenticated connections can be controlled by some configuration options
    *  [MaxStartups](https://man.openbsd.org/sshd_config#MaxStartups) (globally)

        `MaxStartups 10:30:100`
    * [PerSourceMaxStartups](https://man.openbsd.org/sshd_config#PerSourceMaxStartups) (per source IP subnetworks)

        `PerSourceMaxStartups 1`
    * [PerSourceNetBlockSize](https://man.openbsd.org/sshd_config#PerSourceNetBlockSize) (size of the subnetworks grouped together)

        `PerSourceNetBlockSize 32:128`

### Fail2Ban

#### TLS

##### Apache

There are no relevant filters.

1. `apache-ssl.conf` in `fail2ban` directory should be copied to the `filter.d` directory under the fail2ban configuration
    directory
1. the followings should be added to the `jail.local` file in the fail2ban configuration directory

    ```ini
    [apache-ssl]

    port    = https
    logpath = %(apache_error_log)s
    maxretry = 1
    ```

##### Postfix

There is a relevant filter, but it is applied only in ddos mode. The followings should be added to `jail.local`.

```ini
[postfix]
mode = ddos
```

##### Dovecot

There is a relevant filter, but it is applied only in ddos mode. The followings should be added to `jail.local`.

```ini
[dovecot]
mode = aggressive
```

or a specific filter can be used without changing the mode of dovecot.

1. `dovecot-ssl.conf` in `fail2ban` directory should be copied to the `filter.d` directory under the fail2ban configuration
    directory
1. the followings should be added to `jail.local` in tge fail2ban configuration directory

    ```ini
    [dovecot-ssl]

    port    = pop3,pop3s,imap,imaps,submission,465,sieve
    logpath = %(dovecot_log)s
    backend = %(dovecot_backend)s
    maxretry = 1
    ```

#### SSH

##### OpenSSH

There is a relevant filter, but it is applied only in ddos mode. The followings should be added to `jail.local`.

```ini
[sshd]
mode = ddos
```

## License

The code is available under the terms of Apache License Version 2.0. 
A non-comprehensive, but straightforward description and also the full license text can be found at 
[Choose an open source license](https://choosealicense.com/licenses/apache-2.0/) website.
