# D(HE)ater

D(HE)ater is an attacking tool based on CPU heating in that it forces the ephemeral variant of
[Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) (DHE) in given
cryptography protocols (e.g. TLS, SSH). It is performed without calculating a cryptographically correct ephemeral key on
the client side, but with a significant amount of calculation on the server side. Based on this,
a [denial-of-service (DoS) attack](https://en.wikipedia.org/wiki/Denial-of-service_attack) attack can be initiated,
called *D(HE)at attack* ([CVE-2002-20001](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-20001)).

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

## Mitigation

### Configuration

Diffie-Hellman (DHE) key exchange should be disabled if no other mitigation mechanism can be used and either 
elliptic-curve variant of Diffie-Hellman (ECDHE) or RSA key exchange is supported by the clients. The fact that RSA key
exchange is not forward secret should be considered.

#### TLS

##### Apache

```
SSLCipherSuite ...:!kDHE
```

##### NGINX

```
ssl_ciphers ...:!kDHE;
```

##### Postfix


1. Diffie-Hellman key exchange algorithms can be removed by setting the [tls_medium_cipherlist](http://www.postfix.org/postconf.5.html#tls_medium_cipherlist) configuration option.

    `tls_medium_cipherlist ...:!kDHE`

1. Maximal number of new TLS sessions that a remote SMTP client is allowed to negotiate can be controlled by configuration option [smtpd_client_new_tls_session_rate_limit](http://www.postfix.org/postconf.5.html#smtpd_client_new_tls_session_rate_limit) configuration option.

    `smtpd_client_new_tls_session_rate_limit 100`

##### Others

See [moz://a SSL Configuration Generator](https://ssl-config.mozilla.org/) for configuration syntax.

### SSH

##### OpenSSH

1. Diffie-Hellman key exchange algorithms can be removed by setting the [KexAlgorithms](https://man.openbsd.org/sshd_config#KexAlgorithms) configuration option.

    `KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group1-sha256,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group15-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha256,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha512`
1. Maximum number of concurrent unauthenticated connections can be controlled by configuration option [MaxStartups](https://man.openbsd.org/sshd_config#MaxStartups) configuration option.

    `MaxStartups 10:30:100`

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
