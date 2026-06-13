FROM python:3.13-slim

LABEL maintainer="Szilárd Pfeiffer <coroner@pfeifferszilard.hu>"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ADD . /usr/src/dheater

RUN pip3 install --no-cache-dir /usr/src/dheater

USER nobody

ENTRYPOINT ["dheat"]
CMD ["--help"]
