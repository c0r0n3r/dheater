FROM python:3.9-slim

LABEL maintainer Szilárd Pfeiffer "szilard.pfeiffer@balasys.hu"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ADD . /usr/src/dheater

RUN pip3 install --no-cache-dir /usr/src/dheater

USER nobody

ENTRYPOINT ["dheat"]
CMD ["--help"]
