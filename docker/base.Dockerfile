# Common tooling base for CTF specialist containers.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_MIRROR=""
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://archive.ubuntu.com/ubuntu|$APT_MIRROR|g; s|http://security.ubuntu.com/ubuntu|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi \
    && sed -i '/backports/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=10 install -y --fix-missing --no-install-recommends \
        bash coreutils file xxd binutils \
        python3 python3-pip python3-venv \
        curl wget netcat-openbsd \
        ca-certificates git unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ctf
# keep the container alive for `docker exec` driven interaction
CMD ["sleep", "infinity"]
