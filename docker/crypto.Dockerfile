# crypto specialist image (linux/amd64 for the uniform benchmark runtime).
# Build: docker build -t midnight/crypto:latest -f docker/crypto.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_MIRROR=""
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://archive.ubuntu.com/ubuntu|$APT_MIRROR|g; s|http://security.ubuntu.com/ubuntu|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi \
    && sed -i '/backports/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=10 install -y --fix-missing --no-install-recommends \
        bash coreutils file openssl \
        python3 python3-pip python3-venv \
        python3-pycryptodome python3-sympy python3-gmpy2 python3-z3 python3-fpylll \
        libgmp-dev libmpfr-dev libmpc-dev libfplll-dev \
        ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# Debian installs the collision-free Cryptodome namespace. CTF sources commonly
# use PyCryptodome's Crypto namespace, so expose the same packaged modules there.
RUN ln -s /usr/lib/python3/dist-packages/Cryptodome \
        /usr/lib/python3/dist-packages/Crypto

# Fast repeating-key XOR analysis. More specialized suites (RsaCtfTool/Sage)
# remain separate because their full dependency closure is substantially larger.
RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 60 \
        xortool==1.1.0

# Pin RsaCtfTool by immutable commit because upstream does not publish regular
# releases. Install current compatible dependencies without its obsolete exact
# HTTP-library pins; network-backed attacks remain disabled by the evaluator.
ARG RSACTFTOOL_COMMIT=af87bb487666b1bf3070e1bb058d97b78a342808
ARG RSACTFTOOL_SHA256=c68e39b50c7b699bbffb54849cb2f67d927fab01da8f22547a887da2c28effd9
RUN curl -fsSL --retry 5 \
        "https://github.com/RsaCtfTool/RsaCtfTool/archive/${RSACTFTOOL_COMMIT}.tar.gz" \
        -o /tmp/rsactftool.tar.gz \
    && echo "${RSACTFTOOL_SHA256}  /tmp/rsactftool.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/rsactftool \
    && tar -xzf /tmp/rsactftool.tar.gz -C /opt/rsactftool --strip-components=1 \
    && python3 -m pip install --no-cache-dir --retries 10 --timeout 120 \
        six==1.17.0 cryptography==46.0.3 urllib3==2.6.3 requests==2.32.5 \
        gmpy2==2.2.1 tqdm==4.70.0 bitarray==3.11.0 psutil==7.2.2 factordb-pycli==1.3.0 \
    && printf '%s\n' '#!/bin/sh' \
        'PYTHONPATH=/opt/rsactftool/src exec python3 /opt/rsactftool/src/RsaCtfTool/main.py "$@"' \
        > /usr/local/bin/RsaCtfTool \
    && chmod 0755 /usr/local/bin/RsaCtfTool \
    && rm /tmp/rsactftool.tar.gz

# NOTE: SageMath remains a separate optional image because its size would slow
# every competition-machine rebuild and most RSA tasks do not require it.

WORKDIR /ctf
CMD ["sleep", "infinity"]
