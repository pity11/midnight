# crypto specialist image (native arm64 is fine).
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
        bash coreutils file \
        python3 python3-pip python3-venv \
        python3-pycryptodome python3-sympy python3-gmpy2 \
        libgmp-dev libmpfr-dev libmpc-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Debian installs the collision-free Cryptodome namespace. CTF sources commonly
# use PyCryptodome's Crypto namespace, so expose the same packaged modules there.
RUN ln -s /usr/lib/python3/dist-packages/Cryptodome \
        /usr/lib/python3/dist-packages/Crypto

# NOTE: SageMath is heavy; add a dedicated sage image if a challenge needs it.

WORKDIR /ctf
CMD ["sleep", "infinity"]
