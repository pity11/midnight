# crypto specialist image (native arm64 is fine).
# Build: docker build -t midnight/crypto:latest -f docker/crypto.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils file \
        python3 python3-pip python3-venv \
        libgmp-dev libmpfr-dev libmpc-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir pycryptodome sympy gmpy2

# NOTE: SageMath is heavy; add a dedicated sage image if a challenge needs it.

WORKDIR /ctf
CMD ["sleep", "infinity"]
