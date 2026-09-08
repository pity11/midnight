# pwn specialist image — MUST build/run as linux/amd64.
# Build: docker build --platform linux/amd64 -t midnight/pwn:latest -f docker/pwn.Dockerfile .
FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils file xxd binutils \
        python3 python3-pip python3-venv \
        gcc gdb gdbserver \
        netcat-openbsd socat curl \
        libc6-dbg libc6-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir pwntools ROPGadget capstone

# GEF for a friendlier gdb (used by gdb_tool / IAT)
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)" || true

WORKDIR /ctf
CMD ["sleep", "infinity"]
