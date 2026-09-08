# pwn specialist image — MUST build/run as linux/amd64.
# Build: docker build --platform linux/amd64 -t midnight/pwn:latest -f docker/pwn.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i '/backports/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
        bash coreutils file xxd binutils \
        python3 python3-pip python3-venv \
        python3-capstone \
        gcc gdb gdbserver \
        netcat-openbsd socat curl \
        libc6-dbg libc6-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Pwntools and ROPGadget are not packaged by Ubuntu 22.04. Keep this isolated
# from the distro layer and tolerate short-lived package-index interruptions.
RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 60 \
        pwntools ROPGadget

# GEF for a friendlier gdb (used by gdb_tool / IAT)
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)" || true

WORKDIR /ctf
CMD ["sleep", "infinity"]
