# pwn specialist image — MUST build/run as linux/amd64.
# Build: docker build --platform linux/amd64 -t midnight/pwn:latest -f docker/pwn.Dockerfile .
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
        python3-capstone \
        gcc g++ gcc-multilib g++-multilib gdb gdbserver make patchelf nasm qemu-user ruby ruby-dev \
        libc6-i386 libc6-dev-i386 ltrace strace \
        netcat-openbsd socat curl \
        libc6-dbg libc6-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Pwntools and ROPGadget are not packaged by Ubuntu 22.04. Keep this isolated
# from the distro layer and tolerate short-lived package-index interruptions.
RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 120 \
        pwntools ROPGadget ropper angr unicorn keystone-engine==0.9.2

# Repetitive libc setup and one-gadget discovery should be deterministic tool
# calls rather than consume model turns. pwninit's release binary is checksum
# pinned; one_gadget 1.9.0 is the newest release compatible with Ubuntu 22.04's
# Ruby 3.0 (later releases require Ruby 3.1 or 3.3).
ARG PWNINIT_VERSION=3.3.3
ARG PWNINIT_SHA256=f124b6645b01b0fc4adacabe61438fe73eef517dc3e4696a08e1250a8f47eec3
RUN curl -fsSL --retry 5 \
        "https://github.com/io12/pwninit/releases/download/${PWNINIT_VERSION}/pwninit" \
        -o /tmp/pwninit \
    && echo "${PWNINIT_SHA256}  /tmp/pwninit" | sha256sum -c - \
    && install -m 0755 /tmp/pwninit /usr/local/bin/pwninit \
    && rm /tmp/pwninit \
    && gem install one_gadget -v 1.9.0 --no-document \
    && gem install seccomp-tools -v 1.6.0 --no-document

# GEF for a friendlier gdb (used by gdb_tool / IAT)
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)" || true

WORKDIR /ctf
CMD ["sleep", "infinity"]
