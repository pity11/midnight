# disk, memory, image and document forensics sandbox (linux/amd64).
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
        python3 python3-pip python3-venv python3-pil \
        ruby binwalk foremost exiftool steghide yara \
        sleuthkit testdisk xfsprogs tshark tcpdump \
        imagemagick tesseract-ocr ffmpeg sox \
        p7zip-full unzip tar gzip bzip2 xz-utils john fcrackzip crunch \
        ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 120 \
        volatility3==2.28.0 python-evtx==0.8.1
RUN gem install zsteg -v 0.2.14 --no-document

COPY resources/wordlists/ctf-small.txt /opt/midnight/wordlists/ctf-small.txt

# Hayabusa ships its Sigma rules and profiles with the binary. Keep that bundle
# intact under /opt and expose a wrapper that always runs from the expected cwd.
ARG HAYABUSA_VERSION=4.0.0
ARG HAYABUSA_SHA256=04d4daf91ad0cc576654e985315f15e412a3ad460f2702f2a9dde3fbd1104a8b
RUN curl -fsSL --retry 5 \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip" \
        -o /tmp/hayabusa.zip \
    && echo "${HAYABUSA_SHA256}  /tmp/hayabusa.zip" | sha256sum -c - \
    && mkdir -p /opt/hayabusa \
    && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
    && mv "/opt/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl" /opt/hayabusa/hayabusa.bin \
    && chmod 0755 /opt/hayabusa/hayabusa.bin \
    && printf '%s\n' '#!/bin/sh' 'cd /opt/hayabusa || exit 1' 'exec ./hayabusa.bin "$@"' \
        > /usr/local/bin/hayabusa \
    && chmod 0755 /usr/local/bin/hayabusa \
    && rm /tmp/hayabusa.zip

WORKDIR /ctf
CMD ["sleep", "infinity"]
