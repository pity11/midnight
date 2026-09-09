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
        ruby binwalk foremost exiftool steghide \
        sleuthkit testdisk xfsprogs \
        imagemagick tesseract-ocr ffmpeg sox \
        p7zip-full unzip tar gzip bzip2 xz-utils \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 120 \
        volatility3==2.28.0
RUN gem install zsteg -v 0.2.14 --no-document

WORKDIR /ctf
CMD ["sleep", "infinity"]
