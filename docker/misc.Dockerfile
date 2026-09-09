# misc / forensics / stego image (linux/amd64 for the benchmark runtime).
# Build: docker build -t midnight/misc:latest -f docker/misc.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_MIRROR=""
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://archive.ubuntu.com/ubuntu|$APT_MIRROR|g; s|http://security.ubuntu.com/ubuntu|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi \
    && sed -i '/backports/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=10 install -y --fix-missing --no-install-recommends \
        bash coreutils file xxd \
        python3 python3-pip python3-venv \
        python3-pil ruby \
        binwalk foremost exiftool steghide yara \
        imagemagick tesseract-ocr ffmpeg sox \
        p7zip-full unzip john fcrackzip crunch \
        zlib1g-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Pickora compiles small Python-like expressions to pickle bytecode and is
# useful for restricted-unpickler CTFs. Pin the published package for repeatable
# offline runs; pickletools itself remains the validation/disassembly oracle.
RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 60 pickora==1.0.0

# zsteg covers the common PNG/BMP LSB paths and can extract a selected channel
# directly. Version pinning keeps forensic results comparable across runs.
RUN gem install zsteg -v 0.2.14 --no-document

COPY resources/wordlists/ctf-small.txt /opt/midnight/wordlists/ctf-small.txt

# NOTE: volatility and large password dictionaries remain opt-in packs.

WORKDIR /ctf
CMD ["sleep", "infinity"]
