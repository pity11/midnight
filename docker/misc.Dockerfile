# misc / forensics / stego specialist image (native arm64 is fine).
# Build: docker build -t midnight/misc:latest -f docker/misc.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils file xxd \
        python3 python3-pip python3-venv \
        binwalk foremost exiftool steghide \
        zlib1g-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir pillow

# NOTE: volatility / zsteg add on demand for specific forensics challenges.

WORKDIR /ctf
CMD ["sleep", "infinity"]
