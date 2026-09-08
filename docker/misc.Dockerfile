# misc / forensics / stego specialist image (native arm64 is fine).
# Build: docker build -t midnight/misc:latest -f docker/misc.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i '/backports/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
        bash coreutils file xxd \
        python3 python3-pip python3-venv \
        python3-pil \
        binwalk foremost exiftool steghide \
        zlib1g-dev \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# NOTE: volatility / zsteg add on demand for specific forensics challenges.

WORKDIR /ctf
CMD ["sleep", "infinity"]
