# web specialist image (native arm64 is fine).
# Build: docker build -t midnight/web:latest -f docker/web.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils file \
        python3 python3-pip python3-venv \
        python3-requests python3-httpx python3-bs4 \
        curl wget netcat-openbsd \
        sqlmap \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ctf
CMD ["sleep", "infinity"]
