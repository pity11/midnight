# web specialist image (native arm64 is fine).
# Build: docker build -t midnight/web:latest -f docker/web.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_MIRROR=""
RUN if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|http://archive.ubuntu.com/ubuntu|$APT_MIRROR|g; s|http://security.ubuntu.com/ubuntu|$APT_MIRROR|g" /etc/apt/sources.list; \
    fi \
    && sed -i '/backports/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=10 install -y --fix-missing --no-install-recommends \
        bash coreutils file \
        python3 python3-pip python3-venv \
        python3-requests python3-httpx python3-bs4 \
        curl wget netcat-openbsd \
        sqlmap \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ctf
CMD ["sleep", "infinity"]
