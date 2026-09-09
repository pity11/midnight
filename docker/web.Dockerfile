# web specialist image (linux/amd64 for the uniform benchmark runtime).
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
        curl wget netcat-openbsd nmap jq \
        sqlmap nikto whatweb \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Fenjing is purpose-built for Jinja2 SSTI challenges and can generate WAF
# bypass payloads or drive a challenge endpoint. Keep it inside the web image so
# benchmark runs remain self-contained after the image has been built.
RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 60 \
        fenjing==0.9.1

WORKDIR /ctf
CMD ["sleep", "infinity"]
