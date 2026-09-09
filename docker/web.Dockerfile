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
        curl wget netcat-openbsd nmap jq ffuf \
        sqlmap nikto whatweb \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Fenjing is purpose-built for Jinja2 SSTI challenges and can generate WAF
# bypass payloads or drive a challenge endpoint. Keep it inside the web image so
# benchmark runs remain self-contained after the image has been built.
RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 60 \
        fenjing==0.9.1

# Broad template-engine identification and JWT manipulation cover two common
# Web CTF branches that are distinct from Fenjing's Jinja-focused bypass path.
ARG TINJA_VERSION=1.2.0
ARG TINJA_SHA256=7775dd9df477e67ae4a82b1f5fa238cdc017463520b5d7cbbebe52289098701b
RUN curl -fsSL --retry 5 \
        "https://github.com/Hackmanit/TInjA/releases/download/${TINJA_VERSION}/TInjA_${TINJA_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/tinja.tar.gz \
    && echo "${TINJA_SHA256}  /tmp/tinja.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/tinja.tar.gz -C /usr/local/bin \
    && chmod 0755 /usr/local/bin/tinja \
    && rm /tmp/tinja.tar.gz

ARG JWT_TOOL_VERSION=2.3.0
ARG JWT_TOOL_SHA256=0f8c32aa9f67cea4312e5df81d48f72dc5daf57f3cc0ce09d67db78e23fbe451
RUN curl -fsSL --retry 5 \
        "https://github.com/ticarpi/jwt_tool/archive/refs/tags/v${JWT_TOOL_VERSION}.tar.gz" \
        -o /tmp/jwt_tool.tar.gz \
    && echo "${JWT_TOOL_SHA256}  /tmp/jwt_tool.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/jwt_tool \
    && tar -xzf /tmp/jwt_tool.tar.gz -C /opt/jwt_tool --strip-components=1 \
    && python3 -m pip install --no-cache-dir --retries 10 --timeout 60 \
        termcolor==3.3.0 cprint==1.2.2 pycryptodomex==3.23.0 ratelimit==2.2.1 \
    && printf '%s\n' '#!/bin/sh' 'exec python3 /opt/jwt_tool/jwt_tool.py "$@"' \
        > /usr/local/bin/jwt_tool \
    && chmod 0755 /usr/local/bin/jwt_tool \
    && rm /tmp/jwt_tool.tar.gz

# jwt_tool intentionally exits after creating first-run configuration. Seed it
# at build time so the first competition call performs useful work.
RUN jwt_tool -b \
        eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.invalid \
        >/dev/null 2>&1 || test -f /root/.jwt_tool/jwtconf.ini \
    && sed -i 's/^proxy = .*/proxy = False/' /root/.jwt_tool/jwtconf.ini

WORKDIR /ctf
CMD ["sleep", "infinity"]
