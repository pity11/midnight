# reverse engineering specialist image (amd64 for best tool compatibility).
# Build: docker build -t midnight/re:latest -f docker/re.Dockerfile .
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
        python3-capstone python3-pyelftools \
        gdb gcc libc6-dev binwalk curl \
        ca-certificates git unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

# A standard packer should not consume a reverse-engineering budget. Pin and
# verify the official static UPX binary so offline challenge containers have it.
ARG UPX_VERSION=4.2.4
ARG UPX_SHA256=75cab4e57ab72fb4585ee45ff36388d280c7afd72aa03e8d4b9c3cbddb474193
RUN curl -fsSL --retry 5 \
        "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" \
        -o /tmp/upx.tar.xz \
    && echo "${UPX_SHA256}  /tmp/upx.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/upx.tar.xz -C /tmp \
    && install -m 0755 "/tmp/upx-${UPX_VERSION}-amd64_linux/upx" /usr/local/bin/upx \
    && rm -rf /tmp/upx*

# radare2 is not in Ubuntu repos and building from source is heavy/fragile in
# CI. It is OPTIONAL: r2_interact degrades gracefully when r2 is absent. To add
# it, uncomment below (needs ~5 min and the acr build deps):
# RUN apt-get update && apt-get install -y --no-install-recommends \
#         make pkg-config patch gawk \
#     && git clone --depth 1 https://github.com/radareorg/radare2 /opt/radare2 \
#     && /opt/radare2/sys/install.sh --install \
#     && rm -rf /opt/radare2/.git /var/lib/apt/lists/*

# NOTE: ghidra headless is large; install on demand if a challenge needs it.

WORKDIR /ctf
CMD ["sleep", "infinity"]
