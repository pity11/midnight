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
        ca-certificates git unzip \
    && rm -rf /var/lib/apt/lists/*

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
