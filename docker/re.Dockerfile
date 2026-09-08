# reverse engineering specialist image (amd64 for best tool compatibility).
# Build: docker build -t midnight/re:latest -f docker/re.Dockerfile .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
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
