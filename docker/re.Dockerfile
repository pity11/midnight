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
        gdb gcc libc6-dev binwalk curl ltrace strace \
        default-jre-headless apktool \
        ca-certificates git unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Official release package: self-contained apart from glibc.
ARG RADARE2_VERSION=6.2.2
ARG RADARE2_SHA256=09234e4139bf8dfcbb7fc1fdb2519859ad516e63c19d3c27d92aaecdf463b1ad
RUN curl -fsSL --retry 5 \
        "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb" \
        -o /tmp/radare2.deb \
    && echo "${RADARE2_SHA256}  /tmp/radare2.deb" | sha256sum -c - \
    && dpkg -i /tmp/radare2.deb \
    && rm /tmp/radare2.deb

# JADX is not packaged by Ubuntu 22.04. Install the official cross-platform CLI
# bundle with a pinned checksum so Android reverse tasks remain reproducible.
ARG JADX_VERSION=1.5.6
ARG JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
RUN curl -fsSL --retry 5 \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        -o /tmp/jadx.zip \
    && echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum -c - \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

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

# Extract Python bytecode from PyInstaller-built ELF and PE challenges without
# requiring the interpreter version used to build the original executable.
RUN python3 -m pip install --no-cache-dir --retries 10 --timeout 60 \
        pyinstxtractor-ng==2026.7.3 angr unicorn

# NOTE: ghidra headless is large; install on demand if a challenge needs it.

WORKDIR /ctf
CMD ["sleep", "infinity"]
