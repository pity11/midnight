# Common tooling base for CTF specialist containers.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils file xxd binutils \
        python3 python3-pip python3-venv \
        curl wget netcat-openbsd \
        ca-certificates git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --upgrade pip

WORKDIR /ctf
# keep the container alive for `docker exec` driven interaction
CMD ["sleep", "infinity"]
