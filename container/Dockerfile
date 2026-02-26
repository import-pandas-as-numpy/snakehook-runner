# syntax=docker/dockerfile:1.7
FROM docker.io/library/python:3.13-slim-bookworm AS nsjail-builder

ARG NSJAIL_REF=master

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        flex \
        git \
        libcap-dev \
        libnl-3-dev \
        libnl-genl-3-dev \
        libnl-route-3-dev \
        libprotobuf-dev \
        libseccomp-dev \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone --depth 1 --branch "${NSJAIL_REF}" https://github.com/google/nsjail.git
WORKDIR /tmp/nsjail
RUN make -j"$(nproc)"

FROM docker.io/library/python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_CACHE_DIR=/var/cache/pip

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcap2 \
        libnl-3-200 \
        libnl-genl-3-200 \
        libnl-route-3-200 \
        libprotobuf32 \
        libseccomp2 \
        nftables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nsjail-builder /tmp/nsjail/nsjail /usr/local/bin/nsjail

COPY pyproject.toml /app/
COPY src /app/src
COPY container/entrypoint.sh /entrypoint.sh
COPY container/nsjail.cfg /etc/nsjail.cfg

RUN pip install --no-cache-dir .

# Prepare a dedicated nsjail rootfs mount target tree. The jail runs with
# chroot=/app/nsjail/rootfs and receives only explicit bind mounts.
RUN mkdir -p \
    /opt/snakehook/work/site \
    /app/nsjail/rootfs/tmp \
    /app/nsjail/rootfs/etc/ssl/certs \
    /app/nsjail/rootfs/etc \
    /app/nsjail/rootfs/opt/snakehook/work \
    /app/nsjail/rootfs/usr \
    /app/nsjail/rootfs/bin \
    /app/nsjail/rootfs/lib \
    /app/nsjail/rootfs/lib64 \
    /app/nsjail/rootfs/var/cache/pip
RUN chown -R 65534:65534 /opt/snakehook/work

VOLUME ["/var/cache/pip"]
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
