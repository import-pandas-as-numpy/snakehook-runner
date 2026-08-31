# syntax=docker/dockerfile:1.7
FROM docker.io/library/python:3.14-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63 AS nsjail-builder

ARG NSJAIL_REF=f78475530b46d0186111a9096b30725f816b55fe
ARG PASTA_REF=a9c61ffaf15347b8dfcc2347c5440e4b0e82333b

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison=2:3.8.2+dfsg-1+b1 \
        build-essential=12.9 \
        flex=2.6.4-8.2 \
        git=1:2.39.5-0+deb12u3 \
        libcap-dev=1:2.66-4+deb12u3+b1 \
        libnl-3-dev=3.7.0-0.2+b1 \
        libnl-genl-3-dev=3.7.0-0.2+b1 \
        libnl-route-3-dev=3.7.0-0.2+b1 \
        libprotobuf-dev=3.21.12-3+deb12u1 \
        libseccomp-dev=2.5.4-1+deb12u1 \
        pkg-config=1.8.1-1 \
        protobuf-compiler=3.21.12-3+deb12u1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone --no-checkout https://passt.top/passt \
    && git -C passt fetch --depth 1 origin "${PASTA_REF}" \
    && git -C passt checkout --detach "${PASTA_REF}" \
    && test "$(git -C passt rev-parse HEAD)" = "${PASTA_REF}"
COPY container/pasta-embedded.patch /tmp/pasta-embedded.patch
WORKDIR /tmp/passt
RUN git apply --check /tmp/pasta-embedded.patch \
    && git apply /tmp/pasta-embedded.patch \
    && make pasta

COPY container/nsjail-user-net.patch /tmp/nsjail-user-net.patch
COPY container/kafel-makefile.patch /tmp/kafel-makefile.patch

WORKDIR /tmp
RUN git clone --filter=blob:none --no-checkout https://github.com/google/nsjail.git \
    && git -C nsjail fetch --depth 1 origin "${NSJAIL_REF}" \
    && git -C nsjail checkout --detach "${NSJAIL_REF}" \
    && test "$(git -C nsjail rev-parse HEAD)" = "${NSJAIL_REF}" \
    && git -C nsjail apply --check /tmp/nsjail-user-net.patch \
    && git -C nsjail apply /tmp/nsjail-user-net.patch
WORKDIR /tmp/nsjail
# The patch keeps pasta root only for network-namespace entry, assigns its
# sockets gid 65534 for nftables enforcement, and disables all port forwarding.
RUN git submodule update --init --depth 1 \
    && git -C kafel apply --check /tmp/kafel-makefile.patch \
    && git -C kafel apply /tmp/kafel-makefile.patch \
    && make -j"$(nproc)" PASTA_BIN_PATH=/tmp/passt/pasta

FROM docker.io/library/python:3.14-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63 AS app-builder

ENV UV_PROJECT_ENVIRONMENT=/opt/snakehook/venv

WORKDIR /app
COPY container/build-requirements.txt /tmp/build-requirements.txt
RUN pip install --root-user-action=ignore --no-cache-dir --require-hashes \
    -r /tmp/build-requirements.txt
COPY pyproject.toml uv.lock README.md /app/
COPY src /app/src
RUN uv sync --frozen --no-dev --no-editable

FROM docker.io/library/python:3.14-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/snakehook/venv/bin:$PATH

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        libcap2=1:2.66-4+deb12u3+b1 \
        libnl-3-200=3.7.0-0.2+b1 \
        libnl-genl-3-200=3.7.0-0.2+b1 \
        libnl-route-3-200=3.7.0-0.2+b1 \
        libprotobuf32=3.21.12-3+deb12u1 \
        libseccomp2=2.5.4-1+deb12u1 \
        nftables=1.0.6-2+deb12u2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nsjail-builder /tmp/nsjail/nsjail /usr/local/bin/nsjail
COPY --from=app-builder /opt/snakehook/venv /opt/snakehook/venv

COPY container/entrypoint.sh /entrypoint.sh
COPY container/nsjail.cfg /etc/nsjail.cfg
COPY container/nsjail.seccomp /etc/nsjail.seccomp

# Prepare a dedicated nsjail rootfs mount target tree. The jail runs with
# chroot=/app/nsjail/rootfs and receives only explicit bind mounts.
RUN mkdir -p \
    /opt/snakehook/code \
    /opt/snakehook/work \
    /run/snakehook \
    /app/nsjail/rootfs/tmp \
    /app/nsjail/rootfs/etc/ssl/certs \
    /app/nsjail/rootfs/etc \
    /app/nsjail/rootfs/usr/local \
    /app/nsjail/rootfs/bin \
    /app/nsjail/rootfs/lib \
    /app/nsjail/rootfs/lib64 \
    /app/nsjail/rootfs/site \
    /app/nsjail/rootfs/work \
    && touch /app/nsjail/rootfs/etc/hosts
RUN chown -R 65534:65534 /opt/snakehook/code /opt/snakehook/work \
    && chmod 2770 /opt/snakehook/code /opt/snakehook/work

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
