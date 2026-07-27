#!/usr/bin/env bash
set -euo pipefail

: "${SNAKEHOOK_IMAGE:?set SNAKEHOOK_IMAGE to a GHCR image pinned by sha256 digest}"
: "${API_TOKEN:?API_TOKEN is required}"
: "${DISCORD_WEBHOOK_URL:?DISCORD_WEBHOOK_URL is required}"

if [[ ! "${SNAKEHOOK_IMAGE}" =~ @sha256:[[:xdigit:]]{64}$ ]]; then
  echo "SNAKEHOOK_IMAGE must end in @sha256:<64 hexadecimal characters>" >&2
  exit 2
fi

if [[ ! -c /dev/net/tun ]]; then
  echo "/dev/net/tun is required" >&2
  exit 2
fi

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "cgroup v2 is required" >&2
  exit 2
fi

docker pull "${SNAKEHOOK_IMAGE}"
docker run --detach \
  --name snakehook-runner \
  --restart unless-stopped \
  --publish 127.0.0.1:8080:8080 \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --cgroupns=host \
  --device=/dev/net/tun \
  --mount type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --pids-limit=256 \
  --memory=1536m \
  --memory-swap=1536m \
  --cpus=1 \
  --tmpfs /opt/snakehook/code:rw,nosuid,nodev,exec,size=512m,mode=0770,uid=65534,gid=65534 \
  --tmpfs /opt/snakehook/work:rw,nosuid,nodev,noexec,size=384m,mode=0770,uid=65534,gid=65534 \
  --env API_TOKEN \
  --env DISCORD_WEBHOOK_URL \
  --env DNS_RESOLVERS \
  "${SNAKEHOOK_IMAGE}"
