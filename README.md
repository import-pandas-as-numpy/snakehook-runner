# snakehook-runner

Public Python package triage sandbox with constrained execution and webhook reporting.

## Local dev

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest -q
```

## Runtime requirements

Required env vars:

- `API_TOKEN`
- `DISCORD_WEBHOOK_URL`

Common optional limits:

- `MAX_CONCURRENCY` (default `2`)
- `QUEUE_LIMIT` (default `20`)
- `PER_IP_RATE_LIMIT` (default `30`)
- `PER_IP_RATE_WINDOW_SEC` (default `60`)
- `RUN_TIMEOUT_SEC` (default `45`)
- `CGROUP_PIDS_MAX` (default `128`)
- `ENABLE_CGROUP_PIDS_LIMIT` (default `true`)
- `MAX_DOWNLOAD_BYTES` (default `300000000`)
- `PACKAGE_DENYLIST` (default `torch,tensorflow,jaxlib`)
- `DNS_RESOLVERS` (default `1.1.1.1,8.8.8.8`)
- `JAIL_PYTHON_NAME` (default `/usr/local/bin/python3`)
- `NSJAIL_USER` (default `65534`)
- `NSJAIL_GROUP` (default `65534`)
- `NSJAIL_DISABLE_CLONE_NEWUSER` (default `1`)

## Deployment

### 1. Build image

```bash
docker build -f container/Dockerfile -t snakehook-runner:local .
```

### 2. Run container

`entrypoint.sh` applies nftables rules, and nsjail requires namespace/cgroup isolation privileges.

```bash
docker volume create snakehook-pip-cache

docker run --rm -p 8080:8080 \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  -e API_TOKEN='replace-me' \
  -e DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...' \
  -e MAX_CONCURRENCY='2' \
  -e QUEUE_LIMIT='20' \
  -v snakehook-pip-cache:/var/cache/pip \
  snakehook-runner:local
```

If nsjail fails with `clone(...CLONE_NEWUSER|...|CLONE_NEWNET) failed: Operation not permitted`,
the runtime is still blocking namespace clone. On AppArmor-enabled hosts, also add:

```bash
--security-opt apparmor=unconfined
```

If nsjail fails with `Couldn't initialize cgroup user namespace` or
`Launching child process failed`, keep the container unprivileged and disable
the nsjail cgroup pid flag:

```bash
-e ENABLE_CGROUP_PIDS_LIMIT='0'
```

Jail filesystem/runtime notes:

- runtime paths are explicitly bind-mounted (read-only for `/usr`, `/usr/local`, `/bin`, `/lib*`)
- package install target is `/opt/snakehook/work/site/<package>-<version>`
- host pip cache remains mounted read-only in-jail (`/var/cache/pip`)
- optional chroot is available via `NSJAIL_CHROOT_PATH` when compatible with host kernel/runtime
- `clone_newnet` is disabled by default; outbound restrictions are enforced by container nftables policy
- jailed process defaults to uid/gid `65534` with `clone_newuser` disabled (override via envs above)

### 3. Health check

```bash
curl -sS http://127.0.0.1:8080/healthz
```

### 4. Submit a triage request

Default mode is `install` (install package and exit):

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/triage \
  -H 'Authorization: Bearer replace-me' \
  -H 'Content-Type: application/json' \
  -d '{"package_name":"requests","version":"2.32.3"}'
```

Install + execute (auto-discover console entrypoint unless `file_path`/`entrypoint` is provided):

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/triage \
  -H 'Authorization: Bearer replace-me' \
  -H 'Content-Type: application/json' \
  -d '{"package_name":"black","version":"24.10.0","mode":"execute"}'
```

Install + execute module (supports `file_path`, `entrypoint`, and `module_name` overrides):

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/triage \
  -H 'Authorization: Bearer replace-me' \
  -H 'Content-Type: application/json' \
  -d '{"package_name":"uvicorn","version":"0.35.0","mode":"execute_module","module_name":"uvicorn"}'
```

## Deploy from GHCR

The publish workflow pushes:

- `ghcr.io/<owner>/<repo>:sha-<gitsha>`
- `ghcr.io/<owner>/<repo>:main`
- `ghcr.io/<owner>/<repo>:vX.Y.Z` (tag builds)

Deploy by pulling an immutable digest when possible:

```bash
docker pull ghcr.io/<owner>/<repo>@sha256:<digest>
```

Then run it with the same `docker run` pattern shown above.

## Run without Docker (local process)

```bash
uv sync --extra dev
API_TOKEN='replace-me' \
DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...' \
uv run uvicorn snakehook_runner.main:create_app --factory --host 0.0.0.0 --port 8080
```
