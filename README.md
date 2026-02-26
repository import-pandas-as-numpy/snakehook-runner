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
- `MAX_DOWNLOAD_BYTES` (default `300000000`)
- `PACKAGE_DENYLIST` (default `torch,tensorflow,jaxlib`)
- `DNS_RESOLVERS` (default `1.1.1.1,8.8.8.8`)

## Deployment

### 1. Build image

```bash
docker build -f container/Dockerfile -t snakehook-runner:local .
```

### 2. Run container

`entrypoint.sh` applies nftables rules, so the container needs network admin capability.

```bash
docker volume create snakehook-pip-cache

docker run --rm -p 8080:8080 \
  --cap-add=NET_ADMIN \
  -e API_TOKEN='replace-me' \
  -e DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...' \
  -e MAX_CONCURRENCY='2' \
  -e QUEUE_LIMIT='20' \
  -v snakehook-pip-cache:/var/cache/pip \
  snakehook-runner:local
```

### 3. Health check

```bash
curl -sS http://127.0.0.1:8080/healthz
```

### 4. Submit a triage request

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/triage \
  -H 'Authorization: Bearer replace-me' \
  -H 'Content-Type: application/json' \
  -d '{"package_name":"requests","version":"2.32.3"}'
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
