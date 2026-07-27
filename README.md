# snakehook-runner

`snakehook-runner` installs and optionally executes an exact version of a public
Python package inside a constrained nsjail, records CPython audit-hook events,
and sends raw telemetry plus a concise behavioral report to a fixed webhook.

It exists to answer questions such as:

- Which files did installation or execution attempt to read or write?
- Which modules were imported, by whom, and from which origin?
- Which subprocesses were started?
- Which DNS names, IP addresses, ports, and socket operations were used?
- Did an obfuscated payload still expose useful behavioral signals?

This is a hostile-code analysis worker. It is not a safe package installer, a
general CI runner, a complete EDR, or a source-code deobfuscator. Read
[SECURITY.md](SECURITY.md) before deployment; it defines the threat model,
implemented controls, residual weaknesses, and operator responsibilities.

## Execution flow

1. An authenticated producer submits an exact package name and version.
2. A bounded FIFO queue feeds one worker.
3. pip installation runs inside nsjail and receives installation-stage auditing.
4. Optional import, module, file, or entrypoint execution runs in a fresh nsjail
   invocation with installed code mounted read-only.
5. Raw JSONL and an HTML summary are sent by the trusted outer service.
6. Per-job code, cache, output, and telemetry are deleted.

## Local dev

```bash
uv sync --frozen --extra dev
uv run ruff check .
uv run ty check
uv run pytest -q
/home/rem/github/vipyrsec/.tools/bin/prek-workspace run --all-files
```

## Runtime requirements

Required env vars:

- `API_TOKEN`
- `DISCORD_WEBHOOK_URL`

Common optional limits:

- `MAX_CONCURRENCY` (fixed at `1`)
- `QUEUE_LIMIT` (default `20`; waiting jobs, in FIFO order)
- `PER_IP_RATE_LIMIT` (default `30`)
- `PER_IP_RATE_WINDOW_SEC` (default `60`)
- `RUN_TIMEOUT_SEC` (default `45`)
- `CGROUP_PIDS_MAX` (default `64`)
- `CGROUP_MEM_MAX_BYTES` (default `1073741824`)
- `CGROUP_CPU_MS_PER_SEC` (default `800`, maximum `1000`)
- `MAX_DOWNLOAD_BYTES` (default `300000000`)
- `PACKAGE_DENYLIST` (default `torch,tensorflow,jaxlib`)
- `DNS_RESOLVERS` (default `1.1.1.1,8.8.8.8`)
- `JAIL_PYTHON_NAME` (default `/usr/local/bin/python3`)

## Deployment

The supported execution host is a fresh DigitalOcean Droplet or Private Droplet
in a dedicated, unpeered VPC. Do not place the runner in an existing application
or infrastructure VPC.

DigitalOcean App Platform is suitable for a trusted API/controller, but not for
the runner: the runner requires nested namespaces, cgroup v2 controls, nftables,
and nsjail's seccomp policy.

Host prerequisites:

- Linux with cgroup v2
- Docker Engine and `/dev/net/tun`
- at least 2 GiB RAM recommended
- a DigitalOcean Cloud Firewall
- no unrelated workloads, credentials, Docker socket consumers, or VPC peering

During testing, allow SSH only from the operator's `/32` and reach the loopback
API through an SSH tunnel. For production, use a Private Droplet with controlled
outbound routing and terminate TLS on port `443` at a trusted controller or load
balancer. Keep container port `8080` bound to host loopback.

### 1. Obtain and verify an immutable release

The `publish` workflow runs strict validation before publishing. Main and
version-tag builds produce:

- `ghcr.io/import-pandas-as-numpy/snakehook-runner:sha-<full-git-sha>`
- `ghcr.io/import-pandas-as-numpy/snakehook-runner:main`
- `ghcr.io/import-pandas-as-numpy/snakehook-runner:vX.Y.Z` for tag builds
- a canonical `sha256` image digest
- maximum BuildKit provenance and an attached SPDX SBOM
- a GitHub OIDC-signed attestation for the published digest

Take the canonical digest from the successful workflow summary, then verify it:

```bash
export SNAKEHOOK_IMAGE='ghcr.io/import-pandas-as-numpy/snakehook-runner@sha256:<digest>'

docker buildx imagetools inspect "${SNAKEHOOK_IMAGE}"
gh attestation verify "oci://${SNAKEHOOK_IMAGE}" \
  --repo import-pandas-as-numpy/snakehook-runner
docker buildx imagetools inspect "${SNAKEHOOK_IMAGE}" \
  --format '{{ json .SBOM.SPDX }}'
```

The mutable `main` and version tags are discovery aids only. Deploy the digest.

For a reviewed local build:

```bash
docker build -f container/Dockerfile -t snakehook-runner:local .
```

### 2. Configure runtime secrets

Set secrets in the host process environment immediately before launch:

```bash
export API_TOKEN='<random bearer token>'
export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'
export DNS_RESOLVERS='1.1.1.1,8.8.8.8'
```

These values are passed only to `docker run`. They are not Docker build
arguments, image layers, build context, or provenance inputs. The launcher uses
`--env NAME`, so literal values do not appear in its process arguments.

Host root and Docker administrators can inspect runtime container configuration.
The host must therefore remain dedicated. nsjail uses `keep_env: false`; the
payload receives only an explicit minimal environment and never receives the API
token or webhook URL.

### 3. Launch the digest-pinned image

The audited launcher validates the immutable image reference, TUN device, and
cgroup v2 before starting the container:

```bash
sudo --preserve-env=SNAKEHOOK_IMAGE,API_TOKEN,DISCORD_WEBHOOK_URL,DNS_RESOLVERS \
  ./container/run-immutable.sh
```

It fails if `SNAKEHOOK_IMAGE` is not pinned by a 64-character SHA-256 digest.
It intentionally refuses to replace an existing container automatically. For a
reviewed upgrade:

```bash
docker stop snakehook-runner
docker rm snakehook-runner
sudo --preserve-env=SNAKEHOOK_IMAGE,API_TOKEN,DISCORD_WEBHOOK_URL,DNS_RESOLVERS \
  ./container/run-immutable.sh
```

### 4. Manual launch

`entrypoint.sh` applies nftables rules, and nsjail requires namespace/cgroup isolation privileges.

```bash
docker run --rm \
  --name snakehook-runner \
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
```

Do not publish port 8080 on the Droplet's VPC address. A trusted controller on
the same Droplet may call the loopback endpoint. Failure to create any required
namespace, cgroup, chroot, bind mount, or seccomp policy is fatal; there is no
reduced-isolation mode.

Jail filesystem/runtime notes:

- runtime paths are explicitly bind-mounted read-only
- each job receives separate bounded tmpfs directories for installed code and
  mutable work
- pip installs into executable `/site` while that job's code directory is
  writable; execution remounts it read-only so native extensions and PyArmor
  runtimes can load without giving the payload a writable executable path
- pip cache, audit logs, and package output remain on the `noexec` `/work`
  tmpfs
- each install uses a fresh per-job pip cache on the bounded work tmpfs
- the jail always uses a minimal chroot, user/PID/mount/UTS/IPC/network/cgroup
  namespaces, cgroup v2 limits, and a default-deny seccomp policy
- package installation can reach only resolved PyPI endpoints; proxied jail
  sockets use gid `65534` and cannot reach DNS or the Discord webhook
- execution emits raw Python audit-hook JSONL plus an HTML summary of attempted
  file reads/writes, subprocesses, and socket activity by host/IP and port;
  records are stage-labelled so install activity can be separated from
  post-install execution
- import summaries show importer, requested module, and resolved origin when
  CPython provides it; importlib's routine `.py`/`.pyc` opens are represented
  there instead of duplicated as file-read highlights, but remain in raw JSONL
- audit JSONL is capped at 50 MB per stage, below nsjail's explicit 64 MB
  per-file limit and the aggregate 384 MB mutable-work tmpfs limit
- code and work directories are deleted after the reporting attempt

### 5. Connect and check health

For a standard test Droplet with SSH restricted to the operator:

```bash
ssh -N -L 8080:127.0.0.1:8080 root@<droplet-ip>
```

Then, from the operator machine:

```bash
curl -sS http://127.0.0.1:8080/healthz
```

### 6. Submit triage requests

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

All accepted requests return a run ID and execute in FIFO order. The queue is
in-memory and intentionally has no durable status API; a trusted controller
should own persistence, retries, and user-facing status.

## Operations

- Monitor health, queue rejection, rate limiting, timeout, containment startup,
  audit-cap, and webhook-delivery failures.
- Restart after PyPI addressing changes so the nftables allowlist is refreshed.
- Treat nsjail exit `137`, namespace failures, and missing audit output as failed
  analysis, not a clean package result.
- Rebuild the disposable host after suspected compromise.
- Rotate the API token and webhook after suspected exposure.
- Pull a newly reviewed digest rather than updating packages inside a running
  container.

## Run without Docker (local process)

```bash
uv sync --extra dev
API_TOKEN='replace-me' \
DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...' \
uv run uvicorn snakehook_runner.main:create_app --factory --host 0.0.0.0 --port 8080
```

This development mode does not provide the supported Docker/nsjail containment
boundary and must not process untrusted packages.
