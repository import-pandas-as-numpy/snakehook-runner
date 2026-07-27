# Security model

## Purpose

`snakehook-runner` observes the installation and optional execution of an
untrusted public Python package. It records Python audit-hook events and returns
a concise report covering imports, file activity, subprocesses, and network
activity.

The runner is an analysis environment, not a general-purpose package installer,
CI worker, or security boundary for secrets. Treat every submitted package and
all of its dependencies as actively hostile.

## Threat model

The primary threat is arbitrary code execution during either:

1. package installation, including build backends and setup hooks; or
2. explicit post-install import, module, file, or entrypoint execution.

The design attempts to contain that code to one disposable job, limit resource
consumption and egress, preserve useful Python-level behavior, and destroy job
files after reporting.

The following are outside the security boundary:

- a compromised host kernel, container runtime, or hypervisor
- a malicious or compromised runner image already trusted by the operator
- compromise of the trusted API producer or report webhook
- reliable recovery of source code from obfuscated or native payloads

## Implemented controls

| Area | Control |
| --- | --- |
| Host isolation | The supported host is a dedicated Droplet and dedicated, unpeered VPC. No other infrastructure or secrets should share the host or VPC. |
| API exposure | The container publishes the API on host loopback only. Testing uses an SSH tunnel; production should put an authenticated trusted controller or TLS load balancer in front of it. |
| Authentication | `/v1/triage` requires a bearer token. Request bodies cannot override the configured report destination. |
| Input validation | Package names and exact PEP 440 versions are validated. URLs, paths, extras, local versions, environment markers, and pip option injection are rejected. |
| Queue control | One worker executes jobs in FIFO order. Queue depth, per-source rate limits, job time, CPU, memory, process count, file size, open files, and download bytes are bounded. |
| Namespace isolation | nsjail creates user, PID, mount, UTS, IPC, network, and cgroup namespaces inside a minimal chroot. Missing isolation primitives fail closed. |
| Identity and privileges | Payloads run as UID/GID `65534`, with capabilities removed and `no_new_privs` enabled. |
| Syscall restriction | nsjail applies a default-deny seccomp policy. Container-level seccomp is disabled only because nsjail must install the inner policy. |
| Filesystem | Runtime directories are explicit read-only bind mounts. Each job gets a bounded executable code tmpfs and a separate bounded `noexec` work tmpfs. |
| Writable executable files | `/site` is writable only during package installation. It is bind-mounted read-only for post-install execution. `/work` and the jail `/tmp` remain `noexec`. |
| Network | nftables is default-deny. Package installation and execution can reach only resolved PyPI endpoints. Jail DNS, inbound forwarding, UDP, ICMP, IPv6 autoconfiguration, and host port forwarding are disabled. |
| Reporting separation | The webhook is contacted by the trusted outer service, not by the jail. Installation and execution records are stage-labelled. |
| Telemetry bounds | Raw audit JSONL is capped at 50 MB per stage and process output is capped. Reports retain imports while suppressing routine bytecode-loader file noise. |
| Cleanup | Per-job code, cache, output, audit, and report files are deleted after the reporting attempt. |
| Supply chain | Python dependencies and OS packages are pinned. The base image is digest-pinned. nsjail, pasta, actions, and build tools are pinned to immutable commits or hashes. |
| Release | Main and version-tag builds run strict validation first, then publish a GHCR image with a full-commit tag, OCI metadata, maximum BuildKit provenance, an SBOM attestation, a GitHub OIDC-signed digest attestation, and a canonical digest. |

## Residual weaknesses and required mitigations

### The container is deliberately privileged

The outer container requires `SYS_ADMIN`, `NET_ADMIN`, host cgroup access,
`/dev/net/tun`, and relaxed outer AppArmor/seccomp settings so nsjail can create
the inner security boundary. A container escape therefore has unusually serious
consequences.

Mitigations:

- use a dedicated disposable host and dedicated VPC
- place no credentials or unrelated workloads on the host
- apply host and cloud firewalls in addition to nftables
- rebuild the host rather than attempting to clean it after suspected compromise
- patch the host kernel and Docker promptly

### Installation executes hostile code

Python package installation can execute build backends. `/site` must be writable
and executable during that stage so native packages can be installed. The
installation remains inside nsjail, but writable executable code is unavoidable
for this analysis mode.

Mitigations:

- never install outside the jail
- use exact package versions and retain the installation-stage audit
- keep the code tmpfs bounded and delete it after every job
- do not mount host caches, Docker sockets, source trees, or credentials

### Python audit hooks are not an EDR

Audit hooks observe events emitted by CPython. Native extensions, direct
syscalls, another interpreter, memory-only behavior, and kernel exploitation may
produce incomplete or no Python events. An audit event generally records an
attempt, not whether the underlying operation succeeded. Record caps mean a
high-volume payload can cause later events to be omitted.

Mitigations:

- treat nsjail, seccomp, cgroups, and nftables as enforcement
- treat audit output as behavioral evidence, not proof of absence
- retain raw JSONL when investigating a package
- add host-side syscall or kernel telemetry if complete EDR coverage is required

### Allowed egress can be abused

PyPI and file-hosting IPs are permitted so packages can be downloaded and benign
network behavior can be exercised. IP allowlisting cannot authenticate the
remote application protocol, and shared infrastructure can broaden the practical
destination set.

Mitigations:

- never place secrets in the jail
- keep the VPC unpeered
- restrict host egress at the cloud firewall where practical
- restart the service when PyPI addressing changes so the allowlist is refreshed
- use a dedicated validating package proxy if stronger destination identity is
  required

### Reports can contain sensitive observations

Paths, command arguments, hostnames, and selected Python constants may appear in
reports. The webhook is therefore a sensitive destination.

Mitigations:

- use a dedicated webhook with a narrowly held credential
- restrict access and retention at the destination
- rotate the API token and webhook after suspected exposure
- do not analyze private packages containing secrets with this public-package
  configuration

### Obfuscation is not reliably reversible

PyArmor and similar runtimes can preserve observable behavior while preventing
`inspect.getsource()` and normal code-object marshalling. Disassembly and
constants may still reveal capabilities, but the runner does not promise a
faithful unobfuscated package.

Mitigations:

- base decisions on behavior, imports, constants, and network/file activity
- compare installation and execution stages
- perform deeper deobfuscation only in another disposable environment

### Availability and durability are intentionally limited

The queue is in memory, there is one worker, and there is no persistent job
status/result API. Restarting the service loses queued jobs. Per-source rate
limiting is meaningful only when the runner receives a trustworthy source
address.

Mitigations:

- let a trusted durable queue/controller own retries and status
- keep the runner stateless and disposable
- do not blindly retry timeouts or containment failures
- preserve the real producer address through a trusted proxy only

## Operator responsibilities

Before production use:

1. Pin the image by `sha256` digest.
2. Verify the expected repository, commit, SBOM, and provenance attestations.
3. Use a dedicated host and VPC with no peering to unrelated infrastructure.
4. Keep port `8080` on loopback; expose only authenticated TLS on `443`.
5. Use unique, rotated API and webhook credentials.
6. Confirm cgroup v2, nftables, TUN, namespaces, and nsjail initialize without a
   reduced-isolation fallback.
7. Monitor disk, memory, queue rejection, timeout, audit-cap, and report-delivery
   failures.
8. Regularly rebuild from a patched host image and current reviewed dependency
   pins.

## Reporting vulnerabilities

Do not submit a public package to demonstrate a vulnerability. Report the
affected commit, configuration, containment boundary, and a minimal benign
reproducer privately to the repository maintainers.
