from __future__ import annotations

import os
from dataclasses import dataclass
from ipaddress import ip_address


@dataclass(frozen=True)
class Settings:
    api_token: str
    discord_webhook_url: str
    max_concurrency: int
    queue_limit: int
    per_ip_rate_limit: int
    per_ip_rate_window_sec: int
    run_timeout_sec: int
    rlimit_cpu_sec: int
    rlimit_as_mb: int
    cgroup_pids_max: int
    rlimit_nofile: int
    pip_cache_dir: str
    max_download_bytes: int
    package_denylist: tuple[str, ...]
    dns_resolvers: tuple[str, ...]


    @classmethod
    def from_env(cls) -> Settings:
        api_token = _required("API_TOKEN")
        webhook = _required("DISCORD_WEBHOOK_URL")
        denylist = tuple(
            x.strip().lower()
            for x in os.getenv("PACKAGE_DENYLIST", "torch,tensorflow,jaxlib").split(",")
            if x.strip()
        )
        return cls(
            api_token=api_token,
            discord_webhook_url=webhook,
            max_concurrency=_int_env("MAX_CONCURRENCY", 2, minimum=1),
            queue_limit=_int_env("QUEUE_LIMIT", 20, minimum=1),
            per_ip_rate_limit=_int_env("PER_IP_RATE_LIMIT", 30, minimum=1),
            per_ip_rate_window_sec=_int_env("PER_IP_RATE_WINDOW_SEC", 60, minimum=1),
            run_timeout_sec=_int_env("RUN_TIMEOUT_SEC", 45, minimum=1),
            rlimit_cpu_sec=_int_env("RLIMIT_CPU_SEC", 30, minimum=1),
            rlimit_as_mb=_int_env("RLIMIT_AS_MB", 1024, minimum=128),
            cgroup_pids_max=_int_env("CGROUP_PIDS_MAX", 128, minimum=8),
            rlimit_nofile=_int_env("RLIMIT_NOFILE", 1024, minimum=64),
            pip_cache_dir=os.getenv("PIP_CACHE_DIR", "/var/cache/pip"),
            max_download_bytes=_int_env("MAX_DOWNLOAD_BYTES", 300_000_000, minimum=1),
            package_denylist=denylist,
            dns_resolvers=_parse_dns_resolvers(
                os.getenv("DNS_RESOLVERS", "1.1.1.1,8.8.8.8"),
            ),
        )


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


def _int_env(name: str, default: int, minimum: int) -> int:
    raw = os.getenv(name)
    value = default if raw is None else int(raw)
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _parse_dns_resolvers(raw: str) -> tuple[str, ...]:
    resolvers: list[str] = []
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        parsed = ip_address(value)
        if parsed.version != 4:
            raise ValueError("DNS_RESOLVERS currently supports IPv4 addresses only")
        resolvers.append(value)
    if not resolvers:
        raise ValueError("DNS_RESOLVERS must contain at least one IP")
    return tuple(resolvers)
