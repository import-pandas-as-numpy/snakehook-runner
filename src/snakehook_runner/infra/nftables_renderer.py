from __future__ import annotations

import socket
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from snakehook_runner.core.egress_rules import render_nftables_rules


def resolve_ipv4(host: str) -> list[str]:
    _, _, addrs = socket.gethostbyname_ex(host)
    return sorted(set(addrs))


def parse_configured_dns_resolvers(raw: str) -> tuple[str, ...]:
    resolvers: list[str] = []
    for part in raw.split(","):
        value = part.strip()
        if not value:
            continue
        parsed = ip_address(value)
        if parsed.version != 4:
            raise ValueError("DNS_RESOLVERS currently supports IPv4 addresses only")
        if value not in resolvers:
            resolvers.append(value)
    if not resolvers:
        raise ValueError("DNS_RESOLVERS must contain at least one IP")
    return tuple(resolvers)


def read_system_ipv4_resolvers(path: str = "/etc/resolv.conf") -> tuple[str, ...]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    resolvers: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("nameserver"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        candidate = parts[1]
        try:
            parsed = ip_address(candidate)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        if candidate not in resolvers:
            resolvers.append(candidate)
    return tuple(resolvers)


def build_dns_resolver_allowlist(raw: str, resolv_conf_path: str = "/etc/resolv.conf") -> tuple[str, ...]:
    configured = parse_configured_dns_resolvers(raw)
    merged = list(configured)
    for system_resolver in read_system_ipv4_resolvers(resolv_conf_path):
        if system_resolver not in merged:
            merged.append(system_resolver)
    return tuple(merged)


def render_rules_for_webhook(webhook_url: str, dns_resolvers: tuple[str, ...]) -> str:
    parsed = urlparse(webhook_url)
    if not parsed.hostname:
        raise ValueError("DISCORD_WEBHOOK_URL must include a hostname")
    return render_nftables_rules(
        discord_host=parsed.hostname,
        dns_resolvers=dns_resolvers,
        resolver=resolve_ipv4,
    )


def write_rules_file(webhook_url: str, path: str, dns_resolvers: tuple[str, ...]) -> str:
    rules = render_rules_for_webhook(webhook_url=webhook_url, dns_resolvers=dns_resolvers)
    target = Path(path)
    target.write_text(rules, encoding="utf-8")
    return str(target)
