from __future__ import annotations

import socket
from pathlib import Path
from urllib.parse import urlparse

from snakehook_runner.core.egress_rules import render_nftables_rules


def resolve_ipv4(host: str) -> list[str]:
    _, _, addrs = socket.gethostbyname_ex(host)
    return sorted(set(addrs))


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
