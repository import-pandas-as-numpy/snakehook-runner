from __future__ import annotations

from collections.abc import Callable


def render_nftables_rules(
    discord_host: str,
    dns_resolvers: tuple[str, ...],
    resolver: Callable[[str], list[str]],
) -> str:
    allowed_hosts = ["pypi.org", "files.pythonhosted.org", discord_host]
    ip_set: list[str] = []
    for host in allowed_hosts:
        for ip in resolver(host):
            if ip not in ip_set:
                ip_set.append(ip)

    ip_lines = ", ".join(ip_set)
    dns_lines = ", ".join(dns_resolvers)
    return f"""table inet snakehook {{
  set allowed_tls_ips {{
    type ipv4_addr
    elements = {{ {ip_lines} }}
  }}
  set dns_resolvers {{
    type ipv4_addr
    elements = {{ {dns_lines} }}
  }}

  chain output {{
    type filter hook output priority 0;
    policy drop;

    oifname \"lo\" accept
    ct state established,related accept

    ip daddr @dns_resolvers udp dport 53 accept
    ip daddr @dns_resolvers tcp dport 53 accept

    ip daddr @allowed_tls_ips tcp dport 443 accept
  }}
}}
"""
