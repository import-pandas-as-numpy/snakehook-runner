from __future__ import annotations

from collections.abc import Callable


def render_nftables_rules(
    discord_host: str,
    dns_resolvers: tuple[str, ...],
    resolver: Callable[[str], list[str]],
) -> str:
    package_ips: list[str] = []
    for host in ("pypi.org", "files.pythonhosted.org"):
        for ip in resolver(host):
            if ip not in package_ips:
                package_ips.append(ip)
    report_ips = resolver(discord_host)

    package_ip_lines = ", ".join(package_ips)
    report_ip_lines = ", ".join(report_ips)
    dns_lines = ", ".join(dns_resolvers)
    return f"""table inet snakehook {{
  set package_tls_ips {{
    type ipv4_addr
    elements = {{ {package_ip_lines} }}
  }}
  set report_tls_ips {{
    type ipv4_addr
    elements = {{ {report_ip_lines} }}
  }}
  set dns_resolvers {{
    type ipv4_addr
    elements = {{ {dns_lines} }}
  }}

  chain output {{
    type filter hook output priority 0;
    policy drop;

    ct state established,related accept

    meta skgid 65534 ip daddr @package_tls_ips tcp dport 443 accept
    meta skgid 65534 drop

    oifname \"lo\" accept
    tcp sport 8080 accept
    ip daddr @dns_resolvers udp dport 53 accept
    ip daddr @dns_resolvers tcp dport 53 accept

    ip daddr @package_tls_ips tcp dport 443 accept
    ip daddr @report_tls_ips tcp dport 443 accept
  }}
}}
"""
