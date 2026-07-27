from snakehook_runner.core.egress_rules import render_nftables_rules


def test_egress_rules_default_drop_and_allowlist() -> None:
    mapping = {
        "pypi.org": ["151.101.0.223"],
        "files.pythonhosted.org": ["146.75.76.223"],
        "discord.example": ["162.159.128.233"],
    }

    rules = render_nftables_rules(
        discord_host="discord.example",
        dns_resolvers=("1.1.1.1", "8.8.8.8"),
        resolver=lambda host: mapping[host],
    )

    assert "policy drop" in rules
    assert "151.101.0.223" in rules
    assert "146.75.76.223" in rules
    assert "162.159.128.233" in rules
    assert "meta skgid 65534 ip daddr @package_tls_ips tcp dport 443 accept" in rules
    assert "meta skgid 65534 drop" in rules
    assert rules.index("meta skgid 65534 drop") < rules.index("tcp sport 8080 accept")
    assert "ip daddr @report_tls_ips tcp dport 443 accept" in rules
    assert "ip daddr @dns_resolvers udp dport 53 accept" in rules
    assert "ip daddr @dns_resolvers tcp dport 53 accept" in rules
