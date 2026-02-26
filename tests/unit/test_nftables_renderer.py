from __future__ import annotations

from pathlib import Path

import pytest

from snakehook_runner.infra import nftables_renderer


def test_resolve_ipv4_dedupes_and_sorts(monkeypatch) -> None:
    def fake_gethostbyname_ex(host: str):
        return (host, [], ["2.2.2.2", "1.1.1.1", "2.2.2.2"])

    monkeypatch.setattr(nftables_renderer.socket, "gethostbyname_ex", fake_gethostbyname_ex)

    assert nftables_renderer.resolve_ipv4("example.com") == ["1.1.1.1", "2.2.2.2"]


def test_render_rules_for_webhook_requires_hostname() -> None:
    with pytest.raises(ValueError):
        nftables_renderer.render_rules_for_webhook("not-a-url", dns_resolvers=("1.1.1.1",))


def test_write_rules_file_writes_expected_content(monkeypatch, tmp_path: Path) -> None:
    def fake_resolve_ipv4(host: str) -> list[str]:
        mapping = {
            "pypi.org": ["1.1.1.1"],
            "files.pythonhosted.org": ["2.2.2.2"],
            "discord.example": ["3.3.3.3"],
        }
        return mapping[host]

    monkeypatch.setattr(nftables_renderer, "resolve_ipv4", fake_resolve_ipv4)

    out = tmp_path / "rules.nft"
    nftables_renderer.write_rules_file(
        "https://discord.example/webhook",
        str(out),
        dns_resolvers=("9.9.9.9",),
    )

    text = out.read_text(encoding="utf-8")
    assert "policy drop" in text
    assert "9.9.9.9" in text
    assert "3.3.3.3" in text


def test_build_dns_resolver_allowlist_includes_system_resolvers(tmp_path: Path) -> None:
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text(
        "nameserver 10.0.0.2\n"
        "nameserver 1.1.1.1\n"
        "search example.internal\n",
        encoding="utf-8",
    )

    result = nftables_renderer.build_dns_resolver_allowlist(
        raw="1.1.1.1,8.8.8.8",
        resolv_conf_path=str(resolv_conf),
    )

    assert result == ("1.1.1.1", "8.8.8.8", "10.0.0.2")


def test_read_system_ipv4_resolvers_ignores_invalid_and_ipv6(tmp_path: Path) -> None:
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text(
        "# comment\n"
        "nameserver fd00::1\n"
        "nameserver bad-value\n"
        "nameserver 9.9.9.9\n",
        encoding="utf-8",
    )

    assert nftables_renderer.read_system_ipv4_resolvers(str(resolv_conf)) == ("9.9.9.9",)
