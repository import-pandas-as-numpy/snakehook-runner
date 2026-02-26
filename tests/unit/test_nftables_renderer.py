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
