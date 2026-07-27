from __future__ import annotations

import pytest

from snakehook_runner.core.config import Settings


def test_settings_from_env_defaults(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "token")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/webhook")
    monkeypatch.delenv("DNS_RESOLVERS", raising=False)

    cfg = Settings.from_env()

    assert cfg.api_token == "token"
    assert cfg.discord_webhook_url == "https://discord.example/webhook"
    assert cfg.max_concurrency == 1
    assert cfg.queue_limit == 20
    assert cfg.cgroup_pids_max == 64
    assert cfg.cgroup_mem_max_bytes == 1_073_741_824
    assert cfg.cgroup_cpu_ms_per_sec == 800
    assert cfg.dns_resolvers == ("1.1.1.1", "8.8.8.8")


def test_settings_missing_required_env(monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/webhook")

    with pytest.raises(ValueError, match="API_TOKEN"):
        Settings.from_env()


def test_settings_rejects_low_minimum(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "token")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/webhook")
    monkeypatch.setenv("MAX_CONCURRENCY", "0")

    with pytest.raises(ValueError, match="MAX_CONCURRENCY"):
        Settings.from_env()


def test_settings_rejects_ipv6_dns(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "token")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/webhook")
    monkeypatch.setenv("DNS_RESOLVERS", "2001:4860:4860::8888")

    with pytest.raises(ValueError, match="IPv4"):
        Settings.from_env()


def test_settings_rejects_empty_dns_list(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "token")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/webhook")
    monkeypatch.setenv("DNS_RESOLVERS", "   ,   ")

    with pytest.raises(ValueError, match="at least one"):
        Settings.from_env()


def test_settings_rejects_excessive_cgroup_cpu(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKEN", "token")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.example/webhook")
    monkeypatch.setenv("CGROUP_CPU_MS_PER_SEC", "1001")

    with pytest.raises(ValueError, match="CGROUP_CPU_MS_PER_SEC"):
        Settings.from_env()
