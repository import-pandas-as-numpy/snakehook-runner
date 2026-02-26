from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from snakehook_runner.core.config import Settings


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        api_token="test-token",
        discord_webhook_url="https://discord.example/webhook",
        max_concurrency=2,
        queue_limit=2,
        per_ip_rate_limit=5,
        per_ip_rate_window_sec=60,
        run_timeout_sec=30,
        rlimit_cpu_sec=20,
        rlimit_as_mb=512,
        cgroup_pids_max=64,
        rlimit_nofile=512,
        pip_cache_dir="/var/cache/pip",
        max_download_bytes=200_000_000,
        package_denylist=("torch", "tensorflow"),
        dns_resolvers=("1.1.1.1",),
    )


@pytest.fixture
async def block_event() -> AsyncIterator[asyncio.Event]:
    event = asyncio.Event()
    yield event
    event.set()
