from __future__ import annotations

import httpx2

from snakehook_runner.core.config import Settings
from snakehook_runner.main import create_app


def _settings() -> Settings:
    return Settings(
        api_token="secret",
        discord_webhook_url="https://discord.example/webhook",
        max_concurrency=1,
        queue_limit=1,
        per_ip_rate_limit=5,
        per_ip_rate_window_sec=60,
        run_timeout_sec=30,
        rlimit_cpu_sec=20,
        rlimit_as_mb=512,
        cgroup_pids_max=64,
        cgroup_mem_max_bytes=536_870_912,
        cgroup_cpu_ms_per_sec=800,
        rlimit_nofile=512,
        max_download_bytes=200_000_000,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )


async def test_healthz() -> None:
    async def handler(_):
        return None

    app = create_app(settings=_settings(), run_handler=handler)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/healthz")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
