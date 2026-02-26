from __future__ import annotations

from fastapi.testclient import TestClient

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
        enable_cgroup_pids_limit=True,
        rlimit_nofile=512,
        pip_cache_dir="/var/cache/pip",
        max_download_bytes=200_000_000,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )


def test_healthz() -> None:
    async def handler(_):
        return None

    app = create_app(settings=_settings(), run_handler=handler)
    with TestClient(app) as client:
        resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
