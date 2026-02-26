from __future__ import annotations

import asyncio
import time

from fastapi.testclient import TestClient

from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import RunJob, RunMode
from snakehook_runner.main import create_app


def _settings(**overrides: object) -> Settings:
    base = Settings(
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
    values = {**base.__dict__, **overrides}
    return Settings(**values)


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer secret"}


def test_missing_or_invalid_token_returns_401() -> None:
    async def handler(job: RunJob) -> None:
        return None

    app = create_app(settings=_settings(), run_handler=handler)
    with TestClient(app) as client:
        r1 = client.post("/v1/triage", json={"package_name": "requests", "version": "2.0"})
        r2 = client.post(
            "/v1/triage",
            headers={"Authorization": "Bearer wrong"},
            json={"package_name": "requests", "version": "2.0"},
        )

    assert r1.status_code == 401
    assert r2.status_code == 401


def test_webhook_cannot_be_overridden_via_request_body() -> None:
    async def handler(job: RunJob) -> None:
        return None

    app = create_app(settings=_settings(), run_handler=handler)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={
                "package_name": "requests",
                "version": "2.0",
                "webhook_url": "https://attacker.invalid/hook",
            },
        )

    assert resp.status_code == 422


def test_rate_limit_returns_429() -> None:
    async def handler(job: RunJob) -> None:
        return None

    app = create_app(settings=_settings(per_ip_rate_limit=1), run_handler=handler)
    with TestClient(app) as client:
        first = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={"package_name": "requests", "version": "2.0"},
        )
        second = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={"package_name": "requests", "version": "2.0"},
        )

    assert first.status_code == 202
    assert second.status_code == 429


def test_queue_limit_returns_503() -> None:
    gate = asyncio.Event()

    async def handler(job: RunJob) -> None:
        await gate.wait()

    app = create_app(settings=_settings(max_concurrency=1, queue_limit=1), run_handler=handler)
    with TestClient(app) as client:
        first = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={"package_name": "requests", "version": "2.0"},
        )
        time.sleep(0.05)
        second = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={"package_name": "requests", "version": "2.0"},
        )
        third = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={"package_name": "requests", "version": "2.0"},
        )
        gate.set()

    assert first.status_code == 202
    assert second.status_code == 202
    assert third.status_code == 503


def test_mode_defaults_to_install_when_missing() -> None:
    seen: list[RunJob] = []

    async def handler(job: RunJob) -> None:
        seen.append(job)

    app = create_app(settings=_settings(), run_handler=handler)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={"package_name": "requests", "version": "2.0"},
        )

    assert resp.status_code == 202
    assert seen
    assert seen[0].mode == RunMode.INSTALL


def test_mode_and_targets_are_passed_to_job() -> None:
    seen: list[RunJob] = []

    async def handler(job: RunJob) -> None:
        seen.append(job)

    app = create_app(settings=_settings(), run_handler=handler)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/triage",
            headers=_auth_headers(),
            json={
                "package_name": "requests",
                "version": "2.0",
                "mode": "execute_module",
                "file_path": "/tmp/run.py",
                "entrypoint": "requests.__main__:main",
                "module_name": "requests",
            },
        )

    assert resp.status_code == 202
    assert seen
    assert seen[0].mode == RunMode.EXECUTE_MODULE
    assert seen[0].file_path == "/tmp/run.py"
    assert seen[0].entrypoint == "requests.__main__:main"
    assert seen[0].module_name == "requests"
