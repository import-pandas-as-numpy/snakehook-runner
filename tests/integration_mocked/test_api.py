from __future__ import annotations

import asyncio
from dataclasses import replace

import httpx2

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
        cgroup_mem_max_bytes=536_870_912,
        cgroup_cpu_ms_per_sec=800,
        rlimit_nofile=512,
        max_download_bytes=200_000_000,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )
    return replace(base, **overrides)


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer secret"}


async def test_missing_or_invalid_token_returns_401() -> None:
    async def handler(job: RunJob) -> None:
        return None

    app = create_app(settings=_settings(), run_handler=handler)
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            r1 = await client.post(
                "/v1/triage",
                json={"package_name": "requests", "version": "2.0"},
            )
            r2 = await client.post(
                "/v1/triage",
                headers={"Authorization": "Bearer wrong"},
                json={"package_name": "requests", "version": "2.0"},
            )

    assert r1.status_code == 401
    assert r2.status_code == 401


async def test_webhook_cannot_be_overridden_via_request_body() -> None:
    async def handler(job: RunJob) -> None:
        return None

    app = create_app(settings=_settings(), run_handler=handler)
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            resp = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={
                    "package_name": "requests",
                    "version": "2.0",
                    "webhook_url": "https://attacker.invalid/hook",
                },
            )

    assert resp.status_code == 422


async def test_rate_limit_returns_429() -> None:
    async def handler(job: RunJob) -> None:
        return None

    app = create_app(settings=_settings(per_ip_rate_limit=1), run_handler=handler)
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            first = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={"package_name": "requests", "version": "2.0"},
            )
            second = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={"package_name": "requests", "version": "2.0"},
            )

    assert first.status_code == 202
    assert second.status_code == 429


async def test_queue_limit_returns_503() -> None:
    gate = asyncio.Event()

    async def handler(job: RunJob) -> None:
        await gate.wait()

    app = create_app(settings=_settings(max_concurrency=1, queue_limit=1), run_handler=handler)
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            first = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={"package_name": "requests", "version": "2.0"},
            )
            await asyncio.sleep(0.05)
            second = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={"package_name": "requests", "version": "2.0"},
            )
            third = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={"package_name": "requests", "version": "2.0"},
            )
            gate.set()

    assert first.status_code == 202
    assert second.status_code == 202
    assert third.status_code == 503


async def test_multiple_requests_from_one_client_run_in_fifo_order() -> None:
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    seen: list[str] = []
    active = 0
    max_active = 0

    async def handler(job: RunJob) -> None:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        seen.append(job.package_name)
        if job.package_name == "first":
            first_started.set()
            await release_first.wait()
        await asyncio.sleep(0)
        active -= 1

    app = create_app(
        settings=_settings(queue_limit=3, per_ip_rate_limit=10),
        run_handler=handler,
    )
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            first = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={"package_name": "first", "version": "1"},
            )
            await asyncio.wait_for(first_started.wait(), timeout=1)
            queued = [
                await client.post(
                    "/v1/triage",
                    headers=_auth_headers(),
                    json={"package_name": package, "version": "1"},
                )
                for package in ("second", "third", "fourth")
            ]
            release_first.set()
            await asyncio.wait_for(app.state.container.worker_pool.wait_idle(), timeout=1)

    assert first.status_code == 202
    assert [response.status_code for response in queued] == [202, 202, 202]
    assert seen == ["first", "second", "third", "fourth"]
    assert max_active == 1


async def test_mode_defaults_to_install_when_missing() -> None:
    seen: list[RunJob] = []

    async def handler(job: RunJob) -> None:
        seen.append(job)

    app = create_app(settings=_settings(), run_handler=handler)
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            resp = await client.post(
                "/v1/triage",
                headers=_auth_headers(),
                json={"package_name": "requests", "version": "2.0"},
            )
            await app.state.container.worker_pool.wait_idle()

    assert resp.status_code == 202
    assert seen
    assert seen[0].mode == RunMode.INSTALL


async def test_mode_and_targets_are_passed_to_job() -> None:
    seen: list[RunJob] = []

    async def handler(job: RunJob) -> None:
        seen.append(job)

    app = create_app(settings=_settings(), run_handler=handler)
    async with app.router.lifespan_context(app):
        async with _client(app) as client:
            resp = await client.post(
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
            await app.state.container.worker_pool.wait_idle()

    assert resp.status_code == 202
    assert seen
    assert seen[0].mode == RunMode.EXECUTE_MODULE
    assert seen[0].file_path == "/tmp/run.py"
    assert seen[0].entrypoint == "requests.__main__:main"
    assert seen[0].module_name == "requests"


def _client(app) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://testserver",
    )
