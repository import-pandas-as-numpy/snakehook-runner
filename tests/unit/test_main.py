from __future__ import annotations

import pytest

from snakehook_runner.core.config import Settings
from snakehook_runner.main import create_app


def _settings() -> Settings:
    return Settings(
        api_token="t",
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
        max_download_bytes=100,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )


def test_ci_mock_only_requires_injected_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI_MOCK_ONLY", "1")
    with pytest.raises(RuntimeError):
        create_app(settings=_settings())


async def test_lifespan_starts_and_stops_worker_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI_MOCK_ONLY", raising=False)

    async def handler(_):
        return None

    app = create_app(settings=_settings(), run_handler=handler)
    async with app.router.lifespan_context(app):
        assert app.state.container.worker_pool._started is True
    assert app.state.container.worker_pool._started is False


def test_create_app_wires_default_adapters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI_MOCK_ONLY", raising=False)
    called: dict[str, object] = {}

    class FakeProcessRunner:
        pass

    class FakePipInstaller:
        def __init__(self, process_runner, settings) -> None:
            called["pip_runner"] = process_runner
            called["pip_settings"] = settings

    class FakeSandboxExecutor:
        def __init__(self, process_runner, settings) -> None:
            called["sandbox_runner"] = process_runner
            called["sandbox_settings"] = settings

    class FakeWebhookClient:
        def __init__(self, webhook_url: str) -> None:
            called["webhook_url"] = webhook_url

    class FakeOrchestrator:
        def __init__(self, pip_installer, sandbox_executor, webhook_client) -> None:
            called["orchestrator"] = (pip_installer, sandbox_executor, webhook_client)

    class FakeWorkerHandler:
        def __init__(self, orchestrator) -> None:
            called["handler_orchestrator"] = orchestrator

        async def __call__(self, _):
            return None

    monkeypatch.setattr("snakehook_runner.main.AsyncProcessRunner", FakeProcessRunner)
    monkeypatch.setattr("snakehook_runner.main.RealPipInstaller", FakePipInstaller)
    monkeypatch.setattr("snakehook_runner.main.NsJailSandboxExecutor", FakeSandboxExecutor)
    monkeypatch.setattr("snakehook_runner.main.DiscordWebhookClient", FakeWebhookClient)
    monkeypatch.setattr("snakehook_runner.main.TriageOrchestrator", FakeOrchestrator)
    monkeypatch.setattr("snakehook_runner.main.WorkerHandler", FakeWorkerHandler)

    cfg = _settings()
    app = create_app(settings=cfg)

    assert called["pip_runner"] is called["sandbox_runner"]
    assert called["pip_settings"] is cfg
    assert called["sandbox_settings"] is cfg
    assert called["webhook_url"] == "https://discord.example/webhook"
    assert called["handler_orchestrator"] is not None
    assert app.state.container.submission_service is not None
