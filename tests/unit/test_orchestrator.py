from __future__ import annotations

import logging
from pathlib import Path

from snakehook_runner.core.interfaces import PipInstallResult, RunJob, SandboxResult
from snakehook_runner.core.orchestrator import TriageOrchestrator, WorkerHandler


class FakePipInstaller:
    def __init__(self, result: PipInstallResult) -> None:
        self._result = result

    async def install(self, package_name: str, version: str) -> PipInstallResult:
        return self._result


class FakeSandboxExecutor:
    def __init__(self, result: SandboxResult) -> None:
        self._result = result

    async def run(self, job: RunJob) -> SandboxResult:
        return self._result


class FakeWebhookClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    async def send_summary(self, run_id: str, summary: str, attachment_path: str | None) -> None:
        self.calls.append((run_id, summary, attachment_path))


async def test_orchestrator_reports_pip_failure() -> None:
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=False, stdout="", stderr="boom")),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(ok=True, stdout="", stderr="", timed_out=False, audit_jsonl_path=None),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r1", package_name="x", version="1"))

    assert result.ok is False
    assert "pip install failed" in result.message
    assert webhook.calls[0][0] == "r1"


async def test_orchestrator_compresses_audit_and_reports_success(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("event.one\n", encoding="utf-8")
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=True, stdout="", stderr="")),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(
                ok=True,
                stdout="x",
                stderr="",
                timed_out=False,
                audit_jsonl_path=str(audit),
            ),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r2", package_name="x", version="1"))

    assert result.ok is True
    assert result.attachment_path is not None
    assert result.attachment_path.endswith(".gz")
    assert Path(result.attachment_path).exists() is False
    assert webhook.calls[0][2] == result.attachment_path


async def test_worker_handler_logs_exceptions(caplog) -> None:
    class BoomOrchestrator:
        async def execute(self, job: RunJob):
            raise RuntimeError("explode")

    handler = WorkerHandler(orchestrator=BoomOrchestrator())

    caplog.set_level(logging.ERROR)
    await handler(RunJob(run_id="r3", package_name="x", version="1"))

    assert "triage run failed run_id=r3" in caplog.text
