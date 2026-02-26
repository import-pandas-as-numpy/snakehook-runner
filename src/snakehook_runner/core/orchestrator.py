from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from snakehook_runner.core.interfaces import (
    PipInstaller,
    PipInstallResult,
    RunJob,
    RunMode,
    SandboxExecutor,
    WebhookClient,
)
from snakehook_runner.infra.compression import gzip_file

LOG = logging.getLogger(__name__)
INSTALL_ERROR_MAX_CHARS = 350
INSTALL_ERROR_MAX_LINES = 6


@dataclass(frozen=True)
class ExecutionSummary:
    run_id: str
    ok: bool
    message: str
    attachment_path: str | None


class TriageOrchestrator:
    def __init__(
        self,
        pip_installer: PipInstaller,
        sandbox_executor: SandboxExecutor,
        webhook_client: WebhookClient,
    ) -> None:
        self._pip_installer = pip_installer
        self._sandbox_executor = sandbox_executor
        self._webhook_client = webhook_client

    async def execute(self, job: RunJob) -> ExecutionSummary:
        install = await self._pip_installer.install(job.package_name, job.version)
        if not install.ok:
            summary = ExecutionSummary(
                run_id=job.run_id,
                ok=False,
                message=f"pip install failed: {_summarize_install_failure(install)}",
                attachment_path=None,
            )
            await self._webhook_client.send_summary(job.run_id, summary.message, None)
            return summary

        if job.mode == RunMode.INSTALL:
            summary = ExecutionSummary(
                run_id=job.run_id,
                ok=True,
                message="install ok",
                attachment_path=None,
            )
            await self._webhook_client.send_summary(job.run_id, summary.message, None)
            return summary

        sandbox = await self._sandbox_executor.run(job)
        attachment_path: str | None = None
        if sandbox.audit_jsonl_path:
            attachment_path = gzip_file(sandbox.audit_jsonl_path)

        outcome = "ok" if sandbox.ok else "failed"
        timeout_note = " (timed out)" if sandbox.timed_out else ""
        summary = ExecutionSummary(
            run_id=job.run_id,
            ok=sandbox.ok,
            message=(
                f"run {outcome}{timeout_note}; "
                f"stdout={len(sandbox.stdout)}B stderr={len(sandbox.stderr)}B"
            ),
            attachment_path=attachment_path,
        )
        try:
            await self._webhook_client.send_summary(job.run_id, summary.message, attachment_path)
        finally:
            if attachment_path:
                Path(attachment_path).unlink(missing_ok=True)
        return summary


class WorkerHandler:
    def __init__(self, orchestrator: TriageOrchestrator) -> None:
        self._orchestrator = orchestrator

    async def __call__(self, job: RunJob) -> None:
        try:
            await self._orchestrator.execute(job)
        except Exception:
            LOG.exception("triage run failed run_id=%s", job.run_id)


def _summarize_install_failure(install_result: PipInstallResult) -> str:
    raw = install_result.stderr.strip() or install_result.stdout.strip()
    if not raw:
        return "no process output captured"
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return "no process output captured"
    snippet = " | ".join(lines[-INSTALL_ERROR_MAX_LINES:])
    if len(snippet) <= INSTALL_ERROR_MAX_CHARS:
        return snippet
    return f"...{snippet[-(INSTALL_ERROR_MAX_CHARS - 3):]}"
