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
        LOG.info(
            "triage start run_id=%s package=%s version=%s mode=%s",
            job.run_id,
            job.package_name,
            job.version,
            job.mode.value,
        )
        install = await self._pip_installer.install(job.package_name, job.version)
        install_audit_path = _existing_path(install.audit_jsonl_path)
        if not install.ok:
            attachment_path = _compress_audit_sources(
                run_id=job.run_id,
                install_audit_path=install_audit_path,
                sandbox_audit_path=None,
            )
            summary = ExecutionSummary(
                run_id=job.run_id,
                ok=False,
                message=f"pip install failed: {_summarize_install_failure(install)}",
                attachment_path=attachment_path,
            )
            LOG.warning("triage install failed run_id=%s", job.run_id)
            try:
                await self._webhook_client.send_summary(
                    job.run_id,
                    summary.message,
                    attachment_path,
                )
            finally:
                _cleanup_attachment(attachment_path, job.run_id)
            return summary

        if job.mode == RunMode.INSTALL:
            attachment_path = _compress_audit_sources(
                run_id=job.run_id,
                install_audit_path=install_audit_path,
                sandbox_audit_path=None,
            )
            summary = ExecutionSummary(
                run_id=job.run_id,
                ok=True,
                message="install ok",
                attachment_path=attachment_path,
            )
            LOG.info(
                "triage install-only run complete run_id=%s",
                job.run_id,
            )
            try:
                await self._webhook_client.send_summary(
                    job.run_id,
                    summary.message,
                    attachment_path,
                )
            finally:
                _cleanup_attachment(attachment_path, job.run_id)
            return summary

        LOG.info("triage sandbox execution starting run_id=%s", job.run_id)
        sandbox = await self._sandbox_executor.run(job)
        attachment_path = _compress_audit_sources(
            run_id=job.run_id,
            install_audit_path=install_audit_path,
            sandbox_audit_path=_existing_path(sandbox.audit_jsonl_path),
        )

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
            _cleanup_attachment(attachment_path, job.run_id)
        LOG.info("triage complete run_id=%s ok=%s", job.run_id, summary.ok)
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
    summary = _truncate_middle(snippet, INSTALL_ERROR_MAX_CHARS)
    if _looks_like_nsjail_clone_permission_error(raw):
        return (
            f"{summary} | hint: nsjail namespace clone blocked by container runtime; "
            "allow nsjail-required isolation capabilities and seccomp profile"
        )
    if _looks_like_nsjail_cgroup_namespace_error(raw):
        return (
            f"{summary} | hint: nsjail cgroup namespace init failed; "
            "disable clone_newcgroup in nsjail config or run with cgroup namespace support"
        )
    if _looks_like_nsjail_execve_failure(raw):
        return (
            f"{summary} | hint: nsjail could not exec the requested binary; "
            "ensure nsjail exposes runtime filesystem paths (e.g. chroot/mounts include "
            "/usr, /bin, /lib, /lib64) and use an absolute executable path"
        )
    return summary


def _truncate_middle(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 5:
        return text[:max_chars]
    head = (max_chars - 5) // 2
    tail = max_chars - 5 - head
    return f"{text[:head]} ... {text[-tail:]}"


def _looks_like_nsjail_clone_permission_error(output: str) -> bool:
    lowered = output.lower()
    return (
        "clone(" in output
        and "operation not permitted" in lowered
        and "couldn't launch the child process" in lowered
    )


def _looks_like_nsjail_cgroup_namespace_error(output: str) -> bool:
    lowered = output.lower()
    return (
        "couldn't initialize cgroup user namespace" in lowered
        and "launching child process failed" in lowered
    )


def _looks_like_nsjail_execve_failure(output: str) -> bool:
    lowered = output.lower()
    return (
        "execve(" in lowered
        and "no such file or directory" in lowered
        and "couldn't launch the child process" in lowered
    )


def _existing_path(path: str | None) -> str | None:
    if not path:
        return None
    if not Path(path).exists():
        LOG.warning("triage audit telemetry not found path=%s", path)
        return None
    return path


def _compress_audit_sources(
    run_id: str,
    install_audit_path: str | None,
    sandbox_audit_path: str | None,
) -> str | None:
    if install_audit_path and sandbox_audit_path:
        merged_path = str(Path("/tmp") / f"audit-{run_id}.jsonl")
        _merge_audit_logs(
            output_path=merged_path,
            sources=(("install", install_audit_path), ("sandbox", sandbox_audit_path)),
        )
        attachment_path = gzip_file(merged_path)
        Path(install_audit_path).unlink(missing_ok=True)
        Path(sandbox_audit_path).unlink(missing_ok=True)
        LOG.info("triage combined and compressed install+sandbox audit run_id=%s", run_id)
        return attachment_path
    if install_audit_path:
        attachment_path = gzip_file(install_audit_path)
        LOG.info("triage compressed install audit run_id=%s path=%s", run_id, attachment_path)
        return attachment_path
    if sandbox_audit_path:
        attachment_path = gzip_file(sandbox_audit_path)
        LOG.info("triage compressed sandbox audit run_id=%s path=%s", run_id, attachment_path)
        return attachment_path
    return None


def _merge_audit_logs(output_path: str, sources: tuple[tuple[str, str], ...]) -> None:
    output = Path(output_path)
    with output.open("w", encoding="utf-8") as fout:
        for stage, source_path in sources:
            with Path(source_path).open("r", encoding="utf-8", errors="replace") as fin:
                for line in fin:
                    fout.write(f"{stage}:{line}")


def _cleanup_attachment(attachment_path: str | None, run_id: str) -> None:
    if not attachment_path:
        return
    Path(attachment_path).unlink(missing_ok=True)
    LOG.info("triage removed temporary telemetry attachment run_id=%s", run_id)
