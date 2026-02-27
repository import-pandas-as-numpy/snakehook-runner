from __future__ import annotations

import ast
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from snakehook_runner.core.interfaces import (
    PipInstaller,
    PipInstallResult,
    RunJob,
    RunMode,
    SandboxExecutor,
    WebhookClient,
    WebhookSummary,
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
        install_highlights = _collect_audit_highlights(("install", install_audit_path))
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
                    _build_webhook_summary(
                        job=job,
                        ok=False,
                        summary=summary.message,
                        timed_out=False,
                        stdout_bytes=len(install.stdout),
                        stderr_bytes=len(install.stderr),
                        highlights=install_highlights,
                    ),
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
                    _build_webhook_summary(
                        job=job,
                        ok=True,
                        summary=summary.message,
                        timed_out=False,
                        stdout_bytes=len(install.stdout),
                        stderr_bytes=len(install.stderr),
                        highlights=install_highlights,
                    ),
                    attachment_path,
                )
            finally:
                _cleanup_attachment(attachment_path, job.run_id)
            return summary

        LOG.info("triage sandbox execution starting run_id=%s", job.run_id)
        sandbox = await self._sandbox_executor.run(job)
        run_highlights = _collect_audit_highlights(
            ("install", install_audit_path),
            ("sandbox", _existing_path(sandbox.audit_jsonl_path)),
        )
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
            await self._webhook_client.send_summary(
                _build_webhook_summary(
                    job=job,
                    ok=sandbox.ok,
                    summary=summary.message,
                    timed_out=sandbox.timed_out,
                    stdout_bytes=len(sandbox.stdout),
                    stderr_bytes=len(sandbox.stderr),
                    highlights=run_highlights,
                ),
                attachment_path,
            )
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


@dataclass(frozen=True)
class AuditHighlights:
    files_written: tuple[str, ...]
    network_connections: tuple[str, ...]


def _build_webhook_summary(
    job: RunJob,
    ok: bool,
    summary: str,
    timed_out: bool,
    stdout_bytes: int,
    stderr_bytes: int,
    highlights: AuditHighlights,
) -> WebhookSummary:
    return WebhookSummary(
        run_id=job.run_id,
        package_name=job.package_name,
        version=job.version,
        mode=job.mode,
        ok=ok,
        summary=summary,
        timed_out=timed_out,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        file_path=job.file_path,
        entrypoint=job.entrypoint,
        module_name=job.module_name,
        files_written=highlights.files_written,
        network_connections=highlights.network_connections,
    )


def _collect_audit_highlights(*stage_paths: tuple[str, str | None]) -> AuditHighlights:
    files_written: dict[str, None] = {}
    network_connections: dict[str, None] = {}
    for stage, path in stage_paths:
        if not path:
            continue
        with Path(path).open("r", encoding="utf-8", errors="replace") as source:
            for raw_line in source:
                record = _parse_audit_record(raw_line)
                if not record:
                    continue
                event = str(record.get("event") or "")
                args_text = str(record.get("args") or "")
                write_path = _extract_written_file(event, args_text)
                if write_path:
                    files_written[f"{stage}: {write_path}"] = None
                connection = _extract_network_connection(event, args_text)
                if connection:
                    network_connections[f"{stage}: {connection}"] = None
    return AuditHighlights(
        files_written=tuple(files_written.keys()),
        network_connections=tuple(network_connections.keys()),
    )


def _parse_audit_record(raw_line: str) -> dict[str, object] | None:
    line = raw_line.strip()
    if not line:
        return None
    payload = line
    if not payload.startswith("{"):
        prefix, sep, tail = payload.partition(":")
        if sep and prefix in {"install", "sandbox"} and tail.startswith("{"):
            payload = tail
    if not payload.startswith("{"):
        return None
    try:
        loaded = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(loaded, dict):
        return None
    return loaded


def _extract_written_file(event: str, args_text: str) -> str | None:
    parsed = _parse_literal_args(args_text)
    if event == "open" and isinstance(parsed, tuple) and parsed:
        target = parsed[0] if len(parsed) > 0 else None
        mode = parsed[1] if len(parsed) > 1 else "r"
        if isinstance(target, (str, os.PathLike)) and _is_write_mode(str(mode)):
            return os.fspath(target)
        return None
    if event == "os.open" and isinstance(parsed, tuple) and len(parsed) >= 2:
        target, flags = parsed[0], parsed[1]
        if isinstance(target, (str, os.PathLike)) and isinstance(flags, int):
            if flags & (
                os.O_WRONLY
                | os.O_RDWR
                | os.O_APPEND
                | os.O_CREAT
                | os.O_TRUNC
            ):
                return os.fspath(target)
    return None


def _extract_network_connection(event: str, args_text: str) -> str | None:
    if event != "socket.connect":
        return None
    host_match = re.search(
        r"\(\s*([\"']?[^\"',\)\s]+[\"']?)\s*,\s*(\d+)\s*\)",
        args_text,
    )
    if not host_match:
        return None
    host = host_match.group(1).strip("\"'")
    port = host_match.group(2)
    return f"{host}:{port}"


def _parse_literal_args(args_text: str) -> object | None:
    try:
        return ast.literal_eval(args_text)
    except (ValueError, SyntaxError):
        return None


def _is_write_mode(mode: str) -> bool:
    return any(flag in mode for flag in ("w", "a", "x", "+"))
