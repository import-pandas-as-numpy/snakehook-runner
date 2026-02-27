from __future__ import annotations

import ast
import html
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
HIGHLIGHT_MAX_ITEMS = 200
HTML_LIST_MAX_ITEMS = 400
TOP_EVENT_LIMIT = 25


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
            telemetry_attachment_path = _compress_audit_sources(
                run_id=job.run_id,
                install_audit_path=install_audit_path,
                sandbox_audit_path=None,
            )
            summary = ExecutionSummary(
                run_id=job.run_id,
                ok=False,
                message=f"pip install failed: {_summarize_install_failure(install)}",
                attachment_path=telemetry_attachment_path,
            )
            html_attachment_path = _write_html_report(
                run_id=job.run_id,
                job=job,
                summary=summary,
                highlights=install_highlights,
            )
            attachment_paths = _build_attachment_list(
                telemetry_attachment_path=telemetry_attachment_path,
                html_attachment_path=html_attachment_path,
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
                    attachment_paths=attachment_paths,
                )
            finally:
                _cleanup_attachments(attachment_paths, job.run_id)
            return summary

        if job.mode == RunMode.INSTALL:
            telemetry_attachment_path = _compress_audit_sources(
                run_id=job.run_id,
                install_audit_path=install_audit_path,
                sandbox_audit_path=None,
            )
            summary = ExecutionSummary(
                run_id=job.run_id,
                ok=True,
                message="install ok",
                attachment_path=telemetry_attachment_path,
            )
            html_attachment_path = _write_html_report(
                run_id=job.run_id,
                job=job,
                summary=summary,
                highlights=install_highlights,
            )
            attachment_paths = _build_attachment_list(
                telemetry_attachment_path=telemetry_attachment_path,
                html_attachment_path=html_attachment_path,
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
                    attachment_paths=attachment_paths,
                )
            finally:
                _cleanup_attachments(attachment_paths, job.run_id)
            return summary

        LOG.info("triage sandbox execution starting run_id=%s", job.run_id)
        sandbox = await self._sandbox_executor.run(job)
        run_highlights = _collect_audit_highlights(
            ("install", install_audit_path),
            ("sandbox", _existing_path(sandbox.audit_jsonl_path)),
        )
        telemetry_attachment_path = _compress_audit_sources(
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
            attachment_path=telemetry_attachment_path,
        )
        html_attachment_path = _write_html_report(
            run_id=job.run_id,
            job=job,
            summary=summary,
            highlights=run_highlights,
        )
        attachment_paths = _build_attachment_list(
            telemetry_attachment_path=telemetry_attachment_path,
            html_attachment_path=html_attachment_path,
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
                attachment_paths=attachment_paths,
            )
        finally:
            _cleanup_attachments(attachment_paths, job.run_id)
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


def _build_attachment_list(
    telemetry_attachment_path: str | None,
    html_attachment_path: str | None,
) -> tuple[str, ...]:
    paths: list[str] = []
    if telemetry_attachment_path:
        paths.append(telemetry_attachment_path)
    if html_attachment_path:
        paths.append(html_attachment_path)
    return tuple(paths)


def _cleanup_attachments(attachment_paths: tuple[str, ...], run_id: str) -> None:
    for path in attachment_paths:
        Path(path).unlink(missing_ok=True)
    if attachment_paths:
        LOG.info(
            "triage removed temporary telemetry attachments run_id=%s count=%s",
            run_id,
            len(attachment_paths),
        )


@dataclass(frozen=True)
class AuditHighlights:
    files_written: tuple[str, ...]
    files_read: tuple[str, ...]
    network_connections: tuple[str, ...]
    subprocesses: tuple[str, ...]
    top_events: tuple[str, ...]


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
    files_read: dict[str, None] = {}
    network_connections: dict[str, None] = {}
    subprocesses: dict[str, None] = {}
    event_counts: dict[str, int] = {}
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
                if event:
                    event_counts[event] = event_counts.get(event, 0) + 1
                write_path = _extract_written_file(event, args_text)
                if write_path:
                    files_written[f"{stage}: {write_path}"] = None
                    if len(files_written) > HIGHLIGHT_MAX_ITEMS:
                        files_written.pop(next(iter(files_written)))
                read_path = _extract_read_file(event, args_text)
                if read_path:
                    files_read[f"{stage}: {read_path}"] = None
                    if len(files_read) > HIGHLIGHT_MAX_ITEMS:
                        files_read.pop(next(iter(files_read)))
                connection = _extract_network_connection(event, args_text)
                if connection:
                    network_connections[f"{stage}: {connection}"] = None
                    if len(network_connections) > HIGHLIGHT_MAX_ITEMS:
                        network_connections.pop(next(iter(network_connections)))
                subprocess = _extract_subprocess(event, args_text)
                if subprocess:
                    subprocesses[f"{stage}: {subprocess}"] = None
                    if len(subprocesses) > HIGHLIGHT_MAX_ITEMS:
                        subprocesses.pop(next(iter(subprocesses)))
    top_events = tuple(
        f"{event}: {count}"
        for event, count in sorted(
            event_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:TOP_EVENT_LIMIT]
    )
    return AuditHighlights(
        files_written=tuple(files_written.keys()),
        files_read=tuple(files_read.keys()),
        network_connections=tuple(network_connections.keys()),
        subprocesses=tuple(subprocesses.keys()),
        top_events=top_events,
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


def _extract_read_file(event: str, args_text: str) -> str | None:
    parsed = _parse_literal_args(args_text)
    if event == "open" and isinstance(parsed, tuple) and parsed:
        target = parsed[0] if len(parsed) > 0 else None
        mode = parsed[1] if len(parsed) > 1 else "r"
        if isinstance(target, (str, os.PathLike)) and not _is_write_mode(str(mode)):
            return os.fspath(target)
        return None
    if event == "os.open" and isinstance(parsed, tuple) and len(parsed) >= 2:
        target, flags = parsed[0], parsed[1]
        if not isinstance(target, (str, os.PathLike)) or not isinstance(flags, int):
            return None
        has_write_flag = bool(
            flags
            & (
                os.O_WRONLY
                | os.O_RDWR
                | os.O_APPEND
                | os.O_CREAT
                | os.O_TRUNC
            ),
        )
        if not has_write_flag:
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


def _extract_subprocess(event: str, args_text: str) -> str | None:
    parsed = _parse_literal_args(args_text)
    if event in {"subprocess.Popen", "subprocess.run", "os.system"}:
        if isinstance(parsed, tuple) and parsed:
            return _normalize_command(parsed[0])
        if event == "os.system":
            return _truncate_middle(args_text, 120)
    if event in {"os.exec", "os.execve", "os.posix_spawn", "os.spawn"}:
        if isinstance(parsed, tuple) and parsed:
            return _normalize_command(parsed[0])
    return None


def _normalize_command(value: object) -> str:
    if isinstance(value, (str, os.PathLike)):
        return _truncate_middle(os.fspath(value), 120)
    if isinstance(value, (list, tuple)):
        rendered = " ".join(_normalize_command(part) for part in value[:8])
        return _truncate_middle(rendered, 120)
    return _truncate_middle(repr(value), 120)


def _parse_literal_args(args_text: str) -> object | None:
    try:
        return ast.literal_eval(args_text)
    except (ValueError, SyntaxError):
        return None


def _is_write_mode(mode: str) -> bool:
    return any(flag in mode for flag in ("w", "a", "x", "+"))


def _write_html_report(
    run_id: str,
    job: RunJob,
    summary: ExecutionSummary,
    highlights: AuditHighlights,
) -> str | None:
    has_data = any(
        (
            highlights.files_written,
            highlights.files_read,
            highlights.network_connections,
            highlights.subprocesses,
            highlights.top_events,
        ),
    )
    if not has_data:
        return None
    output_path = Path("/tmp") / f"audit-report-{run_id}.html"
    payload = _build_html_report(job=job, summary=summary, highlights=highlights)
    output_path.write_text(payload, encoding="utf-8")
    return str(output_path)


def _build_html_report(job: RunJob, summary: ExecutionSummary, highlights: AuditHighlights) -> str:
    subtitle = f"{job.package_name}=={job.version} | mode={job.mode.value} | run_id={job.run_id}"
    return (
        "<!doctype html>\n"
        "<html lang='en'>\n"
        "<head>\n"
        "  <meta charset='utf-8' />\n"
        "  <meta name='viewport' content='width=device-width, initial-scale=1' />\n"
        "  <title>Snakehook Triage Report</title>\n"
        "  <style>\n"
        "    :root { --bg:#f4f8f6; --text:#1a2c24; --muted:#49675a; --card:#ffffff;"
        " --ok:#1f8f4d; --bad:#b42318; --warn:#b26a00; --line:#d7e6df; }\n"
        "    * { box-sizing:border-box; }\n"
        "    body { margin:0; font-family:'Segoe UI',Tahoma,Verdana,sans-serif;"
        " background:radial-gradient(circle at top left,#e9f7ef,#f4f8f6 45%,#eef4ff);"
        " color:var(--text); }\n"
        "    .wrap { max-width:1200px; margin:0 auto; padding:24px; }\n"
        "    .hero { border:1px solid var(--line); border-radius:16px; background:var(--card);"
        " padding:20px; box-shadow:0 10px 30px rgba(19,49,32,0.08); }\n"
        "    .title { margin:0; font-size:30px; letter-spacing:0.2px; }\n"
        "    .subtitle { margin:8px 0 0; color:var(--muted); font-size:14px; }\n"
        "    .status { margin-top:14px; display:inline-block; padding:6px 12px;"
        " border-radius:999px; font-weight:700; font-size:12px; text-transform:uppercase; }\n"
        "    .status.ok { background:#e7f8ef; color:var(--ok); }\n"
        "    .status.fail { background:#ffe8e6; color:var(--bad); }\n"
        "    .status.timeout { background:#fff1df; color:var(--warn); }\n"
        "    .grid { margin-top:18px; display:grid;"
        " grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:14px; }\n"
        "    .card { border:1px solid var(--line); border-radius:14px; background:var(--card);"
        " box-shadow:0 8px 20px rgba(37,63,51,0.06); }\n"
        "    .card h2 { margin:0; padding:14px 16px; font-size:16px;"
        " border-bottom:1px solid var(--line); }\n"
        "    .list { margin:0; padding:12px 16px 16px; list-style:none; }\n"
        "    .list li { margin:0 0 8px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;"
        " font-size:12px; line-height:1.45; background:#f8fbf9;"
        " border:1px solid #e4efe9; border-radius:8px;"
        " padding:8px 10px; word-break:break-word; }\n"
        "    .empty { padding:14px 16px; color:var(--muted); font-size:13px; }\n"
        "    .meta { margin-top:16px; border-top:1px solid var(--line); padding-top:12px;"
        " font-size:13px; color:var(--muted); }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <div class='wrap'>\n"
        "    <section class='hero'>\n"
        "      <h1 class='title'>Snakehook Triage Report</h1>\n"
        f"      <p class='subtitle'>{html.escape(subtitle)}</p>\n"
        f"      {_render_status_badge(summary)}\n"
        f"      <div class='meta'>{html.escape(summary.message)}</div>\n"
        "    </section>\n"
        "    <section class='grid'>\n"
        f"{_render_html_card('Files Written', highlights.files_written)}\n"
        f"{_render_html_card('Files Opened/Read', highlights.files_read)}\n"
        f"{_render_html_card('Network Connections', highlights.network_connections)}\n"
        f"{_render_html_card('Subprocess Activity', highlights.subprocesses)}\n"
        f"{_render_html_card('Top Audit Events', highlights.top_events)}\n"
        "    </section>\n"
        "  </div>\n"
        "</body>\n"
        "</html>\n"
    )


def _render_status_badge(summary: ExecutionSummary) -> str:
    klass = "ok" if summary.ok else "fail"
    label = "ok" if summary.ok else "failed"
    if not summary.ok and "timed out" in summary.message.lower():
        klass = "timeout"
        label = "timed out"
    return f"<span class='status {klass}'>{html.escape(label)}</span>"


def _render_html_card(title: str, items: tuple[str, ...]) -> str:
    if not items:
        return (
            "<article class='card'>"
            f"<h2>{html.escape(title)}</h2>"
            "<div class='empty'>No events captured.</div>"
            "</article>"
        )
    rows = "".join(
        f"<li>{html.escape(item)}</li>"
        for item in items[:HTML_LIST_MAX_ITEMS]
    )
    extra_note = ""
    if len(items) > HTML_LIST_MAX_ITEMS:
        extra_note = f"<li>... +{len(items) - HTML_LIST_MAX_ITEMS} more</li>"
    return (
        "<article class='card'>"
        f"<h2>{html.escape(title)}</h2>"
        f"<ul class='list'>{rows}{extra_note}</ul>"
        "</article>"
    )
