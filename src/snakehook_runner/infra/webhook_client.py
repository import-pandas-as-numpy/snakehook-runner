from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx

from snakehook_runner.core.interfaces import WebhookSummary

MAX_SUMMARY_CHARS = 1000
MAX_FIELD_ITEMS = 10
MAX_FIELD_VALUE_CHARS = 1000
LOG = logging.getLogger(__name__)


class DiscordWebhookClient:
    def __init__(self, webhook_url: str, timeout_sec: float = 5.0) -> None:
        self._url = webhook_url
        self._timeout_sec = timeout_sec

    async def send_summary(self, summary: WebhookSummary, attachment_path: str | None) -> None:
        resolved_attachment_path: str | None = None
        files = None
        if attachment_path and Path(attachment_path).exists():
            resolved_attachment_path = attachment_path
            files = {
                "files[0]": (
                    Path(attachment_path).name,
                    open(attachment_path, "rb"),
                    "application/gzip",
                )
            }
        elif attachment_path:
            LOG.warning(
                "webhook attachment missing; sending summary without attachment run_id=%s path=%s",
                summary.run_id,
                attachment_path,
            )
        payload = _build_discord_payload(summary, resolved_attachment_path)
        data: dict[str, str] = {"payload_json": json.dumps(payload)}
        LOG.info(
            "posting discord summary run_id=%s has_attachment=%s",
            summary.run_id,
            resolved_attachment_path is not None,
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                response = await client.post(self._url, data=data, files=files)
                response.raise_for_status()
        finally:
            if files:
                files["files[0]"][1].close()


def _build_discord_payload(
    summary: WebhookSummary,
    attachment_path: str | None,
) -> dict[str, object]:
    attachment_note = ""
    if attachment_path:
        attachment_note = f"\nAttachment: `{Path(attachment_path).name}`"
    normalized = _normalize_summary(summary.summary)
    color = 0x2ECC71 if summary.ok else 0xE74C3C
    if summary.timed_out:
        color = 0xF39C12
    embed = {
        "title": "Snakehook Triage Result",
        "description": f"```text\n{normalized}\n```{attachment_note}",
        "color": color,
        "fields": [
            {"name": "Run ID", "value": f"`{summary.run_id}`", "inline": True},
            {"name": "Status", "value": f"`{_status_label(summary)}`", "inline": True},
            {"name": "Mode", "value": f"`{summary.mode.value}`", "inline": True},
            {"name": "Package", "value": f"`{summary.package_name}`", "inline": True},
            {"name": "Version", "value": f"`{summary.version}`", "inline": True},
            {"name": "Timed Out", "value": f"`{summary.timed_out}`", "inline": True},
            {
                "name": "Output",
                "value": (
                    f"`stdout={summary.stdout_bytes}B`"
                    f"\n`stderr={summary.stderr_bytes}B`"
                ),
                "inline": True,
            },
            {
                "name": "Run Details",
                "value": _render_run_details(summary),
                "inline": False,
            },
            {
                "name": "Files Written",
                "value": _render_list_field(
                    summary.files_written,
                    empty="No write events captured.",
                ),
                "inline": False,
            },
            {
                "name": "Network Connections",
                "value": _render_list_field(
                    summary.network_connections,
                    empty="No connect events captured.",
                ),
                "inline": False,
            },
        ],
    }
    return {"embeds": [embed]}


def _normalize_summary(summary: str) -> str:
    normalized = " ".join(summary.split())
    if len(normalized) > MAX_SUMMARY_CHARS:
        normalized = f"{normalized[:MAX_SUMMARY_CHARS - 3]}..."
    return normalized.replace("```", "'''")


def _status_label(summary: WebhookSummary) -> str:
    if summary.ok:
        return "OK"
    if summary.timed_out:
        return "FAILED (TIMED OUT)"
    return "FAILED"


def _render_run_details(summary: WebhookSummary) -> str:
    lines = []
    if summary.file_path:
        lines.append(f"`file_path={summary.file_path}`")
    if summary.entrypoint:
        lines.append(f"`entrypoint={summary.entrypoint}`")
    if summary.module_name:
        lines.append(f"`module_name={summary.module_name}`")
    if not lines:
        return "No optional run targets provided."
    return "\n".join(lines)


def _render_list_field(items: tuple[str, ...], empty: str) -> str:
    if not items:
        return empty
    shown = [f"• `{item}`" for item in items[:MAX_FIELD_ITEMS]]
    if len(items) > MAX_FIELD_ITEMS:
        shown.append(f"• `... +{len(items) - MAX_FIELD_ITEMS} more`")
    rendered = "\n".join(shown)
    if len(rendered) <= MAX_FIELD_VALUE_CHARS:
        return rendered
    return f"{rendered[:MAX_FIELD_VALUE_CHARS - 3]}..."
