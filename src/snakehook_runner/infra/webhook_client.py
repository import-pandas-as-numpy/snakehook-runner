from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx

MAX_SUMMARY_CHARS = 1000
LOG = logging.getLogger(__name__)


class DiscordWebhookClient:
    def __init__(self, webhook_url: str, timeout_sec: float = 5.0) -> None:
        self._url = webhook_url
        self._timeout_sec = timeout_sec

    async def send_summary(self, run_id: str, summary: str, attachment_path: str | None) -> None:
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
                run_id,
                attachment_path,
            )
        content = _format_discord_message(run_id, summary, resolved_attachment_path)
        data: dict[str, str] = {"payload_json": json.dumps({"content": content})}
        LOG.info(
            "posting discord summary run_id=%s has_attachment=%s",
            run_id,
            resolved_attachment_path is not None,
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                response = await client.post(self._url, data=data, files=files)
                response.raise_for_status()
        finally:
            if files:
                files["files[0]"][1].close()


def _format_discord_message(run_id: str, summary: str, attachment_path: str | None) -> str:
    status = "FAILED" if "failed" in summary.lower() else "OK"
    normalized = " ".join(summary.split())
    if len(normalized) > MAX_SUMMARY_CHARS:
        normalized = f"{normalized[:MAX_SUMMARY_CHARS - 3]}..."
    normalized = normalized.replace("```", "'''")
    lines = [
        "**Snakehook Triage Result**",
        f"Status: `{status}`",
        f"Run ID: `{run_id}`",
        "Summary:",
        f"```text\n{normalized}\n```",
    ]
    if attachment_path:
        lines.append(f"Attachment: `{Path(attachment_path).name}`")
    return "\n".join(lines)
