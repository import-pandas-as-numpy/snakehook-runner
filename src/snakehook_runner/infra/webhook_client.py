from __future__ import annotations

from pathlib import Path

import httpx

MAX_SUMMARY_CHARS = 1000


class DiscordWebhookClient:
    def __init__(self, webhook_url: str, timeout_sec: float = 5.0) -> None:
        self._url = webhook_url
        self._timeout_sec = timeout_sec

    async def send_summary(self, run_id: str, summary: str, attachment_path: str | None) -> None:
        data = {"content": _format_discord_message(run_id, summary, attachment_path)}
        files = None
        if attachment_path:
            files = {
                "file": (
                    Path(attachment_path).name,
                    open(attachment_path, "rb"),
                    "application/gzip",
                )
            }
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                await client.post(self._url, data=data, files=files)
        finally:
            if files:
                files["file"][1].close()


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
