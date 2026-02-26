from __future__ import annotations

import httpx


class DiscordWebhookClient:
    def __init__(self, webhook_url: str, timeout_sec: float = 5.0) -> None:
        self._url = webhook_url
        self._timeout_sec = timeout_sec

    async def send_summary(self, run_id: str, summary: str, attachment_path: str | None) -> None:
        data = {"content": f"run_id={run_id} {summary}"}
        files = None
        if attachment_path:
            files = {
                "file": (
                    attachment_path.split("/")[-1],
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
