from __future__ import annotations

import json
from pathlib import Path

from snakehook_runner.infra.webhook_client import DiscordWebhookClient


class FakeAsyncClient:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self.posts: list[tuple[str, dict, object]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url: str, data: dict, files=None):
        self.posts.append((url, data, files))
        return FakeResponse()


class FakeResponse:
    def raise_for_status(self) -> None:
        return None


async def test_webhook_client_posts_summary_without_attachment(monkeypatch) -> None:
    created: list[FakeAsyncClient] = []

    def fake_client(*, timeout: float):
        client = FakeAsyncClient(timeout=timeout)
        created.append(client)
        return client

    monkeypatch.setattr("snakehook_runner.infra.webhook_client.httpx.AsyncClient", fake_client)

    client = DiscordWebhookClient("https://discord.example/webhook")
    await client.send_summary("r1", "done", None)

    assert len(created) == 1
    url, data, files = created[0].posts[0]
    assert url == "https://discord.example/webhook"
    payload = json.loads(data["payload_json"])
    assert "**Snakehook Triage Result**" in payload["content"]
    assert "Status: `OK`" in payload["content"]
    assert "Run ID: `r1`" in payload["content"]
    assert "```text\ndone\n```" in payload["content"]
    assert files is None


async def test_webhook_client_posts_with_attachment_and_closes_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    created: list[FakeAsyncClient] = []

    def fake_client(*, timeout: float):
        c = FakeAsyncClient(timeout=timeout)
        created.append(c)
        return c

    monkeypatch.setattr("snakehook_runner.infra.webhook_client.httpx.AsyncClient", fake_client)

    attachment = tmp_path / "audit.jsonl.gz"
    attachment.write_bytes(b"x")

    client = DiscordWebhookClient("https://discord.example/webhook")
    await client.send_summary("r2", "done", str(attachment))

    _, data, files = created[0].posts[0]
    payload = json.loads(data["payload_json"])
    assert "Attachment: `audit.jsonl.gz`" in payload["content"]
    handle = files["files[0]"][1]
    assert handle.closed is True
