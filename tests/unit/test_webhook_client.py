from __future__ import annotations

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
    assert "**Snakehook Triage Result**" in data["content"]
    assert "Status: `OK`" in data["content"]
    assert "Run ID: `r1`" in data["content"]
    assert "```text\ndone\n```" in data["content"]
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
    assert "Attachment: `audit.jsonl.gz`" in data["content"]
    handle = files["file"][1]
    assert handle.closed is True
