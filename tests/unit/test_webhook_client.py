from __future__ import annotations

import json
from pathlib import Path

from snakehook_runner.core.interfaces import RunMode, WebhookSummary
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


def _summary(run_id: str) -> WebhookSummary:
    return WebhookSummary(
        run_id=run_id,
        package_name="requests",
        version="2.32.0",
        mode=RunMode.EXECUTE,
        ok=True,
        summary="done",
        timed_out=False,
        stdout_bytes=11,
        stderr_bytes=3,
        file_path="/tmp/script.py",
        entrypoint="requests.cli:main",
        module_name="requests",
        files_written=("sandbox: /tmp/out.txt",),
        network_connections=("sandbox: pypi.org:443",),
    )


async def test_webhook_client_posts_summary_without_attachment(monkeypatch) -> None:
    created: list[FakeAsyncClient] = []

    def fake_client(*, timeout: float):
        client = FakeAsyncClient(timeout=timeout)
        created.append(client)
        return client

    monkeypatch.setattr("snakehook_runner.infra.webhook_client.httpx.AsyncClient", fake_client)

    client = DiscordWebhookClient("https://discord.example/webhook")
    await client.send_summary(_summary("r1"), None)

    assert len(created) == 1
    url, data, files = created[0].posts[0]
    assert url == "https://discord.example/webhook"
    payload = json.loads(data["payload_json"])
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert embed["title"] == "Snakehook Triage Result"
    assert "```text\ndone\n```" in embed["description"]
    fields = {field["name"]: field["value"] for field in embed["fields"]}
    assert fields["Run ID"] == "`r1`"
    assert fields["Status"] == "`OK`"
    assert fields["Package"] == "`requests`"
    assert "sandbox: /tmp/out.txt" in fields["Files Written"]
    assert "sandbox: pypi.org:443" in fields["Network Connections"]
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
    await client.send_summary(_summary("r2"), str(attachment))

    _, data, files = created[0].posts[0]
    payload = json.loads(data["payload_json"])
    embed = payload["embeds"][0]
    assert "Attachment: `audit.jsonl.gz`" in embed["description"]
    handle = files["files[0]"][1]
    assert handle.closed is True
