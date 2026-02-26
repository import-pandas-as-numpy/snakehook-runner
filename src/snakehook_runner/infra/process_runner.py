from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

MAX_CAPTURE_BYTES = 1_048_576
LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


class AsyncProcessRunner:
    async def run(
        self,
        command: list[str],
        timeout_sec: int,
        env: dict[str, str] | None = None,
    ) -> ProcessResult:
        LOG.info("process start timeout_sec=%s argv=%s", timeout_sec, command[:8])
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout_task = asyncio.create_task(_read_capped(proc.stdout, MAX_CAPTURE_BYTES))
        stderr_task = asyncio.create_task(_read_capped(proc.stderr, MAX_CAPTURE_BYTES))
        timed_out = False
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
        except TimeoutError:
            timed_out = True
            proc.kill()
            await proc.wait()

        stdout_b, stdout_truncated = await stdout_task
        stderr_b, stderr_truncated = await stderr_task
        process_result = ProcessResult(
            returncode=124 if timed_out else (proc.returncode or 0),
            stdout=_decode_output(stdout_b, stdout_truncated),
            stderr=_decode_output(stderr_b, stderr_truncated),
            timed_out=timed_out,
        )
        LOG.info(
            "process complete timed_out=%s returncode=%s stdout_bytes=%s stderr_bytes=%s",
            process_result.timed_out,
            process_result.returncode,
            len(process_result.stdout),
            len(process_result.stderr),
        )
        return process_result


async def _read_capped(
    stream: asyncio.StreamReader | None,
    max_bytes: int,
) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False

    chunks: list[bytes] = []
    total = 0
    truncated = False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        kept_len = 0
        if total < max_bytes:
            remaining = max_bytes - total
            kept = chunk[:remaining]
            chunks.append(kept)
            kept_len = len(kept)
            total += kept_len
        if len(chunk) > kept_len:
            truncated = True
    return b"".join(chunks), truncated


def _decode_output(raw: bytes, truncated: bool) -> str:
    text = raw.decode("utf-8", errors="replace")
    if truncated:
        return f"{text}\n[output truncated]\n"
    return text
