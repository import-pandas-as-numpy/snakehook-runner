from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RunJob:
    run_id: str
    package_name: str
    version: str


@dataclass(frozen=True)
class PipInstallResult:
    ok: bool
    stdout: str
    stderr: str


@dataclass(frozen=True)
class SandboxResult:
    ok: bool
    stdout: str
    stderr: str
    timed_out: bool
    audit_jsonl_path: str | None


class PipInstaller(Protocol):
    async def install(self, package_name: str, version: str) -> PipInstallResult:
        raise NotImplementedError


class SandboxExecutor(Protocol):
    async def run(self, job: RunJob) -> SandboxResult:
        raise NotImplementedError


class WebhookClient(Protocol):
    async def send_summary(self, run_id: str, summary: str, attachment_path: str | None) -> None:
        raise NotImplementedError
