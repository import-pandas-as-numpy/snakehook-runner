from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class RunMode(StrEnum):
    INSTALL = "install"
    EXECUTE = "execute"
    EXECUTE_MODULE = "execute_module"


@dataclass(frozen=True)
class RunJob:
    run_id: str
    package_name: str
    version: str
    mode: RunMode = RunMode.INSTALL
    file_path: str | None = None
    entrypoint: str | None = None
    module_name: str | None = None


@dataclass(frozen=True)
class PipInstallResult:
    ok: bool
    stdout: str
    stderr: str
    audit_jsonl_path: str | None = None


@dataclass(frozen=True)
class SandboxResult:
    ok: bool
    stdout: str
    stderr: str
    timed_out: bool
    audit_jsonl_path: str | None


@dataclass(frozen=True)
class WebhookSummary:
    run_id: str
    package_name: str
    version: str
    mode: RunMode
    ok: bool
    summary: str
    timed_out: bool
    stdout_bytes: int
    stderr_bytes: int
    file_path: str | None
    entrypoint: str | None
    module_name: str | None
    files_written: tuple[str, ...]
    network_connections: tuple[str, ...]


class PipInstaller(Protocol):
    async def install(self, package_name: str, version: str) -> PipInstallResult:
        raise NotImplementedError


class SandboxExecutor(Protocol):
    async def run(self, job: RunJob) -> SandboxResult:
        raise NotImplementedError


class WebhookClient(Protocol):
    async def send_summary(self, summary: WebhookSummary, attachment_path: str | None) -> None:
        raise NotImplementedError
