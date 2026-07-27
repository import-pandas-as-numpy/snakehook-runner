from __future__ import annotations

from pathlib import Path

import pytest

from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import RunJob
from snakehook_runner.infra.pip_installer import (
    RealPipInstaller,
    _build_pip_audit_sitecustomize,
    _dir_size,
)
from snakehook_runner.infra.process_runner import ProcessResult


class FakeRunner:
    def __init__(self, result: ProcessResult) -> None:
        self._result = result
        self.command: list[str] | None = None
        self.env: dict[str, str] | None = None

    async def run(
        self,
        command: list[str],
        timeout_sec: int,
        env: dict[str, str] | None = None,
    ) -> ProcessResult:
        self.command = command
        self.env = env
        if env and env.get("SNAKEHOOK_AUDIT_PATH"):
            mount = command[command.index("--bindmount") + 1]
            host_job_dir = Path(mount.split(":", 1)[0])
            (host_job_dir / "install-audit.jsonl").write_text("event\n", encoding="utf-8")
        return self._result


def _settings(cap: int) -> Settings:
    return Settings(
        api_token="t",
        discord_webhook_url="https://discord.example/webhook",
        max_concurrency=2,
        queue_limit=20,
        per_ip_rate_limit=10,
        per_ip_rate_window_sec=60,
        run_timeout_sec=45,
        rlimit_cpu_sec=30,
        rlimit_as_mb=1024,
        cgroup_pids_max=128,
        cgroup_mem_max_bytes=1_073_741_824,
        cgroup_cpu_ms_per_sec=800,
        rlimit_nofile=1024,
        max_download_bytes=cap,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )


@pytest.fixture(autouse=True)
def isolated_paths(monkeypatch, tmp_path: Path) -> None:
    work_root = tmp_path / "work"
    code_root = tmp_path / "code"
    work_root.mkdir()
    code_root.mkdir()
    monkeypatch.setenv("SNAKEHOOK_WORK_ROOT", str(work_root))
    monkeypatch.setenv("SNAKEHOOK_CODE_ROOT", str(code_root))
    monkeypatch.setattr(
        "snakehook_runner.infra.nsjail_executor._require_paths",
        lambda *paths: None,
    )


async def test_pip_installer_uses_nsjail_with_per_job_cache(tmp_path: Path) -> None:
    runner = FakeRunner(ProcessResult(returncode=0, stdout="ok", stderr="", timed_out=False))
    installer = RealPipInstaller(
        process_runner=runner,
        settings=_settings(cap=10_000),
    )

    result = await installer.install(RunJob("run-1", "requests", "2.32.0"))

    assert result.ok is True
    command_text = " ".join(runner.command or [])
    assert "nsjail" in command_text
    assert "--env LD_LIBRARY_PATH=" in command_text
    assert "--env PIP_CACHE_DIR=/work/pip-cache" in command_text
    assert "/usr/local/bin/python3 -m pip install requests==2.32.0" in command_text
    assert "--target /site" in command_text
    assert "--cache-dir /work/pip-cache" in command_text
    assert f"--bindmount {tmp_path / 'code' / 'run-1'}:/site" in command_text
    assert result.audit_jsonl_path is not None
    assert result.audit_jsonl_path == str(
        tmp_path / "work" / "run-1" / "install-audit.jsonl"
    )
    assert runner.env is not None
    assert "SNAKEHOOK_AUDIT_PATH" in runner.env
    assert "SNAKEHOOK_AUDIT_LIMIT" in runner.env
    assert runner.env["PYTHONPATH"] == "/work/audit-bootstrap:/site"


async def test_pip_installer_rejects_when_download_cap_exceeded(tmp_path: Path) -> None:
    class GrowingRunner(FakeRunner):
        async def run(
            self,
            command: list[str],
            timeout_sec: int,
            env: dict[str, str] | None = None,
        ) -> ProcessResult:
            mount = command[command.index("--bindmount") + 1]
            cache_dir = Path(mount.split(":", 1)[0]) / "pip-cache"
            cache_dir.mkdir()
            (cache_dir / "after.bin").write_bytes(b"y" * 20)
            return await super().run(command, timeout_sec, env)

    installer = RealPipInstaller(
        process_runner=GrowingRunner(
            ProcessResult(returncode=0, stdout="ok", stderr="", timed_out=False),
        ),
        settings=_settings(cap=5),
    )

    result = await installer.install(RunJob("run-2", "requests", "2.32.0"))

    assert result.ok is False
    assert "download byte cap exceeded" in result.stderr


async def test_pip_installer_rejects_failed_pip_invocation(tmp_path: Path) -> None:
    runner = FakeRunner(
        ProcessResult(returncode=2, stdout="x", stderr="pip failed", timed_out=False),
    )
    installer = RealPipInstaller(
        process_runner=runner,
        settings=_settings(cap=10_000),
    )

    result = await installer.install(RunJob("run-3", "requests", "2.32.0"))

    assert result.ok is False
    assert result.stderr == "pip failed"


def test_dir_size_returns_zero_for_missing_directory(tmp_path: Path) -> None:
    missing = tmp_path / "missing-cache"
    assert _dir_size(missing) == 0


def test_dir_size_handles_vanishing_file(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "pip-cache"
    root.mkdir()
    keep = root / "keep.bin"
    gone = root / "gone.bin"
    keep.write_bytes(b"abc")
    gone.write_bytes(b"def")

    original_stat = Path.stat

    def fake_stat(path: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == gone:
            raise FileNotFoundError
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", lambda self: self.suffix == ".bin")
    monkeypatch.setattr(Path, "stat", fake_stat)

    assert _dir_size(root) == 3


def test_pip_audit_sitecustomize_emits_timestamp_args_and_caller_fields() -> None:
    source = _build_pip_audit_sitecustomize()
    assert "'timestamp'" in source
    assert "'args'" in source
    assert "'caller'" in source
    assert "sys._getframe(1)" in source
    assert "json.dumps(payload" in source
    assert "in_hook=False" in source
    assert "if in_hook or written >= limit" in source
    assert "except OSError" in source
    assert "caller_file=frame_info.get('file')" in source
    assert "if caller_file == __file__" in source
