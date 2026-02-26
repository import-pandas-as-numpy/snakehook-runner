from __future__ import annotations

from pathlib import Path

from snakehook_runner.core.config import Settings
from snakehook_runner.infra.pip_installer import RealPipInstaller, _dir_size
from snakehook_runner.infra.process_runner import ProcessResult


class FakeRunner:
    def __init__(self, result: ProcessResult) -> None:
        self._result = result
        self.command: list[str] | None = None

    async def run(
        self,
        command: list[str],
        timeout_sec: int,
        env: dict[str, str] | None = None,
    ) -> ProcessResult:
        self.command = command
        return self._result


def _settings(cache_dir: str, cap: int) -> Settings:
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
        enable_cgroup_pids_limit=True,
        rlimit_nofile=1024,
        pip_cache_dir=cache_dir,
        max_download_bytes=cap,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )


async def test_pip_installer_uses_nsjail_with_readonly_cache_mount(tmp_path: Path) -> None:
    cache_dir = tmp_path / "pip-cache"
    cache_dir.mkdir()
    runner = FakeRunner(ProcessResult(returncode=0, stdout="ok", stderr="", timed_out=False))
    installer = RealPipInstaller(
        process_runner=runner,
        settings=_settings(str(cache_dir), cap=10_000),
    )

    result = await installer.install("requests", "2.32.0")

    assert result.ok is True
    command_text = " ".join(runner.command or [])
    assert "nsjail" in command_text
    assert f"--bindmount_ro {cache_dir}:{cache_dir}" in command_text
    assert "python -m pip install requests==2.32.0" in command_text


async def test_pip_installer_rejects_when_download_cap_exceeded(tmp_path: Path) -> None:
    cache_dir = tmp_path / "pip-cache"
    cache_dir.mkdir()
    (cache_dir / "before.bin").write_bytes(b"x")

    class GrowingRunner(FakeRunner):
        async def run(
            self,
            command: list[str],
            timeout_sec: int,
            env: dict[str, str] | None = None,
        ) -> ProcessResult:
            (cache_dir / "after.bin").write_bytes(b"y" * 20)
            return await super().run(command, timeout_sec, env)

    installer = RealPipInstaller(
        process_runner=GrowingRunner(
            ProcessResult(returncode=0, stdout="ok", stderr="", timed_out=False),
        ),
        settings=_settings(str(cache_dir), cap=5),
    )

    result = await installer.install("requests", "2.32.0")

    assert result.ok is False
    assert "download byte cap exceeded" in result.stderr


async def test_pip_installer_rejects_failed_pip_invocation(tmp_path: Path) -> None:
    cache_dir = tmp_path / "pip-cache"
    cache_dir.mkdir()
    runner = FakeRunner(
        ProcessResult(returncode=2, stdout="x", stderr="pip failed", timed_out=False),
    )
    installer = RealPipInstaller(
        process_runner=runner,
        settings=_settings(str(cache_dir), cap=10_000),
    )

    result = await installer.install("requests", "2.32.0")

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
