from __future__ import annotations

from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import RunJob, RunMode
from snakehook_runner.infra.nsjail_executor import NsJailSandboxExecutor
from snakehook_runner.infra.process_runner import ProcessResult


class FakeRunner:
    def __init__(self) -> None:
        self.command: list[str] | None = None
        self.timeout_sec: int | None = None

    async def run(
        self,
        command: list[str],
        timeout_sec: int,
        env: dict[str, str] | None = None,
    ) -> ProcessResult:
        self.command = command
        self.timeout_sec = timeout_sec
        return ProcessResult(returncode=124, stdout="", stderr="", timed_out=True)


def _settings() -> Settings:
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
        rlimit_nofile=1024,
        pip_cache_dir="/var/cache/pip",
        max_download_bytes=300_000_000,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )


async def test_nsjail_command_contains_limits_and_readonly_cache_mount() -> None:
    runner = FakeRunner()
    executor = NsJailSandboxExecutor(process_runner=runner, settings=_settings())

    result = await executor.run(RunJob(run_id="r1", package_name="sample", version="1.0"))

    assert result.timed_out is True
    assert runner.command is not None
    command_text = " ".join(runner.command)
    assert "--time_limit 45" in command_text
    assert "--rlimit_cpu 30" in command_text
    assert "--rlimit_as 1024" in command_text
    assert "--cgroup_pids_max 128" in command_text
    assert "--rlimit_nofile 1024" in command_text
    assert "--bindmount_ro /var/cache/pip:/var/cache/pip" in command_text


async def test_execute_mode_embeds_entrypoint_and_file_path() -> None:
    runner = FakeRunner()
    executor = NsJailSandboxExecutor(process_runner=runner, settings=_settings())

    await executor.run(
        RunJob(
            run_id="r2",
            package_name="sample",
            version="1.0",
            mode=RunMode.EXECUTE,
            file_path="/tmp/script.py",
            entrypoint="sample.cli:main",
        ),
    )

    assert runner.command is not None
    command_text = " ".join(runner.command)
    assert "mode='execute'" in command_text
    assert "file_path='/tmp/script.py'" in command_text
    assert "entrypoint='sample.cli:main'" in command_text


async def test_execute_module_mode_embeds_module_name() -> None:
    runner = FakeRunner()
    executor = NsJailSandboxExecutor(process_runner=runner, settings=_settings())

    await executor.run(
        RunJob(
            run_id="r3",
            package_name="sample",
            version="1.0",
            mode=RunMode.EXECUTE_MODULE,
            module_name="sample",
        ),
    )

    assert runner.command is not None
    command_text = " ".join(runner.command)
    assert "mode='execute_module'" in command_text
    assert "module_name='sample'" in command_text
