from __future__ import annotations

import os

import snakehook_runner.infra.nsjail_executor as nsjail_executor
from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import RunJob, RunMode
from snakehook_runner.infra.nsjail_executor import NsJailSandboxExecutor
from snakehook_runner.infra.process_runner import ProcessResult


class FakeRunner:
    def __init__(self) -> None:
        self.command: list[str] | None = None
        self.timeout_sec: int | None = None
        self.env: dict[str, str] | None = None

    async def run(
        self,
        command: list[str],
        timeout_sec: int,
        env: dict[str, str] | None = None,
    ) -> ProcessResult:
        self.command = command
        self.timeout_sec = timeout_sec
        self.env = env
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
        enable_cgroup_pids_limit=True,
        rlimit_nofile=1024,
        pip_cache_dir="/var/cache/pip",
        max_download_bytes=300_000_000,
        package_denylist=("torch",),
        dns_resolvers=("1.1.1.1",),
    )


async def test_nsjail_command_contains_limits_and_readonly_cache_mount(monkeypatch) -> None:
    original_exists = os.path.exists

    def fake_exists(path: str) -> bool:
        if path == "/opt/snakehook/work":
            return True
        return original_exists(path)

    monkeypatch.setattr(nsjail_executor.os.path, "exists", fake_exists)

    runner = FakeRunner()
    executor = NsJailSandboxExecutor(process_runner=runner, settings=_settings())

    result = await executor.run(RunJob(run_id="r1", package_name="sample", version="1.0"))

    assert result.timed_out is True
    assert runner.command is not None
    command_text = " ".join(runner.command)
    assert "--time_limit 45" in command_text
    assert "--user 65534" in command_text
    assert "--group 65534" in command_text
    assert "--disable_clone_newuser" in command_text
    assert "--rlimit_cpu 30" in command_text
    assert "--rlimit_as 1024" in command_text
    assert "--cgroup_pids_max 128" in command_text
    assert "--rlimit_nofile 1024" in command_text
    assert "--bindmount_ro /usr:/usr" in command_text
    assert "--bindmount_ro /usr/local:/usr/local" in command_text
    assert "--bindmount_ro /bin:/bin" in command_text
    assert "--bindmount_ro /lib:/lib" in command_text
    assert "--bindmount /opt/snakehook/work:/opt/snakehook/work" in command_text
    assert "--bindmount /tmp:/tmp" in command_text
    assert "--bindmount_ro /var/cache/pip:/var/cache/pip" in command_text
    assert "--env LD_LIBRARY_PATH=" in command_text
    assert "--env PYTHONPATH=/opt/snakehook/work/site/sample-1.0" in command_text
    assert "/usr/local/bin/python3 -c" in command_text
    assert runner.env is not None
    assert runner.env["PYTHONPATH"] == "/opt/snakehook/work/site/sample-1.0"


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


async def test_nsjail_command_skips_cgroup_pids_when_disabled() -> None:
    runner = FakeRunner()
    settings = _settings()
    settings = Settings(**{**settings.__dict__, "enable_cgroup_pids_limit": False})
    executor = NsJailSandboxExecutor(process_runner=runner, settings=settings)

    await executor.run(RunJob(run_id="r4", package_name="sample", version="1.0"))

    assert runner.command is not None
    command_text = " ".join(runner.command)
    assert "--cgroup_pids_max" not in command_text


def test_audit_code_emits_timestamp_args_and_caller_fields() -> None:
    job = RunJob(run_id="r5", package_name="sample", version="1.0")
    source = nsjail_executor._build_audit_code(job=job, audit_path="/tmp/audit-r5.jsonl")
    assert "'timestamp'" in source
    assert "'args'" in source
    assert "'caller'" in source
    assert "sys._getframe(1)" in source
    assert "json.dumps(payload" in source
