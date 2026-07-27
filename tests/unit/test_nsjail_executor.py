from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

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
        cgroup_mem_max_bytes=1_073_741_824,
        cgroup_cpu_ms_per_sec=800,
        rlimit_nofile=1024,
        max_download_bytes=300_000_000,
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
    monkeypatch.setattr(nsjail_executor, "_require_paths", lambda *paths: None)


async def test_nsjail_command_contains_limits_and_job_mount(tmp_path: Path) -> None:
    runner = FakeRunner()
    executor = NsJailSandboxExecutor(process_runner=runner, settings=_settings())

    result = await executor.run(RunJob(run_id="r1", package_name="sample", version="1.0"))

    assert result.timed_out is True
    assert runner.command is not None
    command_text = " ".join(runner.command)
    assert "--time_limit 45" in command_text
    assert "--user 65534:65534:1" in command_text
    assert "--group 65534:65534:1" in command_text
    assert "--disable_clone_newuser" not in command_text
    assert "--rlimit_cpu 30" in command_text
    assert "--rlimit_as 1024" in command_text
    assert "--rlimit_fsize 64" in command_text
    assert "--cgroup_pids_max 128" in command_text
    assert "--cgroup_mem_max 1073741824" in command_text
    assert "--cgroup_mem_swap_max 0" in command_text
    assert "--cgroup_cpu_ms_per_sec 800" in command_text
    assert "--use_cgroupv2" in command_text
    assert "--rlimit_nofile 1024" in command_text
    assert "--bindmount_ro /usr:/usr" in command_text
    assert "--bindmount_ro /usr/local:/usr/local" in command_text
    assert "--bindmount_ro /bin:/bin" in command_text
    assert "--bindmount_ro /lib:/lib" in command_text
    assert "--bindmount " in command_text
    assert f"--bindmount {tmp_path / 'work' / 'r1'}:/work" in command_text
    assert f"--bindmount_ro {tmp_path / 'code' / 'r1'}:/site" in command_text
    assert "--env LD_LIBRARY_PATH=" in command_text
    assert "--env PYTHONPATH=/site" in command_text
    assert "/usr/local/bin/python3 -c" in command_text
    assert runner.env is not None
    assert runner.env["PYTHONPATH"] == "/site"


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


async def test_nsjail_command_always_applies_aggregate_cgroup_limits() -> None:
    runner = FakeRunner()
    settings = _settings()
    executor = NsJailSandboxExecutor(process_runner=runner, settings=settings)

    await executor.run(RunJob(run_id="r4", package_name="sample", version="1.0"))

    assert runner.command is not None
    command_text = " ".join(runner.command)
    assert "--cgroup_pids_max" in command_text
    assert "--cgroup_mem_max" in command_text
    assert "--cgroup_cpu_ms_per_sec" in command_text


def test_audit_code_emits_timestamp_args_and_caller_fields() -> None:
    job = RunJob(run_id="r5", package_name="sample", version="1.0")
    source = nsjail_executor._build_audit_code(job=job, audit_path="/tmp/audit-r5.jsonl")
    assert "'timestamp'" in source
    assert "'args'" in source
    assert "'caller'" in source
    assert "sys._getframe(1)" in source
    assert "json.dumps(payload" in source
    assert "in_hook=False" in source
    assert "if in_hook or written >= limit" in source
    assert "except OSError" in source
    assert "caller_file=frame_info.get('file')" in source
    assert "if caller_file == '<string>'" in source


def test_audit_code_captures_post_install_file_and_socket_activity(tmp_path: Path) -> None:
    audit_path = tmp_path / "execute-audit.jsonl"
    probe_path = tmp_path / "telemetry_probe.py"
    probe_path.write_text(
        "\n".join(
            (
                "import sys",
                "with open('created.txt', 'w', encoding='utf-8') as target:",
                "    target.write('payload')",
                "with open('created.txt', encoding='utf-8') as target:",
                "    target.read()",
                "sys.audit('socket.connect', None, ('127.0.0.1', 443))",
            ),
        ),
        encoding="utf-8",
    )
    job = RunJob(
        run_id="r-audit",
        package_name="telemetry-probe",
        version="1",
        mode=RunMode.EXECUTE_MODULE,
        module_name="telemetry_probe",
    )
    source = nsjail_executor._build_audit_code(job=job, audit_path=str(audit_path))

    result = subprocess.run(
        [sys.executable, "-c", source],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    records = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    probe_records = [
        record
        for record in records
        if str(record["caller"]["file"]).endswith("telemetry_probe.py")
    ]
    assert any(
        record["event"] == "open" and "created.txt" in record["args"]
        for record in probe_records
    )
    assert any(
        record["event"] == "socket.connect" and "127.0.0.1" in record["args"]
        for record in probe_records
    )
