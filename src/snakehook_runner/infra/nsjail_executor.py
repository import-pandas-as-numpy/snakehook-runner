from __future__ import annotations

import os
from pathlib import Path

from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import RunJob, SandboxResult
from snakehook_runner.infra.process_runner import AsyncProcessRunner

NSJAIL_CONFIG_PATH_DEFAULT = "/etc/nsjail.cfg"
MAX_AUDIT_BYTES = 5_000_000


class NsJailSandboxExecutor:
    def __init__(self, process_runner: AsyncProcessRunner, settings: Settings) -> None:
        self._runner = process_runner
        self._settings = settings

    async def run(self, job: RunJob) -> SandboxResult:
        audit_path = str(Path("/tmp") / f"audit-{job.run_id}.jsonl")
        audit_code = (
            "import sys\n"
            f"limit={MAX_AUDIT_BYTES}\n"
            "written=0\n"
            f"f=open({audit_path!r},'w',encoding='utf-8')\n"
            "def _hook(e,a):\n"
            "    global written\n"
            "    if written >= limit:\n"
            "        return\n"
            "    line=e+'\\n'\n"
            "    remaining=limit-written\n"
            "    chunk=line[:remaining]\n"
            "    f.write(chunk)\n"
            "    written += len(chunk)\n"
            "sys.addaudithook(_hook)\n"
            f"__import__({job.package_name!r})\n"
        )
        command = [
            *build_nsjail_prefix(self._settings),
            "--",
            "python",
            "-c",
            audit_code,
        ]
        result = await self._runner.run(
            command=command,
            timeout_sec=self._settings.run_timeout_sec,
            env=minimal_process_env(),
        )
        return SandboxResult(
            ok=(not result.timed_out and result.returncode == 0),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
            audit_jsonl_path=audit_path,
        )


def build_nsjail_prefix(settings: Settings) -> list[str]:
    config_path = os.getenv("NSJAIL_CONFIG_PATH", NSJAIL_CONFIG_PATH_DEFAULT)
    return [
        "nsjail",
        "--config",
        config_path,
        "--time_limit",
        str(settings.run_timeout_sec),
        "--rlimit_cpu",
        str(settings.rlimit_cpu_sec),
        "--rlimit_as",
        str(settings.rlimit_as_mb),
        "--cgroup_pids_max",
        str(settings.cgroup_pids_max),
        "--rlimit_nofile",
        str(settings.rlimit_nofile),
        "--bindmount_ro",
        f"{settings.pip_cache_dir}:{settings.pip_cache_dir}",
    ]


def minimal_process_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.getenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
    }
    if extra:
        env.update(extra)
    return env
