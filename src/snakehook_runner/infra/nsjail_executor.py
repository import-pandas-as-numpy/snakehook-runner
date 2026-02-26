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
        audit_code = _build_audit_code(job=job, audit_path=audit_path)
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
    command = [
        "nsjail",
        "--config",
        config_path,
        "--time_limit",
        str(settings.run_timeout_sec),
        "--rlimit_cpu",
        str(settings.rlimit_cpu_sec),
        "--rlimit_as",
        str(settings.rlimit_as_mb),
        "--rlimit_nofile",
        str(settings.rlimit_nofile),
        "--bindmount_ro",
        f"{settings.pip_cache_dir}:{settings.pip_cache_dir}",
    ]
    if settings.enable_cgroup_pids_limit:
        command.extend(["--cgroup_pids_max", str(settings.cgroup_pids_max)])
    return command


def minimal_process_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.getenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
    }
    if extra:
        env.update(extra)
    return env


def _build_audit_code(job: RunJob, audit_path: str) -> str:
    return (
        "import importlib\n"
        "import importlib.metadata\n"
        "import importlib.util\n"
        "import runpy\n"
        "import sys\n"
        f"mode={job.mode.value!r}\n"
        f"package_name={job.package_name!r}\n"
        f"file_path={job.file_path!r}\n"
        f"entrypoint={job.entrypoint!r}\n"
        f"module_name={job.module_name!r}\n"
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
        "\n"
        "def _normalize_name(value):\n"
        "    return value.replace('-', '_').lower()\n"
        "\n"
        "def _resolve_attr(value, attr_path):\n"
        "    current=value\n"
        "    for name in attr_path.split('.'):\n"
        "        current=getattr(current,name)\n"
        "    return current\n"
        "\n"
        "def _call_entrypoint(spec):\n"
        "    if ':' in spec:\n"
        "        module_name,attr_path=spec.split(':',1)\n"
        "        fn=_resolve_attr(importlib.import_module(module_name),attr_path)\n"
        "        result=fn()\n"
        "        if isinstance(result,int):\n"
        "            raise SystemExit(result)\n"
        "        return\n"
        "    for candidate in importlib.metadata.entry_points(group='console_scripts'):\n"
        "        if candidate.name == spec:\n"
        "            _call_entrypoint(candidate.value)\n"
        "            return\n"
        "    raise RuntimeError(f'console entrypoint not found: {spec}')\n"
        "\n"
        "def _auto_console_entrypoint(package):\n"
        "    package_norm=_normalize_name(package)\n"
        "    candidates=[]\n"
        "    for item in importlib.metadata.entry_points(group='console_scripts'):\n"
        "        if _normalize_name(item.name) == package_norm:\n"
        "            return item.value\n"
        "        if _normalize_name(item.name).startswith(package_norm):\n"
        "            candidates.append(item.value)\n"
        "    if candidates:\n"
        "        return candidates[0]\n"
        "    return None\n"
        "\n"
        "def _run_module_default(package, requested_module):\n"
        "    if requested_module:\n"
        "        runpy.run_module(requested_module,run_name='__main__',alter_sys=True)\n"
        "        return\n"
        "    base=package.replace('-','_')\n"
        "    runpy.run_module(base,run_name='__main__',alter_sys=True)\n"
        "\n"
        "if mode == 'execute':\n"
        "    if file_path:\n"
        "        runpy.run_path(file_path,run_name='__main__')\n"
        "    elif entrypoint:\n"
        "        _call_entrypoint(entrypoint)\n"
        "    else:\n"
        "        auto_spec=_auto_console_entrypoint(package_name)\n"
        "        if auto_spec is None:\n"
        "            raise RuntimeError('no console script entrypoint found for package')\n"
        "        _call_entrypoint(auto_spec)\n"
        "elif mode == 'execute_module':\n"
        "    if file_path:\n"
        "        runpy.run_path(file_path,run_name='__main__')\n"
        "    elif entrypoint:\n"
        "        _call_entrypoint(entrypoint)\n"
        "    else:\n"
        "        _run_module_default(package_name,module_name)\n"
        "else:\n"
        "    __import__(package_name)\n"
    )
