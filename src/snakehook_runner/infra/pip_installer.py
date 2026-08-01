from __future__ import annotations

import logging
import os
import shutil
import stat
from pathlib import Path

from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import PipInstallResult, RunJob
from snakehook_runner.infra.nsjail_executor import (
    build_nsjail_prefix,
    jailed_python_command,
    minimal_process_env,
)
from snakehook_runner.infra.process_runner import ProcessRunner
from snakehook_runner.infra.runtime_paths import (
    JAILED_JOB_DIR,
    JAILED_SITE_DIR,
    prepare_code_dir,
    prepare_job_dir,
)

LOG = logging.getLogger(__name__)
MAX_PIP_AUDIT_BYTES = 50_000_000


class RealPipInstaller:
    def __init__(
        self,
        process_runner: ProcessRunner,
        settings: Settings,
    ) -> None:
        self._process_runner = process_runner
        self._settings = settings

    async def install(self, job: RunJob) -> PipInstallResult:
        host_job_dir = prepare_job_dir(job.run_id)
        host_install_target = prepare_code_dir(job.run_id)
        jailed_install_target = JAILED_SITE_DIR
        host_pip_cache = host_job_dir / "pip-cache"
        jailed_pip_cache = f"{JAILED_JOB_DIR}/pip-cache"
        host_audit_path = host_job_dir / "install-audit.jsonl"
        jailed_audit_path = f"{JAILED_JOB_DIR}/install-audit.jsonl"
        audit_bootstrap_dir = host_job_dir / "audit-bootstrap"
        audit_bootstrap_dir.mkdir(mode=0o755)
        audit_bootstrap_dir.chmod(0o755)
        audit_sitecustomize = audit_bootstrap_dir / "sitecustomize.py"
        audit_sitecustomize.write_text(_build_pip_audit_sitecustomize(), encoding="utf-8")
        audit_sitecustomize.chmod(0o644)
        LOG.info(
            "pip install start package=%s version=%s target=%s audit_path=%s",
            job.package_name,
            job.version,
            host_install_target,
            host_audit_path,
        )
        jailed_audit_bootstrap = f"{JAILED_JOB_DIR}/audit-bootstrap"
        pythonpath = os.pathsep.join([jailed_audit_bootstrap, jailed_install_target])
        env = minimal_process_env(
            {
                "PIP_CACHE_DIR": jailed_pip_cache,
                "PYTHONPATH": pythonpath,
                "SNAKEHOOK_AUDIT_PATH": jailed_audit_path,
                "SNAKEHOOK_AUDIT_LIMIT": str(MAX_PIP_AUDIT_BYTES),
            },
        )
        command = [
            *build_nsjail_prefix(
                self._settings,
                host_job_dir=host_job_dir,
                host_code_dir=host_install_target,
                code_read_only=False,
                jailed_env=env,
            ),
            "--",
            *jailed_python_command(),
            "-m",
            "pip",
            "install",
            f"{job.package_name}=={job.version}",
            "--disable-pip-version-check",
            "--no-input",
            "--upgrade",
            "--target",
            jailed_install_target,
            "--cache-dir",
            jailed_pip_cache,
        ]
        result = await self._process_runner.run(
            command=command,
            timeout_sec=self._settings.run_timeout_sec + 5,
            env=env,
        )
        shutil.rmtree(audit_bootstrap_dir, ignore_errors=True)
        created_audit_path = str(host_audit_path) if host_audit_path.exists() else None
        if created_audit_path is None:
            LOG.warning(
                "pip install finished without audit file package=%s version=%s path=%s",
                job.package_name,
                job.version,
                host_audit_path,
            )
        if result.timed_out or result.returncode != 0:
            LOG.warning(
                "pip install failed package=%s version=%s timed_out=%s returncode=%s",
                job.package_name,
                job.version,
                result.timed_out,
                result.returncode,
            )
            return PipInstallResult(
                ok=False,
                stdout=result.stdout,
                stderr=result.stderr,
                audit_jsonl_path=created_audit_path,
            )

        downloaded_bytes = _dir_size(host_pip_cache)
        if downloaded_bytes > self._settings.max_download_bytes:
            LOG.warning(
                "pip download cap exceeded package=%s version=%s wrote_bytes=%s cap_bytes=%s",
                job.package_name,
                job.version,
                downloaded_bytes,
                self._settings.max_download_bytes,
            )
            return PipInstallResult(
                ok=False,
                stdout=result.stdout,
                stderr=(
                    f"download byte cap exceeded: wrote {downloaded_bytes} bytes, "
                    f"cap is {self._settings.max_download_bytes}"
                ),
                audit_jsonl_path=created_audit_path,
            )
        LOG.info(
            "pip install complete package=%s version=%s cache_delta_bytes=%s audit_path=%s",
            job.package_name,
            job.version,
            downloaded_bytes,
            created_audit_path,
        )
        return PipInstallResult(
            ok=True,
            stdout=result.stdout,
            stderr=result.stderr,
            audit_jsonl_path=created_audit_path,
        )


def _dir_size(root: Path) -> int:
    if not root.exists():
        return 0
    total = 0
    for path in root.rglob("*"):
        try:
            metadata = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            total += metadata.st_size
    return total


def _build_pip_audit_sitecustomize() -> str:
    return (
        "import datetime\n"
        "import json\n"
        "import os\n"
        "import reprlib\n"
        "import sys\n"
        "\n"
        "path=os.getenv('SNAKEHOOK_AUDIT_PATH','').strip()\n"
        "if path:\n"
        "    limit_raw=os.getenv('SNAKEHOOK_AUDIT_LIMIT','50000000').strip()\n"
        "    try:\n"
        "        limit=max(0,int(limit_raw))\n"
        "    except ValueError:\n"
        "        limit=50000000\n"
        "    _repr=reprlib.Repr()\n"
        "    _repr.maxother=200\n"
        "    _repr.maxstring=500\n"
        "    _repr.maxlist=20\n"
        "    _repr.maxtuple=20\n"
        "    _repr.maxdict=20\n"
        "    written=0\n"
        "    in_hook=False\n"
        "    f=open(path,'a',encoding='utf-8')\n"
        "    def _hook(event,args):\n"
        "        global written,in_hook\n"
        "        if in_hook or written >= limit:\n"
        "            return\n"
        "        in_hook=True\n"
        "        try:\n"
        "            frame_info={'function':None,'file':None,'line':None}\n"
        "            try:\n"
        "                frame=sys._getframe(1)\n"
        "                frame_info={'function':frame.f_code.co_name,"
        "'file':frame.f_code.co_filename,'line':frame.f_lineno}\n"
        "            except Exception:\n"
        "                pass\n"
        "            caller_file=frame_info.get('file')\n"
        "            if caller_file == __file__:\n"
        "                return\n"
        "            payload={'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),"
        "'event':event,'args':_repr.repr(args),'caller':frame_info}\n"
        "            line=json.dumps(payload,separators=(',',':'))+'\\n'\n"
        "            remaining=limit-written\n"
        "            chunk=line[:remaining]\n"
        "            if not chunk:\n"
        "                return\n"
        "            f.write(chunk)\n"
        "            f.flush()\n"
        "            written += len(chunk)\n"
        "        except OSError:\n"
        "            written=limit\n"
        "        finally:\n"
        "            in_hook=False\n"
        "    sys.addaudithook(_hook)\n"
    )
