from __future__ import annotations

import logging
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import PipInstallResult
from snakehook_runner.infra.nsjail_executor import (
    build_nsjail_prefix,
    jailed_python_command,
    minimal_process_env,
)
from snakehook_runner.infra.process_runner import AsyncProcessRunner
from snakehook_runner.infra.runtime_paths import site_packages_dir

LOG = logging.getLogger(__name__)
MAX_PIP_AUDIT_BYTES = 5_000_000


class RealPipInstaller:
    def __init__(
        self,
        process_runner: AsyncProcessRunner,
        settings: Settings,
    ) -> None:
        self._process_runner = process_runner
        self._settings = settings

    async def install(self, package_name: str, version: str) -> PipInstallResult:
        before_size = _dir_size(Path(self._settings.pip_cache_dir))
        install_target = site_packages_dir(package_name, version)
        audit_path = str(Path("/tmp") / f"pip-audit-{uuid.uuid4().hex}.jsonl")
        audit_bootstrap_dir = Path(tempfile.mkdtemp(prefix="snakehook-pip-audit-", dir="/tmp"))
        audit_bootstrap_dir.chmod(0o755)
        audit_sitecustomize = audit_bootstrap_dir / "sitecustomize.py"
        audit_sitecustomize.write_text(_build_pip_audit_sitecustomize(), encoding="utf-8")
        audit_sitecustomize.chmod(0o644)
        LOG.info(
            "pip install start package=%s version=%s target=%s audit_path=%s",
            package_name,
            version,
            install_target,
            audit_path,
        )
        install_target_path = Path(install_target)
        if install_target_path.exists():
            shutil.rmtree(install_target_path, ignore_errors=True)
        pythonpath = os.pathsep.join([str(audit_bootstrap_dir), install_target])
        env = minimal_process_env(
            {
                "PIP_CACHE_DIR": self._settings.pip_cache_dir,
                "PYTHONPATH": pythonpath,
                "SNAKEHOOK_AUDIT_PATH": audit_path,
                "SNAKEHOOK_AUDIT_LIMIT": str(MAX_PIP_AUDIT_BYTES),
            },
        )
        command = [
            *build_nsjail_prefix(self._settings, jailed_env=env),
            "--",
            *jailed_python_command(),
            "-m",
            "pip",
            "install",
            f"{package_name}=={version}",
            "--disable-pip-version-check",
            "--no-input",
            "--upgrade",
            "--target",
            install_target,
            "--cache-dir",
            self._settings.pip_cache_dir,
        ]
        result = await self._process_runner.run(
            command=command,
            timeout_sec=self._settings.run_timeout_sec,
            env=env,
        )
        shutil.rmtree(audit_bootstrap_dir, ignore_errors=True)
        created_audit_path = audit_path if Path(audit_path).exists() else None
        if created_audit_path is None:
            LOG.warning(
                "pip install finished without audit file package=%s version=%s path=%s",
                package_name,
                version,
                audit_path,
            )
        if result.timed_out or result.returncode != 0:
            LOG.warning(
                "pip install failed package=%s version=%s timed_out=%s returncode=%s",
                package_name,
                version,
                result.timed_out,
                result.returncode,
            )
            return PipInstallResult(
                ok=False,
                stdout=result.stdout,
                stderr=result.stderr,
                audit_jsonl_path=created_audit_path,
            )

        after_size = _dir_size(Path(self._settings.pip_cache_dir))
        delta = max(0, after_size - before_size)
        if delta > self._settings.max_download_bytes:
            LOG.warning(
                "pip download cap exceeded package=%s version=%s wrote_bytes=%s cap_bytes=%s",
                package_name,
                version,
                delta,
                self._settings.max_download_bytes,
            )
            return PipInstallResult(
                ok=False,
                stdout=result.stdout,
                stderr=(
                    f"download byte cap exceeded: wrote {delta} bytes, "
                    f"cap is {self._settings.max_download_bytes}"
                ),
                audit_jsonl_path=created_audit_path,
            )
        LOG.info(
            "pip install complete package=%s version=%s cache_delta_bytes=%s audit_path=%s",
            package_name,
            version,
            delta,
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
        if not path.is_file():
            continue
        try:
            total += path.stat().st_size
        except FileNotFoundError:
            continue
    return total


def _build_pip_audit_sitecustomize() -> str:
    return (
        "import os\n"
        "import sys\n"
        "\n"
        "path=os.getenv('SNAKEHOOK_AUDIT_PATH','').strip()\n"
        "if path:\n"
        "    limit_raw=os.getenv('SNAKEHOOK_AUDIT_LIMIT','5000000').strip()\n"
        "    try:\n"
        "        limit=max(0,int(limit_raw))\n"
        "    except ValueError:\n"
        "        limit=5000000\n"
        "    written=0\n"
        "    f=open(path,'a',encoding='utf-8')\n"
        "    def _hook(event,args):\n"
        "        global written\n"
        "        if written >= limit:\n"
        "            return\n"
        "        line=event+'\\n'\n"
        "        remaining=limit-written\n"
        "        chunk=line[:remaining]\n"
        "        f.write(chunk)\n"
        "        f.flush()\n"
        "        written += len(chunk)\n"
        "    sys.addaudithook(_hook)\n"
    )
