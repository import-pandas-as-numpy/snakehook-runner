from __future__ import annotations

import sys
from pathlib import Path

from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import PipInstallResult
from snakehook_runner.infra.nsjail_executor import build_nsjail_prefix, minimal_process_env
from snakehook_runner.infra.process_runner import AsyncProcessRunner


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
        command = [
            *build_nsjail_prefix(self._settings),
            "--",
            sys.executable,
            "-m",
            "pip",
            "install",
            f"{package_name}=={version}",
            "--disable-pip-version-check",
            "--no-input",
            "--cache-dir",
            self._settings.pip_cache_dir,
        ]
        env = minimal_process_env({"PIP_CACHE_DIR": self._settings.pip_cache_dir})
        result = await self._process_runner.run(
            command=command,
            timeout_sec=self._settings.run_timeout_sec,
            env=env,
        )
        if result.timed_out or result.returncode != 0:
            return PipInstallResult(ok=False, stdout=result.stdout, stderr=result.stderr)

        after_size = _dir_size(Path(self._settings.pip_cache_dir))
        delta = max(0, after_size - before_size)
        if delta > self._settings.max_download_bytes:
            return PipInstallResult(
                ok=False,
                stdout=result.stdout,
                stderr=(
                    f"download byte cap exceeded: wrote {delta} bytes, "
                    f"cap is {self._settings.max_download_bytes}"
                ),
            )
        return PipInstallResult(ok=True, stdout=result.stdout, stderr=result.stderr)


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
