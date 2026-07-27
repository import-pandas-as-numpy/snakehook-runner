from __future__ import annotations

import os
import shutil
from pathlib import Path

JAIL_WORK_DIR = "/opt/snakehook/work"
JAIL_CODE_DIR = "/opt/snakehook/code"
JAILED_JOB_DIR = "/work"
JAILED_SITE_DIR = "/site"


def job_dir(run_id: str) -> Path:
    _validate_run_id(run_id)
    return Path(os.getenv("SNAKEHOOK_WORK_ROOT", JAIL_WORK_DIR)) / run_id


def code_dir(run_id: str) -> Path:
    _validate_run_id(run_id)
    return Path(os.getenv("SNAKEHOOK_CODE_ROOT", JAIL_CODE_DIR)) / run_id


def prepare_job_dir(run_id: str) -> Path:
    return _prepare_dir(job_dir(run_id))


def prepare_code_dir(run_id: str) -> Path:
    return _prepare_dir(code_dir(run_id))


def _prepare_dir(root: Path) -> Path:
    root.mkdir(mode=0o770, parents=False, exist_ok=False)
    if os.geteuid() == 0:
        os.chown(root, 65534, 65534)
    return root


def cleanup_job_dir(run_id: str) -> None:
    shutil.rmtree(job_dir(run_id), ignore_errors=True)
    shutil.rmtree(code_dir(run_id), ignore_errors=True)


def _validate_run_id(run_id: str) -> None:
    if not run_id or Path(run_id).name != run_id or run_id in {".", ".."}:
        raise ValueError("run_id must be a single path component")
