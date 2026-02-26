from __future__ import annotations

import re

JAIL_WORK_DIR = "/opt/snakehook/work"
JAIL_SITE_ROOT = f"{JAIL_WORK_DIR}/site"


def site_packages_dir(package_name: str, version: str) -> str:
    safe_package = _sanitize_path_component(package_name)
    safe_version = _sanitize_path_component(version)
    return f"{JAIL_SITE_ROOT}/{safe_package}-{safe_version}"


def _sanitize_path_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)
