from __future__ import annotations

import re

_NORMALIZE_SEPARATORS = re.compile(r"[-_.]+")


def normalize_package_name(package_name: str) -> str:
    return _NORMALIZE_SEPARATORS.sub("-", package_name.strip().lower())


def is_denied_package(package_name: str, denylist: tuple[str, ...]) -> bool:
    candidate = normalize_package_name(package_name)
    for denied in denylist:
        blocked = normalize_package_name(denied)
        if candidate == blocked or candidate.startswith(f"{blocked}-"):
            return True
    return False
