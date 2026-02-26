from __future__ import annotations

from snakehook_runner.infra.runtime_paths import site_packages_dir


def test_site_packages_dir_scopes_to_work_root() -> None:
    path = site_packages_dir("requests", "2.32.0")
    assert path == "/opt/snakehook/work/site/requests-2.32.0"


def test_site_packages_dir_sanitizes_untrusted_components() -> None:
    path = site_packages_dir("../../evil name", "1.0+dev")
    assert path == "/opt/snakehook/work/site/.._.._evil_name-1.0_dev"
