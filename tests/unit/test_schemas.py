from __future__ import annotations

import pytest
from pydantic import ValidationError

from snakehook_runner.api.schemas import TriageRequest


def test_triage_request_accepts_exact_package_and_pep440_version() -> None:
    request = TriageRequest(package_name="zope.interface", version="7.2")

    assert request.package_name == "zope.interface"
    assert request.version == "7.2"


@pytest.mark.parametrize(
    ("package_name", "version"),
    [
        ("requests[security]", "2.32.0"),
        ("requests", "https://example.invalid/package.whl"),
        ("requests", "../package.whl"),
        ("requests", "2.32.0 --index-url=https://example.invalid"),
        ("requests", "2.32.0; python_version>'3.0'"),
        ("requests", "2.32.0+local"),
        ("requests", " 2.32.0"),
    ],
)
def test_triage_request_rejects_non_exact_package_specifiers(
    package_name: str,
    version: str,
) -> None:
    with pytest.raises(ValidationError):
        TriageRequest(package_name=package_name, version=version)
