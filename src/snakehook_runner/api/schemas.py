from __future__ import annotations

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, field_validator

from snakehook_runner.core.interfaces import RunMode


class TriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"(?i)^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$",
    )
    version: str = Field(min_length=1, max_length=100)
    mode: RunMode = RunMode.INSTALL
    file_path: str | None = Field(default=None, min_length=1, max_length=500)
    entrypoint: str | None = Field(default=None, min_length=1, max_length=200)
    module_name: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("version must not contain surrounding whitespace")
        try:
            parsed = Version(value)
        except InvalidVersion as exc:
            raise ValueError("version must be a valid PEP 440 version") from exc
        if parsed.local is not None:
            raise ValueError("local versions are not accepted")
        return value


class TriageAccepted(BaseModel):
    run_id: str
    status: str


class ErrorResponse(BaseModel):
    detail: str
