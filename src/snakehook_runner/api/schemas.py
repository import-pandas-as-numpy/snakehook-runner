from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from snakehook_runner.core.interfaces import RunMode


class TriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    mode: RunMode = RunMode.INSTALL
    file_path: str | None = Field(default=None, min_length=1, max_length=500)
    entrypoint: str | None = Field(default=None, min_length=1, max_length=200)
    module_name: str | None = Field(default=None, min_length=1, max_length=200)


class TriageAccepted(BaseModel):
    run_id: str
    status: str


class ErrorResponse(BaseModel):
    detail: str
