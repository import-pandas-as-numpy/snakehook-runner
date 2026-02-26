from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)


class TriageAccepted(BaseModel):
    run_id: str
    status: str


class ErrorResponse(BaseModel):
    detail: str
