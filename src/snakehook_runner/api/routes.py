from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Request, status

from snakehook_runner.api.schemas import ErrorResponse, TriageAccepted, TriageRequest
from snakehook_runner.core.auth import is_valid_bearer
from snakehook_runner.core.service import SubmissionService, SubmitStatus

router = APIRouter()


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.post(
    "/v1/triage",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=TriageAccepted,
    responses={
        401: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def triage(
    payload: TriageRequest,
    request: Request,
    authorization: str | None = Header(default=None),
) -> TriageAccepted:
    container = request.app.state.container
    if not is_valid_bearer(authorization, container.settings.api_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing token",
        )

    service: SubmissionService = container.submission_service
    client_ip = request.client.host if request.client else "unknown"
    result = service.submit(
        payload.package_name,
        payload.version,
        client_ip=client_ip,
        mode=payload.mode,
        file_path=payload.file_path,
        entrypoint=payload.entrypoint,
        module_name=payload.module_name,
    )

    if result.status == SubmitStatus.DENIED_PACKAGE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="package is denied",
        )
    if result.status == SubmitStatus.RATE_LIMITED:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
        )
    if result.status == SubmitStatus.OVERLOADED:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="queue full")

    return TriageAccepted(run_id=result.run_id or "", status="accepted")
