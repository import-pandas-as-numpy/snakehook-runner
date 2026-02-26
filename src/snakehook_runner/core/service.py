from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from enum import StrEnum

from snakehook_runner.core.interfaces import RunJob
from snakehook_runner.core.policy import is_denied_package
from snakehook_runner.core.queue_gate import QueueGate
from snakehook_runner.core.rate_limit import FixedWindowRateLimiter

LOG = logging.getLogger(__name__)


class SubmitStatus(StrEnum):
    ACCEPTED = "accepted"
    RATE_LIMITED = "rate_limited"
    OVERLOADED = "overloaded"
    DENIED_PACKAGE = "denied_package"


@dataclass(frozen=True)
class SubmitResult:
    status: SubmitStatus
    run_id: str | None


class SubmissionService:
    def __init__(
        self,
        rate_limiter: FixedWindowRateLimiter,
        queue_gate: QueueGate,
        package_denylist: tuple[str, ...],
    ) -> None:
        self._rate_limiter = rate_limiter
        self._queue_gate = queue_gate
        self._package_denylist = package_denylist

    def submit(self, package_name: str, version: str, client_ip: str) -> SubmitResult:
        if is_denied_package(package_name, self._package_denylist):
            return SubmitResult(status=SubmitStatus.DENIED_PACKAGE, run_id=None)

        if not self._rate_limiter.allow(client_ip):
            return SubmitResult(status=SubmitStatus.RATE_LIMITED, run_id=None)

        run_id = str(uuid.uuid4())
        decision = self._queue_gate.submit(
            RunJob(run_id=run_id, package_name=package_name, version=version),
        )
        if not decision.accepted:
            LOG.warning("queue full; rejected run from ip=%s", client_ip)
            return SubmitResult(status=SubmitStatus.OVERLOADED, run_id=None)
        return SubmitResult(status=SubmitStatus.ACCEPTED, run_id=run_id)
