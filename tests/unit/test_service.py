from __future__ import annotations

from snakehook_runner.core.interfaces import RunJob
from snakehook_runner.core.queue_gate import QueueDecision
from snakehook_runner.core.rate_limit import FixedWindowRateLimiter
from snakehook_runner.core.service import SubmissionService, SubmitStatus


class FakeQueueGate:
    def __init__(self, accepted: bool) -> None:
        self.accepted = accepted
        self.jobs: list[RunJob] = []

    def submit(self, job: RunJob) -> QueueDecision:
        self.jobs.append(job)
        return QueueDecision(accepted=self.accepted)


class NeverLimiter:
    def allow(self, key: str, now: float | None = None) -> bool:
        return False


def test_service_rejects_denylisted_package() -> None:
    svc = SubmissionService(
        rate_limiter=FixedWindowRateLimiter(limit=5, window_sec=60),
        queue_gate=FakeQueueGate(accepted=True),
        package_denylist=("torch",),
    )

    result = svc.submit("torch", "1.0", client_ip="1.2.3.4")
    assert result.status == SubmitStatus.DENIED_PACKAGE


def test_service_rejects_normalized_denylist_variants() -> None:
    svc = SubmissionService(
        rate_limiter=FixedWindowRateLimiter(limit=5, window_sec=60),
        queue_gate=FakeQueueGate(accepted=True),
        package_denylist=("torch",),
    )

    result = svc.submit("Torch_CPU", "1.0", client_ip="1.2.3.4")
    assert result.status == SubmitStatus.DENIED_PACKAGE


def test_service_rate_limited_path() -> None:
    svc = SubmissionService(
        rate_limiter=NeverLimiter(),
        queue_gate=FakeQueueGate(accepted=True),
        package_denylist=(),
    )

    result = svc.submit("requests", "1.0", client_ip="1.2.3.4")
    assert result.status == SubmitStatus.RATE_LIMITED
