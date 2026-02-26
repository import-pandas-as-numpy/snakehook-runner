from __future__ import annotations

from dataclasses import dataclass

from snakehook_runner.core.concurrency import QueueSnapshot, WorkerPool
from snakehook_runner.core.interfaces import RunJob


@dataclass(frozen=True)
class QueueDecision:
    accepted: bool


class QueueGate:
    def submit(self, job: RunJob) -> QueueDecision:
        raise NotImplementedError

    def snapshot(self) -> QueueSnapshot:
        raise NotImplementedError


class WorkerPoolQueueGate(QueueGate):
    def __init__(self, worker_pool: WorkerPool) -> None:
        self._worker_pool = worker_pool

    def submit(self, job: RunJob) -> QueueDecision:
        return QueueDecision(accepted=self._worker_pool.submit(job))

    def snapshot(self) -> QueueSnapshot:
        return self._worker_pool.snapshot()
