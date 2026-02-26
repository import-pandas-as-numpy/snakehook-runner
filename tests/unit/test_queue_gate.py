from __future__ import annotations

import asyncio

from snakehook_runner.core.concurrency import WorkerPool
from snakehook_runner.core.interfaces import RunJob
from snakehook_runner.core.queue_gate import WorkerPoolQueueGate


async def test_worker_pool_queue_gate_accepts_and_reports_snapshot() -> None:
    gate = asyncio.Event()

    async def handler(job: RunJob) -> None:
        await gate.wait()

    worker_pool = WorkerPool(max_concurrency=1, queue_limit=1, handler=handler)
    await worker_pool.start()

    try:
        queue_gate = WorkerPoolQueueGate(worker_pool=worker_pool)
        first = queue_gate.submit(RunJob(run_id="1", package_name="x", version="1"))
        await asyncio.sleep(0)
        second = queue_gate.submit(RunJob(run_id="2", package_name="x", version="1"))
        third = queue_gate.submit(RunJob(run_id="3", package_name="x", version="1"))

        snap = queue_gate.snapshot()
        assert first.accepted is True
        assert second.accepted is True
        assert third.accepted is False
        assert snap.queue_limit == 1
        assert snap.workers == 1
    finally:
        gate.set()
        await worker_pool.stop()
