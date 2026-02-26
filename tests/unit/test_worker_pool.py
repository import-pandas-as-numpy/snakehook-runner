from __future__ import annotations

import asyncio

from snakehook_runner.core.concurrency import WorkerPool
from snakehook_runner.core.interfaces import RunJob


async def test_worker_pool_enforces_concurrency_cap() -> None:
    active = 0
    max_seen = 0
    lock = asyncio.Lock()

    async def handler(job: RunJob) -> None:
        nonlocal active, max_seen
        async with lock:
            active += 1
            if active > max_seen:
                max_seen = active
        await asyncio.sleep(0.05)
        async with lock:
            active -= 1

    pool = WorkerPool(max_concurrency=2, queue_limit=20, handler=handler)
    await pool.start()

    try:
        for idx in range(8):
            assert pool.submit(RunJob(run_id=str(idx), package_name="x", version="1"))
        await asyncio.wait_for(pool.wait_idle(), timeout=2)
    finally:
        await pool.stop()

    assert max_seen <= 2


async def test_worker_pool_rejects_when_queue_is_full() -> None:
    gate = asyncio.Event()

    async def handler(job: RunJob) -> None:
        await gate.wait()

    pool = WorkerPool(max_concurrency=1, queue_limit=1, handler=handler)
    await pool.start()

    try:
        assert pool.submit(RunJob(run_id="1", package_name="x", version="1"))
        await asyncio.sleep(0)
        assert pool.submit(RunJob(run_id="2", package_name="x", version="1"))
        assert not pool.submit(RunJob(run_id="3", package_name="x", version="1"))
    finally:
        gate.set()
        await pool.stop()


async def test_worker_pool_start_stop_are_idempotent() -> None:
    async def handler(job: RunJob) -> None:
        return None

    pool = WorkerPool(max_concurrency=1, queue_limit=1, handler=handler)

    await pool.start()
    first_workers = list(pool._workers)
    await pool.start()
    assert pool._workers == first_workers

    await pool.stop()
    assert pool._workers == []
    await pool.stop()


def test_worker_pool_submit_requires_started() -> None:
    async def handler(job: RunJob) -> None:
        return None

    pool = WorkerPool(max_concurrency=1, queue_limit=1, handler=handler)

    try:
        pool.submit(RunJob(run_id="1", package_name="x", version="1"))
    except RuntimeError as exc:
        assert "not started" in str(exc)
    else:
        raise AssertionError("expected RuntimeError when submitting before start")
