from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from snakehook_runner.core.interfaces import RunJob


@dataclass(frozen=True)
class QueueSnapshot:
    queued: int
    queue_limit: int
    workers: int


class WorkerPool:
    def __init__(
        self,
        max_concurrency: int,
        queue_limit: int,
        handler: Callable[[RunJob], Awaitable[None]],
    ) -> None:
        self._handler = handler
        self._queue: asyncio.Queue[RunJob | None] = asyncio.Queue(maxsize=queue_limit)
        self._workers: list[asyncio.Task[None]] = []
        self._max_concurrency = max_concurrency
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._workers = [
            asyncio.create_task(self._worker_loop(), name=f"triage-worker-{idx}")
            for idx in range(self._max_concurrency)
        ]

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        for _ in self._workers:
            await self._queue.put(None)
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []

    def submit(self, job: RunJob) -> bool:
        if not self._started:
            raise RuntimeError("WorkerPool is not started")
        try:
            self._queue.put_nowait(job)
            return True
        except asyncio.QueueFull:
            return False

    def snapshot(self) -> QueueSnapshot:
        return QueueSnapshot(
            queued=self._queue.qsize(),
            queue_limit=self._queue.maxsize,
            workers=self._max_concurrency,
        )

    async def wait_idle(self) -> None:
        await self._queue.join()

    async def _worker_loop(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item is None:
                    return
                await self._handler(item)
            finally:
                self._queue.task_done()
