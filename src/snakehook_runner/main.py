from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI

from snakehook_runner.api.routes import router
from snakehook_runner.core.concurrency import WorkerPool
from snakehook_runner.core.config import Settings
from snakehook_runner.core.interfaces import RunJob
from snakehook_runner.core.orchestrator import TriageOrchestrator, WorkerHandler
from snakehook_runner.core.queue_gate import WorkerPoolQueueGate
from snakehook_runner.core.rate_limit import FixedWindowRateLimiter
from snakehook_runner.core.service import SubmissionService
from snakehook_runner.infra.nsjail_executor import NsJailSandboxExecutor
from snakehook_runner.infra.pip_installer import RealPipInstaller
from snakehook_runner.infra.process_runner import AsyncProcessRunner
from snakehook_runner.infra.webhook_client import DiscordWebhookClient

LOG = logging.getLogger(__name__)


@dataclass
class AppContainer:
    settings: Settings
    worker_pool: WorkerPool
    submission_service: SubmissionService


def create_app(
    settings: Settings | None = None,
    run_handler: Callable[[RunJob], Awaitable[None]] | None = None,
) -> FastAPI:
    _configure_logging()
    cfg = settings or Settings.from_env()

    if os.getenv("CI_MOCK_ONLY") == "1" and run_handler is None:
        raise RuntimeError(
            "CI_MOCK_ONLY=1 forbids real execution adapters; inject a run_handler",
        )

    if run_handler is None:
        process_runner = AsyncProcessRunner()
        pip_installer = RealPipInstaller(
            process_runner=process_runner,
            settings=cfg,
        )
        sandbox = NsJailSandboxExecutor(process_runner=process_runner, settings=cfg)
        webhook_client = DiscordWebhookClient(webhook_url=cfg.discord_webhook_url)
        orchestrator = TriageOrchestrator(
            pip_installer=pip_installer,
            sandbox_executor=sandbox,
            webhook_client=webhook_client,
        )
        run_handler = WorkerHandler(orchestrator)

    worker_pool = WorkerPool(
        max_concurrency=cfg.max_concurrency,
        queue_limit=cfg.queue_limit,
        handler=run_handler,
    )
    limiter = FixedWindowRateLimiter(
        limit=cfg.per_ip_rate_limit,
        window_sec=cfg.per_ip_rate_window_sec,
    )
    service = SubmissionService(
        rate_limiter=limiter,
        queue_gate=WorkerPoolQueueGate(worker_pool=worker_pool),
        package_denylist=cfg.package_denylist,
    )

    container = AppContainer(
        settings=cfg,
        worker_pool=worker_pool,
        submission_service=service,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await container.worker_pool.start()
        try:
            yield
        finally:
            await container.worker_pool.stop()

    app = FastAPI(title="snakehook-runner", lifespan=lifespan)
    app.state.container = container
    app.include_router(router)
    LOG.info(
        "app initialized max_concurrency=%s queue_limit=%s timeout_sec=%s",
        cfg.max_concurrency,
        cfg.queue_limit,
        cfg.run_timeout_sec,
    )
    return app


def _configure_logging() -> None:
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return
    level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO"
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
