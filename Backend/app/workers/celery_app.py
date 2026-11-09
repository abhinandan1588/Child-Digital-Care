"""Celery application and beat schedule.

Celery runs the periodic and deferred work that must not happen inside a
request: publishing outbox events, expiring commands and invitations, sweeping
retention, and carrying out due deletions.

Every task is idempotent and bounded. The Celery tasks are thin wrappers around
async functions in :mod:`app.workers.jobs`, which is also what the tests call
directly - so the logic is testable without a broker.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings
from app.core.logging import configure_logging, get_logger

logger = get_logger(__name__)

configure_logging()

celery_app = Celery(
    "cdc",
    broker=settings.redis_url or "memory://",
    backend=settings.redis_url or "cache+memory://",
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    # With acks_late, a worker that dies mid-task must not have its message
    # redelivered forever; a visibility timeout plus a retry cap bounds it.
    worker_prefetch_multiplier=1,
    task_time_limit=300,
    task_soft_time_limit=270,
    task_default_retry_delay=30,
    task_max_retries=5,
    broker_connection_retry_on_startup=True,
    result_expires=3600,
    worker_hijack_root_logger=False,
    worker_redirect_stdouts=False,
)

celery_app.conf.beat_schedule = {
    "process-outbox": {
        "task": "cdc.outbox.process",
        "schedule": 10.0,
    },
    "expire-commands": {
        "task": "cdc.maintenance.expire_commands",
        "schedule": 60.0,
    },
    "expire-pairing-invitations": {
        "task": "cdc.maintenance.expire_pairing_invitations",
        "schedule": 120.0,
    },
    "mark-stale-devices-offline": {
        "task": "cdc.maintenance.mark_stale_devices",
        "schedule": crontab(minute="*/30"),
    },
    "cleanup-expired-sessions": {
        "task": "cdc.maintenance.cleanup_sessions",
        "schedule": crontab(hour="3", minute="10"),
    },
    "apply-retention": {
        "task": "cdc.maintenance.apply_retention",
        "schedule": crontab(hour="3", minute="30"),
    },
    "execute-due-deletions": {
        "task": "cdc.privacy.execute_due_deletions",
        "schedule": crontab(hour="4", minute="0"),
    },
}

T = TypeVar("T")


def run_async(coroutine_factory: Callable[[], Awaitable[T]]) -> T:
    """Run an async job from a synchronous Celery task.

    A fresh event loop per task keeps the async engine's connections bound to
    the loop that created them, which is the usual source of "attached to a
    different loop" errors in Celery + SQLAlchemy setups.
    """

    async def _main() -> T:
        from app.db.session import dispose_engine

        try:
            return await coroutine_factory()
        finally:
            await dispose_engine()

    return asyncio.run(_main())


def task_result(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    logger.info("task_completed", task=name, **payload)
    return {"task": name, **payload}
