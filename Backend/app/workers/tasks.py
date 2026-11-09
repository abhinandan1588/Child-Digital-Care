"""Celery task wrappers.

Thin by design: each task just runs the matching coroutine from
:mod:`app.workers.jobs` in a fresh event loop and reports counts. The business
logic lives in the jobs module so it is testable without a broker.
"""

from __future__ import annotations

from typing import Any

from app.workers import jobs
from app.workers.celery_app import celery_app, run_async, task_result


@celery_app.task(name="cdc.outbox.process", bind=True, max_retries=3)
def process_outbox(self, batch_size: int | None = None) -> dict[str, Any]:  # noqa: ANN001
    try:
        result = run_async(lambda: jobs.process_outbox(batch_size))
    except Exception as exc:  # noqa: BLE001
        # Retrying is safe: claimed rows have a lease and return to pending.
        raise self.retry(exc=exc, countdown=30) from exc
    return task_result(
        "cdc.outbox.process",
        {
            "claimed": result.claimed,
            "published": result.published,
            "failed": result.failed,
            "skipped": result.skipped,
        },
    )


@celery_app.task(name="cdc.maintenance.expire_commands")
def expire_commands() -> dict[str, Any]:
    count = run_async(jobs.expire_commands)
    return task_result("cdc.maintenance.expire_commands", {"expired": count})


@celery_app.task(name="cdc.maintenance.expire_pairing_invitations")
def expire_pairing_invitations() -> dict[str, Any]:
    count = run_async(jobs.expire_pairing_invitations)
    return task_result("cdc.maintenance.expire_pairing_invitations", {"expired": count})


@celery_app.task(name="cdc.maintenance.mark_stale_devices")
def mark_stale_devices() -> dict[str, Any]:
    count = run_async(jobs.mark_stale_devices)
    return task_result("cdc.maintenance.mark_stale_devices", {"marked_offline": count})


@celery_app.task(name="cdc.maintenance.cleanup_sessions")
def cleanup_sessions() -> dict[str, Any]:
    result = run_async(jobs.cleanup_sessions)
    return task_result(
        "cdc.maintenance.cleanup_sessions",
        {
            "user_sessions": result.user_sessions,
            "device_sessions": result.device_sessions,
            "admin_sessions": result.admin_sessions,
            "verification_tokens": result.verification_tokens,
            "reset_tokens": result.reset_tokens,
            "idempotency_records": result.idempotency_records,
        },
    )


@celery_app.task(name="cdc.maintenance.apply_retention")
def apply_retention() -> dict[str, Any]:
    result = run_async(jobs.apply_retention)
    return task_result(
        "cdc.maintenance.apply_retention",
        {
            "usage_summaries": result.usage_summaries,
            "location_samples": result.location_samples,
            "device_events": result.device_events,
            "commands": result.commands,
        },
    )


@celery_app.task(name="cdc.maintenance.resend_pending_wakeups")
def resend_pending_wakeups() -> dict[str, Any]:
    count = run_async(jobs.resend_pending_wakeups)
    return task_result("cdc.maintenance.resend_pending_wakeups", {"requeued": count})


@celery_app.task(name="cdc.privacy.execute_due_deletions")
def execute_due_deletions() -> dict[str, Any]:
    count = run_async(jobs.execute_due_deletions)
    return task_result("cdc.privacy.execute_due_deletions", {"completed": count})
