"""Async implementations of every background job.

Kept separate from the Celery task wrappers so the tests (and an operator with
``python -m app.workers.run_job``) can call them directly, with no broker.

All jobs share three properties:

* **Idempotent.** Re-running one produces no duplicate side effects.
* **Bounded.** Each processes at most a batch and returns counts, so a backlog
  drains over several runs instead of one unbounded transaction.
* **Loud about failure.** A publish failure reschedules with backoff and
  eventually dead-letters, rather than silently dropping work.
"""

from __future__ import annotations

import socket
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select, update

from app.core.config import settings
from app.core.logging import get_logger
from app.db.enums import (
    AlertSeverity,
    DeliveryChannel,
    DeliveryOutcome,
    NotificationType,
)
from app.db.models.admin import AdminSession
from app.db.models.command import DeviceCommand, DeviceEvent
from app.db.models.device import Device, DeviceSession
from app.db.models.identity import (
    EmailVerificationToken,
    PasswordResetToken,
    UserSession,
)
from app.db.models.usage import Alert
from app.db.session import session_scope
from app.repositories.base import rowcount_of
from app.services import (
    command_service,
    device_service,
    idempotency_service,
    location_service,
    notification_service,
    outbox_service,
    pairing_service,
    privacy_service,
    realtime_service,
    usage_service,
)
from app.services.outbox_service import OutboxTopic
from app.utils.time import utcnow

logger = get_logger(__name__)

WORKER_ID = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"


@dataclass(slots=True)
class OutboxRunResult:
    claimed: int = 0
    published: int = 0
    failed: int = 0
    skipped: int = 0
    details: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Outbox
# ---------------------------------------------------------------------------
async def process_outbox(batch_size: int | None = None) -> OutboxRunResult:
    """Publish pending outbox rows.

    Each row becomes a *content-free* signal: an FCM wake-up for a device, or a
    realtime hint for a family. Losing a push loses nothing, because the
    durable command still sits in PostgreSQL waiting to be polled.
    """
    result = OutboxRunResult()

    async with session_scope() as session:
        events = await outbox_service.claim_batch(session, worker_id=WORKER_ID, limit=batch_size)
        result.claimed = len(events)

        for event in events:
            try:
                published = await _publish(session, event)
            except Exception as exc:  # noqa: BLE001 - one bad row must not stop the batch
                logger.warning(
                    "outbox_publish_error",
                    topic=event.topic,
                    event_id=str(event.id),
                    error=type(exc).__name__,
                )
                await outbox_service.mark_failed(
                    session,
                    event.id,
                    error_code=type(exc).__name__,
                    attempts=event.attempts,
                )
                result.failed += 1
                continue

            if published:
                await outbox_service.mark_sent(session, event.id)
                result.published += 1
            else:
                # Nothing to publish (for example no active push token). That
                # is a terminal, non-error outcome: the device will still poll.
                await outbox_service.mark_sent(session, event.id)
                result.skipped += 1

            result.details[event.topic] = result.details.get(event.topic, 0) + 1

    return result


async def _publish(session, event: outbox_service.ClaimedEvent) -> bool:  # noqa: ANN001
    """Dispatch one outbox row. Returns True when something was delivered."""
    payload: dict[str, Any] = event.payload

    if event.topic == OutboxTopic.COMMAND_QUEUED:
        return await _publish_command_queued(session, event, payload)

    if event.topic == OutboxTopic.POLICY_CHANGED:
        if event.family_id:
            await realtime_service.publish_to_family(
                event.family_id,
                realtime_service.RealtimeEvent.POLICY_SYNC_STATUS_CHANGED,
                {
                    "child_profile_id": payload.get("child_profile_id"),
                    "policy_version": payload.get("policy_version"),
                    "sync_status": "pending_sync",
                },
            )
        return True

    if event.topic in (
        OutboxTopic.COMMAND_STATUS_CHANGED,
        OutboxTopic.POLICY_SYNC_STATUS_CHANGED,
        OutboxTopic.DEVICE_STATUS_CHANGED,
        OutboxTopic.DEVICE_REVOKED,
        OutboxTopic.USAGE_SUMMARY_RECEIVED,
        OutboxTopic.SUBSCRIPTION_STATUS_CHANGED,
    ):
        if event.family_id:
            await realtime_service.publish_to_family(
                event.family_id, _realtime_event_for(event.topic), payload
            )
        return True

    if event.topic == OutboxTopic.ALERT_CREATED:
        return await _publish_alert(session, event, payload)

    logger.warning("outbox_unknown_topic", topic=event.topic)
    return False


def _realtime_event_for(topic: str) -> str:
    return {
        OutboxTopic.COMMAND_STATUS_CHANGED: realtime_service.RealtimeEvent.COMMAND_STATUS_CHANGED,
        OutboxTopic.POLICY_SYNC_STATUS_CHANGED: (
            realtime_service.RealtimeEvent.POLICY_SYNC_STATUS_CHANGED
        ),
        OutboxTopic.DEVICE_STATUS_CHANGED: realtime_service.RealtimeEvent.DEVICE_STATUS_CHANGED,
        OutboxTopic.DEVICE_REVOKED: realtime_service.RealtimeEvent.DEVICE_STATUS_CHANGED,
        OutboxTopic.USAGE_SUMMARY_RECEIVED: (realtime_service.RealtimeEvent.USAGE_SUMMARY_RECEIVED),
        OutboxTopic.SUBSCRIPTION_STATUS_CHANGED: (
            realtime_service.RealtimeEvent.SUBSCRIPTION_STATUS_CHANGED
        ),
    }[topic]


async def _publish_command_queued(
    session,
    event: outbox_service.ClaimedEvent,
    payload: dict[str, Any],  # noqa: ANN001
) -> bool:
    device_id_raw = payload.get("device_id")
    if not device_id_raw:
        return False
    device_id = uuid.UUID(str(device_id_raw))

    command: DeviceCommand | None = None
    command_id_raw = payload.get("command_id")
    if command_id_raw:
        command = await session.get(DeviceCommand, uuid.UUID(str(command_id_raw)))

    if command is not None and command_service.is_terminal(command.status):
        # Cancelled or already expired before the wake-up went out.
        return False

    pending = await command_service.count_pending(session, device_id=device_id)
    summary = await notification_service.send_device_wakeup(
        session,
        device_id=device_id,
        reason="commands_pending",
        command_id=command.id if command else None,
        pending_count=pending,
    )

    if command is not None:
        outcome = (
            DeliveryOutcome.sent
            if summary.sent
            else (
                DeliveryOutcome.provider_not_configured
                if summary.not_configured
                else (
                    DeliveryOutcome.no_active_token
                    if summary.attempted == 0
                    else DeliveryOutcome.provider_error
                )
            )
        )
        await command_service.record_delivery_attempt(
            session, command=command, channel=DeliveryChannel.fcm, outcome=outcome
        )

    # A realtime hint as well, so a Parent App watching the device sees the
    # queued command immediately.
    if event.family_id:
        await realtime_service.publish_to_family(
            event.family_id,
            realtime_service.RealtimeEvent.DEVICE_COMMANDS_PENDING,
            {"device_id": str(device_id), "pending": pending},
        )
    return bool(summary.sent)


async def _publish_alert(
    session,
    event: outbox_service.ClaimedEvent,
    payload: dict[str, Any],  # noqa: ANN001
) -> bool:
    alert = await session.get(Alert, event.aggregate_id)
    if alert is None:
        return False

    if event.family_id:
        await realtime_service.publish_to_family(
            event.family_id,
            realtime_service.RealtimeEvent.ALERT_CREATED,
            {
                "alert_id": str(alert.id),
                "alert_type": alert.alert_type.value,
                "severity": alert.severity.value,
            },
        )

    # Only medium/high alerts interrupt a parent; the rest are collected in-app.
    if alert.severity in (AlertSeverity.high, AlertSeverity.medium) and event.family_id:
        summary = await notification_service.notify_family_guardians(
            session,
            family_id=event.family_id,
            notification_type=NotificationType.alert_raised,
            data={"alert_type": alert.alert_type.value},
        )
        return bool(summary.sent)
    return True


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------
async def expire_commands(limit: int = 500) -> int:
    async with session_scope() as session:
        return await command_service.expire_overdue(session, limit=limit)


async def expire_pairing_invitations(limit: int = 500) -> int:
    async with session_scope() as session:
        return await pairing_service.expire_stale_invitations(session, limit=limit)


async def mark_stale_devices(limit: int = 500) -> int:
    async with session_scope() as session:
        return await device_service.mark_stale_devices_offline(session, limit=limit)


@dataclass(slots=True)
class SessionCleanupResult:
    user_sessions: int = 0
    device_sessions: int = 0
    admin_sessions: int = 0
    verification_tokens: int = 0
    reset_tokens: int = 0
    idempotency_records: int = 0


async def cleanup_sessions(grace_days: int = 7) -> SessionCleanupResult:
    """Remove expired sessions and consumed single-use tokens.

    A grace period keeps recently expired rows around long enough to diagnose a
    refresh problem, and retains reuse-detection evidence a little past expiry.
    """
    cutoff = utcnow() - timedelta(days=grace_days)
    result = SessionCleanupResult()

    async with session_scope() as session:
        for model, attribute in (
            (UserSession, "user_sessions"),
            (DeviceSession, "device_sessions"),
            (AdminSession, "admin_sessions"),
        ):
            deleted = await session.execute(delete(model).where(model.expires_at < cutoff))
            setattr(result, attribute, rowcount_of(deleted))

        verification = await session.execute(
            delete(EmailVerificationToken).where(EmailVerificationToken.expires_at < cutoff)
        )
        result.verification_tokens = rowcount_of(verification)

        reset = await session.execute(
            delete(PasswordResetToken).where(PasswordResetToken.expires_at < cutoff)
        )
        result.reset_tokens = rowcount_of(reset)

        result.idempotency_records = await idempotency_service.purge_expired(session)

    return result


@dataclass(slots=True)
class RetentionResult:
    usage_summaries: int = 0
    location_samples: int = 0
    device_events: int = 0
    commands: int = 0


async def apply_retention() -> RetentionResult:
    """Delete data past its category's retention deadline."""
    result = RetentionResult()
    now = utcnow()

    async with session_scope() as session:
        result.usage_summaries = await usage_service.purge_expired_summaries(session)
        result.location_samples = await location_service.purge_expired(session)

        events = await session.execute(
            delete(DeviceEvent).where(
                DeviceEvent.retention_expires_at.is_not(None),
                DeviceEvent.retention_expires_at <= now,
            )
        )
        result.device_events = rowcount_of(events)

        command_cutoff = now - timedelta(days=settings.retention_command_history_days)
        commands = await session.execute(
            delete(DeviceCommand).where(
                DeviceCommand.completed_at.is_not(None),
                DeviceCommand.completed_at <= command_cutoff,
            )
        )
        result.commands = rowcount_of(commands)

    return result


async def execute_due_deletions(limit: int = 20) -> int:
    async with session_scope() as session:
        outcomes = await privacy_service.execute_due_deletions(session, limit=limit)
        return len(outcomes)


async def resend_pending_wakeups(limit: int = 100) -> int:
    """Re-notify devices with long-pending commands.

    A device may have missed every push (force-stopped, battery-restricted,
    offline). Re-queueing a wake-up gives it another chance without touching
    the command's own retry accounting.
    """
    cutoff = utcnow() - timedelta(hours=1)
    requeued = 0

    async with session_scope() as session:
        rows = await session.execute(
            select(DeviceCommand)
            .where(
                DeviceCommand.status.in_(command_service.PENDING_STATUSES),
                DeviceCommand.expires_at > utcnow(),
                DeviceCommand.fetched_at.is_(None),
                DeviceCommand.created_at <= cutoff,
                DeviceCommand.delivery_attempt_count < settings.command_max_delivery_attempts,
            )
            .limit(limit)
        )
        for command in rows.scalars().all():
            await outbox_service.enqueue(
                session,
                topic=OutboxTopic.COMMAND_QUEUED,
                aggregate_type="device_command",
                aggregate_id=command.id,
                family_id=command.family_id,
                payload={
                    "device_id": str(command.device_id),
                    "command_type": command.command_type.value,
                    "command_id": str(command.id),
                    "retry": True,
                },
            )
            requeued += 1

    return requeued


async def deactivate_revoked_device_tokens() -> int:
    """Safety net: ensure no revoked device still has an active push token."""
    async with session_scope() as session:
        from app.db.enums import DeviceStatus
        from app.db.models.notification import PushToken

        revoked = await session.execute(
            select(Device.id).where(Device.device_status == DeviceStatus.revoked)
        )
        ids = [row[0] for row in revoked.all()]
        if not ids:
            return 0
        updated = await session.execute(
            update(PushToken)
            .where(PushToken.device_id.in_(ids), PushToken.active.is_(True))
            .values(
                active=False,
                deactivated_at=utcnow(),
                deactivated_reason="device_revoked_sweep",
            )
        )
        return rowcount_of(updated)
