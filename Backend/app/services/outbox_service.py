"""Transactional outbox.

A state change and the intent to publish it commit together. Nothing is sent
from inside a request handler, so a slow or failing FCM call can never roll
back a policy change or leave a command half-created.

Publication is idempotent and safe under concurrent workers: a row is claimed
with a conditional UPDATE (``WHERE status = 'pending' AND available_at <= now``),
so exactly one worker owns it, and a crash after claiming simply lets the lease
expire back into ``pending``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.db.enums import OutboxStatus
from app.db.models.command import OutboxEvent
from app.repositories.base import rowcount_of
from app.utils.time import utcnow

logger = get_logger(__name__)

#: How long a claimed row may stay locked before another worker may retry it.
LOCK_LEASE_SECONDS = 300


class OutboxTopic:
    """Published topics. Payloads carry ids and status only."""

    COMMAND_QUEUED = "device.command_queued"
    COMMAND_STATUS_CHANGED = "command.status_changed"
    POLICY_CHANGED = "policy.sync_requested"
    POLICY_SYNC_STATUS_CHANGED = "policy.sync_status_changed"
    DEVICE_STATUS_CHANGED = "device.status_changed"
    DEVICE_REVOKED = "device.revoked"
    ALERT_CREATED = "alert.created"
    USAGE_SUMMARY_RECEIVED = "usage.summary_received"
    SUBSCRIPTION_STATUS_CHANGED = "subscription.status_changed"
    PARENT_NOTIFICATION = "parent.notification"


async def enqueue(
    session: AsyncSession,
    *,
    topic: str,
    aggregate_type: str,
    aggregate_id: uuid.UUID,
    family_id: uuid.UUID | None = None,
    payload: dict[str, Any] | None = None,
    delay_seconds: int = 0,
) -> OutboxEvent:
    """Add an outbox row to the *current* transaction. Never commits."""
    event = OutboxEvent(
        topic=topic,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        family_id=family_id,
        payload=_safe_payload(payload or {}),
        status=OutboxStatus.pending,
        available_at=utcnow() + timedelta(seconds=delay_seconds),
    )
    session.add(event)
    return event


#: Keys that must never ride along in an outbox payload: the payload reaches a
#: push provider and a WebSocket fan-out.
_FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "latitude",
        "longitude",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "claim_token",
        "email",
        "display_name",
        "child_name",
        "message_body",
    }
)


def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower() in _FORBIDDEN_PAYLOAD_KEYS:
            raise ValueError(f"Outbox payload must not contain '{key}'.")
        cleaned[key] = str(value) if isinstance(value, uuid.UUID) else value
    return cleaned


@dataclass(frozen=True, slots=True)
class ClaimedEvent:
    id: uuid.UUID
    topic: str
    aggregate_type: str
    aggregate_id: uuid.UUID
    family_id: uuid.UUID | None
    payload: dict[str, Any]
    attempts: int


async def claim_batch(
    session: AsyncSession, *, worker_id: str, limit: int | None = None
) -> list[ClaimedEvent]:
    """Atomically claim up to ``limit`` publishable rows."""
    batch_size = limit or settings.outbox_batch_size
    now = utcnow()
    lease_cutoff = now - timedelta(seconds=LOCK_LEASE_SECONDS)

    candidates = await session.execute(
        select(OutboxEvent.id)
        .where(
            OutboxEvent.available_at <= now,
            (OutboxEvent.status == OutboxStatus.pending)
            | (
                (OutboxEvent.status == OutboxStatus.processing)
                & (OutboxEvent.locked_at < lease_cutoff)
            ),
        )
        .order_by(OutboxEvent.available_at.asc())
        .limit(batch_size)
    )
    ids = [row[0] for row in candidates.all()]
    if not ids:
        return []

    claimed: list[ClaimedEvent] = []
    for event_id in ids:
        # One conditional UPDATE per row: whichever worker's UPDATE matches
        # owns the row, and the loser simply sees rowcount 0.
        result = await session.execute(
            update(OutboxEvent)
            .where(
                OutboxEvent.id == event_id,
                OutboxEvent.available_at <= now,
                (OutboxEvent.status == OutboxStatus.pending)
                | (
                    (OutboxEvent.status == OutboxStatus.processing)
                    & (OutboxEvent.locked_at < lease_cutoff)
                ),
            )
            .values(
                status=OutboxStatus.processing,
                locked_at=now,
                locked_by=worker_id[:64],
                attempts=OutboxEvent.attempts + 1,
            )
        )
        if not rowcount_of(result):
            continue
        row = await session.get(OutboxEvent, event_id)
        if row is None:  # pragma: no cover - defensive
            continue
        claimed.append(
            ClaimedEvent(
                id=row.id,
                topic=row.topic,
                aggregate_type=row.aggregate_type,
                aggregate_id=row.aggregate_id,
                family_id=row.family_id,
                payload=dict(row.payload or {}),
                attempts=row.attempts,
            )
        )
    return claimed


async def mark_sent(session: AsyncSession, event_id: uuid.UUID) -> None:
    await session.execute(
        update(OutboxEvent)
        .where(OutboxEvent.id == event_id)
        .values(
            status=OutboxStatus.sent,
            processed_at=utcnow(),
            locked_at=None,
            locked_by=None,
            last_error_code=None,
        )
    )


async def mark_failed(
    session: AsyncSession, event_id: uuid.UUID, *, error_code: str, attempts: int
) -> None:
    """Reschedule with bounded exponential backoff, or dead-letter."""
    if attempts >= settings.outbox_max_attempts:
        await session.execute(
            update(OutboxEvent)
            .where(OutboxEvent.id == event_id)
            .values(
                status=OutboxStatus.dead_letter,
                processed_at=utcnow(),
                locked_at=None,
                locked_by=None,
                last_error_code=error_code[:64],
            )
        )
        logger.error("outbox_event_dead_lettered", event_id=str(event_id), error_code=error_code)
        return

    backoff_seconds = min(2**attempts * 15, 3600)
    await session.execute(
        update(OutboxEvent)
        .where(OutboxEvent.id == event_id)
        .values(
            status=OutboxStatus.pending,
            available_at=utcnow() + timedelta(seconds=backoff_seconds),
            locked_at=None,
            locked_by=None,
            last_error_code=error_code[:64],
        )
    )


async def backlog_size(session: AsyncSession) -> int:
    from sqlalchemy import func

    result = await session.execute(
        select(func.count())
        .select_from(OutboxEvent)
        .where(OutboxEvent.status.in_([OutboxStatus.pending, OutboxStatus.processing]))
    )
    return int(result.scalar_one())
