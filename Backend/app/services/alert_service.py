"""Parent-facing alerts and device-event ingestion.

Alerts are deduplicated by a caller-supplied key so a persistent condition
(a device that stays offline, a permission that stays revoked) produces one
alert rather than one per poll. Device events are deduplicated the same way, so
the Child App can retry a batch safely.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import Conflict, NotFound
from app.core.logging import get_logger
from app.db.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    DeviceEventType,
    NotificationType,
)
from app.db.models.command import DeviceEvent
from app.db.models.device import Device
from app.db.models.usage import Alert
from app.repositories.base import rowcount_of
from app.services import notification_service, outbox_service
from app.services.outbox_service import OutboxTopic
from app.utils.time import ensure_utc, utcnow

logger = get_logger(__name__)

#: Device events that should surface to a parent, with the alert they produce.
EVENT_ALERT_MAP: dict[DeviceEventType, tuple[AlertType, AlertSeverity, str, str]] = {
    DeviceEventType.uninstall_attempted: (
        AlertType.uninstall_attempted,
        AlertSeverity.high,
        "Someone tried to remove the app",
        "An attempt was made to uninstall or disable Child Digital Care on a device.",
    ),
    DeviceEventType.policy_apply_failed: (
        AlertType.policy_sync_failed,
        AlertSeverity.medium,
        "Rules could not be applied",
        "A device could not apply the current rules. Open the app to see why.",
    ),
    DeviceEventType.screen_time_limit_reached: (
        AlertType.screen_time_limit_reached,
        AlertSeverity.info,
        "Daily limit reached",
        "A device reached its daily screen-time limit.",
    ),
    DeviceEventType.blocked_app_launch_attempt: (
        AlertType.blocked_app_launch_attempt,
        AlertSeverity.low,
        "A blocked app was opened",
        "A device reported an attempt to open a restricted app.",
    ),
}

#: Alert types worth a push notification. Low/info alerts are collected in-app
#: rather than interrupting a parent.
PUSH_WORTHY_SEVERITIES: frozenset[AlertSeverity] = frozenset(
    {AlertSeverity.high, AlertSeverity.medium}
)


async def raise_alert(
    session: AsyncSession,
    *,
    family_id: uuid.UUID,
    alert_type: AlertType,
    severity: AlertSeverity,
    title: str,
    message: str,
    child_profile_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
    deduplication_key: str | None = None,
    occurred_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> Alert | None:
    """Create an alert, or return ``None`` when it duplicates an open one."""
    key = deduplication_key[:160] if deduplication_key else None

    if key is not None:
        existing = await session.execute(
            select(Alert)
            .where(Alert.family_id == family_id, Alert.deduplication_key == key)
            .limit(1)
        )
        if existing.scalars().first() is not None:
            return None

    alert = Alert(
        family_id=family_id,
        child_profile_id=child_profile_id,
        device_id=device_id,
        alert_type=alert_type,
        severity=severity,
        status=AlertStatus.open,
        title=title[:120],
        message=message[:500],
        alert_metadata=metadata,
        occurred_at=occurred_at or utcnow(),
        deduplication_key=key,
    )
    session.add(alert)
    try:
        await session.flush()
    except IntegrityError:
        # Lost a race on the dedup key; the other writer's alert stands.
        await session.rollback()
        logger.info("alert_deduplicated", alert_type=alert_type.value)
        return None

    await outbox_service.enqueue(
        session,
        topic=OutboxTopic.ALERT_CREATED,
        aggregate_type="alert",
        aggregate_id=alert.id,
        family_id=family_id,
        payload={
            "alert_id": str(alert.id),
            "alert_type": alert_type.value,
            "severity": severity.value,
            "device_id": str(device_id) if device_id else None,
            "notify": severity in PUSH_WORTHY_SEVERITIES,
        },
    )
    return alert


async def resolve_alerts(
    session: AsyncSession,
    *,
    family_id: uuid.UUID,
    alert_type: AlertType,
    device_id: uuid.UUID | None = None,
) -> int:
    """Auto-resolve open alerts whose condition has cleared."""
    statement = update(Alert).where(
        Alert.family_id == family_id,
        Alert.alert_type == alert_type,
        Alert.status.in_([AlertStatus.open, AlertStatus.acknowledged]),
    )
    if device_id is not None:
        statement = statement.where(Alert.device_id == device_id)
    result = await session.execute(
        statement.values(status=AlertStatus.resolved, resolved_at=utcnow())
    )
    return rowcount_of(result)


async def get_alert(
    session: AsyncSession, *, alert_id: uuid.UUID, family_ids: list[uuid.UUID]
) -> Alert:
    if not family_ids:
        raise NotFound("Alert not found.")
    result = await session.execute(
        select(Alert).where(Alert.id == alert_id, Alert.family_id.in_(family_ids)).limit(1)
    )
    alert = result.scalars().first()
    if alert is None:
        raise NotFound("Alert not found.")
    return alert


async def update_alert_status(
    session: AsyncSession,
    *,
    alert: Alert,
    status: AlertStatus,
    user_id: uuid.UUID,
) -> Alert:
    if alert.status is status:
        return alert
    if alert.status in (AlertStatus.resolved, AlertStatus.dismissed):
        raise Conflict("This alert has already been closed.")

    alert.status = status
    now = utcnow()
    if status is AlertStatus.acknowledged:
        alert.acknowledged_at = now
        alert.acknowledged_by_user_id = user_id
    elif status in (AlertStatus.resolved, AlertStatus.dismissed):
        alert.resolved_at = now
        if alert.acknowledged_at is None:
            alert.acknowledged_at = now
            alert.acknowledged_by_user_id = user_id
    return alert


# ---------------------------------------------------------------------------
# Device events
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class EventIngestResult:
    accepted: int
    duplicates: int
    alerts_created: int


async def ingest_events(
    session: AsyncSession,
    *,
    device: Device,
    events: list[tuple[DeviceEventType, datetime, str, dict | None]],
) -> EventIngestResult:
    """Store device events idempotently and raise any resulting alerts."""
    keys = [key for _, _, key, _ in events]
    existing_keys: set[str] = set()
    if keys:
        result = await session.execute(
            select(DeviceEvent.deduplication_key).where(
                DeviceEvent.device_id == device.id,
                DeviceEvent.deduplication_key.in_(keys),
            )
        )
        existing_keys = {row[0] for row in result.all()}

    retention_cutoff = utcnow() + timedelta(days=settings.retention_device_events_days)
    accepted = duplicates = alerts_created = 0

    for event_type, occurred_at, dedup_key, payload in events:
        if dedup_key in existing_keys:
            duplicates += 1
            continue
        existing_keys.add(dedup_key)

        session.add(
            DeviceEvent(
                family_id=device.family_id,
                device_id=device.id,
                child_profile_id=device.child_profile_id,
                event_type=event_type,
                payload=_safe_event_payload(payload),
                occurred_at=ensure_utc(occurred_at),
                deduplication_key=dedup_key[:128],
                retention_expires_at=retention_cutoff,
            )
        )
        accepted += 1

        mapping = EVENT_ALERT_MAP.get(event_type)
        if mapping is not None:
            alert_type, severity, title, message = mapping
            # Bucket by day so a recurring condition yields one alert per day.
            bucket = ensure_utc(occurred_at).date().isoformat()
            alert = await raise_alert(
                session,
                family_id=device.family_id,
                child_profile_id=device.child_profile_id,
                device_id=device.id,
                alert_type=alert_type,
                severity=severity,
                title=title,
                message=message,
                occurred_at=ensure_utc(occurred_at),
                deduplication_key=f"{alert_type.value}:{device.id}:{bucket}",
            )
            if alert is not None:
                alerts_created += 1

    device.last_seen_at = utcnow()
    await session.flush()
    return EventIngestResult(
        accepted=accepted, duplicates=duplicates, alerts_created=alerts_created
    )


#: Event payload keys that would turn telemetry into surveillance.
_FORBIDDEN_EVENT_KEYS = frozenset(
    {
        "latitude",
        "longitude",
        "coordinates",
        "message",
        "message_body",
        "sms",
        "contacts",
        "keystrokes",
        "screenshot",
        "clipboard",
        "url",
        "browsing_history",
        "audio",
        "photo",
    }
)
_MAX_EVENT_PAYLOAD_KEYS = 15


def _safe_event_payload(payload: dict | None) -> dict | None:
    """Reject payload keys that fall outside the agreed telemetry scope."""
    if not payload:
        return None
    cleaned: dict[str, Any] = {}
    for key, value in list(payload.items())[:_MAX_EVENT_PAYLOAD_KEYS]:
        if key.lower() in _FORBIDDEN_EVENT_KEYS:
            raise Conflict(
                f"Device events must not include '{key}'. This product does not collect "
                "message content, browsing history, media or location through events."
            )
        if isinstance(value, bool | int | float) or value is None:
            cleaned[key] = value
        else:
            cleaned[key] = str(value)[:200]
    return cleaned or None


async def notify_alert_subscribers(
    session: AsyncSession, *, family_id: uuid.UUID, alert_type: AlertType
) -> None:
    """Send the generic 'new activity' push to the family's guardians."""
    await notification_service.notify_family_guardians(
        session,
        family_id=family_id,
        notification_type=NotificationType.alert_raised,
        data={"alert_type": alert_type.value},
    )
