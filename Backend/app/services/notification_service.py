"""Push tokens, notification preferences, and content-free push delivery.

Two kinds of push exist in this product:

* **Device wake-ups.** Sent to a child device so it polls the API. Data-only,
  no notification UI, collapsible, and carrying nothing but a reason code.
* **Parent notifications.** A generic title/body ("New activity to review")
  plus a type code. The Parent App fetches the detail with its own credential.

Nothing child-identifying, no usage figures and no coordinates ever go into a
payload, because a push traverses a third party and can surface on a lock
screen.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import time
from zoneinfo import ZoneInfo

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.security import hash_opaque_token
from app.db.enums import (
    DevicePlatform,
    NotificationDeliveryStatus,
    NotificationType,
)
from app.db.models.notification import (
    NotificationDelivery,
    NotificationPreference,
    PushToken,
)
from app.integrations.firebase import PushMessage, PushSendOutcome, get_push_provider
from app.repositories.base import rowcount_of
from app.utils.time import utcnow

logger = get_logger(__name__)

#: Types the product never suppresses, whatever the stored preference says.
ALWAYS_DELIVERED: frozenset[NotificationType] = frozenset(
    {NotificationType.security, NotificationType.device_wakeup}
)

#: Generic, non-revealing copy for parent notifications.
PARENT_NOTIFICATION_COPY: dict[NotificationType, tuple[str, str]] = {
    NotificationType.device_paired: ("Device paired", "A new device finished setup."),
    NotificationType.device_offline: ("Device not reporting", "A device has stopped checking in."),
    NotificationType.policy_sync_failed: (
        "Rules not applied",
        "Open the app to see which rules need attention.",
    ),
    NotificationType.alert_raised: ("New activity to review", "Open the app for details."),
    NotificationType.weekly_report: ("Weekly summary ready", "Your family summary is available."),
    NotificationType.subscription: ("Subscription update", "Open the app for details."),
    NotificationType.security: ("Security alert", "Review recent account activity."),
}


# ---------------------------------------------------------------------------
# Token registration
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class TokenRegistration:
    token: PushToken
    created: bool


async def register_push_token(
    session: AsyncSession,
    *,
    raw_token: str,
    platform: DevicePlatform,
    app_version: str | None,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
) -> TokenRegistration:
    """Register or re-home an FCM token.

    A token is globally unique to one install. If the same token arrives for a
    different owner (app reinstalled, device handed to someone else), ownership
    moves, which prevents notifications being delivered to the wrong person.
    """
    if (user_id is None) == (device_id is None):
        raise ValueError("Exactly one of user_id or device_id must be supplied.")

    token_hash = hash_opaque_token(raw_token)
    result = await session.execute(
        select(PushToken).where(PushToken.token_hash == token_hash).limit(1)
    )
    existing = result.scalars().first()

    if existing is not None:
        existing.token_value = raw_token
        existing.platform = platform
        existing.app_version = app_version
        existing.active = True
        existing.deactivated_at = None
        existing.deactivated_reason = None
        existing.user_id = user_id
        existing.device_id = device_id
        await session.flush()
        return TokenRegistration(token=existing, created=False)

    row = PushToken(
        user_id=user_id,
        device_id=device_id,
        token_value=raw_token,
        token_hash=token_hash,
        platform=platform,
        app_version=app_version,
        active=True,
    )
    session.add(row)
    await session.flush()
    return TokenRegistration(token=row, created=True)


async def deactivate_push_token(
    session: AsyncSession,
    *,
    raw_token: str,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
    reason: str = "client_request",
) -> bool:
    """Deactivate a token, scoped to its owner so one principal cannot
    deregister another's install."""
    statement = update(PushToken).where(
        PushToken.token_hash == hash_opaque_token(raw_token), PushToken.active.is_(True)
    )
    if user_id is not None:
        statement = statement.where(PushToken.user_id == user_id)
    if device_id is not None:
        statement = statement.where(PushToken.device_id == device_id)

    result = await session.execute(
        statement.values(active=False, deactivated_at=utcnow(), deactivated_reason=reason[:64])
    )
    return rowcount_of(result) > 0


async def deactivate_device_tokens(
    session: AsyncSession, *, device_id: uuid.UUID, reason: str
) -> int:
    result = await session.execute(
        update(PushToken)
        .where(PushToken.device_id == device_id, PushToken.active.is_(True))
        .values(active=False, deactivated_at=utcnow(), deactivated_reason=reason[:64])
    )
    return rowcount_of(result)


async def list_user_push_tokens(session: AsyncSession, *, user_id: uuid.UUID) -> list[PushToken]:
    result = await session.execute(
        select(PushToken)
        .where(PushToken.user_id == user_id, PushToken.active.is_(True))
        .order_by(PushToken.updated_at.desc())
    )
    return list(result.scalars().all())


async def active_device_tokens(session: AsyncSession, *, device_id: uuid.UUID) -> list[PushToken]:
    result = await session.execute(
        select(PushToken)
        .where(PushToken.device_id == device_id, PushToken.active.is_(True))
        .order_by(PushToken.updated_at.desc())
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------
async def get_preferences(
    session: AsyncSession, *, user_id: uuid.UUID
) -> dict[NotificationType, NotificationPreference]:
    result = await session.execute(
        select(NotificationPreference).where(NotificationPreference.user_id == user_id)
    )
    return {row.notification_type: row for row in result.scalars().all()}


async def upsert_preferences(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    items: list[tuple[NotificationType, bool, dict | None]],
) -> list[NotificationPreference]:
    current = await get_preferences(session, user_id=user_id)
    for notification_type, enabled, quiet_hours in items:
        if notification_type in ALWAYS_DELIVERED:
            enabled = True
        row = current.get(notification_type)
        if row is None:
            row = NotificationPreference(
                user_id=user_id,
                notification_type=notification_type,
                enabled=enabled,
                quiet_hours=quiet_hours,
            )
            session.add(row)
            current[notification_type] = row
        else:
            row.enabled = enabled
            row.quiet_hours = quiet_hours
    await session.flush()
    return list(current.values())


def _in_quiet_hours(quiet_hours: dict | None) -> bool:
    if not quiet_hours:
        return False
    try:
        tz = ZoneInfo(str(quiet_hours["timezone"]))
        start = time.fromisoformat(str(quiet_hours["start"]))
        end = time.fromisoformat(str(quiet_hours["end"]))
    except Exception:  # noqa: BLE001 - malformed stored preference must not raise
        return False

    now_local = utcnow().astimezone(tz).time()
    if start <= end:
        return start <= now_local < end
    # Window crosses midnight.
    return now_local >= start or now_local < end


async def should_notify_user(
    session: AsyncSession, *, user_id: uuid.UUID, notification_type: NotificationType
) -> bool:
    if notification_type in ALWAYS_DELIVERED:
        return True
    preferences = await get_preferences(session, user_id=user_id)
    row = preferences.get(notification_type)
    if row is None:
        return True  # opt-out model: unset means enabled
    if not row.enabled:
        return False
    return not _in_quiet_hours(row.quiet_hours)


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class PushSummary:
    attempted: int
    sent: int
    invalid_tokens: int
    not_configured: bool


async def send_device_wakeup(
    session: AsyncSession,
    *,
    device_id: uuid.UUID,
    reason: str,
    command_id: uuid.UUID | None = None,
    pending_count: int | None = None,
) -> PushSummary:
    """Nudge a device to poll. Failure here loses nothing: the command is durable."""
    tokens = await active_device_tokens(session, device_id=device_id)
    provider = get_push_provider()

    if not tokens:
        session.add(
            NotificationDelivery(
                device_id=device_id,
                notification_type=NotificationType.device_wakeup,
                status=NotificationDeliveryStatus.failed,
                error_code="NO_ACTIVE_TOKEN",
                related_command_id=command_id,
            )
        )
        return PushSummary(0, 0, 0, not provider.configured)

    data = {"action": "poll_commands"}
    if pending_count is not None:
        data["pending"] = str(min(pending_count, 999))

    sent = invalid = 0
    for token in tokens:
        result = await provider.send(
            PushMessage(
                token=token.token_value,
                reason=reason,
                data=data,
                collapse_key=f"wakeup:{device_id}",
                high_priority=True,
                ttl_seconds=3600,
            )
        )
        status = _delivery_status(result.outcome)
        session.add(
            NotificationDelivery(
                device_id=device_id,
                push_token_id=token.id,
                notification_type=NotificationType.device_wakeup,
                status=status,
                provider_message_id=result.provider_message_id,
                error_code=result.error_code,
                related_command_id=command_id,
                delivered_at=utcnow() if result.sent else None,
            )
        )
        if result.sent:
            sent += 1
            token.last_success_at = utcnow()
        elif result.outcome is PushSendOutcome.token_invalid:
            invalid += 1
            token.active = False
            token.deactivated_at = utcnow()
            token.deactivated_reason = "provider_reported_invalid"

    return PushSummary(len(tokens), sent, invalid, not provider.configured)


async def notify_user(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    notification_type: NotificationType,
    data: dict[str, str] | None = None,
) -> PushSummary:
    """Send a generic parent notification, respecting preferences."""
    provider = get_push_provider()

    if not await should_notify_user(session, user_id=user_id, notification_type=notification_type):
        session.add(
            NotificationDelivery(
                user_id=user_id,
                notification_type=notification_type,
                status=NotificationDeliveryStatus.suppressed_by_preference,
            )
        )
        return PushSummary(0, 0, 0, not provider.configured)

    tokens = await list_user_push_tokens(session, user_id=user_id)
    if not tokens:
        return PushSummary(0, 0, 0, not provider.configured)

    title, body = PARENT_NOTIFICATION_COPY.get(
        notification_type, ("Child Digital Care", "Open the app for details.")
    )
    sent = invalid = 0
    for token in tokens:
        result = await provider.send(
            PushMessage(
                token=token.token_value,
                reason=notification_type.value,
                data=dict(data or {}),
                title=title,
                body=body,
                collapse_key=f"{notification_type.value}:{user_id}",
            )
        )
        session.add(
            NotificationDelivery(
                user_id=user_id,
                push_token_id=token.id,
                notification_type=notification_type,
                status=_delivery_status(result.outcome),
                provider_message_id=result.provider_message_id,
                error_code=result.error_code,
                delivered_at=utcnow() if result.sent else None,
            )
        )
        if result.sent:
            sent += 1
            token.last_success_at = utcnow()
        elif result.outcome is PushSendOutcome.token_invalid:
            invalid += 1
            token.active = False
            token.deactivated_at = utcnow()
            token.deactivated_reason = "provider_reported_invalid"

    return PushSummary(len(tokens), sent, invalid, not provider.configured)


def _delivery_status(outcome: PushSendOutcome) -> NotificationDeliveryStatus:
    return {
        PushSendOutcome.sent: NotificationDeliveryStatus.sent,
        PushSendOutcome.token_invalid: NotificationDeliveryStatus.token_invalid,
        PushSendOutcome.provider_error: NotificationDeliveryStatus.failed,
        PushSendOutcome.rate_limited: NotificationDeliveryStatus.failed,
        PushSendOutcome.not_configured: NotificationDeliveryStatus.provider_not_configured,
    }[outcome]


def token_suffix(raw_token: str) -> str:
    return raw_token[-6:] if len(raw_token) >= 6 else "******"


async def notify_family_guardians(
    session: AsyncSession,
    *,
    family_id: uuid.UUID,
    notification_type: NotificationType,
    data: dict[str, str] | None = None,
) -> PushSummary:
    """Fan a generic notification out to every active guardian of a family.

    Imported lazily to keep this module free of a dependency on the family
    layer (which depends on notifications in the other direction).
    """
    from sqlalchemy import select as _select

    from app.db.enums import MembershipStatus
    from app.db.models.family import FamilyMember

    result = await session.execute(
        _select(FamilyMember.user_id).where(
            FamilyMember.family_id == family_id,
            FamilyMember.membership_status == MembershipStatus.active,
        )
    )
    user_ids = [row[0] for row in result.all()]

    attempted = sent = invalid = 0
    not_configured = False
    for user_id in user_ids:
        summary = await notify_user(
            session, user_id=user_id, notification_type=notification_type, data=data
        )
        attempted += summary.attempted
        sent += summary.sent
        invalid += summary.invalid_tokens
        not_configured = not_configured or summary.not_configured
    return PushSummary(attempted, sent, invalid, not_configured)
