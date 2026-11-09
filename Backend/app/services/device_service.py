"""Device registration, heartbeat, capability/permission reports, revocation."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.logging import get_logger
from app.db.enums import (
    AlertSeverity,
    AlertType,
    AuditActorType,
    CapabilityKey,
    CapabilitySupport,
    DeviceStatus,
    NotificationType,
    PermissionKey,
    PermissionState,
    SyncStatus,
)
from app.db.models.device import (
    Device,
    DeviceCapability,
    DevicePermissionReport,
)
from app.db.models.family import ChildProfile
from app.services import (
    alert_service,
    audit_service,
    command_service,
    notification_service,
    outbox_service,
    token_service,
)
from app.services.audit_service import AuditAction
from app.services.outbox_service import OutboxTopic
from app.utils.time import utcnow

logger = get_logger(__name__)

#: A device that has not checked in for this long is treated as offline.
OFFLINE_AFTER = timedelta(hours=24)
RECENTLY_SEEN_WITHIN = timedelta(minutes=15)

#: How long the device should wait before polling again. Kept generous: Android
#: background limits mean aggressive polling is both futile and battery-hostile.
DEFAULT_POLL_INTERVAL_SECONDS = 900
BUSY_POLL_INTERVAL_SECONDS = 60

#: Capabilities whose loss degrades the product enough to tell the parent.
CRITICAL_CAPABILITIES: frozenset[CapabilityKey] = frozenset(
    {
        CapabilityKey.app_usage_stats,
        CapabilityKey.app_blocking,
        CapabilityKey.screen_time_enforcement,
        CapabilityKey.background_execution,
    }
)

BLOCKING_PERMISSION_STATES: frozenset[PermissionState] = frozenset(
    {
        PermissionState.denied,
        PermissionState.permanently_denied,
        PermissionState.restricted,
    }
)


def presence_of(device: Device) -> str:
    """Derive a presence label. An inference, labelled as such in the API."""
    if device.device_status is DeviceStatus.revoked:
        return "revoked"
    if device.last_seen_at is None:
        return "unknown"
    age = utcnow() - device.last_seen_at
    if age <= RECENTLY_SEEN_WITHIN:
        return "online"
    if age <= OFFLINE_AFTER:
        return "recently_seen"
    return "offline"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class RegistrationOutcome:
    device: Device
    newly_registered: bool


async def register_device(
    session: AsyncSession,
    *,
    device: Device,
    app_version: str,
    os_version: str | None,
    device_label: str | None,
    device_model: str | None,
    manufacturer: str | None,
    timezone: str,
    install_id: str | None,
    client_ip: str | None = None,
) -> RegistrationOutcome:
    """Idempotent: a repeated call refreshes metadata without side effects."""
    newly_registered = device.device_status is DeviceStatus.pending_registration

    device.app_version = app_version
    device.os_version = os_version
    device.device_model = device_model
    device.manufacturer = manufacturer
    device.timezone = timezone
    if device_label:
        device.device_label = device_label[:80]
    if install_id and not device.install_id:
        device.install_id = install_id

    now = utcnow()
    device.last_seen_at = now
    if newly_registered:
        device.device_status = DeviceStatus.active
        device.registered_at = now

    await audit_service.record(
        session,
        action=AuditAction.DEVICE_REGISTERED,
        actor_type=AuditActorType.child_device,
        actor_id=device.id,
        target_type="device",
        target_id=device.id,
        family_id=device.family_id,
        client_ip=client_ip,
        metadata={"newly_registered": newly_registered, "app_version": app_version},
    )

    if newly_registered:
        await outbox_service.enqueue(
            session,
            topic=OutboxTopic.DEVICE_STATUS_CHANGED,
            aggregate_type="device",
            aggregate_id=device.id,
            family_id=device.family_id,
            payload={
                "device_id": str(device.id),
                "device_status": device.device_status.value,
                "event": "registered",
            },
        )
        await alert_service.raise_alert(
            session,
            family_id=device.family_id,
            child_profile_id=device.child_profile_id,
            device_id=device.id,
            alert_type=AlertType.new_device_paired,
            severity=AlertSeverity.medium,
            title="A new device finished setup",
            message=(f"'{device.device_label}' completed setup and is now linked to this family."),
            deduplication_key=f"device_registered:{device.id}",
        )
    return RegistrationOutcome(device=device, newly_registered=newly_registered)


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class HeartbeatOutcome:
    policy_version: int
    policy_sync_required: bool
    pending_commands: int
    next_poll_after_seconds: int


async def heartbeat(
    session: AsyncSession,
    *,
    device: Device,
    app_version: str | None,
    os_version: str | None,
    timezone: str | None,
    applied_policy_version: int | None,
) -> HeartbeatOutcome:
    now = utcnow()
    was_offline = presence_of(device) == "offline"

    device.last_seen_at = now
    device.last_heartbeat_at = now
    if app_version:
        device.app_version = app_version
    if os_version:
        device.os_version = os_version
    if timezone:
        device.timezone = timezone
    if device.device_status is DeviceStatus.inactive:
        device.device_status = DeviceStatus.active

    child = await session.get(ChildProfile, device.child_profile_id)
    if child is None:  # pragma: no cover - FK guarantees this
        raise NotFound("Child profile not found.")

    # A heartbeat may report the version the device currently has applied. It
    # is accepted as a *report*, and only ever used to mark convergence - never
    # to claim success for a version the device has not confirmed.
    if (
        applied_policy_version is not None
        and applied_policy_version == child.policy_version
        and device.policy_sync_status in (SyncStatus.pending_sync, SyncStatus.delivered)
    ):
        device.applied_policy_version = applied_policy_version
        device.policy_sync_status = SyncStatus.synced
        device.policy_synced_at = now

    pending = await command_service.count_pending(session, device_id=device.id)
    sync_required = (device.applied_policy_version or 0) < child.policy_version

    if was_offline:
        await alert_service.resolve_alerts(
            session,
            family_id=device.family_id,
            device_id=device.id,
            alert_type=AlertType.device_offline,
        )
        await outbox_service.enqueue(
            session,
            topic=OutboxTopic.DEVICE_STATUS_CHANGED,
            aggregate_type="device",
            aggregate_id=device.id,
            family_id=device.family_id,
            payload={"device_id": str(device.id), "event": "back_online"},
        )

    return HeartbeatOutcome(
        policy_version=child.policy_version,
        policy_sync_required=sync_required,
        pending_commands=pending,
        next_poll_after_seconds=(
            BUSY_POLL_INTERVAL_SECONDS
            if pending or sync_required
            else DEFAULT_POLL_INTERVAL_SECONDS
        ),
    )


# ---------------------------------------------------------------------------
# Capability / permission reports
# ---------------------------------------------------------------------------
async def report_capabilities(
    session: AsyncSession,
    *,
    device: Device,
    app_version: str | None,
    items: list[tuple[CapabilityKey, CapabilitySupport, PermissionState, int | None, str | None]],
) -> list[DeviceCapability]:
    """Upsert capability rows and alert on a newly lost critical capability."""
    existing = {
        row.capability_key: row
        for row in (
            await session.execute(
                select(DeviceCapability).where(DeviceCapability.device_id == device.id)
            )
        )
        .scalars()
        .all()
    }
    now = utcnow()
    degraded: list[str] = []

    for key, support, permission_state, api_level, note in items:
        row = existing.get(key)
        previously_usable = row is not None and _capability_usable(
            row.support, row.permission_state
        )
        if row is None:
            row = DeviceCapability(device_id=device.id, capability_key=key)
            session.add(row)
            existing[key] = row

        row.support = support
        row.permission_state = permission_state
        row.os_api_level = api_level
        row.app_version = app_version
        row.reported_at = now
        row.capability_metadata = {"note": note[:160]} if note else None

        now_usable = _capability_usable(support, permission_state)
        if key in CRITICAL_CAPABILITIES and previously_usable and not now_usable:
            degraded.append(key.value)

    device.last_seen_at = now
    await session.flush()

    if degraded:
        await alert_service.raise_alert(
            session,
            family_id=device.family_id,
            child_profile_id=device.child_profile_id,
            device_id=device.id,
            alert_type=AlertType.capability_unsupported,
            severity=AlertSeverity.high,
            title="A device can no longer apply some rules",
            message=(
                f"'{device.device_label}' reported that it can no longer enforce: "
                f"{', '.join(degraded)}. Open the app to see what to re-enable on the device."
            ),
            deduplication_key=f"capability_lost:{device.id}:{','.join(sorted(degraded))}",
            metadata={"capabilities": degraded},
        )
        await notification_service.notify_family_guardians(
            session,
            family_id=device.family_id,
            notification_type=NotificationType.policy_sync_failed,
            data={"reason": "capability_lost"},
        )

    await audit_service.record(
        session,
        action=AuditAction.DEVICE_CAPABILITIES_REPORTED,
        actor_type=AuditActorType.child_device,
        actor_id=device.id,
        target_type="device",
        target_id=device.id,
        family_id=device.family_id,
        metadata={"count": len(items), "degraded": degraded},
    )
    return list(existing.values())


def _capability_usable(support: CapabilitySupport, state: PermissionState) -> bool:
    return support is CapabilitySupport.supported and state not in BLOCKING_PERMISSION_STATES


async def report_permissions(
    session: AsyncSession,
    *,
    device: Device,
    app_version: str | None,
    items: list[tuple[PermissionKey, PermissionState, str | None]],
) -> list[DevicePermissionReport]:
    existing = {
        row.permission_key: row
        for row in (
            await session.execute(
                select(DevicePermissionReport).where(DevicePermissionReport.device_id == device.id)
            )
        )
        .scalars()
        .all()
    }
    now = utcnow()
    newly_blocked: list[str] = []

    for key, state, note in items:
        row = existing.get(key)
        was_granted = row is not None and row.state is PermissionState.granted
        if row is None:
            row = DevicePermissionReport(device_id=device.id, permission_key=key, state=state)
            session.add(row)
            existing[key] = row

        row.state = state
        row.app_version = app_version
        row.reported_at = now
        row.explanatory_metadata = {"note": note[:160]} if note else None

        if was_granted and state in BLOCKING_PERMISSION_STATES:
            newly_blocked.append(key.value)

    device.last_seen_at = now
    await session.flush()

    if newly_blocked:
        await alert_service.raise_alert(
            session,
            family_id=device.family_id,
            child_profile_id=device.child_profile_id,
            device_id=device.id,
            alert_type=AlertType.permission_revoked_on_device,
            severity=AlertSeverity.high,
            title="A permission was turned off on a device",
            message=(
                f"'{device.device_label}' reported that these permissions are no longer "
                f"granted: {', '.join(newly_blocked)}. Some rules cannot be applied until "
                "they are re-enabled on the device."
            ),
            deduplication_key=(f"permission_revoked:{device.id}:{','.join(sorted(newly_blocked))}"),
            metadata={"permissions": newly_blocked},
        )

    await audit_service.record(
        session,
        action=AuditAction.DEVICE_PERMISSIONS_REPORTED,
        actor_type=AuditActorType.child_device,
        actor_id=device.id,
        target_type="device",
        target_id=device.id,
        family_id=device.family_id,
        metadata={"count": len(items), "newly_blocked": newly_blocked},
    )
    return list(existing.values())


async def list_capabilities(
    session: AsyncSession, *, device_id: uuid.UUID
) -> list[DeviceCapability]:
    result = await session.execute(
        select(DeviceCapability)
        .where(DeviceCapability.device_id == device_id)
        .order_by(DeviceCapability.capability_key.asc())
    )
    return list(result.scalars().all())


async def list_permissions(
    session: AsyncSession, *, device_id: uuid.UUID
) -> list[DevicePermissionReport]:
    result = await session.execute(
        select(DevicePermissionReport)
        .where(DevicePermissionReport.device_id == device_id)
        .order_by(DevicePermissionReport.permission_key.asc())
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Listing and mutation
# ---------------------------------------------------------------------------
async def list_devices(
    session: AsyncSession,
    *,
    family_ids: list[uuid.UUID],
    child_profile_id: uuid.UUID | None = None,
    include_revoked: bool = False,
) -> list[Device]:
    if not family_ids:
        return []
    statement = select(Device).where(Device.family_id.in_(family_ids))
    if child_profile_id is not None:
        statement = statement.where(Device.child_profile_id == child_profile_id)
    if not include_revoked:
        statement = statement.where(Device.device_status != DeviceStatus.revoked)
    result = await session.execute(statement.order_by(Device.created_at.asc()))
    return list(result.scalars().all())


async def update_label(
    session: AsyncSession,
    *,
    device: Device,
    label: str,
    user_id: uuid.UUID,
    client_ip: str | None = None,
) -> Device:
    device.device_label = label.strip()[:80]
    await audit_service.record(
        session,
        action=AuditAction.DEVICE_LABEL_UPDATED,
        actor_type=AuditActorType.parent_user,
        actor_id=user_id,
        target_type="device",
        target_id=device.id,
        family_id=device.family_id,
        client_ip=client_ip,
    )
    return device


@dataclass(frozen=True, slots=True)
class RevocationOutcome:
    device: Device
    sessions_revoked: int
    commands_cancelled: int
    push_tokens_deactivated: int


async def revoke_device(
    session: AsyncSession,
    *,
    device: Device,
    reason: str,
    actor_type: AuditActorType,
    actor_id: uuid.UUID | None,
    client_ip: str | None = None,
) -> RevocationOutcome:
    """Unlink a device.

    The device is told nothing it can rely on: its credentials simply stop
    working on the next call, which is the only mechanism that works whether or
    not the device is reachable. Pending commands are cancelled so a parent is
    not shown work that will never run.
    """
    now = utcnow()
    device.device_status = DeviceStatus.revoked
    device.revoked_at = now
    device.revoked_reason = reason[:120]
    if actor_type is AuditActorType.parent_user:
        device.revoked_by_user_id = actor_id

    sessions = await token_service.revoke_all_device_sessions(
        session, device_id=device.id, reason="device_revoked"
    )
    commands = await command_service.cancel_pending_for_device(
        session, device_id=device.id, reason=f"device unlinked: {reason}"[:255]
    )
    tokens = await notification_service.deactivate_device_tokens(
        session, device_id=device.id, reason="device_revoked"
    )

    await outbox_service.enqueue(
        session,
        topic=OutboxTopic.DEVICE_REVOKED,
        aggregate_type="device",
        aggregate_id=device.id,
        family_id=device.family_id,
        payload={"device_id": str(device.id), "event": "revoked"},
    )
    await alert_service.raise_alert(
        session,
        family_id=device.family_id,
        child_profile_id=device.child_profile_id,
        device_id=device.id,
        alert_type=AlertType.device_revoked,
        severity=AlertSeverity.medium,
        title="A device was unlinked",
        message=f"'{device.device_label}' was unlinked from this family.",
        deduplication_key=f"device_revoked:{device.id}:{int(now.timestamp())}",
    )
    await audit_service.record(
        session,
        action=(
            AuditAction.ADMIN_DEVICE_REVOKED
            if actor_type is AuditActorType.admin_user
            else AuditAction.DEVICE_REVOKED
        ),
        actor_type=actor_type,
        actor_id=actor_id,
        target_type="device",
        target_id=device.id,
        family_id=device.family_id,
        reason=reason,
        client_ip=client_ip,
        metadata={
            "sessions_revoked": sessions,
            "commands_cancelled": commands,
            "push_tokens_deactivated": tokens,
        },
    )
    return RevocationOutcome(
        device=device,
        sessions_revoked=sessions,
        commands_cancelled=commands,
        push_tokens_deactivated=tokens,
    )


async def mark_stale_devices_offline(session: AsyncSession, *, limit: int = 500) -> int:
    """Raise an offline alert for devices that stopped reporting.

    Run by the scheduler. Deduplicated per device per day so a device that
    stays off does not generate a daily-growing pile of identical alerts.
    """
    cutoff = utcnow() - OFFLINE_AFTER
    result = await session.execute(
        select(Device)
        .where(
            Device.device_status == DeviceStatus.active,
            Device.last_seen_at.is_not(None),
            Device.last_seen_at < cutoff,
        )
        .limit(limit)
    )
    devices = list(result.scalars().all())
    for device in devices:
        device.device_status = DeviceStatus.inactive
        await alert_service.raise_alert(
            session,
            family_id=device.family_id,
            child_profile_id=device.child_profile_id,
            device_id=device.id,
            alert_type=AlertType.device_offline,
            severity=AlertSeverity.medium,
            title="A device has stopped checking in",
            message=(
                f"'{device.device_label}' has not reported for over 24 hours. It may be off, "
                "offline, or restricted by battery settings."
            ),
            deduplication_key=f"device_offline:{device.id}:{utcnow().date().isoformat()}",
        )
    return len(devices)
