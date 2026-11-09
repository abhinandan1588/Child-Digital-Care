"""Device command lifecycle.

One module owns the state machine, so every transition is validated in the
same place:

``queued -> delivery_attempted -> delivered -> acknowledged ->
succeeded | failed | unsupported | partially_applied``

with ``expired`` and ``cancelled`` reachable from any non-terminal state.

Reconciliation rules that matter in practice:

* A command is created **durably** before any push is attempted.
* ``(device_id, idempotency_key)`` is unique, so a retried create returns the
  original command instead of queueing a second one.
* A late acknowledgement for an already-terminal command is accepted and
  reported as a duplicate; it never overwrites the terminal state.
* ``unsupported`` and ``permission_denied`` are preserved verbatim. They are
  never translated into success.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import (
    Conflict,
    ErrorCode,
    FeatureDisabled,
    InvalidStateTransition,
    NotFound,
    PermissionDenied,
)
from app.core.logging import get_logger
from app.db.enums import (
    PARENT_ISSUABLE_COMMANDS,
    TERMINAL_COMMAND_STATUSES,
    CapabilityKey,
    CapabilitySupport,
    CommandResult,
    CommandStatus,
    CommandType,
    DeliveryChannel,
    DeliveryOutcome,
    DeviceStatus,
    PermissionState,
    SyncStatus,
)
from app.db.models.command import DeviceCommand, DeviceCommandAttempt
from app.db.models.device import Device, DeviceCapability
from app.db.models.policy import DevicePolicyState
from app.repositories.base import rowcount_of
from app.schemas.command import PAYLOAD_MODELS
from app.services import outbox_service
from app.services.outbox_service import OutboxTopic
from app.utils.time import utcnow

logger = get_logger(__name__)

#: Allowed transitions. Anything missing here is rejected.
ALLOWED_TRANSITIONS: dict[CommandStatus, frozenset[CommandStatus]] = {
    CommandStatus.queued: frozenset(
        {
            CommandStatus.delivery_attempted,
            CommandStatus.delivered,
            CommandStatus.acknowledged,
            CommandStatus.cancelled,
            CommandStatus.expired,
        }
    ),
    CommandStatus.delivery_attempted: frozenset(
        {
            CommandStatus.delivery_attempted,
            CommandStatus.delivered,
            CommandStatus.acknowledged,
            CommandStatus.cancelled,
            CommandStatus.expired,
        }
    ),
    CommandStatus.delivered: frozenset(
        {
            CommandStatus.acknowledged,
            CommandStatus.succeeded,
            CommandStatus.failed,
            CommandStatus.unsupported,
            CommandStatus.cancelled,
            CommandStatus.expired,
        }
    ),
    CommandStatus.acknowledged: frozenset(
        {
            CommandStatus.succeeded,
            CommandStatus.failed,
            CommandStatus.unsupported,
            CommandStatus.expired,
        }
    ),
    # Terminal states accept nothing further.
    CommandStatus.succeeded: frozenset(),
    CommandStatus.failed: frozenset(),
    CommandStatus.expired: frozenset(),
    CommandStatus.cancelled: frozenset(),
    CommandStatus.unsupported: frozenset(),
}

#: Device result -> command status.
RESULT_TO_STATUS: dict[CommandResult, CommandStatus] = {
    CommandResult.succeeded: CommandStatus.succeeded,
    CommandResult.failed: CommandStatus.failed,
    CommandResult.unsupported: CommandStatus.unsupported,
    CommandResult.permission_denied: CommandStatus.failed,
    CommandResult.partially_applied: CommandStatus.succeeded,
}

#: Capability each command type depends on, when it depends on one.
#: ``request_location_update`` is absent because its gating is richer than a
#: single capability and is delegated to :mod:`app.services.location_service`,
#: so the command check and the ingestion check cannot drift apart.
COMMAND_CAPABILITY_REQUIREMENTS: dict[CommandType, CapabilityKey] = {
    CommandType.request_usage_sync: CapabilityKey.app_usage_stats,
}


def is_terminal(status: CommandStatus) -> bool:
    return status in TERMINAL_COMMAND_STATUSES


def can_transition(current: CommandStatus, target: CommandStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(current: CommandStatus, target: CommandStatus) -> None:
    if not can_transition(current, target):
        raise InvalidStateTransition(
            f"A command cannot move from '{current.value}' to '{target.value}'."
        )


def derive_idempotency_key(
    *, device_id: uuid.UUID, command_type: CommandType, payload: dict[str, Any]
) -> str:
    """Stable key for a server-generated command.

    Two policy changes a second apart should each queue a sync, but a retry of
    the *same* change must not. Hashing the payload plus a coarse time bucket
    achieves both without the caller tracking keys.
    """
    bucket = int(utcnow().timestamp() // 5)
    material = f"{device_id}:{command_type.value}:{sorted(payload.items())}:{bucket}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:40]
    return f"auto-{command_type.value}-{digest}"


@dataclass(frozen=True, slots=True)
class CreatedCommand:
    command: DeviceCommand
    created: bool


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------
async def create_command(
    session: AsyncSession,
    *,
    device: Device,
    command_type: CommandType,
    payload: dict[str, Any],
    created_by_user_id: uuid.UUID | None = None,
    created_by_admin_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
    expires_in_seconds: int | None = None,
    enqueue_outbox: bool = True,
) -> CreatedCommand:
    """Create a command durably and queue a wake-up through the outbox."""
    if device.device_status is DeviceStatus.revoked:
        raise PermissionDenied("This device has been unlinked.", code=ErrorCode.DEVICE_REVOKED)

    # Re-validate the payload against its model, so a stored payload can never
    # diverge from the allow-listed schema.
    model = PAYLOAD_MODELS.get(command_type)
    if model is None:  # pragma: no cover - CommandType is exhaustive
        raise Conflict(
            f"Command type '{command_type}' is not supported.",
            code=ErrorCode.COMMAND_NOT_SUPPORTED,
        )
    validated = model.model_validate({"command_type": command_type.value, **payload})
    clean_payload = validated.model_dump(mode="json")

    key = idempotency_key or derive_idempotency_key(
        device_id=device.id, command_type=command_type, payload=clean_payload
    )

    existing = await session.execute(
        select(DeviceCommand)
        .where(DeviceCommand.device_id == device.id, DeviceCommand.idempotency_key == key)
        .limit(1)
    )
    duplicate = existing.scalars().first()
    if duplicate is not None:
        return CreatedCommand(command=duplicate, created=False)

    ttl = expires_in_seconds or settings.command_default_ttl_seconds
    command = DeviceCommand(
        family_id=device.family_id,
        device_id=device.id,
        child_profile_id=device.child_profile_id,
        command_type=command_type,
        payload=clean_payload,
        status=CommandStatus.queued,
        idempotency_key=key,
        created_by_user_id=created_by_user_id,
        created_by_admin_id=created_by_admin_id,
        expires_at=utcnow() + timedelta(seconds=ttl),
    )
    session.add(command)
    try:
        await session.flush()
    except IntegrityError:
        # Concurrent create with the same key: return the winner.
        await session.rollback()
        again = await session.execute(
            select(DeviceCommand)
            .where(DeviceCommand.device_id == device.id, DeviceCommand.idempotency_key == key)
            .limit(1)
        )
        winner = again.scalars().first()
        if winner is None:  # pragma: no cover - defensive
            raise
        return CreatedCommand(command=winner, created=False)

    if enqueue_outbox:
        await outbox_service.enqueue(
            session,
            topic=OutboxTopic.COMMAND_QUEUED,
            aggregate_type="device_command",
            aggregate_id=command.id,
            family_id=device.family_id,
            payload={
                "device_id": str(device.id),
                "command_type": command_type.value,
                "command_id": str(command.id),
            },
        )
    return CreatedCommand(command=command, created=True)


async def create_parent_command(
    session: AsyncSession,
    *,
    device: Device,
    command_type: CommandType,
    payload: dict[str, Any],
    user_id: uuid.UUID,
    idempotency_key: str | None,
    expires_in_seconds: int | None,
) -> CreatedCommand:
    """Create a command on a parent's behalf, with the extra checks that
    a parent-initiated request needs."""
    if command_type not in PARENT_ISSUABLE_COMMANDS:
        raise PermissionDenied(
            f"'{command_type.value}' cannot be requested through the API.",
            code=ErrorCode.COMMAND_NOT_SUPPORTED,
        )
    if device.device_status is not DeviceStatus.active:
        raise Conflict(
            "The device has not completed registration, so it cannot accept commands yet.",
            code=ErrorCode.DEVICE_NOT_ACTIVE,
        )

    await assert_command_supported(session, device=device, command_type=command_type)

    return await create_command(
        session,
        device=device,
        command_type=command_type,
        payload=payload,
        created_by_user_id=user_id,
        idempotency_key=idempotency_key,
        expires_in_seconds=expires_in_seconds,
    )


async def assert_command_supported(
    session: AsyncSession, *, device: Device, command_type: CommandType
) -> None:
    """Refuse a command the device has told us it cannot carry out.

    Queueing a command that will certainly fail would show a parent a pending
    action that silently expires. Failing now, with a specific code, lets the
    Parent App explain what is missing on the device.
    """
    if command_type is CommandType.request_location_update:
        # Delegated so the command gate and the ingestion gate are the same
        # four checks: feature flag, consent, reported capability, reported
        # permission. Duplicating them here would let them drift.
        from app.services import location_service

        availability = await location_service.evaluate_availability(session, device=device)
        if not availability.available:
            if availability.reason == location_service.LocationRejection.FEATURE_DISABLED:
                raise FeatureDisabled("Location requests are not enabled for this deployment.")
            if availability.reason == location_service.LocationRejection.CONSENT_MISSING:
                raise PermissionDenied(
                    "Location collection has not been consented to for this family.",
                    code=ErrorCode.PERMISSION_STATE_BLOCKS_ACTION,
                )
            if availability.reason == location_service.LocationRejection.CAPABILITY_UNSUPPORTED:
                raise Conflict(
                    "This device has not reported support for location.",
                    code=ErrorCode.CAPABILITY_UNSUPPORTED,
                )
            raise Conflict(
                "The location permission is not granted on this device.",
                code=ErrorCode.PERMISSION_STATE_BLOCKS_ACTION,
            )
        return

    required = COMMAND_CAPABILITY_REQUIREMENTS.get(command_type)
    if required is None:
        return

    result = await session.execute(
        select(DeviceCapability)
        .where(
            DeviceCapability.device_id == device.id,
            DeviceCapability.capability_key == required,
        )
        .limit(1)
    )
    capability = result.scalars().first()
    if capability is None:
        raise Conflict(
            f"The device has not reported support for '{required.value}' yet.",
            code=ErrorCode.CAPABILITY_UNSUPPORTED,
        )
    if capability.support is CapabilitySupport.unsupported:
        raise Conflict(
            f"This device reports that '{required.value}' is not supported.",
            code=ErrorCode.CAPABILITY_UNSUPPORTED,
        )
    if capability.permission_state in (
        PermissionState.denied,
        PermissionState.permanently_denied,
        PermissionState.restricted,
    ):
        raise Conflict(
            f"The required permission for '{required.value}' is not granted on the device.",
            code=ErrorCode.PERMISSION_STATE_BLOCKS_ACTION,
        )


# ---------------------------------------------------------------------------
# Delivery bookkeeping
# ---------------------------------------------------------------------------
async def record_delivery_attempt(
    session: AsyncSession,
    *,
    command: DeviceCommand,
    channel: DeliveryChannel,
    outcome: DeliveryOutcome,
    provider_message_id: str | None = None,
    error_code: str | None = None,
) -> DeviceCommandAttempt:
    attempt_number = command.delivery_attempt_count + 1
    attempt = DeviceCommandAttempt(
        command_id=command.id,
        attempt_number=attempt_number,
        channel=channel,
        outcome=outcome,
        provider_message_id=provider_message_id,
        error_code=error_code[:64] if error_code else None,
    )
    session.add(attempt)

    command.delivery_attempt_count = attempt_number
    if command.first_delivery_attempt_at is None:
        command.first_delivery_attempt_at = utcnow()

    if command.status is CommandStatus.queued and can_transition(
        command.status, CommandStatus.delivery_attempted
    ):
        command.status = CommandStatus.delivery_attempted
    return attempt


async def mark_fetched_by_device(session: AsyncSession, *, commands: list[DeviceCommand]) -> None:
    """A device polling for a command is the only honest 'delivered' signal.

    A push receipt means the provider accepted the message, not that the device
    received or ran anything, so ``delivered`` is set here rather than there.
    """
    now = utcnow()
    for command in commands:
        if command.fetched_at is None:
            command.fetched_at = now
        if can_transition(command.status, CommandStatus.delivered):
            command.status = CommandStatus.delivered
            command.delivered_at = now
        session.add(
            DeviceCommandAttempt(
                command_id=command.id,
                attempt_number=command.delivery_attempt_count + 1,
                channel=DeliveryChannel.device_poll,
                outcome=DeliveryOutcome.sent,
            )
        )
        command.delivery_attempt_count += 1


# ---------------------------------------------------------------------------
# Device-side transitions
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class TransitionResult:
    command: DeviceCommand
    duplicate: bool


async def acknowledge(
    session: AsyncSession, *, device_id: uuid.UUID, command_id: uuid.UUID
) -> TransitionResult:
    command = await _load_device_command(session, device_id=device_id, command_id=command_id)
    now = utcnow()

    if is_terminal(command.status):
        # Late ack after the command already finished (or expired). Accept it
        # without rewriting the terminal state.
        logger.info(
            "command_ack_after_terminal",
            command_id=str(command.id),
            status=command.status.value,
        )
        return TransitionResult(command=command, duplicate=True)

    if command.status is CommandStatus.acknowledged:
        return TransitionResult(command=command, duplicate=True)

    if command.expires_at <= now:
        command.status = CommandStatus.expired
        command.completed_at = now
        raise Conflict(
            "This command has expired and no longer needs to be run.",
            code=ErrorCode.COMMAND_EXPIRED,
        )

    assert_transition(command.status, CommandStatus.acknowledged)
    command.status = CommandStatus.acknowledged
    command.acknowledged_at = now
    if command.delivered_at is None:
        command.delivered_at = now
    return TransitionResult(command=command, duplicate=False)


async def record_result(
    session: AsyncSession,
    *,
    device: Device,
    command_id: uuid.UUID,
    result: CommandResult,
    applied_policy_version: int | None,
    error_code: str | None,
    message: str | None,
    item_results: dict[str, str] | None,
) -> TransitionResult:
    command = await _load_device_command(session, device_id=device.id, command_id=command_id)
    now = utcnow()

    if is_terminal(command.status):
        if command.result is result:
            return TransitionResult(command=command, duplicate=True)
        # Conflicting late result: keep the first terminal outcome and record
        # the discrepancy rather than silently flip-flopping.
        logger.warning(
            "command_result_after_terminal",
            command_id=str(command.id),
            stored_status=command.status.value,
            reported_result=result.value,
        )
        return TransitionResult(command=command, duplicate=True)

    target = RESULT_TO_STATUS[result]
    assert_transition(command.status, target)

    command.status = target
    command.result = result
    command.completed_at = now
    command.applied_policy_version = applied_policy_version
    command.failure_code = error_code[:64] if error_code else None
    command.failure_message = message[:255] if message else None

    if command.command_type in (CommandType.sync_policies, CommandType.apply_supported_policy):
        await _apply_policy_sync_result(
            session,
            device=device,
            command=command,
            result=result,
            applied_policy_version=applied_policy_version,
            detail=message,
            item_results=item_results,
        )

    await outbox_service.enqueue(
        session,
        topic=OutboxTopic.COMMAND_STATUS_CHANGED,
        aggregate_type="device_command",
        aggregate_id=command.id,
        family_id=command.family_id,
        payload={
            "device_id": str(device.id),
            "command_type": command.command_type.value,
            "status": command.status.value,
            "result": result.value,
        },
    )
    return TransitionResult(command=command, duplicate=False)


async def _apply_policy_sync_result(
    session: AsyncSession,
    *,
    device: Device,
    command: DeviceCommand,
    result: CommandResult,
    applied_policy_version: int | None,
    detail: str | None,
    item_results: dict[str, str] | None,
) -> None:
    """Translate a device result into the per-device policy sync state.

    This is the only place ``Device.policy_sync_status`` moves forward, which is
    what keeps the Parent App honest: the server shows "applied" only because a
    device said so.
    """
    sync_status = {
        CommandResult.succeeded: SyncStatus.synced,
        CommandResult.partially_applied: SyncStatus.partially_applied,
        CommandResult.unsupported: SyncStatus.unsupported,
        CommandResult.permission_denied: SyncStatus.failed,
        CommandResult.failed: SyncStatus.failed,
    }[result]

    # Two different numbers, deliberately kept apart:
    #  * the version the command was trying to deliver (from its payload), and
    #  * the version the device says it currently has applied.
    # The outcome is recorded against the *target*, so a failed move to v2 shows
    # as "v2 unsupported" while the device is still honestly reported on v1.
    payload = command.payload or {}
    target_raw = payload.get("target_policy_version") or payload.get("policy_version")
    try:
        state_version = int(target_raw) if target_raw is not None else applied_policy_version
    except (TypeError, ValueError):  # pragma: no cover - payload is schema-validated
        state_version = applied_policy_version

    if applied_policy_version is not None:
        device.applied_policy_version = applied_policy_version
    device.policy_sync_status = sync_status
    device.policy_sync_detail = (detail or None) and detail[:255]
    device.policy_synced_at = utcnow()

    if state_version is None:
        return

    existing = await session.execute(
        select(DevicePolicyState)
        .where(
            DevicePolicyState.device_id == device.id,
            DevicePolicyState.policy_version == state_version,
        )
        .limit(1)
    )
    row = existing.scalars().first()
    if row is None:
        row = DevicePolicyState(
            device_id=device.id,
            child_profile_id=device.child_profile_id,
            policy_version=state_version,
        )
        session.add(row)
    row.sync_status = sync_status
    row.detail = (detail or None) and detail[:255]
    row.item_results = item_results
    row.reported_at = utcnow()

    await outbox_service.enqueue(
        session,
        topic=OutboxTopic.POLICY_SYNC_STATUS_CHANGED,
        aggregate_type="device",
        aggregate_id=device.id,
        family_id=device.family_id,
        payload={
            "device_id": str(device.id),
            "policy_version": state_version,
            "applied_policy_version": applied_policy_version,
            "sync_status": sync_status.value,
        },
    )


async def _load_device_command(
    session: AsyncSession, *, device_id: uuid.UUID, command_id: uuid.UUID
) -> DeviceCommand:
    """Load a command scoped to its own device.

    The ``device_id`` predicate is the tenant check: one device can never
    acknowledge, inspect or complete another device's command.
    """
    result = await session.execute(
        select(DeviceCommand)
        .where(DeviceCommand.id == command_id, DeviceCommand.device_id == device_id)
        .limit(1)
    )
    command = result.scalars().first()
    if command is None:
        raise NotFound("Command not found.")
    return command


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
PENDING_STATUSES = (
    CommandStatus.queued,
    CommandStatus.delivery_attempted,
    CommandStatus.delivered,
    CommandStatus.acknowledged,
)


async def pending_for_device(
    session: AsyncSession, *, device_id: uuid.UUID, limit: int = 50
) -> list[DeviceCommand]:
    result = await session.execute(
        select(DeviceCommand)
        .where(
            DeviceCommand.device_id == device_id,
            DeviceCommand.status.in_(PENDING_STATUSES),
            DeviceCommand.expires_at > utcnow(),
        )
        .order_by(DeviceCommand.created_at.asc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def count_pending(session: AsyncSession, *, device_id: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(DeviceCommand)
        .where(
            DeviceCommand.device_id == device_id,
            DeviceCommand.status.in_(PENDING_STATUSES),
            DeviceCommand.expires_at > utcnow(),
        )
    )
    return int(result.scalar_one())


async def cancel_pending_for_device(
    session: AsyncSession, *, device_id: uuid.UUID, reason: str
) -> int:
    result = await session.execute(
        update(DeviceCommand)
        .where(
            DeviceCommand.device_id == device_id,
            DeviceCommand.status.in_(PENDING_STATUSES),
        )
        .values(
            status=CommandStatus.cancelled,
            cancelled_at=utcnow(),
            completed_at=utcnow(),
            failure_code="CANCELLED",
            failure_message=reason[:255],
        )
    )
    return rowcount_of(result)


async def expire_overdue(session: AsyncSession, *, limit: int = 500) -> int:
    """Move past-TTL commands to ``expired``. Run by the scheduler."""
    now = utcnow()
    candidates = await session.execute(
        select(DeviceCommand.id)
        .where(DeviceCommand.status.in_(PENDING_STATUSES), DeviceCommand.expires_at <= now)
        .limit(limit)
    )
    ids = [row[0] for row in candidates.all()]
    if not ids:
        return 0
    result = await session.execute(
        update(DeviceCommand)
        .where(DeviceCommand.id.in_(ids))
        .values(
            status=CommandStatus.expired,
            completed_at=now,
            failure_code="EXPIRED",
            failure_message="The device did not run this command before it expired.",
        )
    )
    return rowcount_of(result)


async def list_for_device_parent_view(
    session: AsyncSession, *, device_id: uuid.UUID, limit: int = 50
) -> list[DeviceCommand]:
    result = await session.execute(
        select(DeviceCommand)
        .where(DeviceCommand.device_id == device_id)
        .order_by(DeviceCommand.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
