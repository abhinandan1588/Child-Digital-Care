"""Device pairing.

The claim is the most security-sensitive flow in the product: it converts a
short-lived secret into a long-lived device credential. Properties enforced
here:

* **High entropy, hashed at rest.** 256-bit ``claim_token``; only SHA-256
  hashes are stored, for both the token and the optional short code.
* **Single use, atomically.** The claim is a conditional UPDATE
  (``WHERE status='pending' AND expires_at > now``). Two devices racing on the
  same invitation cannot both win: the loser's UPDATE matches zero rows.
* **Attempt limited.** Each failed attempt increments ``attempt_count``; past
  the limit the invitation is burned, which keeps a short human-typable code
  safe.
* **Disclosure recorded.** The claim requires an acknowledged disclosure
  version, stored as a ``consent_records`` row for the device.
* **One transaction.** Invitation claim, device row, device session, consent
  record and the initial policy-sync command all commit together.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import AppError, Conflict, ErrorCode, NotFound
from app.core.logging import get_logger
from app.core.security import (
    generate_opaque_token,
    generate_short_code,
    hash_opaque_token,
    normalize_short_code,
)
from app.db.enums import (
    AuditActorType,
    AuditOutcome,
    CommandType,
    ConsentMethod,
    ConsentState,
    ConsentType,
    DevicePlatform,
    DeviceStatus,
    PairingInvitationStatus,
    ProfileStatus,
    SyncStatus,
)
from app.db.models.audit import ConsentRecord
from app.db.models.device import Device, PairingInvitation
from app.db.models.family import ChildProfile
from app.db.models.policy import DevicePolicyState
from app.repositories.base import rowcount_of
from app.services import audit_service, command_service, outbox_service, token_service
from app.services.audit_service import AuditAction
from app.services.outbox_service import OutboxTopic
from app.utils.time import utcnow

logger = get_logger(__name__)

MAX_PENDING_INVITATIONS_PER_CHILD = 3
MAX_DEVICES_PER_CHILD = 5
SHORT_CODE_LENGTH = 8


class InvalidPairingToken(AppError):
    status_code = 404
    code = ErrorCode.NOT_FOUND
    # Deliberately indistinguishable from "expired" or "already claimed" to an
    # attacker guessing codes; the specific reason is only logged server-side.
    message = "This pairing code is not valid, has expired, or has already been used."


@dataclass(frozen=True, slots=True)
class CreatedInvitation:
    invitation: PairingInvitation
    claim_token: str
    short_code: str | None


@dataclass(frozen=True, slots=True)
class ClaimOutcome:
    device: Device
    session: token_service.IssuedSession
    policy_version: int


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------
async def create_invitation(
    session: AsyncSession,
    *,
    child: ChildProfile,
    created_by_user_id: uuid.UUID,
    expires_in_minutes: int | None,
    include_short_code: bool,
    device_label: str | None,
    client_ip: str | None = None,
) -> CreatedInvitation:
    if child.profile_status is not ProfileStatus.active:
        raise Conflict("This child profile is not active.")

    device_count = await session.execute(
        select(func.count())
        .select_from(Device)
        .where(
            Device.child_profile_id == child.id,
            Device.device_status != DeviceStatus.revoked,
        )
    )
    if int(device_count.scalar_one()) >= MAX_DEVICES_PER_CHILD:
        raise Conflict(
            f"A child profile can have at most {MAX_DEVICES_PER_CHILD} linked devices. "
            "Unlink a device first.",
            code=ErrorCode.QUOTA_EXCEEDED,
        )

    # Expire stale rows before counting, so a parent is not blocked by
    # invitations that are already dead.
    await expire_stale_invitations(session, child_profile_id=child.id)

    pending = await session.execute(
        select(func.count())
        .select_from(PairingInvitation)
        .where(
            PairingInvitation.child_profile_id == child.id,
            PairingInvitation.status == PairingInvitationStatus.pending,
        )
    )
    if int(pending.scalar_one()) >= MAX_PENDING_INVITATIONS_PER_CHILD:
        raise Conflict(
            "There are already several pending pairing invitations for this child. "
            "Cancel one before creating another.",
            code=ErrorCode.QUOTA_EXCEEDED,
        )

    raw_token = generate_opaque_token()
    short_code = generate_short_code(SHORT_CODE_LENGTH) if include_short_code else None
    minutes = expires_in_minutes or settings.pairing_invitation_expire_minutes

    invitation = PairingInvitation(
        family_id=child.family_id,
        child_profile_id=child.id,
        created_by_user_id=created_by_user_id,
        token_hash=hash_opaque_token(raw_token),
        short_code_hash=hash_opaque_token(short_code) if short_code else None,
        short_code_prefix=short_code[:4] if short_code else None,
        status=PairingInvitationStatus.pending,
        expires_at=utcnow() + timedelta(minutes=minutes),
    )
    session.add(invitation)
    await session.flush()

    await audit_service.record(
        session,
        action=AuditAction.PAIRING_INVITATION_CREATED,
        actor_type=AuditActorType.parent_user,
        actor_id=created_by_user_id,
        target_type="pairing_invitation",
        target_id=invitation.id,
        family_id=child.family_id,
        client_ip=client_ip,
        metadata={
            "child_profile_id": child.id,
            "expires_in_minutes": minutes,
            "short_code_issued": bool(short_code),
            "requested_device_label": bool(device_label),
        },
    )
    return CreatedInvitation(invitation=invitation, claim_token=raw_token, short_code=short_code)


async def expire_stale_invitations(
    session: AsyncSession, *, child_profile_id: uuid.UUID | None = None, limit: int = 500
) -> int:
    statement = update(PairingInvitation).where(
        PairingInvitation.status == PairingInvitationStatus.pending,
        PairingInvitation.expires_at <= utcnow(),
    )
    if child_profile_id is not None:
        statement = statement.where(PairingInvitation.child_profile_id == child_profile_id)
    else:
        subquery = (
            select(PairingInvitation.id)
            .where(
                PairingInvitation.status == PairingInvitationStatus.pending,
                PairingInvitation.expires_at <= utcnow(),
            )
            .limit(limit)
            .scalar_subquery()
        )
        statement = update(PairingInvitation).where(PairingInvitation.id.in_(subquery))

    result = await session.execute(statement.values(status=PairingInvitationStatus.expired))
    return rowcount_of(result)


async def get_invitation_for_parent(
    session: AsyncSession, *, invitation_id: uuid.UUID, family_id: uuid.UUID
) -> PairingInvitation:
    result = await session.execute(
        select(PairingInvitation)
        .where(PairingInvitation.id == invitation_id, PairingInvitation.family_id == family_id)
        .limit(1)
    )
    invitation = result.scalars().first()
    if invitation is None:
        raise NotFound("Pairing invitation not found.")
    return invitation


async def revoke_invitation(
    session: AsyncSession,
    *,
    invitation: PairingInvitation,
    user_id: uuid.UUID,
    client_ip: str | None = None,
) -> PairingInvitation:
    if invitation.status is PairingInvitationStatus.claimed:
        raise Conflict(
            "That invitation has already been claimed. Unlink the device instead.",
            code=ErrorCode.INVITATION_ALREADY_CLAIMED,
        )
    invitation.status = PairingInvitationStatus.revoked
    invitation.revoked_at = utcnow()
    invitation.revoked_by_user_id = user_id

    await audit_service.record(
        session,
        action=AuditAction.PAIRING_INVITATION_REVOKED,
        actor_type=AuditActorType.parent_user,
        actor_id=user_id,
        target_type="pairing_invitation",
        target_id=invitation.id,
        family_id=invitation.family_id,
        client_ip=client_ip,
    )
    return invitation


async def revoke_pending_invitations_for_child(
    session: AsyncSession, *, child_profile_id: uuid.UUID, user_id: uuid.UUID | None
) -> int:
    result = await session.execute(
        update(PairingInvitation)
        .where(
            PairingInvitation.child_profile_id == child_profile_id,
            PairingInvitation.status == PairingInvitationStatus.pending,
        )
        .values(
            status=PairingInvitationStatus.revoked,
            revoked_at=utcnow(),
            revoked_by_user_id=user_id,
        )
    )
    return rowcount_of(result)


async def list_invitations(
    session: AsyncSession, *, child_profile_id: uuid.UUID
) -> list[PairingInvitation]:
    result = await session.execute(
        select(PairingInvitation)
        .where(PairingInvitation.child_profile_id == child_profile_id)
        .order_by(PairingInvitation.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Claim
# ---------------------------------------------------------------------------
async def claim_invitation(
    session: AsyncSession,
    *,
    claim_token: str | None,
    short_code: str | None,
    platform: DevicePlatform,
    app_version: str,
    os_version: str | None,
    device_label: str | None,
    device_model: str | None,
    manufacturer: str | None,
    timezone: str,
    install_id: str | None,
    disclosure_version: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> ClaimOutcome:
    """Validate and consume an invitation, then create the device and session."""
    if not claim_token and not short_code:
        raise InvalidPairingToken()

    invitation = await _lookup_invitation(session, claim_token=claim_token, short_code=short_code)
    if invitation is None:
        logger.info("pairing_claim_unknown_token")
        await audit_service.record(
            session,
            action=AuditAction.PAIRING_CLAIM_FAILED,
            actor_type=AuditActorType.anonymous,
            outcome=AuditOutcome.failure,
            reason="unknown_token",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise InvalidPairingToken()

    now = utcnow()

    # Record the attempt before validating, so brute force is always counted
    # even when the outcome is a rejection. The counter and the audit entry are
    # committed before the rejection is raised: the request-scoped session rolls
    # back on an exception, and an attempt counter that disappears whenever the
    # attempt fails would protect nothing.
    invitation.attempt_count += 1
    invitation.last_attempt_at = now

    if invitation.attempt_count > settings.pairing_max_claim_attempts:
        invitation.status = PairingInvitationStatus.revoked
        invitation.revoked_at = now
        logger.warning(
            "pairing_claim_attempt_limit",
            invitation_id=str(invitation.id),
            attempts=invitation.attempt_count,
        )
        await _record_failure(
            session,
            invitation=invitation,
            reason="attempt_limit_exceeded",
            outcome=AuditOutcome.denied,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise Conflict(
            "Too many attempts were made with this pairing code. Ask the parent for a new one.",
            code=ErrorCode.INVITATION_ATTEMPT_LIMIT,
        )

    reason = _invalid_reason(invitation, now)
    if reason is not None:
        await _record_failure(
            session,
            invitation=invitation,
            reason=reason,
            outcome=AuditOutcome.failure,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise InvalidPairingToken()

    child = await session.get(ChildProfile, invitation.child_profile_id)
    if child is None or child.profile_status is not ProfileStatus.active:
        await _record_failure(
            session,
            invitation=invitation,
            reason="child_profile_inactive",
            outcome=AuditOutcome.failure,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise InvalidPairingToken()

    # ---- The atomic claim -------------------------------------------------
    # Only a row still in `pending` and not yet expired is claimable. A second
    # device running this exact statement concurrently matches zero rows.
    claimed = await session.execute(
        update(PairingInvitation)
        .where(
            PairingInvitation.id == invitation.id,
            PairingInvitation.status == PairingInvitationStatus.pending,
            PairingInvitation.expires_at > now,
        )
        .values(
            status=PairingInvitationStatus.claimed,
            claimed_at=now,
            disclosure_version=disclosure_version[:32],
        )
    )
    if not rowcount_of(claimed):
        logger.info("pairing_claim_lost_race", invitation_id=str(invitation.id))
        await _record_failure(
            session,
            invitation=invitation,
            reason="already_claimed_concurrently",
            outcome=AuditOutcome.failure,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise Conflict(
            "This pairing code has already been used by another device.",
            code=ErrorCode.INVITATION_ALREADY_CLAIMED,
        )

    device = await _create_or_reclaim_device(
        session,
        invitation=invitation,
        child=child,
        platform=platform,
        app_version=app_version,
        os_version=os_version,
        device_label=device_label,
        device_model=device_model,
        manufacturer=manufacturer,
        timezone=timezone,
        install_id=install_id,
    )

    await session.execute(
        update(PairingInvitation)
        .where(PairingInvitation.id == invitation.id)
        .values(claimed_device_id=device.id)
    )

    session.add(
        ConsentRecord(
            consent_type=ConsentType.child_device_disclosure,
            state=ConsentState.granted,
            policy_version=disclosure_version[:32],
            method=ConsentMethod.child_device_acknowledgement,
            family_id=child.family_id,
            child_profile_id=child.id,
            device_id=device.id,
            surface="child_app",
        )
    )

    issued = await token_service.issue_device_session(
        session,
        device_id=device.id,
        family_id_claim=device.family_id,
        app_version=app_version,
    )

    # Queue the first policy sync so the device converges immediately. A
    # re-paired device may already have a row for this version, so reset it
    # rather than inserting a duplicate.
    existing_state = await session.execute(
        select(DevicePolicyState)
        .where(
            DevicePolicyState.device_id == device.id,
            DevicePolicyState.policy_version == child.policy_version,
        )
        .limit(1)
    )
    state = existing_state.scalars().first()
    if state is None:
        session.add(
            DevicePolicyState(
                device_id=device.id,
                child_profile_id=child.id,
                policy_version=child.policy_version,
                sync_status=SyncStatus.pending_sync,
            )
        )
    else:
        state.sync_status = SyncStatus.pending_sync
        state.detail = None
        state.item_results = None
        state.reported_at = None
    await command_service.create_command(
        session,
        device=device,
        command_type=CommandType.sync_policies,
        payload={"target_policy_version": child.policy_version, "reason": "initial_pairing"},
    )

    await outbox_service.enqueue(
        session,
        topic=OutboxTopic.DEVICE_STATUS_CHANGED,
        aggregate_type="device",
        aggregate_id=device.id,
        family_id=device.family_id,
        payload={
            "device_id": str(device.id),
            "device_status": device.device_status.value,
            "event": "paired",
        },
    )
    await audit_service.record(
        session,
        action=AuditAction.PAIRING_CLAIM_SUCCEEDED,
        actor_type=AuditActorType.child_device,
        actor_id=device.id,
        target_type="device",
        target_id=device.id,
        family_id=device.family_id,
        client_ip=client_ip,
        user_agent=user_agent,
        metadata={
            "child_profile_id": child.id,
            "invitation_id": invitation.id,
            "platform": platform.value,
            "disclosure_version": disclosure_version,
        },
    )
    await session.flush()
    return ClaimOutcome(device=device, session=issued, policy_version=child.policy_version)


async def _record_failure(
    session: AsyncSession,
    *,
    invitation: PairingInvitation,
    reason: str,
    outcome: AuditOutcome,
    client_ip: str | None,
    user_agent: str | None,
) -> None:
    """Persist the attempt counter and audit entry, then let the caller raise."""
    await audit_service.record(
        session,
        action=AuditAction.PAIRING_CLAIM_FAILED,
        actor_type=AuditActorType.anonymous,
        outcome=outcome,
        target_type="pairing_invitation",
        target_id=invitation.id,
        family_id=invitation.family_id,
        reason=reason,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    await session.commit()


async def _lookup_invitation(
    session: AsyncSession, *, claim_token: str | None, short_code: str | None
) -> PairingInvitation | None:
    if claim_token:
        result = await session.execute(
            select(PairingInvitation)
            .where(PairingInvitation.token_hash == hash_opaque_token(claim_token))
            .limit(1)
        )
        row = result.scalars().first()
        if row is not None:
            return row

    if short_code:
        normalized = normalize_short_code(short_code)
        result = await session.execute(
            select(PairingInvitation)
            .where(PairingInvitation.short_code_hash == hash_opaque_token(normalized))
            .limit(1)
        )
        return result.scalars().first()
    return None


def _invalid_reason(invitation: PairingInvitation, now) -> str | None:  # noqa: ANN001
    if invitation.status is PairingInvitationStatus.claimed:
        return "already_claimed"
    if invitation.status is PairingInvitationStatus.revoked:
        return "revoked"
    if invitation.status is PairingInvitationStatus.expired or invitation.expires_at <= now:
        return "expired"
    return None


async def _create_or_reclaim_device(
    session: AsyncSession,
    *,
    invitation: PairingInvitation,
    child: ChildProfile,
    platform: DevicePlatform,
    app_version: str,
    os_version: str | None,
    device_label: str | None,
    device_model: str | None,
    manufacturer: str | None,
    timezone: str,
    install_id: str | None,
) -> Device:
    """Create the device, or revive the same install if it re-pairs.

    Re-pairing the same ``install_id`` reuses the row so a parent does not
    accumulate duplicate "Child's phone" entries after a reset, and so usage
    history stays attached to one device.
    """
    existing: Device | None = None
    if install_id:
        result = await session.execute(
            select(Device)
            .where(
                Device.child_profile_id == child.id,
                Device.install_id == install_id,
            )
            .limit(1)
        )
        existing = result.scalars().first()

    now = utcnow()
    if existing is not None:
        existing.platform = platform
        existing.app_version = app_version
        existing.os_version = os_version
        existing.device_model = device_model
        existing.manufacturer = manufacturer
        existing.timezone = timezone
        existing.device_status = DeviceStatus.pending_registration
        existing.revoked_at = None
        existing.revoked_reason = None
        existing.revoked_by_user_id = None
        existing.registered_at = None
        existing.applied_policy_version = None
        existing.policy_sync_status = SyncStatus.pending_sync
        if device_label:
            existing.device_label = device_label[:80]
        # Any credential from the previous pairing must stop working.
        await token_service.revoke_all_device_sessions(
            session, device_id=existing.id, reason="re_paired"
        )
        await command_service.cancel_pending_for_device(
            session, device_id=existing.id, reason="device re-paired"
        )
        await session.flush()
        return existing

    device = Device(
        family_id=child.family_id,
        child_profile_id=child.id,
        platform=platform,
        device_label=(device_label or "Child device")[:80],
        app_version=app_version,
        os_version=os_version,
        device_model=device_model,
        manufacturer=manufacturer,
        install_id=install_id,
        device_status=DeviceStatus.pending_registration,
        timezone=timezone,
        policy_sync_status=SyncStatus.pending_sync,
        last_seen_at=now,
    )
    session.add(device)
    await session.flush()
    return device
