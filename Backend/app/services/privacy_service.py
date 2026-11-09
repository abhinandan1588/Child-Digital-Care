"""Consent records, data export, and deletion workflows.

Design choices:

* **Deletion has a grace period.** A parent who deletes by mistake, or whose
  account has been taken over, has a window to cancel. During the window the
  account cannot be used and every device is unlinked immediately, so the
  monitoring stops at once even though the data has not yet been erased.
* **Revoking location consent deletes the data.** Consent is not just a flag:
  withdrawing it purges the samples it authorised.
* **Retention exceptions are explicit.** When something must be kept (billing
  records, audit trail), the kept categories are recorded on the request rather
  than quietly ignored.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import Conflict, ErrorCode, NotFound, PermissionDenied
from app.core.logging import get_logger
from app.core.security import verify_password
from app.db.enums import (
    AccountStatus,
    AuditActorType,
    ConsentMethod,
    ConsentState,
    ConsentType,
    DeviceStatus,
    FamilyStatus,
    PrivacyRequestStatus,
    PrivacyRequestType,
    ProfileStatus,
)
from app.db.models.audit import ConsentRecord, PrivacyRequest
from app.db.models.command import DeviceEvent
from app.db.models.device import Device
from app.db.models.family import ChildProfile, Family
from app.db.models.identity import User
from app.db.models.location import LocationSample
from app.db.models.usage import UsageDailySummary
from app.repositories.base import rowcount_of
from app.services import audit_service, device_service, location_service, token_service
from app.services.audit_service import AuditAction
from app.utils.time import utcnow

logger = get_logger(__name__)

#: How long a deletion request can be cancelled for.
DELETION_GRACE_PERIOD_DAYS = 14
#: Regulatory response window used to set ``due_at``.
PRIVACY_REQUEST_SLA_DAYS = 30

#: Categories retained after a deletion request, with the reason.
RETENTION_EXCEPTIONS: dict[str, str] = {
    "audit_logs": (
        "Security and abuse-investigation records are retained for the configured "
        "audit retention period and are not linked to deleted personal data."
    ),
    "billing_records": (
        "Payment and invoice records are retained where required by tax or accounting obligations."
    ),
    "abuse_reports": (
        "Trust-and-safety reports are retained so a repeat pattern can still be "
        "identified after an account is removed."
    ),
}


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------
async def record_consent(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    family_id: uuid.UUID | None,
    consent_type: ConsentType,
    state: ConsentState,
    policy_version: str,
    method: ConsentMethod,
    child_profile_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
    surface: str | None = None,
    client_ip: str | None = None,
) -> ConsentRecord:
    record = ConsentRecord(
        consent_type=consent_type,
        state=state,
        policy_version=policy_version[:32],
        method=method,
        user_id=user_id,
        family_id=family_id,
        child_profile_id=child_profile_id,
        device_id=device_id,
        surface=(surface or "parent_app")[:32],
    )
    session.add(record)
    await session.flush()

    await audit_service.record(
        session,
        action=AuditAction.CONSENT_RECORDED,
        actor_type=AuditActorType.parent_user,
        actor_id=user_id,
        target_type="consent_record",
        target_id=record.id,
        family_id=family_id,
        client_ip=client_ip,
        metadata={
            "consent_type": consent_type.value,
            "state": state.value,
            "policy_version": policy_version,
        },
    )
    return record


async def list_consents(
    session: AsyncSession, *, user_id: uuid.UUID, family_ids: list[uuid.UUID]
) -> list[ConsentRecord]:
    conditions = [ConsentRecord.user_id == user_id]
    if family_ids:
        conditions.append(ConsentRecord.family_id.in_(family_ids))
    from sqlalchemy import or_

    result = await session.execute(
        select(ConsentRecord)
        .where(or_(*conditions))
        .order_by(ConsentRecord.recorded_at.desc())
        .limit(200)
    )
    return list(result.scalars().all())


async def revoke_consent(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    consent_id: uuid.UUID,
    family_ids: list[uuid.UUID],
    client_ip: str | None = None,
) -> tuple[ConsentRecord, int]:
    """Revoke a consent and delete the data it authorised.

    Returns the revoked record and the number of rows purged.
    """
    result = await session.execute(
        select(ConsentRecord).where(ConsentRecord.id == consent_id).limit(1)
    )
    record = result.scalars().first()
    if record is None or (
        record.user_id != user_id
        and (record.family_id is None or record.family_id not in family_ids)
    ):
        raise NotFound("Consent record not found.")
    if record.state is ConsentState.revoked:
        raise Conflict("That consent has already been withdrawn.")

    record.state = ConsentState.revoked
    record.revoked_at = utcnow()

    purged = 0
    if record.consent_type is ConsentType.location_collection and record.family_id:
        purged = await location_service.purge_for_family(session, family_id=record.family_id)

    await audit_service.record(
        session,
        action=AuditAction.CONSENT_REVOKED,
        actor_type=AuditActorType.parent_user,
        actor_id=user_id,
        target_type="consent_record",
        target_id=record.id,
        family_id=record.family_id,
        client_ip=client_ip,
        metadata={"consent_type": record.consent_type.value, "rows_purged": purged},
    )
    return record, purged


# ---------------------------------------------------------------------------
# Export / deletion requests
# ---------------------------------------------------------------------------
async def create_request(
    session: AsyncSession,
    *,
    user: User,
    request_type: PrivacyRequestType,
    family_id: uuid.UUID | None,
    reason: str | None,
    client_ip: str | None = None,
) -> PrivacyRequest:
    pending = await session.execute(
        select(PrivacyRequest)
        .where(
            PrivacyRequest.user_id == user.id,
            PrivacyRequest.request_type == request_type,
            PrivacyRequest.status.in_(
                [PrivacyRequestStatus.pending, PrivacyRequestStatus.in_progress]
            ),
        )
        .limit(1)
    )
    existing = pending.scalars().first()
    if existing is not None:
        return existing

    request = PrivacyRequest(
        request_type=request_type,
        status=PrivacyRequestStatus.pending,
        user_id=user.id,
        family_id=family_id,
        requester_email=user.email,
        due_at=utcnow() + timedelta(days=PRIVACY_REQUEST_SLA_DAYS),
        retention_exceptions=(
            RETENTION_EXCEPTIONS if request_type is PrivacyRequestType.deletion else None
        ),
        rejection_reason=None,
    )
    session.add(request)
    await session.flush()

    await audit_service.record(
        session,
        action=(
            AuditAction.DELETION_REQUESTED
            if request_type is PrivacyRequestType.deletion
            else AuditAction.EXPORT_REQUESTED
        ),
        actor_type=AuditActorType.parent_user,
        actor_id=user.id,
        target_type="privacy_request",
        target_id=request.id,
        family_id=family_id,
        reason=reason,
        client_ip=client_ip,
    )
    return request


async def list_requests(session: AsyncSession, *, user_id: uuid.UUID) -> list[PrivacyRequest]:
    result = await session.execute(
        select(PrivacyRequest)
        .where(PrivacyRequest.user_id == user_id)
        .order_by(PrivacyRequest.requested_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


@dataclass(frozen=True, slots=True)
class DeletionScheduled:
    request: PrivacyRequest
    scheduled_for: object
    devices_revoked: int


async def schedule_account_deletion(
    session: AsyncSession,
    *,
    user: User,
    password: str,
    reason: str | None,
    client_ip: str | None = None,
) -> DeletionScheduled:
    """Start account deletion.

    Re-authentication is required, because an attacker with a stolen session
    should not be able to destroy a family's data. Devices are unlinked
    immediately so monitoring stops now, not in two weeks.
    """
    if not verify_password(password, user.password_hash):
        raise PermissionDenied("Password confirmation failed.", code=ErrorCode.INVALID_CREDENTIALS)

    now = utcnow()
    scheduled_for = now + timedelta(days=DELETION_GRACE_PERIOD_DAYS)

    request = await create_request(
        session,
        user=user,
        request_type=PrivacyRequestType.deletion,
        family_id=None,
        reason=reason,
        client_ip=client_ip,
    )

    user.account_status = AccountStatus.pending_deletion
    user.deletion_requested_at = now

    owned = await session.execute(
        select(Family).where(Family.owner_user_id == user.id, Family.deleted_at.is_(None))
    )
    devices_revoked = 0
    for family in owned.scalars().all():
        family.status = FamilyStatus.pending_deletion
        device_rows = await session.execute(
            select(Device).where(
                Device.family_id == family.id,
                Device.device_status != DeviceStatus.revoked,
            )
        )
        for device in device_rows.scalars().all():
            await device_service.revoke_device(
                session,
                device=device,
                reason="account deletion requested",
                actor_type=AuditActorType.parent_user,
                actor_id=user.id,
                client_ip=client_ip,
            )
            devices_revoked += 1

    await token_service.revoke_all_user_sessions(
        session, user_id=user.id, reason="account_deletion_requested"
    )
    return DeletionScheduled(
        request=request, scheduled_for=scheduled_for, devices_revoked=devices_revoked
    )


async def cancel_account_deletion(
    session: AsyncSession, *, user: User, client_ip: str | None = None
) -> PrivacyRequest:
    result = await session.execute(
        select(PrivacyRequest)
        .where(
            PrivacyRequest.user_id == user.id,
            PrivacyRequest.request_type == PrivacyRequestType.deletion,
            PrivacyRequest.status == PrivacyRequestStatus.pending,
        )
        .order_by(PrivacyRequest.requested_at.desc())
        .limit(1)
    )
    request = result.scalars().first()
    if request is None:
        raise NotFound("There is no pending deletion request to cancel.")

    request.status = PrivacyRequestStatus.cancelled
    user.account_status = AccountStatus.active
    user.deletion_requested_at = None

    await session.execute(
        update(Family)
        .where(Family.owner_user_id == user.id, Family.status == FamilyStatus.pending_deletion)
        .values(status=FamilyStatus.active)
    )
    await audit_service.record(
        session,
        action=AuditAction.DELETION_CANCELLED,
        actor_type=AuditActorType.parent_user,
        actor_id=user.id,
        target_type="privacy_request",
        target_id=request.id,
        client_ip=client_ip,
    )
    return request


@dataclass(frozen=True, slots=True)
class DeletionResult:
    user_id: uuid.UUID
    families_deleted: int
    devices_deleted: int
    usage_rows_deleted: int
    location_rows_deleted: int
    event_rows_deleted: int


async def execute_due_deletions(session: AsyncSession, *, limit: int = 20) -> list[DeletionResult]:
    """Carry out deletion requests whose grace period has elapsed.

    Run by the scheduler. Personal data is removed; the audit trail is kept
    (it holds no personal payloads) and the request row is kept as proof the
    obligation was met.
    """
    cutoff = utcnow() - timedelta(days=DELETION_GRACE_PERIOD_DAYS)
    result = await session.execute(
        select(PrivacyRequest)
        .where(
            PrivacyRequest.request_type == PrivacyRequestType.deletion,
            PrivacyRequest.status == PrivacyRequestStatus.pending,
            PrivacyRequest.requested_at <= cutoff,
        )
        .limit(limit)
    )
    outcomes: list[DeletionResult] = []

    for request in result.scalars().all():
        if request.user_id is None:
            request.status = PrivacyRequestStatus.rejected
            request.rejection_reason = "The account no longer exists."
            continue

        request.status = PrivacyRequestStatus.in_progress
        request.started_at = utcnow()
        outcome = await _delete_user_data(session, user_id=request.user_id)
        request.status = PrivacyRequestStatus.completed
        request.completed_at = utcnow()
        outcomes.append(outcome)

        await audit_service.record(
            session,
            action=AuditAction.DATA_DELETED,
            actor_type=AuditActorType.system,
            target_type="user",
            target_id=request.user_id,
            metadata={
                "families_deleted": outcome.families_deleted,
                "devices_deleted": outcome.devices_deleted,
                "usage_rows_deleted": outcome.usage_rows_deleted,
                "location_rows_deleted": outcome.location_rows_deleted,
            },
        )
    return outcomes


async def _delete_user_data(session: AsyncSession, *, user_id: uuid.UUID) -> DeletionResult:
    families = (
        (await session.execute(select(Family).where(Family.owner_user_id == user_id)))
        .scalars()
        .all()
    )
    family_ids = [family.id for family in families]

    usage_deleted = location_deleted = events_deleted = devices_deleted = 0

    if family_ids:
        usage_result = await session.execute(
            delete(UsageDailySummary).where(UsageDailySummary.family_id.in_(family_ids))
        )
        usage_deleted = rowcount_of(usage_result)

        location_result = await session.execute(
            delete(LocationSample).where(LocationSample.family_id.in_(family_ids))
        )
        location_deleted = rowcount_of(location_result)

        events_result = await session.execute(
            delete(DeviceEvent).where(DeviceEvent.family_id.in_(family_ids))
        )
        events_deleted = rowcount_of(events_result)

        device_rows = await session.execute(
            select(Device.id).where(Device.family_id.in_(family_ids))
        )
        devices_deleted = len(device_rows.all())

        await session.execute(
            update(ChildProfile)
            .where(ChildProfile.family_id.in_(family_ids))
            .values(
                profile_status=ProfileStatus.deleted,
                deleted_at=utcnow(),
                display_name="[deleted]",
                avatar_key=None,
            )
        )
        # Cascades remove devices, policies, commands and alerts.
        for family in families:
            await session.delete(family)

    user = await session.get(User, user_id)
    if user is not None:
        # Anonymise rather than delete the row: foreign keys elsewhere use
        # ON DELETE SET NULL, and keeping a tombstone prevents id reuse.
        user.email = f"deleted+{user.id}@invalid"
        user.normalized_email = f"deleted+{user.id}@invalid"
        user.display_name = "[deleted]"
        user.password_hash = "!"
        user.account_status = AccountStatus.deleted
        user.deleted_at = utcnow()
        user.email_verified_at = None

    return DeletionResult(
        user_id=user_id,
        families_deleted=len(family_ids),
        devices_deleted=devices_deleted,
        usage_rows_deleted=usage_deleted,
        location_rows_deleted=location_deleted,
        event_rows_deleted=events_deleted,
    )


async def build_export_payload(session: AsyncSession, *, user: User) -> dict:
    """Assemble the account's data for an export.

    Returned inline (rather than as a stored artifact) because object storage
    is not configured in this release; the shape is the same either way.
    """
    families = await session.execute(
        select(Family).where(Family.owner_user_id == user.id, Family.deleted_at.is_(None))
    )
    family_rows = list(families.scalars().all())
    family_ids = [family.id for family in family_rows]

    children: list[ChildProfile] = []
    devices: list[Device] = []
    if family_ids:
        children = list(
            (
                await session.execute(
                    select(ChildProfile).where(ChildProfile.family_id.in_(family_ids))
                )
            )
            .scalars()
            .all()
        )
        devices = list(
            (await session.execute(select(Device).where(Device.family_id.in_(family_ids))))
            .scalars()
            .all()
        )

    consents = await list_consents(session, user_id=user.id, family_ids=family_ids)

    return {
        "generated_at": utcnow().isoformat(),
        "account": {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "timezone": user.timezone,
            "locale": user.locale,
            "account_status": user.account_status.value,
            "created_at": user.created_at.isoformat(),
            "email_verified_at": (
                user.email_verified_at.isoformat() if user.email_verified_at else None
            ),
        },
        "families": [
            {
                "id": str(family.id),
                "name": family.name,
                "timezone": family.timezone,
                "created_at": family.created_at.isoformat(),
            }
            for family in family_rows
        ],
        "children": [
            {
                "id": str(child.id),
                "family_id": str(child.family_id),
                "display_name": child.display_name,
                "age_band": child.age_band.value,
                "timezone": child.timezone,
                "policy_version": child.policy_version,
            }
            for child in children
        ],
        "devices": [
            {
                "id": str(device.id),
                "child_profile_id": str(device.child_profile_id),
                "device_label": device.device_label,
                "platform": device.platform.value,
                "device_status": device.device_status.value,
                "registered_at": (
                    device.registered_at.isoformat() if device.registered_at else None
                ),
                "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
            }
            for device in devices
        ],
        "consents": [
            {
                "consent_type": record.consent_type.value,
                "state": record.state.value,
                "policy_version": record.policy_version,
                "recorded_at": record.recorded_at.isoformat(),
                "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
            }
            for record in consents
        ],
        "notes": {
            "usage_and_location": (
                "Usage summaries and any location samples are available per child through "
                "the usage and location endpoints while the account is active."
            ),
            "retention_exceptions": RETENTION_EXCEPTIONS,
        },
    }
