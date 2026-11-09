"""Consent, data export, and account deletion endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import ClientIp, CurrentParent, DbSession, VerifiedParent
from app.core.response import ApiResponse, ok
from app.db.enums import PrivacyRequestType
from app.schemas.auth import GenericMessageOut
from app.schemas.privacy import (
    AccountDeletionRequest,
    AccountDeletionScheduledOut,
    ConsentRecordCreate,
    ConsentRecordOut,
    PrivacyRequestCreate,
    PrivacyRequestOut,
)
from app.services import family_service, privacy_service

router = APIRouter(prefix="/privacy", tags=["privacy"])


def consent_out(row) -> ConsentRecordOut:  # noqa: ANN001
    return ConsentRecordOut(
        id=row.id,
        consent_type=row.consent_type,
        state=row.state,
        policy_version=row.policy_version,
        method=row.method,
        child_profile_id=row.child_profile_id,
        device_id=row.device_id,
        recorded_at=row.recorded_at,
        revoked_at=row.revoked_at,
    )


def request_out(row) -> PrivacyRequestOut:  # noqa: ANN001
    return PrivacyRequestOut(
        id=row.id,
        request_type=row.request_type,
        status=row.status,
        requested_at=row.requested_at,
        due_at=row.due_at,
        completed_at=row.completed_at,
        download_available=bool(row.artifact_key),
        artifact_expires_at=row.artifact_expires_at,
        retention_exceptions=row.retention_exceptions,
    )


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------
@router.get(
    "/consents",
    response_model=ApiResponse[list[ConsentRecordOut]],
    summary="List consent and disclosure records",
)
async def list_consents(principal: CurrentParent, session: DbSession) -> dict:
    """Every record pins the exact policy version that was presented, so what
    was agreed and when stays auditable."""
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    rows = await privacy_service.list_consents(
        session,
        user_id=principal.id,
        family_ids=[family.id for family, _ in memberships],
    )
    return ok([consent_out(row) for row in rows])


@router.post(
    "/consents",
    response_model=ApiResponse[ConsentRecordOut],
    status_code=status.HTTP_201_CREATED,
    summary="Record a consent or disclosure acceptance",
)
async def create_consent(
    payload: ConsentRecordCreate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    """Granting ``location_collection`` here is a precondition for the location
    module; it does not by itself enable the feature, which also needs
    ``FEATURE_LOCATION_ENABLED`` and a device-reported permission."""
    family_id = None
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    if memberships:
        family_id = memberships[0][0].id

    record = await privacy_service.record_consent(
        session,
        user_id=principal.id,
        family_id=family_id,
        consent_type=payload.consent_type,
        state=payload.state,
        policy_version=payload.policy_version,
        method=payload.method,
        child_profile_id=payload.child_profile_id,
        device_id=payload.device_id,
        surface=payload.surface,
        client_ip=client_ip,
    )
    return ok(consent_out(record), message="Consent recorded.")


@router.delete(
    "/consents/{consent_id}",
    response_model=ApiResponse[GenericMessageOut],
    summary="Withdraw a consent",
)
async def revoke_consent(
    consent_id: uuid.UUID,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    """Withdrawing location consent deletes the samples it authorised.

    Consent is not a flag that merely stops future collection; the data
    collected under it goes too.
    """
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    _, purged = await privacy_service.revoke_consent(
        session,
        user_id=principal.id,
        consent_id=consent_id,
        family_ids=[family.id for family, _ in memberships],
        client_ip=client_ip,
    )
    return ok(
        GenericMessageOut(
            detail=(
                f"Consent withdrawn. {purged} record(s) collected under it were deleted."
                if purged
                else "Consent withdrawn."
            )
        ),
        message="Consent withdrawn.",
    )


# ---------------------------------------------------------------------------
# Export / deletion
# ---------------------------------------------------------------------------
@router.get(
    "/requests",
    response_model=ApiResponse[list[PrivacyRequestOut]],
    summary="List the caller's privacy requests",
)
async def list_requests(principal: CurrentParent, session: DbSession) -> dict:
    rows = await privacy_service.list_requests(session, user_id=principal.id)
    return ok([request_out(row) for row in rows])


@router.post(
    "/requests",
    response_model=ApiResponse[PrivacyRequestOut],
    status_code=status.HTTP_201_CREATED,
    summary="Request a data export or deletion",
)
async def create_request(
    payload: PrivacyRequestCreate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    """An existing open request of the same type is returned rather than
    duplicated. ``retention_exceptions`` states plainly what will be kept and
    why."""
    request = await privacy_service.create_request(
        session,
        user=principal.user,
        request_type=payload.request_type,
        family_id=payload.family_id,
        reason=payload.reason,
        client_ip=client_ip,
    )
    return ok(request_out(request), message="Request recorded.")


@router.get(
    "/export",
    response_model=ApiResponse[dict],
    summary="Download the account's data now",
)
async def export_now(principal: VerifiedParent, session: DbSession, client_ip: ClientIp) -> dict:
    """Returns the export inline.

    Object storage is not configured in this release, so there is no signed
    download URL; the same payload would be written to a private bucket once it
    is. Per-child usage and location remain available through their own
    endpoints while the account is active.
    """
    await privacy_service.create_request(
        session,
        user=principal.user,
        request_type=PrivacyRequestType.export,
        family_id=None,
        reason="self-service export",
        client_ip=client_ip,
    )
    payload = await privacy_service.build_export_payload(session, user=principal.user)
    return ok(payload, message="Export generated.")


@router.post(
    "/account/delete",
    response_model=ApiResponse[AccountDeletionScheduledOut],
    summary="Schedule account deletion",
)
async def request_account_deletion(
    payload: AccountDeletionRequest,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    """Requires the account password and an explicit confirmation phrase.

    Devices are unlinked immediately, so monitoring stops now. The data itself
    is erased after a grace period, during which the request can be cancelled -
    which matters if the request came from someone who should not have had
    access.
    """
    outcome = await privacy_service.schedule_account_deletion(
        session,
        user=principal.user,
        password=payload.password,
        reason=payload.reason,
        client_ip=client_ip,
    )
    return ok(
        AccountDeletionScheduledOut(
            request_id=outcome.request.id,
            scheduled_for=outcome.scheduled_for,
            grace_period_days=privacy_service.DELETION_GRACE_PERIOD_DAYS,
            devices_revoked=outcome.devices_revoked,
            note=(
                "All devices have been unlinked and every session signed out. "
                "Sign in again within the grace period to cancel. Some records are "
                "retained for legal reasons; see retention_exceptions on the request."
            ),
        ),
        message="Account deletion scheduled.",
    )


@router.post(
    "/account/delete/cancel",
    response_model=ApiResponse[PrivacyRequestOut],
    summary="Cancel a pending account deletion",
)
async def cancel_account_deletion(
    principal: CurrentParent, session: DbSession, client_ip: ClientIp
) -> dict:
    """Devices are not automatically re-linked: they must be paired again,
    because their credentials were revoked."""
    request = await privacy_service.cancel_account_deletion(
        session, user=principal.user, client_ip=client_ip
    )
    return ok(
        request_out(request),
        message="Deletion cancelled. Devices must be paired again.",
    )
