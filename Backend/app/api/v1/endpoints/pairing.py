"""Pairing: parent-side invitation management and the device-side claim."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import (
    ClientIp,
    CurrentParent,
    DbSession,
    UserAgent,
    VerifiedParent,
    require_child_access,
)
from app.core.config import settings
from app.core.errors import NotFound
from app.core.permissions import FamilyPermission
from app.core.rate_limit import RateLimit, check_rate_limit, hash_identifier
from app.core.response import ApiResponse, ok
from app.core.security import hash_opaque_token, normalize_short_code
from app.db.models.family import ChildProfile
from app.schemas.auth import GenericMessageOut
from app.schemas.device import (
    PairingClaimRequest,
    PairingClaimResponse,
    PairingInvitationCreate,
    PairingInvitationCreated,
    PairingInvitationOut,
)
from app.services import family_service, pairing_service

router = APIRouter(tags=["pairing"])

FamilyAccess = family_service.FamilyAccess
ChildContext = tuple[FamilyAccess, ChildProfile]
PairingManage = Annotated[
    ChildContext, Depends(require_child_access(FamilyPermission.PAIRING_MANAGE))
]


def invitation_out(invitation) -> PairingInvitationOut:  # noqa: ANN001
    return PairingInvitationOut(
        invitation_id=invitation.id,
        family_id=invitation.family_id,
        child_profile_id=invitation.child_profile_id,
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        attempt_count=invitation.attempt_count,
        short_code_prefix=invitation.short_code_prefix,
        claimed_at=invitation.claimed_at,
        claimed_device_id=invitation.claimed_device_id,
    )


# ---------------------------------------------------------------------------
# Parent side
# ---------------------------------------------------------------------------
@router.post(
    "/children/{child_profile_id}/pairing-invitations",
    response_model=ApiResponse[PairingInvitationCreated],
    status_code=status.HTTP_201_CREATED,
    summary="Create a pairing invitation",
    dependencies=[Depends(RateLimit("pairing.create"))],
)
async def create_pairing_invitation(
    payload: PairingInvitationCreate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: PairingManage,
) -> dict:
    """Mint a short-lived, single-use pairing invitation.

    ``claim_token`` is returned **once**, here. The server stores only its
    SHA-256 hash, so it cannot be retrieved again and never appears in a log.
    Encode this token (not a parent JWT, and no account details) in the QR code.
    """
    _, child = context
    created = await pairing_service.create_invitation(
        session,
        child=child,
        created_by_user_id=principal.id,
        expires_in_minutes=payload.expires_in_minutes,
        include_short_code=payload.include_short_code,
        device_label=payload.device_label,
        client_ip=client_ip,
    )
    base = invitation_out(created.invitation)
    return ok(
        PairingInvitationCreated(
            **base.model_dump(),
            claim_token=created.claim_token,
            short_code=created.short_code,
        ),
        message="Pairing invitation created.",
    )


@router.get(
    "/children/{child_profile_id}/pairing-invitations",
    response_model=ApiResponse[list[PairingInvitationOut]],
    summary="List pairing invitations for a child",
)
async def list_pairing_invitations(session: DbSession, context: PairingManage) -> dict:
    _, child = context
    rows = await pairing_service.list_invitations(session, child_profile_id=child.id)
    return ok([invitation_out(row) for row in rows])


@router.get(
    "/pairing-invitations/{invitation_id}",
    response_model=ApiResponse[PairingInvitationOut],
    summary="Get a pairing invitation",
)
async def get_pairing_invitation(
    invitation_id: uuid.UUID, principal: CurrentParent, session: DbSession
) -> dict:
    """Scoped to the caller's families: an invitation id from another family is
    reported as not found."""
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    for family, member in memberships:
        access = FamilyAccess(family=family, member=member)
        if not access.can(FamilyPermission.PAIRING_MANAGE):
            continue
        try:
            invitation = await pairing_service.get_invitation_for_parent(
                session, invitation_id=invitation_id, family_id=family.id
            )
        except NotFound:
            continue
        return ok(invitation_out(invitation))
    raise NotFound("Pairing invitation not found.")


@router.delete(
    "/pairing-invitations/{invitation_id}",
    response_model=ApiResponse[GenericMessageOut],
    summary="Revoke a pairing invitation",
)
async def revoke_pairing_invitation(
    invitation_id: uuid.UUID,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    for family, member in memberships:
        access = FamilyAccess(family=family, member=member)
        if not access.can(FamilyPermission.PAIRING_MANAGE):
            continue
        try:
            invitation = await pairing_service.get_invitation_for_parent(
                session, invitation_id=invitation_id, family_id=family.id
            )
        except NotFound:
            continue
        await pairing_service.revoke_invitation(
            session, invitation=invitation, user_id=principal.id, client_ip=client_ip
        )
        return ok(
            GenericMessageOut(detail="Pairing invitation revoked."),
            message="Pairing invitation revoked.",
        )
    raise NotFound("Pairing invitation not found.")


# ---------------------------------------------------------------------------
# Device side (unauthenticated: the claim token *is* the credential)
# ---------------------------------------------------------------------------
@router.post(
    "/device/pairing/claim",
    response_model=ApiResponse[PairingClaimResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Claim a pairing invitation (Child App)",
    dependencies=[Depends(RateLimit("pairing.claim.ip"))],
)
async def claim_pairing_invitation(
    payload: PairingClaimRequest,
    request: Request,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    """Exchange a pairing invitation for a device-scoped credential.

    This is the only unauthenticated write in the device API. It is protected
    by: short expiry, single use enforced by a conditional UPDATE (so two
    devices racing cannot both win), a per-token attempt limit, and rate limits
    on both the client address and the presented secret.

    The response contains the device's own credential. It is not a parent token
    and carries no parent permissions.
    """
    # Throttle per presented secret as well as per IP, so a distributed guesser
    # cannot sidestep the IP bucket.
    secret = payload.claim_token or normalize_short_code(payload.short_code or "")
    await check_rate_limit("pairing.claim.token", hash_identifier(hash_opaque_token(secret)))

    outcome = await pairing_service.claim_invitation(
        session,
        claim_token=payload.claim_token,
        short_code=payload.short_code,
        platform=payload.device.platform,
        app_version=payload.device.app_version,
        os_version=payload.device.os_version,
        device_label=payload.device.device_label,
        device_model=payload.device.device_model,
        manufacturer=payload.device.manufacturer,
        timezone=payload.device.timezone,
        install_id=payload.device.install_id,
        disclosure_version=payload.disclosure_version,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return ok(
        PairingClaimResponse(
            device_id=outcome.device.id,
            child_profile_id=outcome.device.child_profile_id,
            family_id=outcome.device.family_id,
            device_access_token=outcome.session.access_token,
            device_refresh_token=outcome.session.refresh_token,
            expires_in=outcome.session.expires_in,
            refresh_expires_in=outcome.session.refresh_expires_in,
            status=outcome.device.device_status,
            policy_version=outcome.policy_version,
        ),
        message="Device paired. Complete registration next.",
        pairing_invitation_expire_minutes=settings.pairing_invitation_expire_minutes,
    )
