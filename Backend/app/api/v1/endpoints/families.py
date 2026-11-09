"""Family and guardian-membership endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import (
    ClientIp,
    CurrentParent,
    DbSession,
    UserAgent,
    VerifiedParent,
    require_family_membership,
)
from app.core.config import settings
from app.core.permissions import FamilyPermission
from app.core.response import ApiResponse, ok
from app.schemas.auth import GenericMessageOut
from app.schemas.family import (
    FamilyCreate,
    FamilyMemberOut,
    FamilyOut,
    FamilyUpdate,
    GuardianInvitationAccept,
    GuardianInvitationCreate,
    GuardianInvitationOut,
)
from app.services import family_service

router = APIRouter(tags=["families"])

FamilyAccess = family_service.FamilyAccess

# Each alias both resolves `{family_id}` through the caller's membership and
# enforces one permission, so a route body never repeats an authorization check.
ReadAccess = Annotated[
    FamilyAccess, Depends(require_family_membership(FamilyPermission.FAMILY_READ))
]
UpdateAccess = Annotated[
    FamilyAccess, Depends(require_family_membership(FamilyPermission.FAMILY_UPDATE))
]
MembersAccess = Annotated[
    FamilyAccess, Depends(require_family_membership(FamilyPermission.MEMBERS_MANAGE))
]


async def family_out(session, access: FamilyAccess) -> FamilyOut:  # noqa: ANN001
    children, devices = await family_service.family_counts(session, family_id=access.family_id)
    return FamilyOut(
        id=access.family.id,
        name=access.family.name,
        status=access.family.status,
        timezone=access.family.timezone,
        owner_user_id=access.family.owner_user_id,
        created_at=access.family.created_at,
        updated_at=access.family.updated_at,
        my_permissions=(
            [perm.value for perm in FamilyPermission] if access.is_owner else access.permissions
        ),
        my_role_is_owner=access.is_owner,
        child_count=children,
        device_count=devices,
    )


@router.post(
    "/families",
    response_model=ApiResponse[FamilyOut],
    status_code=status.HTTP_201_CREATED,
    summary="Create a family",
)
async def create_family(
    payload: FamilyCreate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    """The caller becomes the family owner and holds every family permission."""
    access = await family_service.create_family(
        session,
        owner=principal.user,
        name=payload.name,
        timezone=payload.timezone,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return ok(await family_out(session, access), message="Family created.")


@router.get(
    "/families",
    response_model=ApiResponse[list[FamilyOut]],
    summary="List the caller's families",
)
async def list_families(principal: CurrentParent, session: DbSession) -> dict:
    """Only families the caller is an active member of are returned."""
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    items = [
        await family_out(session, FamilyAccess(family=family, member=member))
        for family, member in memberships
    ]
    return ok(items)


@router.get(
    "/families/{family_id}",
    response_model=ApiResponse[FamilyOut],
    summary="Get one family",
)
async def get_family(session: DbSession, access: ReadAccess) -> dict:
    """A non-member receives 404, not 403: the existence of another tenant's
    family must not be discoverable by guessing identifiers."""
    return ok(await family_out(session, access))


@router.patch(
    "/families/{family_id}",
    response_model=ApiResponse[FamilyOut],
    summary="Update a family",
)
async def update_family(
    payload: FamilyUpdate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    access: UpdateAccess,
) -> dict:
    await family_service.update_family(
        session,
        access=access,
        actor=principal.user,
        name=payload.name,
        timezone=payload.timezone,
        client_ip=client_ip,
    )
    return ok(await family_out(session, access), message="Family updated.")


@router.get(
    "/families/{family_id}/members",
    response_model=ApiResponse[list[FamilyMemberOut]],
    summary="List guardians in a family",
)
async def list_members(session: DbSession, access: ReadAccess) -> dict:
    rows = await family_service.list_members(session, family_id=access.family_id)
    return ok(
        [
            FamilyMemberOut(
                id=member.id,
                user_id=member.user_id,
                display_name=user.display_name,
                email=user.email,
                relationship_type=member.relationship_type,
                membership_status=member.membership_status,
                is_owner=member.is_owner,
                permissions=(
                    [perm.value for perm in FamilyPermission]
                    if member.is_owner
                    else list(member.permissions or [])
                ),
                joined_at=member.joined_at,
            )
            for member, user in rows
        ]
    )


@router.delete(
    "/families/{family_id}/members/{member_id}",
    response_model=ApiResponse[GenericMessageOut],
    summary="Remove a guardian",
)
async def remove_member(
    member_id: uuid.UUID,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    access: MembersAccess,
) -> dict:
    """The owner cannot be removed; ownership transfer is a separate flow."""
    await family_service.remove_member(
        session,
        access=access,
        actor=principal.user,
        member_id=member_id,
        client_ip=client_ip,
    )
    return ok(GenericMessageOut(detail="Guardian removed."), message="Guardian removed.")


# ---------------------------------------------------------------------------
# Guardian invitations
# ---------------------------------------------------------------------------
@router.post(
    "/families/{family_id}/guardian-invitations",
    response_model=ApiResponse[GuardianInvitationOut],
    status_code=status.HTTP_201_CREATED,
    summary="Invite a second guardian",
)
async def create_guardian_invitation(
    payload: GuardianInvitationCreate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    access: MembersAccess,
) -> dict:
    """Family restructuring, billing and privacy permissions are never delegated:
    they are stripped from the request before the invitation is stored."""
    invitation, raw_token = await family_service.create_guardian_invitation(
        session,
        access=access,
        actor=principal.user,
        invited_email=str(payload.invited_email),
        relationship_type=payload.relationship_type,
        requested_permissions=[perm.value for perm in payload.permissions],
        client_ip=client_ip,
    )
    # The raw token only leaves the server through email. It is echoed here
    # solely for the local console mail sink.
    include_token = settings.email_provider == "console" and not settings.is_production
    return ok(
        GuardianInvitationOut(
            id=invitation.id,
            family_id=invitation.family_id,
            invited_email=invitation.invited_email,
            relationship_type=invitation.relationship_type,
            permissions=list(invitation.permissions or []),
            status=invitation.status,
            expires_at=invitation.expires_at,
            created_at=invitation.created_at,
            accepted_at=invitation.accepted_at,
            invitation_token=raw_token if include_token else None,
        ),
        message="Invitation sent.",
    )


@router.get(
    "/families/{family_id}/guardian-invitations",
    response_model=ApiResponse[list[GuardianInvitationOut]],
    summary="List guardian invitations",
)
async def list_guardian_invitations(session: DbSession, access: MembersAccess) -> dict:
    rows = await family_service.list_guardian_invitations(session, family_id=access.family_id)
    return ok(
        [
            GuardianInvitationOut(
                id=row.id,
                family_id=row.family_id,
                invited_email=row.invited_email,
                relationship_type=row.relationship_type,
                permissions=list(row.permissions or []),
                status=row.status,
                expires_at=row.expires_at,
                created_at=row.created_at,
                accepted_at=row.accepted_at,
            )
            for row in rows
        ]
    )


@router.delete(
    "/families/{family_id}/guardian-invitations/{invitation_id}",
    response_model=ApiResponse[GenericMessageOut],
    summary="Revoke a guardian invitation",
)
async def revoke_guardian_invitation(
    invitation_id: uuid.UUID,
    principal: VerifiedParent,
    session: DbSession,
    access: MembersAccess,
) -> dict:
    await family_service.revoke_guardian_invitation(
        session, access=access, actor=principal.user, invitation_id=invitation_id
    )
    return ok(GenericMessageOut(detail="Invitation revoked."), message="Invitation revoked.")


@router.post(
    "/guardian-invitations/accept",
    response_model=ApiResponse[FamilyOut],
    summary="Accept a guardian invitation",
)
async def accept_guardian_invitation(
    payload: GuardianInvitationAccept,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    """The invitation is bound to the invited email address, so a leaked link
    cannot be redeemed by a different account."""
    member = await family_service.accept_guardian_invitation(
        session, raw_token=payload.token, acceptor=principal.user, client_ip=client_ip
    )
    access = await family_service.resolve_family_access(
        session, user_id=principal.id, family_id=member.family_id
    )
    return ok(await family_out(session, access), message="Invitation accepted.")
