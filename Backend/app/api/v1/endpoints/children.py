"""Child profile endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import (
    ClientIp,
    DbSession,
    VerifiedParent,
    require_child_access,
    require_family_membership,
)
from app.core.permissions import FamilyPermission
from app.core.response import ApiResponse, ok
from app.db.enums import AuditActorType, DeviceStatus, ProfileStatus
from app.db.models.family import ChildProfile
from app.schemas.family import (
    ChildProfileCreate,
    ChildProfileDeleteResult,
    ChildProfileOut,
    ChildProfileUpdate,
)
from app.services import audit_service, device_service, family_service, pairing_service
from app.services.audit_service import AuditAction

router = APIRouter(tags=["children"])

FamilyAccess = family_service.FamilyAccess

ChildrenRead = Annotated[
    FamilyAccess, Depends(require_family_membership(FamilyPermission.CHILDREN_READ))
]
ChildrenManage = Annotated[
    FamilyAccess, Depends(require_family_membership(FamilyPermission.CHILDREN_MANAGE))
]
ChildContext = tuple[FamilyAccess, ChildProfile]
ChildRead = Annotated[ChildContext, Depends(require_child_access(FamilyPermission.CHILDREN_READ))]
ChildManage = Annotated[
    ChildContext, Depends(require_child_access(FamilyPermission.CHILDREN_MANAGE))
]


async def child_out(session, child) -> ChildProfileOut:  # noqa: ANN001
    total, active = await family_service.child_device_counts(session, child_profile_id=child.id)
    return ChildProfileOut(
        id=child.id,
        family_id=child.family_id,
        display_name=child.display_name,
        age_band=child.age_band,
        timezone=child.timezone,
        avatar_key=child.avatar_key,
        profile_status=child.profile_status,
        policy_version=child.policy_version,
        created_at=child.created_at,
        updated_at=child.updated_at,
        device_count=total,
        active_device_count=active,
    )


@router.post(
    "/families/{family_id}/children",
    response_model=ApiResponse[ChildProfileOut],
    status_code=status.HTTP_201_CREATED,
    summary="Create a child profile",
)
async def create_child(
    payload: ChildProfileCreate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    access: ChildrenManage,
) -> dict:
    """Stores an age band rather than a date of birth: the product does not
    need an exact birthday, and collecting one would be unnecessary data about
    a child."""
    child = await family_service.create_child_profile(
        session,
        access=access,
        actor=principal.user,
        display_name=payload.display_name,
        age_band=payload.age_band,
        timezone=payload.timezone,
        avatar_key=payload.avatar_key,
        client_ip=client_ip,
    )
    return ok(await child_out(session, child), message="Child profile created.")


@router.get(
    "/families/{family_id}/children",
    response_model=ApiResponse[list[ChildProfileOut]],
    summary="List child profiles in a family",
)
async def list_children(
    session: DbSession,
    access: ChildrenRead,
    include_inactive: Annotated[bool, Query()] = False,
) -> dict:
    rows = await family_service.list_child_profiles(
        session, family_id=access.family_id, include_inactive=include_inactive
    )
    return ok([await child_out(session, child) for child in rows])


@router.get(
    "/children/{child_profile_id}",
    response_model=ApiResponse[ChildProfileOut],
    summary="Get one child profile",
)
async def get_child(session: DbSession, context: ChildRead) -> dict:
    _, child = context
    return ok(await child_out(session, child))


@router.patch(
    "/children/{child_profile_id}",
    response_model=ApiResponse[ChildProfileOut],
    summary="Update a child profile",
)
async def update_child(
    payload: ChildProfileUpdate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: ChildManage,
) -> dict:
    access, child = context
    await family_service.update_child_profile(
        session,
        access=access,
        actor=principal.user,
        child=child,
        display_name=payload.display_name,
        age_band=payload.age_band,
        timezone=payload.timezone,
        avatar_key=payload.avatar_key,
        profile_status=payload.profile_status,
        client_ip=client_ip,
    )
    return ok(await child_out(session, child), message="Child profile updated.")


@router.delete(
    "/children/{child_profile_id}",
    response_model=ApiResponse[ChildProfileDeleteResult],
    summary="Deactivate a child profile",
)
async def delete_child(
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: ChildManage,
) -> dict:
    """Deactivates rather than hard-deletes.

    Every linked device is unlinked and every pending pairing invitation is
    revoked first, so monitoring stops immediately and no orphaned device keeps
    a working credential. The usage history is kept until the retention window
    elapses or an explicit deletion request is made, which is why this returns
    a retention note rather than claiming the data is gone.
    """
    access, child = context

    devices = await device_service.list_devices(
        session, family_ids=[access.family_id], child_profile_id=child.id
    )
    revoked = 0
    for device in devices:
        if device.device_status is DeviceStatus.revoked:
            continue
        await device_service.revoke_device(
            session,
            device=device,
            reason="child profile deactivated",
            actor_type=AuditActorType.parent_user,
            actor_id=principal.id,
            client_ip=client_ip,
        )
        revoked += 1

    invitations_revoked = await pairing_service.revoke_pending_invitations_for_child(
        session, child_profile_id=child.id, user_id=principal.id
    )

    child.profile_status = ProfileStatus.inactive

    await audit_service.record(
        session,
        action=AuditAction.CHILD_DEACTIVATED,
        actor_type=AuditActorType.parent_user,
        actor_id=principal.id,
        target_type="child_profile",
        target_id=child.id,
        family_id=access.family_id,
        client_ip=client_ip,
        metadata={"devices_revoked": revoked, "invitations_revoked": invitations_revoked},
    )
    return ok(
        ChildProfileDeleteResult(
            child_profile_id=child.id,
            profile_status=child.profile_status,
            devices_revoked=revoked,
            pairing_invitations_revoked=invitations_revoked,
            retention_note=(
                "The profile is deactivated and all devices are unlinked. Usage history is "
                "kept until its retention period expires. Use the privacy endpoints to "
                "request immediate deletion of the account's data."
            ),
        ),
        message="Child profile deactivated.",
    )
