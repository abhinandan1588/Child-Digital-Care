"""Family, guardian membership and child-profile logic.

This module is the tenant boundary in code form. Every lookup takes the
acting user and resolves membership from the database; nothing trusts a
``family_id`` just because a client sent one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.errors import (
    Conflict,
    ErrorCode,
    FeatureDisabled,
    NotFound,
    PermissionDenied,
)
from app.core.logging import get_logger
from app.core.permissions import (
    FAMILY_GUARDIAN_DEFAULT_PERMISSIONS,
    NON_DELEGATABLE_FAMILY_PERMISSIONS,
    FamilyPermission,
    family_member_can,
    normalize_family_permissions,
)
from app.core.security import generate_opaque_token, hash_opaque_token
from app.db.enums import (
    AuditActorType,
    AuditOutcome,
    DeviceStatus,
    FamilyStatus,
    GuardianRelationship,
    InvitationStatus,
    MembershipStatus,
    ProfileStatus,
)
from app.db.models.device import Device
from app.db.models.family import ChildProfile, Family, FamilyMember, GuardianInvitation
from app.db.models.identity import User
from app.integrations.email import get_email_provider
from app.integrations.email.templates import guardian_invitation_email
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.utils.time import utcnow

logger = get_logger(__name__)

GUARDIAN_INVITATION_EXPIRE_HOURS = 72
MAX_FAMILIES_PER_OWNER = 3
MAX_CHILDREN_PER_FAMILY = 10


@dataclass(frozen=True, slots=True)
class FamilyAccess:
    """Resolved authorization context for one (user, family) pair."""

    family: Family
    member: FamilyMember

    @property
    def family_id(self) -> uuid.UUID:
        return self.family.id

    @property
    def is_owner(self) -> bool:
        return self.member.is_owner

    @property
    def permissions(self) -> list[str]:
        return list(self.member.permissions or [])

    def can(self, permission: FamilyPermission) -> bool:
        return family_member_can(
            is_owner=self.is_owner, granted=self.member.permissions, required=permission
        )

    def require(self, permission: FamilyPermission) -> None:
        if not self.can(permission):
            raise PermissionDenied(
                f"This action requires the '{permission.value}' permission in this family."
            )


# ---------------------------------------------------------------------------
# Access resolution
# ---------------------------------------------------------------------------
async def resolve_family_access(
    session: AsyncSession, *, user_id: uuid.UUID, family_id: uuid.UUID
) -> FamilyAccess:
    """Load a family *through* the caller's membership.

    A non-member gets ``404``, not ``403``: confirming that a family id exists
    would leak the existence of other tenants' records to an id-guessing client.
    """
    result = await session.execute(
        select(Family, FamilyMember)
        .join(FamilyMember, FamilyMember.family_id == Family.id)
        .where(
            Family.id == family_id,
            Family.deleted_at.is_(None),
            FamilyMember.user_id == user_id,
            FamilyMember.membership_status == MembershipStatus.active,
        )
        .limit(1)
    )
    row = result.first()
    if row is None:
        logger.info("family_access_denied", family_id=str(family_id))
        raise NotFound("Family not found.")

    family, member = row
    if family.status is FamilyStatus.suspended:
        raise PermissionDenied(
            "This family is suspended. Contact support.", code=ErrorCode.ACCOUNT_SUSPENDED
        )
    return FamilyAccess(family=family, member=member)


async def resolve_child_access(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    child_profile_id: uuid.UUID,
    include_inactive: bool = False,
) -> tuple[FamilyAccess, ChildProfile]:
    """Resolve a child profile and the caller's rights over its family."""
    result = await session.execute(
        select(ChildProfile).where(ChildProfile.id == child_profile_id).limit(1)
    )
    child = result.scalars().first()
    if child is None or child.deleted_at is not None:
        raise NotFound("Child profile not found.")
    if not include_inactive and child.profile_status in (
        ProfileStatus.deleted,
        ProfileStatus.pending_deletion,
    ):
        raise NotFound("Child profile not found.")

    access = await resolve_family_access(session, user_id=user_id, family_id=child.family_id)
    return access, child


async def resolve_device_access(
    session: AsyncSession, *, user_id: uuid.UUID, device_id: uuid.UUID
) -> tuple[FamilyAccess, Device]:
    result = await session.execute(select(Device).where(Device.id == device_id).limit(1))
    device = result.scalars().first()
    if device is None:
        raise NotFound("Device not found.")
    access = await resolve_family_access(session, user_id=user_id, family_id=device.family_id)
    return access, device


async def list_user_families(
    session: AsyncSession, *, user_id: uuid.UUID
) -> list[tuple[Family, FamilyMember]]:
    result = await session.execute(
        select(Family, FamilyMember)
        .join(FamilyMember, FamilyMember.family_id == Family.id)
        .where(
            FamilyMember.user_id == user_id,
            FamilyMember.membership_status == MembershipStatus.active,
            Family.deleted_at.is_(None),
        )
        .order_by(Family.created_at.asc())
    )
    return [(family, member) for family, member in result.all()]


# ---------------------------------------------------------------------------
# Family CRUD
# ---------------------------------------------------------------------------
async def create_family(
    session: AsyncSession,
    *,
    owner: User,
    name: str,
    timezone: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> FamilyAccess:
    owned = await session.execute(
        select(func.count())
        .select_from(Family)
        .where(Family.owner_user_id == owner.id, Family.deleted_at.is_(None))
    )
    if int(owned.scalar_one()) >= MAX_FAMILIES_PER_OWNER:
        raise Conflict(
            f"An account can own at most {MAX_FAMILIES_PER_OWNER} families.",
            code=ErrorCode.QUOTA_EXCEEDED,
        )

    family = Family(name=name.strip(), owner_user_id=owner.id, timezone=timezone)
    session.add(family)
    await session.flush()

    member = FamilyMember(
        family_id=family.id,
        user_id=owner.id,
        relationship_type=GuardianRelationship.parent,
        membership_status=MembershipStatus.active,
        is_owner=True,
        # Owner permissions are implicit; the list is stored for transparency.
        permissions=normalize_family_permissions([perm.value for perm in FamilyPermission]),
        joined_at=utcnow(),
    )
    session.add(member)
    await session.flush()

    await audit_service.record(
        session,
        action=AuditAction.FAMILY_CREATED,
        actor_type=AuditActorType.parent_user,
        actor_id=owner.id,
        target_type="family",
        target_id=family.id,
        family_id=family.id,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return FamilyAccess(family=family, member=member)


async def update_family(
    session: AsyncSession,
    *,
    access: FamilyAccess,
    actor: User,
    name: str | None,
    timezone: str | None,
    client_ip: str | None = None,
) -> Family:
    access.require(FamilyPermission.FAMILY_UPDATE)
    changed: dict[str, str] = {}
    if name is not None and name.strip() != access.family.name:
        access.family.name = name.strip()
        changed["name"] = "updated"
    if timezone is not None and timezone != access.family.timezone:
        access.family.timezone = timezone
        changed["timezone"] = timezone

    if changed:
        await audit_service.record(
            session,
            action=AuditAction.FAMILY_UPDATED,
            actor_type=AuditActorType.parent_user,
            actor_id=actor.id,
            target_type="family",
            target_id=access.family.id,
            family_id=access.family.id,
            client_ip=client_ip,
            metadata=changed,
        )
    return access.family


async def family_counts(session: AsyncSession, *, family_id: uuid.UUID) -> tuple[int, int]:
    """(active child count, non-revoked device count)."""
    children = await session.execute(
        select(func.count())
        .select_from(ChildProfile)
        .where(
            ChildProfile.family_id == family_id,
            ChildProfile.profile_status == ProfileStatus.active,
            ChildProfile.deleted_at.is_(None),
        )
    )
    devices = await session.execute(
        select(func.count())
        .select_from(Device)
        .where(Device.family_id == family_id, Device.device_status != DeviceStatus.revoked)
    )
    return int(children.scalar_one()), int(devices.scalar_one())


async def list_members(
    session: AsyncSession, *, family_id: uuid.UUID
) -> list[tuple[FamilyMember, User]]:
    result = await session.execute(
        select(FamilyMember, User)
        .join(User, User.id == FamilyMember.user_id)
        .where(
            FamilyMember.family_id == family_id,
            FamilyMember.membership_status != MembershipStatus.removed,
        )
        .order_by(FamilyMember.is_owner.desc(), FamilyMember.created_at.asc())
    )
    return [(member, user) for member, user in result.all()]


async def remove_member(
    session: AsyncSession,
    *,
    access: FamilyAccess,
    actor: User,
    member_id: uuid.UUID,
    client_ip: str | None = None,
) -> FamilyMember:
    access.require(FamilyPermission.MEMBERS_MANAGE)

    result = await session.execute(
        select(FamilyMember)
        .where(FamilyMember.id == member_id, FamilyMember.family_id == access.family_id)
        .limit(1)
    )
    member = result.scalars().first()
    if member is None or member.membership_status is MembershipStatus.removed:
        raise NotFound("Family member not found.")
    if member.is_owner:
        raise Conflict(
            "The family owner cannot be removed. Transfer ownership or delete the family instead."
        )

    member.membership_status = MembershipStatus.removed
    member.removed_at = utcnow()
    member.permissions = []

    await audit_service.record(
        session,
        action=AuditAction.FAMILY_MEMBER_REMOVED,
        actor_type=AuditActorType.parent_user,
        actor_id=actor.id,
        target_type="family_member",
        target_id=member.id,
        family_id=access.family_id,
        client_ip=client_ip,
        metadata={"removed_user_id": member.user_id},
    )
    return member


# ---------------------------------------------------------------------------
# Guardian invitations
# ---------------------------------------------------------------------------
def filter_delegatable_permissions(requested: list[str] | None) -> list[str]:
    """Strip permissions that may not be handed to a second guardian."""
    candidate = normalize_family_permissions(requested) or [
        perm.value for perm in FAMILY_GUARDIAN_DEFAULT_PERMISSIONS
    ]
    blocked = {perm.value for perm in NON_DELEGATABLE_FAMILY_PERMISSIONS}
    return sorted(set(candidate) - blocked)


async def create_guardian_invitation(
    session: AsyncSession,
    *,
    access: FamilyAccess,
    actor: User,
    invited_email: str,
    relationship_type: GuardianRelationship,
    requested_permissions: list[str] | None,
    client_ip: str | None = None,
) -> tuple[GuardianInvitation, str]:
    if not settings.feature_guardian_invitations_enabled:
        raise FeatureDisabled("Guardian invitations are not enabled for this deployment.")
    access.require(FamilyPermission.MEMBERS_MANAGE)

    normalized = invited_email.strip().lower()
    if normalized == actor.normalized_email:
        raise Conflict("You are already a member of this family.")

    existing_member = await session.execute(
        select(FamilyMember)
        .join(User, User.id == FamilyMember.user_id)
        .where(
            FamilyMember.family_id == access.family_id,
            FamilyMember.membership_status == MembershipStatus.active,
            User.normalized_email == normalized,
        )
        .limit(1)
    )
    if existing_member.scalars().first() is not None:
        raise Conflict("That person is already a guardian in this family.")

    pending = await session.execute(
        select(GuardianInvitation)
        .where(
            GuardianInvitation.family_id == access.family_id,
            GuardianInvitation.normalized_invited_email == normalized,
            GuardianInvitation.status == InvitationStatus.pending,
            GuardianInvitation.expires_at > utcnow(),
        )
        .limit(1)
    )
    if pending.scalars().first() is not None:
        raise Conflict(
            "An invitation for that address is already pending.",
            code=ErrorCode.ALREADY_EXISTS,
        )

    raw_token = generate_opaque_token()
    invitation = GuardianInvitation(
        family_id=access.family_id,
        invited_email=invited_email.strip(),
        normalized_invited_email=normalized,
        token_hash=hash_opaque_token(raw_token),
        relationship_type=relationship_type,
        permissions=filter_delegatable_permissions(requested_permissions),
        status=InvitationStatus.pending,
        expires_at=utcnow() + timedelta(hours=GUARDIAN_INVITATION_EXPIRE_HOURS),
        created_by_user_id=actor.id,
    )
    session.add(invitation)
    await session.flush()

    await get_email_provider().send(
        guardian_invitation_email(
            to=invitation.invited_email,
            family_name=access.family.name,
            inviter_name=actor.display_name,
            token=raw_token,
            expires_hours=GUARDIAN_INVITATION_EXPIRE_HOURS,
        )
    )
    await audit_service.record(
        session,
        action=AuditAction.GUARDIAN_INVITED,
        actor_type=AuditActorType.parent_user,
        actor_id=actor.id,
        target_type="guardian_invitation",
        target_id=invitation.id,
        family_id=access.family_id,
        client_ip=client_ip,
        metadata={"permissions": invitation.permissions},
    )
    return invitation, raw_token


async def accept_guardian_invitation(
    session: AsyncSession,
    *,
    raw_token: str,
    acceptor: User,
    client_ip: str | None = None,
) -> FamilyMember:
    result = await session.execute(
        select(GuardianInvitation)
        .where(GuardianInvitation.token_hash == hash_opaque_token(raw_token))
        .limit(1)
    )
    invitation = result.scalars().first()
    now = utcnow()

    if invitation is None:
        raise NotFound("This invitation is not valid.")
    if invitation.status is InvitationStatus.accepted:
        raise Conflict(
            "This invitation has already been used.", code=ErrorCode.INVITATION_ALREADY_CLAIMED
        )
    if invitation.status is InvitationStatus.revoked or invitation.revoked_at is not None:
        raise Conflict("This invitation was revoked.", code=ErrorCode.INVITATION_REVOKED)
    if invitation.expires_at <= now:
        invitation.status = InvitationStatus.expired
        raise Conflict("This invitation has expired.", code=ErrorCode.INVITATION_EXPIRED)

    # Binding to the invited address stops a leaked link from being redeemed by
    # whoever happens to find it.
    if invitation.normalized_invited_email != acceptor.normalized_email:
        invitation.attempt_count += 1
        await audit_service.record(
            session,
            action=AuditAction.GUARDIAN_INVITATION_ACCEPTED,
            actor_type=AuditActorType.parent_user,
            actor_id=acceptor.id,
            outcome=AuditOutcome.denied,
            target_type="guardian_invitation",
            target_id=invitation.id,
            family_id=invitation.family_id,
            reason="email_mismatch",
            client_ip=client_ip,
        )
        raise PermissionDenied(
            "This invitation was sent to a different email address. "
            "Sign in with that address to accept it."
        )

    existing = await session.execute(
        select(FamilyMember)
        .where(
            FamilyMember.family_id == invitation.family_id,
            FamilyMember.user_id == acceptor.id,
        )
        .limit(1)
    )
    member = existing.scalars().first()
    if member is not None and member.membership_status is MembershipStatus.active:
        invitation.status = InvitationStatus.accepted
        invitation.accepted_at = now
        invitation.accepted_by_user_id = acceptor.id
        return member

    if member is None:
        member = FamilyMember(
            family_id=invitation.family_id,
            user_id=acceptor.id,
            relationship_type=invitation.relationship_type,
            membership_status=MembershipStatus.active,
            is_owner=False,
            permissions=list(invitation.permissions or []),
            invited_by_user_id=invitation.created_by_user_id,
            joined_at=now,
        )
        session.add(member)
    else:
        member.membership_status = MembershipStatus.active
        member.permissions = list(invitation.permissions or [])
        member.relationship_type = invitation.relationship_type
        member.joined_at = now
        member.removed_at = None

    invitation.status = InvitationStatus.accepted
    invitation.accepted_at = now
    invitation.accepted_by_user_id = acceptor.id
    await session.flush()

    await audit_service.record(
        session,
        action=AuditAction.GUARDIAN_INVITATION_ACCEPTED,
        actor_type=AuditActorType.parent_user,
        actor_id=acceptor.id,
        target_type="family_member",
        target_id=member.id,
        family_id=invitation.family_id,
        client_ip=client_ip,
    )
    return member


async def list_guardian_invitations(
    session: AsyncSession, *, family_id: uuid.UUID
) -> list[GuardianInvitation]:
    result = await session.execute(
        select(GuardianInvitation)
        .where(GuardianInvitation.family_id == family_id)
        .order_by(GuardianInvitation.created_at.desc())
        .limit(100)
    )
    return list(result.scalars().all())


async def revoke_guardian_invitation(
    session: AsyncSession,
    *,
    access: FamilyAccess,
    actor: User,
    invitation_id: uuid.UUID,
) -> GuardianInvitation:
    access.require(FamilyPermission.MEMBERS_MANAGE)
    result = await session.execute(
        select(GuardianInvitation)
        .where(
            GuardianInvitation.id == invitation_id,
            GuardianInvitation.family_id == access.family_id,
        )
        .limit(1)
    )
    invitation = result.scalars().first()
    if invitation is None:
        raise NotFound("Invitation not found.")
    if invitation.status is InvitationStatus.accepted:
        raise Conflict("That invitation has already been accepted.")

    invitation.status = InvitationStatus.revoked
    invitation.revoked_at = utcnow()

    await audit_service.record(
        session,
        action=AuditAction.GUARDIAN_INVITATION_REVOKED,
        actor_type=AuditActorType.parent_user,
        actor_id=actor.id,
        target_type="guardian_invitation",
        target_id=invitation.id,
        family_id=access.family_id,
    )
    return invitation


# ---------------------------------------------------------------------------
# Child profiles
# ---------------------------------------------------------------------------
async def create_child_profile(
    session: AsyncSession,
    *,
    access: FamilyAccess,
    actor: User,
    display_name: str,
    age_band,  # AgeBand
    timezone: str | None,
    avatar_key: str | None,
    client_ip: str | None = None,
) -> ChildProfile:
    access.require(FamilyPermission.CHILDREN_MANAGE)

    count = await session.execute(
        select(func.count())
        .select_from(ChildProfile)
        .where(
            ChildProfile.family_id == access.family_id,
            ChildProfile.profile_status == ProfileStatus.active,
            ChildProfile.deleted_at.is_(None),
        )
    )
    if int(count.scalar_one()) >= MAX_CHILDREN_PER_FAMILY:
        raise Conflict(
            f"A family can hold at most {MAX_CHILDREN_PER_FAMILY} active child profiles.",
            code=ErrorCode.QUOTA_EXCEEDED,
        )

    child = ChildProfile(
        family_id=access.family_id,
        display_name=display_name.strip(),
        age_band=age_band,
        timezone=timezone or access.family.timezone,
        avatar_key=avatar_key,
        profile_status=ProfileStatus.active,
        policy_version=1,
    )
    session.add(child)
    await session.flush()

    await audit_service.record(
        session,
        action=AuditAction.CHILD_CREATED,
        actor_type=AuditActorType.parent_user,
        actor_id=actor.id,
        target_type="child_profile",
        target_id=child.id,
        family_id=access.family_id,
        client_ip=client_ip,
        metadata={"age_band": str(age_band)},
    )
    return child


async def list_child_profiles(
    session: AsyncSession, *, family_id: uuid.UUID, include_inactive: bool = False
) -> list[ChildProfile]:
    statement = select(ChildProfile).where(
        ChildProfile.family_id == family_id, ChildProfile.deleted_at.is_(None)
    )
    if not include_inactive:
        statement = statement.where(ChildProfile.profile_status == ProfileStatus.active)
    result = await session.execute(statement.order_by(ChildProfile.created_at.asc()))
    return list(result.scalars().all())


async def child_device_counts(
    session: AsyncSession, *, child_profile_id: uuid.UUID
) -> tuple[int, int]:
    """(all non-revoked devices, active devices)."""
    result = await session.execute(
        select(Device.device_status, func.count())
        .where(Device.child_profile_id == child_profile_id)
        .group_by(Device.device_status)
    )
    rows = result.all()
    total = sum(count for status, count in rows if status is not DeviceStatus.revoked)
    active = sum(count for status, count in rows if status is DeviceStatus.active)
    return total, active


async def update_child_profile(
    session: AsyncSession,
    *,
    access: FamilyAccess,
    actor: User,
    child: ChildProfile,
    display_name: str | None,
    age_band,  # AgeBand | None
    timezone: str | None,
    avatar_key: str | None,
    profile_status: ProfileStatus | None,
    client_ip: str | None = None,
) -> ChildProfile:
    access.require(FamilyPermission.CHILDREN_MANAGE)

    changed: dict[str, str] = {}
    if display_name is not None:
        child.display_name = display_name.strip()
        changed["display_name"] = "updated"
    if age_band is not None:
        child.age_band = age_band
        changed["age_band"] = str(age_band)
    if timezone is not None:
        child.timezone = timezone
        changed["timezone"] = timezone
    if avatar_key is not None:
        child.avatar_key = avatar_key
        changed["avatar_key"] = "updated"
    if profile_status is not None:
        child.profile_status = profile_status
        changed["profile_status"] = str(profile_status)

    if changed:
        await audit_service.record(
            session,
            action=AuditAction.CHILD_UPDATED,
            actor_type=AuditActorType.parent_user,
            actor_id=actor.id,
            target_type="child_profile",
            target_id=child.id,
            family_id=access.family_id,
            client_ip=client_ip,
            metadata=changed,
        )
    return child


async def load_family_with_members(session: AsyncSession, family_id: uuid.UUID) -> Family | None:
    result = await session.execute(
        select(Family)
        .options(selectinload(Family.members))
        .where(Family.id == family_id, Family.deleted_at.is_(None))
        .limit(1)
    )
    return result.scalars().first()
