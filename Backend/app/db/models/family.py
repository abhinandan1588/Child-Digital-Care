"""Family (tenant boundary), guardian membership, child profiles, invitations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    AgeBand,
    FamilyStatus,
    GuardianRelationship,
    InvitationStatus,
    MembershipStatus,
    ProfileStatus,
)
from app.db.types import EmailText, JSONBType, TZTimestamp, UUIDType, enum_column

if TYPE_CHECKING:
    from app.db.models.device import Device
    from app.db.models.identity import User


class Family(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """The tenant boundary. Every child, device, policy, command, usage row and
    alert carries ``family_id`` so authorization can be enforced with a single
    predicate."""

    __tablename__ = "families"

    name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[FamilyStatus] = mapped_column(
        enum_column(FamilyStatus, "family_status"), nullable=False, default=FamilyStatus.active
    )
    timezone: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="UTC")

    members: Mapped[list[FamilyMember]] = relationship(
        back_populates="family", cascade="all, delete-orphan", passive_deletes=True
    )
    children: Mapped[list[ChildProfile]] = relationship(
        back_populates="family", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        sa.Index("ix_families_owner_user_id", "owner_user_id"),
        sa.Index("ix_families_status", "status"),
    )

    @property
    def is_active(self) -> bool:
        return self.status is FamilyStatus.active and self.deleted_at is None


class FamilyMember(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A guardian's membership of a family, with explicit granted permissions.

    Permissions are a JSON array of :class:`app.core.permissions.FamilyPermission`
    values. The owner's permissions are implicit (owner can do everything), so
    an empty array on the owner row is still fully privileged.
    """

    __tablename__ = "family_members"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[GuardianRelationship] = mapped_column(
        enum_column(GuardianRelationship, "guardian_relationship"),
        nullable=False,
        default=GuardianRelationship.parent,
    )
    membership_status: Mapped[MembershipStatus] = mapped_column(
        enum_column(MembershipStatus, "membership_status"),
        nullable=False,
        default=MembershipStatus.active,
    )
    is_owner: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    permissions: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)

    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    joined_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    removed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    family: Mapped[Family] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="memberships", foreign_keys=[user_id])

    __table_args__ = (
        sa.UniqueConstraint("family_id", "user_id", name="uq_family_members_family_id_user_id"),
        sa.Index("ix_family_members_user_id_membership_status", "user_id", "membership_status"),
        sa.Index("ix_family_members_family_id_membership_status", "family_id", "membership_status"),
    )


class ChildProfile(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A child in a family.

    Data minimisation: an :class:`AgeBand` is stored instead of a date of
    birth. ``birth_year`` is nullable and only populated when a deployment has
    a documented legal basis for it (see docs/PRIVACY_AND_RETENTION.md).
    """

    __tablename__ = "child_profiles"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    display_name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    age_band: Mapped[AgeBand] = mapped_column(
        enum_column(AgeBand, "age_band"), nullable=False, default=AgeBand.undisclosed
    )
    birth_year: Mapped[int | None] = mapped_column(sa.SmallInteger)
    avatar_key: Mapped[str | None] = mapped_column(sa.String(255))
    timezone: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="UTC")

    profile_status: Mapped[ProfileStatus] = mapped_column(
        enum_column(ProfileStatus, "profile_status"), nullable=False, default=ProfileStatus.active
    )

    #: Monotonically increasing policy version for this child's policy set.
    #: Incremented inside the same transaction as any policy mutation.
    policy_version: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    family: Mapped[Family] = relationship(back_populates="children")
    devices: Mapped[list[Device]] = relationship(
        back_populates="child_profile", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        sa.Index("ix_child_profiles_family_id_profile_status", "family_id", "profile_status"),
        sa.CheckConstraint(
            "birth_year IS NULL OR (birth_year >= 1990 AND birth_year <= 2100)",
            name="birth_year_plausible",
        ),
        sa.CheckConstraint("policy_version >= 1", name="policy_version_positive"),
        sa.CheckConstraint("length(display_name) >= 1", name="display_name_not_empty"),
    )

    @property
    def is_active(self) -> bool:
        return self.profile_status is ProfileStatus.active and self.deleted_at is None


class GuardianInvitation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An invitation for a second guardian to join a family.

    Only the token hash is stored. Permissions requested by the inviter are
    filtered against ``NON_DELEGATABLE_FAMILY_PERMISSIONS`` before storage.
    """

    __tablename__ = "guardian_invitations"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    invited_email: Mapped[str] = mapped_column(EmailText, nullable=False)
    normalized_invited_email: Mapped[str] = mapped_column(EmailText, nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    relationship_type: Mapped[GuardianRelationship] = mapped_column(
        enum_column(GuardianRelationship, "guardian_relationship"),
        nullable=False,
        default=GuardianRelationship.guardian,
    )
    permissions: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)
    status: Mapped[InvitationStatus] = mapped_column(
        enum_column(InvitationStatus, "invitation_status"),
        nullable=False,
        default=InvitationStatus.pending,
    )

    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    accepted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    attempt_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    invitation_metadata: Mapped[dict | None] = mapped_column(JSONBType)

    family: Mapped[Family] = relationship()

    __table_args__ = (
        sa.UniqueConstraint("token_hash", name="uq_guardian_invitations_token_hash"),
        sa.Index("ix_guardian_invitations_family_id_status", "family_id", "status"),
        sa.Index(
            "ix_guardian_invitations_normalized_invited_email_status",
            "normalized_invited_email",
            "status",
        ),
    )
