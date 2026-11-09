"""Family, guardian membership, and child profile schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator

from app.core.permissions import FamilyPermission, normalize_family_permissions
from app.db.enums import (
    AgeBand,
    FamilyStatus,
    GuardianRelationship,
    InvitationStatus,
    MembershipStatus,
    ProfileStatus,
)
from app.schemas.common import EmailAddress, OutSchema, SchemaBase, validate_timezone


class FamilyCreate(SchemaBase):
    name: str = Field(min_length=1, max_length=120)
    timezone: str = Field(default="UTC", max_length=64)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        return validate_timezone(value)


class FamilyUpdate(SchemaBase):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    timezone: str | None = Field(default=None, max_length=64)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str | None) -> str | None:
        return validate_timezone(value) if value else value


class FamilyOut(OutSchema):
    id: uuid.UUID
    name: str
    status: FamilyStatus
    timezone: str
    owner_user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    #: The requesting guardian's own effective permissions in this family.
    my_permissions: list[str] = Field(default_factory=list)
    my_role_is_owner: bool = False
    child_count: int = 0
    device_count: int = 0


class FamilyMemberOut(OutSchema):
    id: uuid.UUID
    user_id: uuid.UUID
    display_name: str
    email: str
    relationship_type: GuardianRelationship
    membership_status: MembershipStatus
    is_owner: bool
    permissions: list[str]
    joined_at: datetime | None


class GuardianInvitationCreate(SchemaBase):
    invited_email: EmailAddress
    relationship_type: GuardianRelationship = GuardianRelationship.guardian
    permissions: list[FamilyPermission] = Field(
        default_factory=list,
        description=(
            "Permissions to grant. Omit for the default guardian set. "
            "Family restructuring, billing and privacy permissions cannot be delegated."
        ),
    )

    @field_validator("permissions")
    @classmethod
    def _dedupe(cls, value: list[FamilyPermission]) -> list[FamilyPermission]:
        return [
            FamilyPermission(item)
            for item in normalize_family_permissions([perm.value for perm in value])
        ]


class GuardianInvitationOut(OutSchema):
    id: uuid.UUID
    family_id: uuid.UUID
    invited_email: str
    relationship_type: GuardianRelationship
    permissions: list[str]
    status: InvitationStatus
    expires_at: datetime
    created_at: datetime
    accepted_at: datetime | None = None
    #: Returned exactly once, to the creating parent. Never stored in clear.
    invitation_token: str | None = None


class GuardianInvitationAccept(SchemaBase):
    token: str = Field(min_length=20, max_length=512)


# ---------------------------------------------------------------------------
# Child profiles
# ---------------------------------------------------------------------------
class ChildProfileCreate(SchemaBase):
    display_name: str = Field(min_length=1, max_length=80)
    age_band: AgeBand = AgeBand.undisclosed
    timezone: str | None = Field(
        default=None,
        max_length=64,
        description="Defaults to the family timezone.",
    )
    avatar_key: str | None = Field(default=None, max_length=255)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str | None) -> str | None:
        return validate_timezone(value) if value else value


class ChildProfileUpdate(SchemaBase):
    display_name: str | None = Field(default=None, min_length=1, max_length=80)
    age_band: AgeBand | None = None
    timezone: str | None = Field(default=None, max_length=64)
    avatar_key: str | None = Field(default=None, max_length=255)
    profile_status: ProfileStatus | None = Field(
        default=None,
        description="Only `active` and `inactive` may be set here; use DELETE to deactivate.",
    )

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str | None) -> str | None:
        return validate_timezone(value) if value else value

    @field_validator("profile_status")
    @classmethod
    def _status(cls, value: ProfileStatus | None) -> ProfileStatus | None:
        if value in (ProfileStatus.deleted, ProfileStatus.pending_deletion):
            raise ValueError("Use the delete endpoint to remove a child profile.")
        return value


class ChildProfileOut(OutSchema):
    id: uuid.UUID
    family_id: uuid.UUID
    display_name: str
    age_band: AgeBand
    timezone: str
    avatar_key: str | None
    profile_status: ProfileStatus
    policy_version: int
    created_at: datetime
    updated_at: datetime
    device_count: int = 0
    active_device_count: int = 0


class ChildProfileDeleteResult(OutSchema):
    child_profile_id: uuid.UUID
    profile_status: ProfileStatus
    devices_revoked: int
    pairing_invitations_revoked: int
    retention_note: str
