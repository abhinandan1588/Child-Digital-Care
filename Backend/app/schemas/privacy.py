"""Consent, data-export and data-deletion schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator, model_validator

from app.db.enums import (
    ConsentMethod,
    ConsentState,
    ConsentType,
    PrivacyRequestStatus,
    PrivacyRequestType,
)
from app.schemas.common import OutSchema, SchemaBase


class ConsentRecordCreate(SchemaBase):
    consent_type: ConsentType
    state: ConsentState
    policy_version: str = Field(max_length=32, examples=["2026-01"])
    method: ConsentMethod = ConsentMethod.parent_app_acceptance
    child_profile_id: uuid.UUID | None = None
    device_id: uuid.UUID | None = None
    surface: str | None = Field(default=None, max_length=32)

    @field_validator("state")
    @classmethod
    def _no_declined_via_create(cls, value: ConsentState) -> ConsentState:
        if value is ConsentState.revoked:
            raise ValueError("Use the revoke endpoint to withdraw a consent.")
        return value


class ConsentRecordOut(OutSchema):
    id: uuid.UUID
    consent_type: ConsentType
    state: ConsentState
    policy_version: str
    method: ConsentMethod
    child_profile_id: uuid.UUID | None
    device_id: uuid.UUID | None
    recorded_at: datetime
    revoked_at: datetime | None


class PrivacyRequestCreate(SchemaBase):
    request_type: PrivacyRequestType
    family_id: uuid.UUID | None = Field(
        default=None,
        description="Required for a family-scoped export; omit for an account-wide request.",
    )
    reason: str | None = Field(default=None, max_length=255)
    #: Deletion is irreversible once processed; require an explicit confirmation.
    confirm: bool = False

    @model_validator(mode="after")
    def _deletion_requires_confirmation(self) -> PrivacyRequestCreate:
        if self.request_type is PrivacyRequestType.deletion and not self.confirm:
            raise ValueError("Set confirm=true to request deletion.")
        return self


class PrivacyRequestOut(OutSchema):
    id: uuid.UUID
    request_type: PrivacyRequestType
    status: PrivacyRequestStatus
    requested_at: datetime
    due_at: datetime | None
    completed_at: datetime | None
    #: Present only while an export artifact is available.
    download_available: bool = False
    artifact_expires_at: datetime | None = None
    retention_exceptions: dict | None = None


class AccountDeletionRequest(SchemaBase):
    password: str = Field(min_length=1, max_length=128)
    confirm_phrase: str = Field(
        description="Must be exactly 'DELETE MY ACCOUNT'.",
        max_length=32,
    )
    reason: str | None = Field(default=None, max_length=255)

    @field_validator("confirm_phrase")
    @classmethod
    def _phrase(cls, value: str) -> str:
        if value.strip() != "DELETE MY ACCOUNT":
            raise ValueError("confirm_phrase must be exactly 'DELETE MY ACCOUNT'.")
        return value.strip()


class AccountDeletionScheduledOut(OutSchema):
    request_id: uuid.UUID
    scheduled_for: datetime
    grace_period_days: int
    devices_revoked: int
    note: str
