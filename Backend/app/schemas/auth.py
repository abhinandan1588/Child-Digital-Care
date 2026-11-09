"""Authentication request/response schemas (parent, device, admin)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from app.core.security import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from app.db.enums import AccountStatus
from app.schemas.common import EmailAddress, OutSchema, SchemaBase, validate_timezone

Password = Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)]

# A small, obvious-password screen. This is not a substitute for a breached
# password service; it just stops the worst choices at registration time.
_WEAK_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password123",
        "passw0rd123",
        "qwertyuiop",
        "123456789012",
        "1234567890123",
        "letmeinplease",
        "iloveyou1234",
        "childdigitalcare",
        "administrator",
    }
)


def _screen_password(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in _WEAK_PASSWORDS:
        raise ValueError("This password is too common. Choose something less guessable.")
    if len(set(value)) < 5:
        raise ValueError("Use a password with more variety of characters.")
    return value


class RegisterRequest(SchemaBase):
    email: EmailAddress
    password: Password
    display_name: str = Field(min_length=1, max_length=120)
    timezone: str = Field(default="UTC", max_length=64)
    locale: str = Field(default="en", max_length=16)
    accepted_terms_version: str = Field(max_length=32, examples=["2026-01"])
    accepted_privacy_version: str = Field(max_length=32, examples=["2026-01"])

    @field_validator("password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        return _screen_password(value)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        return validate_timezone(value)

    @model_validator(mode="after")
    def _password_not_email(self) -> RegisterRequest:
        local_part = str(self.email).split("@", 1)[0].lower()
        if len(local_part) >= 4 and local_part in self.password.lower():
            raise ValueError("The password must not contain your email address.")
        return self


class RegisterResponse(OutSchema):
    user_id: uuid.UUID
    email: str
    account_status: AccountStatus
    email_verification_required: bool
    #: Only populated when the email provider is `console` in local development,
    #: so a developer can finish the flow without an inbox. Never in production.
    dev_verification_token: str | None = None


class LoginRequest(SchemaBase):
    email: EmailAddress
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    device_label: str | None = Field(default=None, max_length=120)


class TokenPair(OutSchema):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(description="Access-token lifetime in seconds.")
    refresh_expires_in: int = Field(description="Refresh-token lifetime in seconds.")


class LoginResponse(TokenPair):
    user: UserOut


class RefreshRequest(SchemaBase):
    refresh_token: str = Field(min_length=20, max_length=512)


class LogoutRequest(SchemaBase):
    refresh_token: str | None = Field(default=None, min_length=20, max_length=512)


class VerifyEmailRequest(SchemaBase):
    token: str = Field(min_length=20, max_length=512)


class ForgotPasswordRequest(SchemaBase):
    email: EmailAddress


class ResetPasswordRequest(SchemaBase):
    token: str = Field(min_length=20, max_length=512)
    new_password: Password

    @field_validator("new_password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        return _screen_password(value)


class ChangePasswordRequest(SchemaBase):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: Password
    revoke_other_sessions: bool = True

    @field_validator("new_password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        return _screen_password(value)

    @model_validator(mode="after")
    def _must_change(self) -> ChangePasswordRequest:
        if self.current_password == self.new_password:
            raise ValueError("The new password must be different from the current password.")
        return self


class UserOut(OutSchema):
    id: uuid.UUID
    email: str
    display_name: str
    account_status: AccountStatus
    email_verified: bool
    timezone: str
    locale: str
    created_at: datetime
    last_login_at: datetime | None = None


class MeOut(OutSchema):
    user: UserOut
    families: list[FamilyMembershipSummary] = Field(default_factory=list)


class FamilyMembershipSummary(OutSchema):
    family_id: uuid.UUID
    family_name: str
    is_owner: bool
    permissions: list[str]
    membership_status: str


class SessionOut(OutSchema):
    id: uuid.UUID
    device_label: str | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    current: bool = False


class GenericMessageOut(OutSchema):
    detail: str


# ---------------------------------------------------------------------------
# Device auth
# ---------------------------------------------------------------------------
class DeviceRefreshRequest(SchemaBase):
    device_refresh_token: str = Field(min_length=20, max_length=512)
    app_version: str | None = Field(default=None, max_length=32)


class DeviceTokenPair(OutSchema):
    device_access_token: str
    device_refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_expires_in: int


class DeviceMeOut(OutSchema):
    device_id: uuid.UUID
    child_profile_id: uuid.UUID
    family_id: uuid.UUID
    device_label: str
    device_status: str
    policy_version: int
    applied_policy_version: int | None
    policy_sync_status: str
    server_time: datetime


# ---------------------------------------------------------------------------
# Admin auth
# ---------------------------------------------------------------------------
class AdminLoginRequest(SchemaBase):
    email: EmailAddress
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    #: Verified by the identity provider in production; accepted here so the
    #: contract is stable and local development can exercise the branch.
    mfa_code: str | None = Field(default=None, min_length=6, max_length=12)


class AdminTokenPair(OutSchema):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_expires_in: int


class AdminOut(OutSchema):
    id: uuid.UUID
    email: str
    display_name: str
    status: str
    mfa_enrolled: bool
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)


class AdminLoginResponse(AdminTokenPair):
    admin: AdminOut


MeOut.model_rebuild()
LoginResponse.model_rebuild()
