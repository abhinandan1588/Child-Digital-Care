"""Parent/guardian identity, sessions, and single-use email tokens."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import AccountStatus
from app.db.types import EmailText, JSONBType, TZTimestamp, UUIDType, enum_column

if TYPE_CHECKING:
    from app.db.models.family import FamilyMember


class User(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A parent/guardian account.

    ``normalized_email`` (lower-cased, trimmed) carries the uniqueness
    constraint so that ``Alice@Example.com`` and ``alice@example.com`` cannot
    both register. ``email`` keeps the address as the user typed it.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(EmailText, nullable=False)
    normalized_email: Mapped[str] = mapped_column(EmailText, nullable=False)
    password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    locale: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="en")
    timezone: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="UTC")

    account_status: Mapped[AccountStatus] = mapped_column(
        enum_column(AccountStatus, "account_status"),
        nullable=False,
        default=AccountStatus.pending_verification,
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    password_changed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    last_login_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    #: Consecutive failed logins. Used for exponential delay, never for a hard
    #: lock, so an attacker cannot deny service to a victim's account.
    failed_login_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    last_failed_login_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    #: Set when the account is scheduled for deletion (grace period).
    deletion_requested_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    # `family_members` also carries `invited_by_user_id`, so the join path has
    # to be stated explicitly.
    memberships: Mapped[list[FamilyMember]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        foreign_keys="FamilyMember.user_id",
    )

    __table_args__ = (
        sa.UniqueConstraint("normalized_email", name="uq_users_normalized_email"),
        sa.Index("ix_users_account_status", "account_status"),
        # `length()` is portable across PostgreSQL and the SQLite test backend.
        sa.CheckConstraint("length(display_name) >= 1", name="display_name_not_empty"),
        sa.CheckConstraint("failed_login_count >= 0", name="failed_login_count_non_negative"),
    )

    @property
    def is_email_verified(self) -> bool:
        return self.email_verified_at is not None

    @property
    def is_active(self) -> bool:
        return self.account_status is AccountStatus.active and self.deleted_at is None


class UserSession(UUIDPrimaryKeyMixin, Base):
    """A refresh-token session for a parent account.

    Only the SHA-256 hash of the refresh token is stored. ``token_family_id``
    groups every rotation of one original login: if a consumed token is
    replayed, the whole family is revoked (reuse detection).
    """

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    refresh_token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    token_family_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False)
    #: Monotonic counter within a family; helps diagnose replay.
    rotation_counter: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)

    device_label: Mapped[str | None] = mapped_column(sa.String(120))
    user_agent: Mapped[str | None] = mapped_column(sa.String(255))
    #: Truncated/derived client address. Full addresses are not retained.
    ip_prefix: Mapped[str | None] = mapped_column(sa.String(64))

    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    revoked_reason: Mapped[str | None] = mapped_column(sa.String(64))
    last_used_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    user: Mapped[User] = relationship(back_populates="sessions")

    __table_args__ = (
        sa.UniqueConstraint("refresh_token_hash", name="uq_user_sessions_refresh_token_hash"),
        sa.Index("ix_user_sessions_user_id_revoked_at", "user_id", "revoked_at"),
        sa.Index("ix_user_sessions_token_family_id", "token_family_id"),
        sa.Index("ix_user_sessions_expires_at", "expires_at"),
    )


class EmailVerificationToken(UUIDPrimaryKeyMixin, Base):
    """Single-use email-verification token (hash stored, never the raw value)."""

    __tablename__ = "email_verification_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.UniqueConstraint("token_hash", name="uq_email_verification_tokens_token_hash"),
        sa.Index("ix_email_verification_tokens_user_id_used_at", "user_id", "used_at"),
    )


class PasswordResetToken(UUIDPrimaryKeyMixin, Base):
    """Single-use password-reset token (hash stored, never the raw value)."""

    __tablename__ = "password_reset_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    invalidated_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    request_metadata: Mapped[dict | None] = mapped_column(JSONBType)
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.UniqueConstraint("token_hash", name="uq_password_reset_tokens_token_hash"),
        sa.Index("ix_password_reset_tokens_user_id_used_at", "user_id", "used_at"),
    )
