"""Admin identity and role-based access control.

Admin accounts live in their own table with their own sessions and audience.
An admin credential is therefore never interchangeable with a parent
credential, even though both use the same lower-level token utilities.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import AdminAccountStatus
from app.db.types import EmailText, TZTimestamp, UUIDType, enum_column


class AdminUser(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "admin_users"

    email: Mapped[str] = mapped_column(EmailText, nullable=False)
    normalized_email: Mapped[str] = mapped_column(EmailText, nullable=False)
    password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(120), nullable=False)

    status: Mapped[AdminAccountStatus] = mapped_column(
        enum_column(AdminAccountStatus, "admin_account_status"),
        nullable=False,
        default=AdminAccountStatus.active,
    )
    #: True once MFA is enrolled. Enforcement itself is delegated to the
    #: identity provider / reverse proxy in production (see docs/DEPLOYMENT.md).
    mfa_enrolled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    mfa_required: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    last_login_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    failed_login_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    password_changed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    # `admin_user_roles` also carries `granted_by_admin_id`, so the join path
    # has to be stated explicitly.
    roles: Mapped[list[AdminUserRole]] = relationship(
        back_populates="admin_user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        foreign_keys="AdminUserRole.admin_user_id",
    )
    sessions: Mapped[list[AdminSession]] = relationship(
        back_populates="admin_user", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        sa.UniqueConstraint("normalized_email", name="uq_admin_users_normalized_email"),
        sa.Index("ix_admin_users_status", "status"),
    )


class AdminRole(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "admin_roles"

    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    description: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    is_system: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    permissions: Mapped[list[AdminRolePermission]] = relationship(
        back_populates="role", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (sa.UniqueConstraint("name", name="uq_admin_roles_name"),)


class AdminPermissionRow(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A grantable admin permission (``users.read``, ``child_location.read``...)."""

    __tablename__ = "admin_permissions"

    key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    description: Mapped[str] = mapped_column(sa.String(255), nullable=False, default="")
    is_sensitive: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    __table_args__ = (sa.UniqueConstraint("key", name="uq_admin_permissions_key"),)


class AdminRolePermission(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "admin_role_permissions"

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("admin_roles.id", ondelete="CASCADE"), nullable=False
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("admin_permissions.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    role: Mapped[AdminRole] = relationship(back_populates="permissions")
    permission: Mapped[AdminPermissionRow] = relationship()

    __table_args__ = (
        sa.UniqueConstraint(
            "role_id", "permission_id", name="uq_admin_role_permissions_role_id_permission_id"
        ),
    )


class AdminUserRole(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "admin_user_roles"

    admin_user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("admin_roles.id", ondelete="RESTRICT"), nullable=False
    )
    granted_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    admin_user: Mapped[AdminUser] = relationship(
        back_populates="roles", foreign_keys=[admin_user_id]
    )
    role: Mapped[AdminRole] = relationship()

    __table_args__ = (
        sa.UniqueConstraint(
            "admin_user_id", "role_id", name="uq_admin_user_roles_admin_user_id_role_id"
        ),
    )


class AdminSession(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "admin_sessions"

    admin_user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="CASCADE"), nullable=False
    )
    refresh_token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    token_family_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False)
    rotation_counter: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    mfa_satisfied: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    ip_prefix: Mapped[str | None] = mapped_column(sa.String(64))
    user_agent: Mapped[str | None] = mapped_column(sa.String(255))

    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    revoked_reason: Mapped[str | None] = mapped_column(sa.String(64))
    last_used_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    admin_user: Mapped[AdminUser] = relationship(back_populates="sessions")

    __table_args__ = (
        sa.UniqueConstraint("refresh_token_hash", name="uq_admin_sessions_refresh_token_hash"),
        sa.Index("ix_admin_sessions_admin_user_id_revoked_at", "admin_user_id", "revoked_at"),
        sa.Index("ix_admin_sessions_token_family_id", "token_family_id"),
    )
