"""Policy intent: app restrictions, screen-time policies, schedules, versions.

Important framing: these tables record *parent intent*. They never assert that
a restriction is in force on a device. Enforcement happens in the Child App
using platform-permitted Android APIs, and what the server knows about it comes
only from device acknowledgements (:class:`DevicePolicyState`).
"""

from __future__ import annotations

import uuid
from datetime import datetime, time
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    RestrictionAction,
    ScheduleAction,
    SyncStatus,
    WebsiteRestrictionMode,
    Weekday,
)
from app.db.types import JSONBType, TZTimestamp, UUIDType, enum_column

if TYPE_CHECKING:
    pass


class AppCatalogEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Optional curated metadata about an Android package.

    Purely advisory. The server never assumes it knows every installed package,
    so a restriction may reference a package that has no catalog entry.
    """

    __tablename__ = "app_catalog"

    package_identifier: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    display_label: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    category: Mapped[str | None] = mapped_column(sa.String(40))
    icon_key: Mapped[str | None] = mapped_column(sa.String(255))
    is_system_app: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    #: Blocking some packages (dialer, settings, the Child App itself) is unsafe
    #: or impossible; flagged so the API can reject such a restriction up front.
    is_restriction_blocked: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    notes: Mapped[str | None] = mapped_column(sa.String(255))

    __table_args__ = (
        sa.UniqueConstraint("package_identifier", name="uq_app_catalog_package_identifier"),
        sa.Index("ix_app_catalog_category", "category"),
    )


class PolicyVersion(UUIDPrimaryKeyMixin, Base):
    """One row per policy change for a child profile.

    ``ChildProfile.policy_version`` holds the current number; this table is the
    audit trail of how it got there. Both are written inside the same
    transaction as the policy mutation and the outbox event.
    """

    __tablename__ = "policy_versions"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    change_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    change_summary: Mapped[str | None] = mapped_column(sa.String(255))
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now(), index=True
    )

    __table_args__ = (
        sa.UniqueConstraint(
            "child_profile_id", "version", name="uq_policy_versions_child_profile_id_version"
        ),
        sa.Index("ix_policy_versions_family_id", "family_id"),
        sa.CheckConstraint("version >= 1", name="version_positive"),
    )


class DevicePolicyState(UUIDPrimaryKeyMixin, Base):
    """What a specific device reported about a specific policy version.

    Lets the Parent App distinguish "saved on server" from "applied on device",
    per device, and explain partial/unsupported application honestly.
    """

    __tablename__ = "device_policy_states"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    policy_version: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    sync_status: Mapped[SyncStatus] = mapped_column(
        enum_column(SyncStatus, "sync_status"), nullable=False, default=SyncStatus.pending_sync
    )
    detail: Mapped[str | None] = mapped_column(sa.String(255))
    #: Per-item outcome, e.g. {"app_restrictions": "applied", "schedules": "unsupported"}
    item_results: Mapped[dict | None] = mapped_column(JSONBType)
    queued_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    reported_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id", "policy_version", name="uq_device_policy_states_device_id_policy_version"
        ),
        sa.Index("ix_device_policy_states_child_profile_id", "child_profile_id"),
        sa.Index("ix_device_policy_states_sync_status", "sync_status"),
    )


class AppRestriction(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An app-level restriction.

    ``device_id`` is nullable: NULL means the restriction applies to every
    device of the child profile. A device-scoped row overrides the
    profile-wide row for the same package (see docs/API_CONTRACT.md -
    "Policy precedence").
    """

    __tablename__ = "app_restrictions"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE")
    )

    package_identifier: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    display_label: Mapped[str | None] = mapped_column(sa.String(120))
    action: Mapped[RestrictionAction] = mapped_column(
        enum_column(RestrictionAction, "restriction_action"), nullable=False
    )
    #: Only meaningful when ``action = time_limit``.
    daily_limit_seconds: Mapped[int | None] = mapped_column(sa.Integer)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    #: Version at which this row last changed; used for optimistic concurrency.
    revision: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    __table_args__ = (
        sa.Index(
            "ix_app_restrictions_child_profile_id_package",
            "child_profile_id",
            "package_identifier",
        ),
        # NULLs compare as distinct in a UNIQUE constraint, so the composite
        # constraint below only covers device-scoped rows. Profile-wide rows
        # (device_id IS NULL) need this partial unique index.
        sa.Index(
            "uq_app_restrictions_profile_wide_package",
            "child_profile_id",
            "package_identifier",
            unique=True,
            postgresql_where=sa.text("device_id IS NULL"),
            sqlite_where=sa.text("device_id IS NULL"),
        ),
        sa.Index("ix_app_restrictions_family_id_enabled", "family_id", "enabled"),
        sa.Index("ix_app_restrictions_device_id", "device_id"),
        sa.UniqueConstraint(
            "child_profile_id",
            "device_id",
            "package_identifier",
            name="uq_app_restrictions_profile_device_package",
        ),
        sa.CheckConstraint(
            "(action <> 'time_limit') OR "
            "(daily_limit_seconds IS NOT NULL AND daily_limit_seconds > 0)",
            name="time_limit_requires_limit",
        ),
        sa.CheckConstraint(
            "daily_limit_seconds IS NULL OR "
            "(daily_limit_seconds > 0 AND daily_limit_seconds <= 86400)",
            name="daily_limit_in_range",
        ),
        sa.CheckConstraint("length(package_identifier) >= 3", name="package_identifier_plausible"),
    )


class ScreenTimePolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A daily screen-time budget plus an optional set of schedules.

    ``timezone`` is an IANA identifier and is what makes the attached schedules
    meaningful: schedules store local wall-clock intent and are resolved
    against this zone, so DST changes do not shift bedtime.
    """

    __tablename__ = "screen_time_policies"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE")
    )

    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    daily_limit_seconds: Mapped[int | None] = mapped_column(sa.Integer)
    timezone: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="UTC")
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    #: Higher wins when two policies cover the same instant.
    priority: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=100)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    revision: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    schedules: Mapped[list[ScreenTimeSchedule]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScreenTimeSchedule.weekday",
    )

    __table_args__ = (
        sa.Index("ix_screen_time_policies_child_profile_id_enabled", "child_profile_id", "enabled"),
        sa.Index("ix_screen_time_policies_family_id", "family_id"),
        sa.UniqueConstraint(
            "child_profile_id", "name", name="uq_screen_time_policies_child_profile_id_name"
        ),
        sa.CheckConstraint(
            "daily_limit_seconds IS NULL OR "
            "(daily_limit_seconds >= 0 AND daily_limit_seconds <= 86400)",
            name="daily_limit_in_range",
        ),
        sa.CheckConstraint("priority >= 0 AND priority <= 1000", name="priority_in_range"),
    )


class ScreenTimeSchedule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A recurring local-time window within a screen-time policy.

    ``end_local_time <= start_local_time`` is valid and means the window crosses
    midnight (a 21:00-07:00 bedtime). Overlap within a weekday is rejected by
    :mod:`app.services.policy_service`.
    """

    __tablename__ = "screen_time_schedules"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("screen_time_policies.id", ondelete="CASCADE"), nullable=False
    )
    weekday: Mapped[Weekday] = mapped_column(enum_column(Weekday, "weekday"), nullable=False)
    start_local_time: Mapped[time] = mapped_column(sa.Time(timezone=False), nullable=False)
    end_local_time: Mapped[time] = mapped_column(sa.Time(timezone=False), nullable=False)
    action: Mapped[ScheduleAction] = mapped_column(
        enum_column(ScheduleAction, "schedule_action"),
        nullable=False,
        default=ScheduleAction.block_all,
    )
    #: Packages exempt from this window (e.g. phone, messages, an education app).
    allowlisted_packages: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    policy: Mapped[ScreenTimePolicy] = relationship(back_populates="schedules")

    __table_args__ = (
        sa.Index("ix_screen_time_schedules_policy_id_weekday", "policy_id", "weekday"),
    )


class WebsiteRestriction(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Domain-level restriction.

    Gated behind ``FEATURE_WEBSITE_RESTRICTIONS_ENABLED``: the server stores the
    intent, but on Android there is no general, policy-compliant way to filter
    web content across all browsers, so this remains disabled until the Child
    App has a supported implementation (see docs/FEATURE_CAPABILITY_MATRIX.md).
    """

    __tablename__ = "website_restrictions"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    mode: Mapped[WebsiteRestrictionMode] = mapped_column(
        enum_column(WebsiteRestrictionMode, "website_restriction_mode"),
        nullable=False,
        default=WebsiteRestrictionMode.blocklist,
    )
    #: Registrable domain, lower-cased. No full URLs and no query strings, so
    #: the server never stores a browsing history.
    domain: Mapped[str] = mapped_column(sa.String(253), nullable=False)
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        sa.UniqueConstraint(
            "child_profile_id", "domain", name="uq_website_restrictions_child_profile_id_domain"
        ),
        sa.Index("ix_website_restrictions_family_id", "family_id"),
    )
