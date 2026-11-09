"""Device-reported usage summaries and parent-facing alerts.

Only *aggregates* are stored: per-day totals and per-package foreground
seconds. No message content, no keystrokes, no screenshots, no browsing
history, no per-launch timeline.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import AlertSeverity, AlertStatus, AlertType
from app.db.types import JSONBType, TZTimestamp, UUIDType, enum_column


class UsageDailySummary(UUIDPrimaryKeyMixin, Base):
    """One row per (device, local date).

    ``local_date`` is the date *on the device*, together with the timezone it
    was computed in, because a "Tuesday" total only means something relative to
    the child's own clock. Re-submission of the same day replaces the totals
    (upsert), which makes the Child App's retry logic trivial.
    """

    __tablename__ = "usage_daily_summaries"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )

    local_date: Mapped[date] = mapped_column(sa.Date, nullable=False)
    timezone: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    total_screen_time_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    unlock_count: Mapped[int | None] = mapped_column(sa.Integer)
    #: {"social": 1200, "games": 900, ...} - seconds per UsageCategory.
    category_totals: Mapped[dict] = mapped_column(JSONBType, nullable=False, default=dict)

    source_app_version: Mapped[str | None] = mapped_column(sa.String(32))
    received_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    retention_expires_at: Mapped[datetime | None] = mapped_column(TZTimestamp, index=True)

    app_summaries: Mapped[list[AppUsageSummary]] = relationship(
        back_populates="daily_summary", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id", "local_date", name="uq_usage_daily_summaries_device_id_local_date"
        ),
        sa.Index(
            "ix_usage_daily_summaries_child_profile_id_local_date",
            "child_profile_id",
            "local_date",
        ),
        sa.Index("ix_usage_daily_summaries_family_id_local_date", "family_id", "local_date"),
        sa.CheckConstraint(
            "total_screen_time_seconds >= 0 AND total_screen_time_seconds <= 86400",
            name="total_screen_time_plausible",
        ),
        sa.CheckConstraint(
            "unlock_count IS NULL OR (unlock_count >= 0 AND unlock_count <= 5000)",
            name="unlock_count_plausible",
        ),
    )


class AppUsageSummary(UUIDPrimaryKeyMixin, Base):
    """Per-package foreground time inside one daily summary."""

    __tablename__ = "app_usage_summaries"

    daily_summary_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("usage_daily_summaries.id", ondelete="CASCADE"), nullable=False
    )
    package_identifier: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    display_label: Mapped[str | None] = mapped_column(sa.String(120))
    category: Mapped[str | None] = mapped_column(sa.String(40))
    foreground_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    launch_count: Mapped[int | None] = mapped_column(sa.Integer)

    daily_summary: Mapped[UsageDailySummary] = relationship(back_populates="app_summaries")

    __table_args__ = (
        sa.UniqueConstraint(
            "daily_summary_id",
            "package_identifier",
            name="uq_app_usage_summaries_daily_summary_id_package_identifier",
        ),
        sa.Index("ix_app_usage_summaries_daily_summary_id", "daily_summary_id"),
        sa.CheckConstraint(
            "foreground_seconds >= 0 AND foreground_seconds <= 86400",
            name="foreground_seconds_plausible",
        ),
    )


class Alert(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A parent-facing alert.

    ``deduplication_key`` prevents an offline device from generating a new
    alert on every poll cycle.
    """

    __tablename__ = "alerts"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE")
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE")
    )

    alert_type: Mapped[AlertType] = mapped_column(
        enum_column(AlertType, "alert_type"), nullable=False
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        enum_column(AlertSeverity, "alert_severity"), nullable=False, default=AlertSeverity.info
    )
    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus, "alert_status"), nullable=False, default=AlertStatus.open
    )
    title: Mapped[str] = mapped_column(sa.String(120), nullable=False)
    message: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    #: Safe context only (ids, counts, status strings).
    alert_metadata: Mapped[dict | None] = mapped_column(JSONBType)

    occurred_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    acknowledged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    deduplication_key: Mapped[str | None] = mapped_column(sa.String(160))

    __table_args__ = (
        sa.UniqueConstraint(
            "family_id", "deduplication_key", name="uq_alerts_family_id_deduplication_key"
        ),
        sa.Index("ix_alerts_family_id_status_occurred_at", "family_id", "status", "occurred_at"),
        sa.Index("ix_alerts_child_profile_id", "child_profile_id"),
        sa.Index("ix_alerts_device_id", "device_id"),
    )
