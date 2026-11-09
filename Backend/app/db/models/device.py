"""Child devices, device sessions, pairing invitations, capability reports."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    CapabilityKey,
    CapabilitySupport,
    DevicePlatform,
    DeviceStatus,
    PairingInvitationStatus,
    PermissionKey,
    PermissionState,
    SyncStatus,
)
from app.db.types import JSONBType, TZTimestamp, UUIDType, enum_column

if TYPE_CHECKING:
    from app.db.models.family import ChildProfile


class Device(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A paired child device.

    One child profile may have several devices. Device-reported fields
    (``os_version``, ``last_seen_at``, ``applied_policy_version``) are exactly
    that - reported, not verified - and the API labels them accordingly.
    """

    __tablename__ = "devices"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )

    platform: Mapped[DevicePlatform] = mapped_column(
        enum_column(DevicePlatform, "device_platform"),
        nullable=False,
        default=DevicePlatform.android,
    )
    device_label: Mapped[str] = mapped_column(sa.String(80), nullable=False, default="Child device")
    app_version: Mapped[str | None] = mapped_column(sa.String(32))
    os_version: Mapped[str | None] = mapped_column(sa.String(48))
    #: Coarse model/manufacturer only. No hardware serial, IMEI or ad id.
    device_model: Mapped[str | None] = mapped_column(sa.String(80))
    manufacturer: Mapped[str | None] = mapped_column(sa.String(80))
    #: Client-generated install id, used purely to make registration idempotent.
    install_id: Mapped[str | None] = mapped_column(sa.String(64))

    device_status: Mapped[DeviceStatus] = mapped_column(
        enum_column(DeviceStatus, "device_status"),
        nullable=False,
        default=DeviceStatus.pending_registration,
    )
    timezone: Mapped[str] = mapped_column(sa.String(64), nullable=False, default="UTC")

    registered_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    last_seen_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    revoked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    revoked_reason: Mapped[str | None] = mapped_column(sa.String(120))
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )

    #: Policy synchronisation state, only advanced by device acknowledgements.
    applied_policy_version: Mapped[int | None] = mapped_column(sa.Integer)
    policy_sync_status: Mapped[SyncStatus] = mapped_column(
        enum_column(SyncStatus, "sync_status"), nullable=False, default=SyncStatus.pending_sync
    )
    policy_sync_detail: Mapped[str | None] = mapped_column(sa.String(255))
    policy_synced_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    child_profile: Mapped[ChildProfile] = relationship(back_populates="devices")
    capabilities: Mapped[list[DeviceCapability]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        sa.Index("ix_devices_family_id_device_status", "family_id", "device_status"),
        sa.Index("ix_devices_child_profile_id_device_status", "child_profile_id", "device_status"),
        sa.Index("ix_devices_last_seen_at", "last_seen_at"),
        sa.UniqueConstraint(
            "child_profile_id", "install_id", name="uq_devices_child_profile_id_install_id"
        ),
    )

    @property
    def is_active(self) -> bool:
        return self.device_status is DeviceStatus.active and self.revoked_at is None


class DeviceSession(UUIDPrimaryKeyMixin, Base):
    """Refresh-token session for a device principal.

    Same rotation/reuse-detection design as :class:`UserSession`. A device
    refresh token is long-lived because a child device cannot be asked to
    re-enter a password, which is exactly why reuse detection and parent-side
    revocation matter.
    """

    __tablename__ = "device_sessions"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    refresh_token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    token_family_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False)
    rotation_counter: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)

    app_version: Mapped[str | None] = mapped_column(sa.String(32))
    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    revoked_reason: Mapped[str | None] = mapped_column(sa.String(64))
    last_used_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    device: Mapped[Device] = relationship()

    __table_args__ = (
        sa.UniqueConstraint("refresh_token_hash", name="uq_device_sessions_refresh_token_hash"),
        sa.Index("ix_device_sessions_device_id_revoked_at", "device_id", "revoked_at"),
        sa.Index("ix_device_sessions_token_family_id", "token_family_id"),
    )


class PairingInvitation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single-use, short-lived invitation that a child device claims.

    Security properties enforced by :mod:`app.services.pairing_service`:
    256-bit random token stored only as a SHA-256 hash, short expiry, single
    use via a conditional UPDATE (so two simultaneous claims cannot both win),
    per-token and per-IP attempt throttling, and parent-side revocation.
    """

    __tablename__ = "pairing_invitations"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Optional human-transcribable code; hashed, never stored in the clear.
    short_code_hash: Mapped[str | None] = mapped_column(sa.String(64))
    #: Non-secret display prefix so a parent can tell two invitations apart.
    short_code_prefix: Mapped[str | None] = mapped_column(sa.String(4))

    status: Mapped[PairingInvitationStatus] = mapped_column(
        enum_column(PairingInvitationStatus, "pairing_invitation_status"),
        nullable=False,
        default=PairingInvitationStatus.pending,
    )
    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    claimed_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="SET NULL")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    attempt_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    disclosure_version: Mapped[str | None] = mapped_column(sa.String(32))

    __table_args__ = (
        sa.UniqueConstraint("token_hash", name="uq_pairing_invitations_token_hash"),
        sa.UniqueConstraint("short_code_hash", name="uq_pairing_invitations_short_code_hash"),
        sa.Index("ix_pairing_invitations_family_id_status", "family_id", "status"),
        sa.Index("ix_pairing_invitations_child_profile_id_status", "child_profile_id", "status"),
        sa.Index("ix_pairing_invitations_expires_at_status", "expires_at", "status"),
        sa.CheckConstraint("attempt_count >= 0", name="attempt_count_non_negative"),
    )


class DeviceCapability(UUIDPrimaryKeyMixin, Base):
    """What the device says it can do.

    The server never assumes a capability exists. If a device has not reported
    a capability, policies that depend on it are surfaced as ``unsupported``
    rather than silently treated as applied.
    """

    __tablename__ = "device_capabilities"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    capability_key: Mapped[CapabilityKey] = mapped_column(
        enum_column(CapabilityKey, "capability_key"), nullable=False
    )
    support: Mapped[CapabilitySupport] = mapped_column(
        enum_column(CapabilitySupport, "capability_support"),
        nullable=False,
        default=CapabilitySupport.unknown,
    )
    permission_state: Mapped[PermissionState] = mapped_column(
        enum_column(PermissionState, "permission_state"),
        nullable=False,
        default=PermissionState.unknown,
    )
    app_version: Mapped[str | None] = mapped_column(sa.String(32))
    os_api_level: Mapped[int | None] = mapped_column(sa.SmallInteger)
    reported_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    capability_metadata: Mapped[dict | None] = mapped_column(JSONBType)

    device: Mapped[Device] = relationship(back_populates="capabilities")

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id", "capability_key", name="uq_device_capabilities_device_id_capability_key"
        ),
        sa.Index("ix_device_capabilities_device_id", "device_id"),
    )


class DevicePermissionReport(UUIDPrimaryKeyMixin, Base):
    """Current state of an Android permission, as last reported by the device.

    One row per (device, permission): the latest state. Historical transitions
    are recorded as ``device_events`` instead, so this table stays small.
    """

    __tablename__ = "device_permission_reports"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    permission_key: Mapped[PermissionKey] = mapped_column(
        enum_column(PermissionKey, "permission_key"), nullable=False
    )
    state: Mapped[PermissionState] = mapped_column(
        enum_column(PermissionState, "permission_state"), nullable=False
    )
    app_version: Mapped[str | None] = mapped_column(sa.String(32))
    reported_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    #: Why the state matters to the user, e.g. which features are degraded.
    explanatory_metadata: Mapped[dict | None] = mapped_column(JSONBType)

    device: Mapped[Device] = relationship()

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id",
            "permission_key",
            name="uq_device_permission_reports_device_id_permission_key",
        ),
        sa.Index("ix_device_permission_reports_device_id", "device_id"),
    )
