"""Push tokens, notification preferences, delivery records."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    DevicePlatform,
    NotificationDeliveryStatus,
    NotificationType,
)
from app.db.types import JSONBType, TZTimestamp, UUIDType, enum_column


class PushToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An FCM registration token owned by exactly one principal.

    The raw token is a routing credential: anyone holding it can be targeted,
    and it identifies an install. Only a SHA-256 ``token_hash`` is indexed and
    logged; ``token_value`` holds the token needed to actually call FCM and is
    excluded from every API response and log line.
    """

    __tablename__ = "push_tokens"

    #: Exactly one of these is set; enforced by a CHECK constraint.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="CASCADE")
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE")
    )

    token_value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    platform: Mapped[DevicePlatform] = mapped_column(
        enum_column(DevicePlatform, "device_platform"), nullable=False
    )
    app_version: Mapped[str | None] = mapped_column(sa.String(32))
    active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    last_success_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    deactivated_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    deactivated_reason: Mapped[str | None] = mapped_column(sa.String(64))

    __table_args__ = (
        sa.UniqueConstraint("token_hash", name="uq_push_tokens_token_hash"),
        sa.Index("ix_push_tokens_user_id_active", "user_id", "active"),
        sa.Index("ix_push_tokens_device_id_active", "device_id", "active"),
        sa.CheckConstraint(
            "(user_id IS NOT NULL AND device_id IS NULL) OR "
            "(user_id IS NULL AND device_id IS NOT NULL)",
            name="exactly_one_owner",
        ),
    )


class NotificationPreference(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Per-user, per-type notification preference with optional quiet hours.

    Security notifications are never suppressed; the service layer enforces
    that regardless of what is stored here.
    """

    __tablename__ = "notification_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    notification_type: Mapped[NotificationType] = mapped_column(
        enum_column(NotificationType, "notification_type"), nullable=False
    )
    enabled: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    #: {"timezone": "Europe/London", "start": "22:00", "end": "07:00"}
    quiet_hours: Mapped[dict | None] = mapped_column(JSONBType)

    __table_args__ = (
        sa.UniqueConstraint(
            "user_id",
            "notification_type",
            name="uq_notification_preferences_user_id_notification_type",
        ),
    )


class NotificationDelivery(UUIDPrimaryKeyMixin, Base):
    """Audit/observability record for one attempted notification.

    Stores the notification *type* and provider status only. Push payloads are
    content-free by design, and nothing child-identifying is recorded here.
    """

    __tablename__ = "notification_deliveries"

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="SET NULL")
    )
    push_token_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("push_tokens.id", ondelete="SET NULL")
    )

    notification_type: Mapped[NotificationType] = mapped_column(
        enum_column(NotificationType, "notification_type"), nullable=False
    )
    status: Mapped[NotificationDeliveryStatus] = mapped_column(
        enum_column(NotificationDeliveryStatus, "notification_delivery_status"),
        nullable=False,
        default=NotificationDeliveryStatus.queued,
    )
    provider_message_id: Mapped[str | None] = mapped_column(sa.String(128))
    error_code: Mapped[str | None] = mapped_column(sa.String(64))
    #: Correlates a wake-up push with the command that triggered it.
    related_command_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("device_commands.id", ondelete="SET NULL")
    )

    attempted_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now(), index=True
    )
    delivered_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    __table_args__ = (
        sa.Index("ix_notification_deliveries_user_id_attempted_at", "user_id", "attempted_at"),
        sa.Index("ix_notification_deliveries_device_id_attempted_at", "device_id", "attempted_at"),
        sa.Index("ix_notification_deliveries_status", "status"),
    )


class WebSocketConnection(UUIDPrimaryKeyMixin, Base):
    """Optional durable record of an open realtime connection.

    A connection is *not* an identity: authorization is re-evaluated per
    subscription. This table exists only for operational visibility (how many
    clients are attached to which instance) and is safe to truncate.
    """

    __tablename__ = "websocket_connections"

    principal_type: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="CASCADE")
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE")
    )
    family_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE")
    )
    instance_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    connected_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    last_ping_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    disconnected_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    __table_args__ = (
        sa.Index(
            "ix_websocket_connections_family_id_disconnected_at", "family_id", "disconnected_at"
        ),
        sa.Index("ix_websocket_connections_instance_id", "instance_id"),
    )
