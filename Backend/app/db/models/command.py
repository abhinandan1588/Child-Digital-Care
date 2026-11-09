"""Durable device commands, delivery attempts, device events, outbox.

The reliability model (docs/COMMAND_DELIVERY.md):

1. The parent's mutation and the command row commit in one transaction.
2. The same transaction writes an ``outbox_events`` row.
3. A worker publishes the outbox row as a *content-free FCM wake-up*.
4. The device wakes, polls ``GET /device/commands``, acts, and reports back.

FCM is never the queue. Losing a push loses nothing: the command is still in
PostgreSQL waiting to be polled.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    CommandResult,
    CommandStatus,
    CommandType,
    DeliveryChannel,
    DeliveryOutcome,
    DeviceEventType,
    OutboxStatus,
)
from app.db.types import JSONBType, TZTimestamp, UUIDType, enum_column


class DeviceCommand(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A typed, allow-listed instruction for one device.

    ``command_type`` is constrained to :class:`CommandType`; the payload is
    validated by a per-type Pydantic model before the row is written. There is
    deliberately no generic ``execute``/``shell``/``capture`` type, and the
    payload is never interpreted as code on the device.
    """

    __tablename__ = "device_commands"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )

    command_type: Mapped[CommandType] = mapped_column(
        enum_column(CommandType, "command_type"), nullable=False
    )
    payload: Mapped[dict] = mapped_column(JSONBType, nullable=False, default=dict)
    status: Mapped[CommandStatus] = mapped_column(
        enum_column(CommandStatus, "command_status"), nullable=False, default=CommandStatus.queued
    )

    #: Supplied by the client (``Idempotency-Key``) or derived server-side for
    #: automatic commands, so a retried request cannot create a duplicate.
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    #: NULL for commands the server generated itself (e.g. a policy sync).
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    created_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="SET NULL")
    )

    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    delivery_attempt_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    first_delivery_attempt_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    delivered_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    fetched_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    acknowledged_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    completed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    cancelled_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    result: Mapped[CommandResult | None] = mapped_column(
        enum_column(CommandResult, "command_result")
    )
    applied_policy_version: Mapped[int | None] = mapped_column(sa.Integer)
    failure_code: Mapped[str | None] = mapped_column(sa.String(64))
    failure_message: Mapped[str | None] = mapped_column(sa.String(255))

    attempts: Mapped[list[DeviceCommandAttempt]] = relationship(
        back_populates="command", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id", "idempotency_key", name="uq_device_commands_device_id_idempotency_key"
        ),
        sa.Index("ix_device_commands_device_id_status", "device_id", "status"),
        sa.Index("ix_device_commands_family_id_created_at", "family_id", "created_at"),
        sa.Index("ix_device_commands_status_expires_at", "status", "expires_at"),
        sa.Index("ix_device_commands_child_profile_id", "child_profile_id"),
        sa.CheckConstraint("delivery_attempt_count >= 0", name="attempt_count_non_negative"),
    )


class DeviceCommandAttempt(UUIDPrimaryKeyMixin, Base):
    """One delivery attempt. Kept separate so retries are observable."""

    __tablename__ = "device_command_attempts"

    command_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("device_commands.id", ondelete="CASCADE"), nullable=False
    )
    attempt_number: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    channel: Mapped[DeliveryChannel] = mapped_column(
        enum_column(DeliveryChannel, "delivery_channel"), nullable=False
    )
    outcome: Mapped[DeliveryOutcome] = mapped_column(
        enum_column(DeliveryOutcome, "delivery_outcome"), nullable=False
    )
    provider_message_id: Mapped[str | None] = mapped_column(sa.String(128))
    #: Provider error *code*, never a raw provider payload.
    error_code: Mapped[str | None] = mapped_column(sa.String(64))
    attempted_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    command: Mapped[DeviceCommand] = relationship(back_populates="attempts")

    __table_args__ = (
        sa.UniqueConstraint(
            "command_id",
            "attempt_number",
            name="uq_device_command_attempts_command_id_attempt_number",
        ),
        sa.Index("ix_device_command_attempts_command_id", "command_id"),
    )


class OutboxEvent(UUIDPrimaryKeyMixin, Base):
    """Transactional outbox row.

    Written in the same transaction as the state change it describes, then
    published by :mod:`app.workers.tasks.outbox`. Publication is idempotent:
    a row only moves ``pending -> processing -> sent`` under a conditional
    UPDATE, so two workers cannot both publish it.
    """

    __tablename__ = "outbox_events"

    topic: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    aggregate_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False)
    family_id: Mapped[uuid.UUID | None] = mapped_column(UUIDType)
    #: Payload is metadata only: ids and status, never child telemetry or secrets.
    payload: Mapped[dict] = mapped_column(JSONBType, nullable=False, default=dict)

    status: Mapped[OutboxStatus] = mapped_column(
        enum_column(OutboxStatus, "outbox_status"), nullable=False, default=OutboxStatus.pending
    )
    attempts: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    locked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    locked_by: Mapped[str | None] = mapped_column(sa.String(64))
    processed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    last_error_code: Mapped[str | None] = mapped_column(sa.String(64))
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now(), index=True
    )

    __table_args__ = (
        sa.Index("ix_outbox_events_status_available_at", "status", "available_at"),
        sa.Index("ix_outbox_events_aggregate_type_aggregate_id", "aggregate_type", "aggregate_id"),
        sa.CheckConstraint("attempts >= 0", name="attempts_non_negative"),
    )


class DeviceEvent(UUIDPrimaryKeyMixin, Base):
    """A device-reported event.

    ``deduplication_key`` makes submission idempotent: the Child App can resend
    a batch after a network failure without creating duplicates.
    """

    __tablename__ = "device_events"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )

    event_type: Mapped[DeviceEventType] = mapped_column(
        enum_column(DeviceEventType, "device_event_type"), nullable=False
    )
    payload: Mapped[dict | None] = mapped_column(JSONBType)
    occurred_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    deduplication_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    #: Set when retention sweeps should remove the row.
    retention_expires_at: Mapped[datetime | None] = mapped_column(TZTimestamp, index=True)

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id", "deduplication_key", name="uq_device_events_device_id_deduplication_key"
        ),
        sa.Index("ix_device_events_family_id_occurred_at", "family_id", "occurred_at"),
        sa.Index("ix_device_events_device_id_occurred_at", "device_id", "occurred_at"),
        sa.Index("ix_device_events_event_type", "event_type"),
    )


class DeviceSyncCursor(UUIDPrimaryKeyMixin, Base):
    """Per-device synchronisation bookkeeping.

    Lets a device resume an interrupted usage upload and lets the server detect
    a device that has stopped syncing without relying on push receipts.
    """

    __tablename__ = "device_sync_cursors"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    cursor_key: Mapped[str] = mapped_column(sa.String(48), nullable=False)
    cursor_value: Mapped[str | None] = mapped_column(sa.String(128))
    updated_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id", "cursor_key", name="uq_device_sync_cursors_device_id_cursor_key"
        ),
    )
