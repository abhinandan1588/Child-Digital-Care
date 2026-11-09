"""Alert and device-event schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator

from app.db.enums import AlertSeverity, AlertStatus, AlertType, DeviceEventType
from app.schemas.common import OutSchema, SchemaBase
from app.utils.time import utcnow

MAX_EVENTS_PER_BATCH = 100
#: Events timestamped further ahead than this are clamped: a device with a
#: skewed clock should not be able to insert events "in the future".
MAX_CLOCK_SKEW_SECONDS = 300


class AlertOut(OutSchema):
    id: uuid.UUID
    family_id: uuid.UUID
    child_profile_id: uuid.UUID | None
    device_id: uuid.UUID | None
    alert_type: AlertType
    severity: AlertSeverity
    status: AlertStatus
    title: str
    message: str
    occurred_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime
    metadata: dict | None = Field(default=None, validation_alias="alert_metadata")


class AlertUpdate(SchemaBase):
    status: AlertStatus

    @field_validator("status")
    @classmethod
    def _allowed(cls, value: AlertStatus) -> AlertStatus:
        if value is AlertStatus.open:
            raise ValueError("An alert cannot be reopened.")
        return value


class DeviceEventItem(SchemaBase):
    event_type: DeviceEventType
    occurred_at: datetime
    #: Must be stable for the same logical event so retries de-duplicate.
    deduplication_key: str = Field(min_length=8, max_length=128)
    payload: dict | None = Field(
        default=None,
        description=(
            "Safe context only: package identifiers, counts, enum values. "
            "Never message content, keystrokes, screenshots or coordinates."
        ),
    )

    @field_validator("occurred_at")
    @classmethod
    def _not_far_future(cls, value: datetime) -> datetime:
        now = utcnow()
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone offset.")
        if (value - now).total_seconds() > MAX_CLOCK_SKEW_SECONDS:
            raise ValueError("occurred_at is too far in the future.")
        return value


class DeviceEventBatch(SchemaBase):
    events: list[DeviceEventItem] = Field(min_length=1, max_length=MAX_EVENTS_PER_BATCH)


class DeviceEventIngestResult(OutSchema):
    accepted: int
    duplicates: int
    alerts_created: int
    received_at: datetime


class DeviceEventOut(OutSchema):
    id: uuid.UUID
    device_id: uuid.UUID
    child_profile_id: uuid.UUID
    event_type: DeviceEventType
    occurred_at: datetime
    received_at: datetime
    payload: dict | None
