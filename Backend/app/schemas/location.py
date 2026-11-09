"""Location schemas for the optional, consent-gated location module."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator

from app.db.enums import LocationSource
from app.schemas.common import OutSchema, SchemaBase
from app.utils.time import utcnow

#: Coordinates are rounded to 3 decimal places (~110 m) before storage. A
#: parent needs "which part of town", not a doorstep-accurate fix.
LOCATION_COORDINATE_PRECISION = 3
MAX_LOCATION_AGE_HOURS = 24


class LocationSubmit(SchemaBase):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    accuracy_meters: float | None = Field(default=None, ge=0, le=100_000)
    source: LocationSource = LocationSource.unknown
    recorded_at: datetime
    deduplication_key: str | None = Field(default=None, min_length=8, max_length=128)
    #: The command that asked for this fix, when it was command-driven.
    command_id: uuid.UUID | None = None

    @field_validator("recorded_at")
    @classmethod
    def _plausible(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("recorded_at must include a timezone offset.")
        now = utcnow()
        if (value - now).total_seconds() > 300:
            raise ValueError("recorded_at is in the future.")
        if (now - value).total_seconds() > MAX_LOCATION_AGE_HOURS * 3600:
            raise ValueError("recorded_at is too old to accept.")
        return value


class LocationAcceptedOut(OutSchema):
    accepted: bool
    sample_id: uuid.UUID | None = None
    duplicate: bool = False
    retention_expires_at: datetime | None = None
    #: Set when the sample was rejected, e.g. feature disabled or consent absent.
    rejection_code: str | None = None


class LocationSampleOut(OutSchema):
    id: uuid.UUID
    child_profile_id: uuid.UUID
    device_id: uuid.UUID
    latitude: float
    longitude: float
    accuracy_meters: float | None
    source: LocationSource
    recorded_at: datetime
    received_at: datetime
    retention_expires_at: datetime
    coordinate_precision_decimals: int = LOCATION_COORDINATE_PRECISION


class LocationStatusOut(OutSchema):
    """Why location is or is not available, without fabricating data."""

    child_profile_id: uuid.UUID
    feature_enabled: bool
    consent_state: str
    devices: list[LocationDeviceStatus] = Field(default_factory=list)
    availability: str = Field(
        description=(
            "One of: available, feature_disabled, consent_missing, permission_denied, unsupported."
        )
    )


class LocationDeviceStatus(OutSchema):
    device_id: uuid.UUID
    device_label: str
    capability_support: str
    permission_state: str
    last_sample_at: datetime | None = None


LocationStatusOut.model_rebuild()
