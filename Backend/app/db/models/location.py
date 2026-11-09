"""Optional, gated location module.

This table only ever receives rows when **all** of the following hold:

* ``FEATURE_LOCATION_ENABLED=true`` for the deployment.
* A ``location_collection`` consent record exists and is ``granted``.
* The device reported the required Android permission as ``granted``.

There is no continuous or covert collection path: a sample is only accepted in
response to a ``request_location_update`` command or an explicitly consented
interval configured on the device, and every parent read is audited.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin
from app.db.enums import LocationSource
from app.db.types import TZTimestamp, UUIDType, enum_column


class LocationSample(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "location_samples"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    child_profile_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )

    #: Stored at reduced precision (see ``LOCATION_COORDINATE_PRECISION``) so a
    #: sample identifies an area, not an exact doorstep.
    latitude: Mapped[float] = mapped_column(sa.Float, nullable=False)
    longitude: Mapped[float] = mapped_column(sa.Float, nullable=False)
    accuracy_meters: Mapped[float | None] = mapped_column(sa.Float)
    source: Mapped[LocationSource] = mapped_column(
        enum_column(LocationSource, "location_source"),
        nullable=False,
        default=LocationSource.unknown,
    )

    recorded_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    #: Hard retention deadline; the retention worker deletes past this instant.
    retention_expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False, index=True)
    #: Links the sample to the consent record that authorised it.
    consent_record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("consent_records.id", ondelete="SET NULL")
    )
    #: Command that requested it, when applicable.
    requested_by_command_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("device_commands.id", ondelete="SET NULL")
    )
    deduplication_key: Mapped[str | None] = mapped_column(sa.String(128))

    __table_args__ = (
        sa.UniqueConstraint(
            "device_id", "deduplication_key", name="uq_location_samples_device_id_deduplication_key"
        ),
        sa.Index(
            "ix_location_samples_child_profile_id_recorded_at", "child_profile_id", "recorded_at"
        ),
        sa.Index("ix_location_samples_device_id_recorded_at", "device_id", "recorded_at"),
        sa.CheckConstraint("latitude >= -90 AND latitude <= 90", name="latitude_in_range"),
        sa.CheckConstraint("longitude >= -180 AND longitude <= 180", name="longitude_in_range"),
        sa.CheckConstraint(
            "accuracy_meters IS NULL OR accuracy_meters >= 0", name="accuracy_non_negative"
        ),
    )
