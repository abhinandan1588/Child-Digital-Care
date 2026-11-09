"""Optional, consent-gated location module.

Every write passes four independent gates, and the first failure is reported
honestly rather than silently dropping the sample:

1. ``FEATURE_LOCATION_ENABLED`` for the deployment.
2. A ``granted``, un-revoked ``location_collection`` consent record for the family.
3. A device capability report saying coarse/fine location is supported.
4. A device permission report saying the permission is granted.

Reads are tightly scoped (family membership plus the ``location.read`` family
permission) and every read is written to the audit log. Ordinary admin roles
have no access at all: that needs ``child_location.read``, which no default
role carries.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import ErrorCode, FeatureDisabled, PermissionDenied
from app.core.logging import get_logger
from app.db.enums import (
    AuditActorType,
    CapabilityKey,
    CapabilitySupport,
    ConsentState,
    ConsentType,
    LocationSource,
    PermissionKey,
    PermissionState,
)
from app.db.models.audit import ConsentRecord
from app.db.models.device import Device, DeviceCapability, DevicePermissionReport
from app.db.models.location import LocationSample
from app.repositories.base import rowcount_of
from app.schemas.location import LOCATION_COORDINATE_PRECISION
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.utils.time import utcnow

logger = get_logger(__name__)

LOCATION_CAPABILITIES = (CapabilityKey.location_fine, CapabilityKey.location_coarse)
LOCATION_PERMISSIONS = (PermissionKey.location_fine, PermissionKey.location_coarse)


class LocationRejection:
    FEATURE_DISABLED = "FEATURE_DISABLED"
    CONSENT_MISSING = "CONSENT_MISSING"
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    PERMISSION_NOT_GRANTED = "PERMISSION_NOT_GRANTED"


@dataclass(frozen=True, slots=True)
class LocationAvailability:
    available: bool
    reason: str | None
    consent_state: str
    consent_record_id: uuid.UUID | None


def round_coordinate(value: float) -> float:
    """Reduce precision before storage.

    Three decimal places is roughly 110 m. A parent needs "which part of town",
    and storing a doorstep-accurate fix would increase harm from a breach
    without improving the product.
    """
    return round(value, LOCATION_COORDINATE_PRECISION)


async def family_consent(session: AsyncSession, *, family_id: uuid.UUID) -> ConsentRecord | None:
    result = await session.execute(
        select(ConsentRecord)
        .where(
            ConsentRecord.family_id == family_id,
            ConsentRecord.consent_type == ConsentType.location_collection,
            ConsentRecord.state == ConsentState.granted,
            ConsentRecord.revoked_at.is_(None),
        )
        .order_by(ConsentRecord.recorded_at.desc())
        .limit(1)
    )
    return result.scalars().first()


async def evaluate_availability(session: AsyncSession, *, device: Device) -> LocationAvailability:
    if not settings.feature_location_enabled:
        return LocationAvailability(
            False, LocationRejection.FEATURE_DISABLED, "not_applicable", None
        )

    consent = await family_consent(session, family_id=device.family_id)
    if consent is None:
        return LocationAvailability(False, LocationRejection.CONSENT_MISSING, "missing", None)

    capability_rows = (
        (
            await session.execute(
                select(DeviceCapability).where(
                    DeviceCapability.device_id == device.id,
                    DeviceCapability.capability_key.in_(LOCATION_CAPABILITIES),
                )
            )
        )
        .scalars()
        .all()
    )
    if not any(row.support is CapabilitySupport.supported for row in capability_rows):
        return LocationAvailability(
            False, LocationRejection.CAPABILITY_UNSUPPORTED, "granted", consent.id
        )

    permission_rows = (
        (
            await session.execute(
                select(DevicePermissionReport).where(
                    DevicePermissionReport.device_id == device.id,
                    DevicePermissionReport.permission_key.in_(LOCATION_PERMISSIONS),
                )
            )
        )
        .scalars()
        .all()
    )
    if not any(row.state is PermissionState.granted for row in permission_rows):
        return LocationAvailability(
            False, LocationRejection.PERMISSION_NOT_GRANTED, "granted", consent.id
        )

    return LocationAvailability(True, None, "granted", consent.id)


@dataclass(frozen=True, slots=True)
class SubmitOutcome:
    accepted: bool
    sample: LocationSample | None
    duplicate: bool
    rejection_code: str | None


async def submit_sample(
    session: AsyncSession,
    *,
    device: Device,
    latitude: float,
    longitude: float,
    accuracy_meters: float | None,
    source: LocationSource,
    recorded_at: datetime,
    deduplication_key: str | None,
    command_id: uuid.UUID | None,
) -> SubmitOutcome:
    availability = await evaluate_availability(session, device=device)
    if not availability.available:
        logger.info(
            "location_sample_rejected",
            device_id=str(device.id),
            reason=availability.reason,
        )
        return SubmitOutcome(False, None, False, availability.reason)

    if deduplication_key:
        existing = await session.execute(
            select(LocationSample)
            .where(
                LocationSample.device_id == device.id,
                LocationSample.deduplication_key == deduplication_key,
            )
            .limit(1)
        )
        duplicate = existing.scalars().first()
        if duplicate is not None:
            return SubmitOutcome(True, duplicate, True, None)

    sample = LocationSample(
        family_id=device.family_id,
        child_profile_id=device.child_profile_id,
        device_id=device.id,
        latitude=round_coordinate(latitude),
        longitude=round_coordinate(longitude),
        accuracy_meters=accuracy_meters,
        source=source,
        recorded_at=recorded_at,
        retention_expires_at=utcnow() + timedelta(days=settings.retention_location_samples_days),
        consent_record_id=availability.consent_record_id,
        requested_by_command_id=command_id,
        deduplication_key=deduplication_key[:128] if deduplication_key else None,
    )
    session.add(sample)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        return SubmitOutcome(True, None, True, None)

    device.last_seen_at = utcnow()
    await audit_service.record(
        session,
        action=AuditAction.LOCATION_SAMPLE_ACCEPTED,
        actor_type=AuditActorType.child_device,
        actor_id=device.id,
        target_type="location_sample",
        target_id=sample.id,
        family_id=device.family_id,
        # Deliberately no coordinates in the audit metadata.
        metadata={"source": source.value, "command_driven": command_id is not None},
    )
    return SubmitOutcome(True, sample, False, None)


async def latest_sample(
    session: AsyncSession, *, child_profile_id: uuid.UUID
) -> LocationSample | None:
    result = await session.execute(
        select(LocationSample)
        .where(LocationSample.child_profile_id == child_profile_id)
        .order_by(LocationSample.recorded_at.desc())
        .limit(1)
    )
    return result.scalars().first()


async def sample_history(
    session: AsyncSession,
    *,
    child_profile_id: uuid.UUID,
    since: datetime,
    until: datetime,
    limit: int,
) -> list[LocationSample]:
    result = await session.execute(
        select(LocationSample)
        .where(
            LocationSample.child_profile_id == child_profile_id,
            LocationSample.recorded_at >= since,
            LocationSample.recorded_at <= until,
        )
        .order_by(LocationSample.recorded_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def record_read_access(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    family_id: uuid.UUID,
    child_profile_id: uuid.UUID,
    sample_count: int,
    client_ip: str | None,
) -> None:
    """Audit every location read.

    Reads of a child's location are exactly the kind of access that must be
    reviewable after the fact, including by the family itself.
    """
    await audit_service.record(
        session,
        action=AuditAction.LOCATION_READ,
        actor_type=AuditActorType.parent_user,
        actor_id=user_id,
        target_type="child_profile",
        target_id=child_profile_id,
        family_id=family_id,
        client_ip=client_ip,
        metadata={"sample_count": sample_count},
    )


def assert_enabled() -> None:
    if not settings.feature_location_enabled:
        raise FeatureDisabled(
            "Location features are not enabled for this deployment.",
        )


async def assert_consented(session: AsyncSession, *, family_id: uuid.UUID) -> ConsentRecord:
    consent = await family_consent(session, family_id=family_id)
    if consent is None:
        raise PermissionDenied(
            "Location collection has not been consented to for this family.",
            code=ErrorCode.PERMISSION_STATE_BLOCKS_ACTION,
        )
    return consent


async def purge_expired(session: AsyncSession, *, limit: int = 2000) -> int:
    """Hard-delete samples past their retention deadline."""
    now = utcnow()
    result = await session.execute(
        select(LocationSample.id).where(LocationSample.retention_expires_at <= now).limit(limit)
    )
    ids = [row[0] for row in result.all()]
    if not ids:
        return 0
    await session.execute(delete(LocationSample).where(LocationSample.id.in_(ids)))
    return len(ids)


async def purge_for_family(session: AsyncSession, *, family_id: uuid.UUID) -> int:
    """Delete all samples for a family (consent revoked, or deletion request)."""
    result = await session.execute(
        delete(LocationSample).where(LocationSample.family_id == family_id)
    )
    return rowcount_of(result)
