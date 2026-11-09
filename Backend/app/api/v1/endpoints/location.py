"""Parent-facing location endpoints (optional, gated, audited).

The whole module sits behind ``FEATURE_LOCATION_ENABLED``. When the feature is
off these routes return ``403 FEATURE_DISABLED``; they never return an empty
list that could be mistaken for "the child has not moved".
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import (
    ClientIp,
    DbSession,
    VerifiedParent,
    require_child_access,
    require_location_feature,
)
from app.core.config import settings
from app.core.permissions import FamilyPermission
from app.core.response import ApiResponse, ok
from app.db.models.family import ChildProfile
from app.schemas.location import (
    LocationDeviceStatus,
    LocationSampleOut,
    LocationStatusOut,
)
from app.services import device_service, family_service, location_service
from app.utils.time import utcnow

router = APIRouter(
    tags=["location"],
    dependencies=[Depends(require_location_feature)],
)

FamilyAccess = family_service.FamilyAccess
ChildContext = tuple[FamilyAccess, ChildProfile]
# Location requires its own family permission, which the default guardian grant
# does not include: it has to be given deliberately.
LocationRead = Annotated[
    ChildContext, Depends(require_child_access(FamilyPermission.LOCATION_READ))
]

MAX_HISTORY_SAMPLES = 500


def sample_out(row) -> LocationSampleOut:  # noqa: ANN001
    return LocationSampleOut(
        id=row.id,
        child_profile_id=row.child_profile_id,
        device_id=row.device_id,
        latitude=row.latitude,
        longitude=row.longitude,
        accuracy_meters=row.accuracy_meters,
        source=row.source,
        recorded_at=row.recorded_at,
        received_at=row.received_at,
        retention_expires_at=row.retention_expires_at,
    )


@router.get(
    "/children/{child_profile_id}/location/status",
    response_model=ApiResponse[LocationStatusOut],
    summary="Why location is or is not available",
)
async def location_status(session: DbSession, context: LocationRead) -> dict:
    """Explains the real state per device: feature flag, consent record, the
    device's reported capability, and its reported permission. No fabricated
    availability."""
    access, child = context
    consent = await location_service.family_consent(session, family_id=access.family_id)
    devices = await device_service.list_devices(
        session, family_ids=[access.family_id], child_profile_id=child.id
    )

    device_statuses: list[LocationDeviceStatus] = []
    availability = "unsupported"
    for device in devices:
        evaluation = await location_service.evaluate_availability(session, device=device)
        capabilities = await device_service.list_capabilities(session, device_id=device.id)
        permissions = await device_service.list_permissions(session, device_id=device.id)
        capability_state = next(
            (
                row.support.value
                for row in capabilities
                if row.capability_key in location_service.LOCATION_CAPABILITIES
            ),
            "unknown",
        )
        permission_state = next(
            (
                row.state.value
                for row in permissions
                if row.permission_key in location_service.LOCATION_PERMISSIONS
            ),
            "unknown",
        )
        latest = await location_service.latest_sample(session, child_profile_id=child.id)
        device_statuses.append(
            LocationDeviceStatus(
                device_id=device.id,
                device_label=device.device_label,
                capability_support=capability_state,
                permission_state=permission_state,
                last_sample_at=latest.recorded_at if latest else None,
            )
        )
        if evaluation.available:
            availability = "available"
        elif availability != "available" and evaluation.reason:
            availability = {
                location_service.LocationRejection.FEATURE_DISABLED: "feature_disabled",
                location_service.LocationRejection.CONSENT_MISSING: "consent_missing",
                location_service.LocationRejection.PERMISSION_NOT_GRANTED: "permission_denied",
                location_service.LocationRejection.CAPABILITY_UNSUPPORTED: "unsupported",
            }[evaluation.reason]

    return ok(
        LocationStatusOut(
            child_profile_id=child.id,
            feature_enabled=settings.feature_location_enabled,
            consent_state="granted" if consent else "missing",
            devices=device_statuses,
            availability=availability,
        )
    )


@router.get(
    "/children/{child_profile_id}/location/latest",
    response_model=ApiResponse[LocationSampleOut | None],
    summary="Most recent location sample",
)
async def latest_location(
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: LocationRead,
) -> dict:
    """Every read is written to the audit log, including when it returns
    nothing. Coordinates are stored rounded to roughly 110 m."""
    access, child = context
    await location_service.assert_consented(session, family_id=access.family_id)

    sample = await location_service.latest_sample(session, child_profile_id=child.id)
    await location_service.record_read_access(
        session,
        user_id=principal.id,
        family_id=access.family_id,
        child_profile_id=child.id,
        sample_count=1 if sample else 0,
        client_ip=client_ip,
    )
    return ok(
        sample_out(sample) if sample else None,
        message="Latest location." if sample else "No location has been reported.",
    )


@router.get(
    "/children/{child_profile_id}/location/history",
    response_model=ApiResponse[list[LocationSampleOut]],
    summary="Location history within the retention window",
)
async def location_history(
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: LocationRead,
    hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
    limit: Annotated[int, Query(ge=1, le=MAX_HISTORY_SAMPLES)] = 100,
) -> dict:
    """History is bounded by ``RETENTION_LOCATION_SAMPLES_DAYS``; older samples
    have been deleted, not hidden."""
    access, child = context
    await location_service.assert_consented(session, family_id=access.family_id)

    until = utcnow()
    since = until - timedelta(hours=hours)
    samples = await location_service.sample_history(
        session, child_profile_id=child.id, since=since, until=until, limit=limit
    )
    await location_service.record_read_access(
        session,
        user_id=principal.id,
        family_id=access.family_id,
        child_profile_id=child.id,
        sample_count=len(samples),
        client_ip=client_ip,
    )
    return ok(
        [sample_out(row) for row in samples],
        message=f"{len(samples)} sample(s).",
        retention_days=settings.retention_location_samples_days,
    )
