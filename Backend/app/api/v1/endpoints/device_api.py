"""The complete Child App surface.

Every route here authenticates as a **device principal**. A device can only
ever read and write its own records: the device id comes from the verified
token, never from the request, so there is no parameter a device could tamper
with to reach another device's data.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from app.api.deps import (
    ActiveDevice,
    ClientIp,
    CurrentDevice,
    DbSession,
    require_location_feature,
)
from app.core.rate_limit import RateLimit
from app.core.response import ApiResponse, ok
from app.core.security import hash_opaque_token
from app.db.enums import AuditActorType, DeliveryChannel, DeliveryOutcome
from app.db.models.family import ChildProfile
from app.schemas.alert import DeviceEventBatch, DeviceEventIngestResult
from app.schemas.auth import DeviceMeOut, DeviceRefreshRequest, DeviceTokenPair, GenericMessageOut
from app.schemas.command import (
    CommandAcknowledgeRequest,
    CommandResultRequest,
    CommandStateChangeOut,
    DeviceCommandListOut,
    DeviceCommandOut,
)
from app.schemas.device import (
    CapabilityReportRequest,
    DeviceHeartbeatRequest,
    DeviceHeartbeatResponse,
    DeviceRegisterRequest,
    PermissionReportRequest,
)
from app.schemas.location import LocationAcceptedOut, LocationSubmit
from app.schemas.notification import PushTokenDelete, PushTokenOut, PushTokenRegister
from app.schemas.policy import DevicePolicySnapshot
from app.schemas.usage import DailySummaryBatchSubmit, DailySummarySubmit, UsageIngestResult
from app.services import (
    alert_service,
    audit_service,
    command_service,
    device_service,
    location_service,
    notification_service,
    policy_service,
    token_service,
    usage_service,
)
from app.services.audit_service import AuditAction
from app.utils.time import utcnow

router = APIRouter(prefix="/device", tags=["device"])
auth_router = APIRouter(prefix="/device-auth", tags=["device-auth"])


async def _child_of(session, device) -> ChildProfile:  # noqa: ANN001
    child = await session.get(ChildProfile, device.child_profile_id)
    if child is None:  # pragma: no cover - FK guarantees this
        from app.core.errors import NotFound

        raise NotFound("Child profile not found.")
    return child


# ---------------------------------------------------------------------------
# Device authentication
# ---------------------------------------------------------------------------
@auth_router.post(
    "/refresh",
    response_model=ApiResponse[DeviceTokenPair],
    summary="Rotate the device credential",
)
async def refresh_device_token(
    payload: DeviceRefreshRequest, session: DbSession, client_ip: ClientIp
) -> dict:
    """Rotate the device session.

    The presented refresh token is consumed. Replaying it revokes the whole
    token family, which is how a cloned or extracted credential is contained.
    The Child App must store these in Android Keystore-backed storage, never in
    plain SharedPreferences.
    """
    # The family claim is re-read from the device row inside the service, so a
    # token cannot keep working after the device is moved or re-paired.
    from sqlalchemy import select

    from app.core.errors import AuthenticationRequired, ErrorCode
    from app.db.models.device import Device, DeviceSession

    lookup = await session.execute(
        select(DeviceSession)
        .where(DeviceSession.refresh_token_hash == hash_opaque_token(payload.device_refresh_token))
        .limit(1)
    )
    row = lookup.scalars().first()
    if row is None:
        raise AuthenticationRequired(
            "The device credential is not valid.", code=ErrorCode.TOKEN_INVALID
        )
    device = await session.get(Device, row.device_id)
    if device is None:
        raise AuthenticationRequired(
            "The device credential is not valid.", code=ErrorCode.TOKEN_INVALID
        )

    outcome = await token_service.rotate_device_session(
        session,
        raw_refresh_token=payload.device_refresh_token,
        family_id_claim=device.family_id,
        app_version=payload.app_version,
    )
    await audit_service.record(
        session,
        action=AuditAction.DEVICE_TOKEN_REFRESHED,
        actor_type=AuditActorType.child_device,
        actor_id=device.id,
        target_type="device_session",
        target_id=outcome.issued.session_id,
        family_id=device.family_id,
        client_ip=client_ip,
    )
    return ok(
        DeviceTokenPair(
            device_access_token=outcome.issued.access_token,
            device_refresh_token=outcome.issued.refresh_token,
            expires_in=outcome.issued.expires_in,
            refresh_expires_in=outcome.issued.refresh_expires_in,
        ),
        message="Device credential rotated.",
    )


@auth_router.post(
    "/logout",
    response_model=ApiResponse[GenericMessageOut],
    summary="End this device session",
)
async def device_logout(
    payload: DeviceRefreshRequest, principal: CurrentDevice, session: DbSession
) -> dict:
    """Ends the presented session only. A device cannot unlink itself from the
    family: that is a parent action, so a child cannot end supervision from the
    device."""
    revoked = await token_service.revoke_device_session_by_token(
        session, raw_refresh_token=payload.device_refresh_token, reason="device_logout"
    )
    return ok(
        GenericMessageOut(detail="Session ended." if revoked else "Session already inactive."),
        message="Request processed.",
    )


@auth_router.get(
    "/me",
    response_model=ApiResponse[DeviceMeOut],
    summary="Who this device credential belongs to",
)
async def device_me(principal: CurrentDevice, session: DbSession) -> dict:
    child = await _child_of(session, principal.device)
    return ok(
        DeviceMeOut(
            device_id=principal.device.id,
            child_profile_id=principal.device.child_profile_id,
            family_id=principal.device.family_id,
            device_label=principal.device.device_label,
            device_status=principal.device.device_status.value,
            policy_version=child.policy_version,
            applied_policy_version=principal.device.applied_policy_version,
            policy_sync_status=principal.device.policy_sync_status.value,
            server_time=utcnow(),
        )
    )


# ---------------------------------------------------------------------------
# Registration, heartbeat, capability reports
# ---------------------------------------------------------------------------
@router.post(
    "/register",
    response_model=ApiResponse[DeviceHeartbeatResponse],
    summary="Complete or refresh device registration",
)
async def register_device(
    payload: DeviceRegisterRequest,
    principal: CurrentDevice,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    """Idempotent. Safe to call on every app start."""
    await device_service.register_device(
        session,
        device=principal.device,
        app_version=payload.device.app_version,
        os_version=payload.device.os_version,
        device_label=payload.device.device_label,
        device_model=payload.device.device_model,
        manufacturer=payload.device.manufacturer,
        timezone=payload.device.timezone,
        install_id=payload.device.install_id,
        client_ip=client_ip,
    )

    if payload.capabilities:
        await device_service.report_capabilities(
            session,
            device=principal.device,
            app_version=payload.device.app_version,
            items=[
                (
                    item.capability_key,
                    item.support,
                    item.permission_state,
                    item.os_api_level,
                    item.note,
                )
                for item in payload.capabilities
            ],
        )
    if payload.permissions:
        await device_service.report_permissions(
            session,
            device=principal.device,
            app_version=payload.device.app_version,
            items=[(item.permission_key, item.state, item.note) for item in payload.permissions],
        )

    outcome = await device_service.heartbeat(
        session,
        device=principal.device,
        app_version=payload.device.app_version,
        os_version=payload.device.os_version,
        timezone=payload.device.timezone,
        applied_policy_version=None,
    )
    return ok(
        DeviceHeartbeatResponse(
            server_time=utcnow(),
            policy_version=outcome.policy_version,
            policy_sync_required=outcome.policy_sync_required,
            pending_command_count=outcome.pending_commands,
            next_poll_after_seconds=outcome.next_poll_after_seconds,
        ),
        message="Device registered.",
    )


@router.post(
    "/heartbeat",
    response_model=ApiResponse[DeviceHeartbeatResponse],
    summary="Report that the device is alive",
    dependencies=[Depends(RateLimit("device.heartbeat"))],
)
async def heartbeat(
    payload: DeviceHeartbeatRequest, principal: ActiveDevice, session: DbSession
) -> dict:
    """The response tells the device whether to fetch policies or commands, so
    one call replaces several polls."""
    outcome = await device_service.heartbeat(
        session,
        device=principal.device,
        app_version=payload.app_version,
        os_version=payload.os_version,
        timezone=payload.timezone,
        applied_policy_version=payload.applied_policy_version,
    )
    return ok(
        DeviceHeartbeatResponse(
            server_time=utcnow(),
            policy_version=outcome.policy_version,
            policy_sync_required=outcome.policy_sync_required,
            pending_command_count=outcome.pending_commands,
            next_poll_after_seconds=outcome.next_poll_after_seconds,
        )
    )


@router.post(
    "/capabilities",
    response_model=ApiResponse[GenericMessageOut],
    summary="Report what this device can do",
)
async def report_capabilities(
    payload: CapabilityReportRequest, principal: ActiveDevice, session: DbSession
) -> dict:
    """The server never assumes a capability. Anything not reported as
    ``supported`` with a usable permission state is surfaced to the parent as
    unsupported rather than silently treated as working."""
    rows = await device_service.report_capabilities(
        session,
        device=principal.device,
        app_version=payload.app_version,
        items=[
            (
                item.capability_key,
                item.support,
                item.permission_state,
                item.os_api_level,
                item.note,
            )
            for item in payload.capabilities
        ],
    )
    return ok(
        GenericMessageOut(detail=f"{len(rows)} capability record(s) stored."),
        message="Capabilities recorded.",
    )


@router.post(
    "/permissions/report",
    response_model=ApiResponse[GenericMessageOut],
    summary="Report Android permission states",
)
async def report_permissions(
    payload: PermissionReportRequest, principal: ActiveDevice, session: DbSession
) -> dict:
    """A permission moving from granted to denied raises a parent alert, because
    that is the common way enforcement silently stops working."""
    rows = await device_service.report_permissions(
        session,
        device=principal.device,
        app_version=payload.app_version,
        items=[(item.permission_key, item.state, item.note) for item in payload.permissions],
    )
    return ok(
        GenericMessageOut(detail=f"{len(rows)} permission record(s) stored."),
        message="Permissions recorded.",
    )


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
@router.get(
    "/policies/current",
    response_model=ApiResponse[DevicePolicySnapshot],
    summary="Fetch the current policy snapshot",
)
async def current_policies(principal: ActiveDevice, session: DbSession) -> dict:
    """Precedence is already resolved server-side.

    The device applies this document and reports the outcome; it never has to
    reconcile overlapping rules itself.
    """
    child = await _child_of(session, principal.device)
    snapshot = await policy_service.build_device_snapshot(
        session, device=principal.device, child=child
    )
    principal.device.last_seen_at = utcnow()
    return ok(DevicePolicySnapshot.model_validate(snapshot))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@router.get(
    "/commands",
    response_model=ApiResponse[DeviceCommandListOut],
    summary="Fetch pending commands",
)
async def fetch_commands(principal: ActiveDevice, session: DbSession) -> dict:
    """A successful fetch is the only honest "delivered" signal.

    A push receipt means the provider accepted a message, not that the device
    got it, so ``delivered`` is recorded here rather than at send time.
    """
    commands = await command_service.pending_for_device(session, device_id=principal.device.id)
    await command_service.mark_fetched_by_device(session, commands=commands)

    child = await _child_of(session, principal.device)
    principal.device.last_seen_at = utcnow()

    return ok(
        DeviceCommandListOut(
            commands=[
                DeviceCommandOut(
                    command_id=command.id,
                    command_type=command.command_type,
                    payload=dict(command.payload or {}),
                    created_at=command.created_at,
                    expires_at=command.expires_at,
                )
                for command in commands
            ],
            policy_version=child.policy_version,
            server_time=utcnow(),
            next_poll_after_seconds=(
                device_service.BUSY_POLL_INTERVAL_SECONDS
                if commands
                else device_service.DEFAULT_POLL_INTERVAL_SECONDS
            ),
        )
    )


@router.post(
    "/commands/{command_id}/acknowledge",
    response_model=ApiResponse[CommandStateChangeOut],
    summary="Acknowledge a command",
)
async def acknowledge_command(
    command_id: uuid.UUID,
    payload: CommandAcknowledgeRequest,
    principal: ActiveDevice,
    session: DbSession,
) -> dict:
    """Safe to retry: a repeated acknowledgement is reported as a duplicate and
    never overwrites a terminal state."""
    outcome = await command_service.acknowledge(
        session, device_id=principal.device.id, command_id=command_id
    )
    await command_service.record_delivery_attempt(
        session,
        command=outcome.command,
        channel=DeliveryChannel.device_poll,
        outcome=DeliveryOutcome.sent,
    )
    return ok(
        CommandStateChangeOut(
            command_id=outcome.command.id,
            status=outcome.command.status,
            result=outcome.command.result,
            duplicate=outcome.duplicate,
        ),
        message="Acknowledged." if not outcome.duplicate else "Already acknowledged.",
    )


@router.post(
    "/commands/{command_id}/result",
    response_model=ApiResponse[CommandStateChangeOut],
    summary="Report a command outcome",
)
async def report_command_result(
    command_id: uuid.UUID,
    payload: CommandResultRequest,
    principal: ActiveDevice,
    session: DbSession,
) -> dict:
    """``unsupported`` and ``permission_denied`` are stored exactly as reported.

    They are never translated into success, because a parent being told a rule
    is active when it is not is the worst failure this product can have.
    """
    outcome = await command_service.record_result(
        session,
        device=principal.device,
        command_id=command_id,
        result=payload.result,
        applied_policy_version=payload.applied_policy_version,
        error_code=payload.error_code,
        message=payload.message,
        item_results=payload.item_results,
    )
    return ok(
        CommandStateChangeOut(
            command_id=outcome.command.id,
            status=outcome.command.status,
            result=outcome.command.result,
            duplicate=outcome.duplicate,
        ),
        message="Result recorded." if not outcome.duplicate else "Result already recorded.",
    )


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------
@router.post(
    "/usage/daily-summary",
    response_model=ApiResponse[UsageIngestResult],
    summary="Submit one day of usage",
    dependencies=[Depends(RateLimit("device.usage_submit"))],
)
async def submit_daily_summary(
    payload: DailySummarySubmit, principal: ActiveDevice, session: DbSession
) -> dict:
    """Upsert: re-sending a day replaces its totals, so retries are safe."""
    return await _ingest_usage(session, principal, [payload])


@router.post(
    "/usage/app-summaries",
    response_model=ApiResponse[UsageIngestResult],
    summary="Submit a batch of days",
    dependencies=[Depends(RateLimit("device.usage_submit"))],
)
async def submit_usage_batch(
    payload: DailySummaryBatchSubmit, principal: ActiveDevice, session: DbSession
) -> dict:
    """Backfill after a period offline. Implausible or out-of-window days are
    rejected individually and reported, rather than failing the whole batch."""
    return await _ingest_usage(session, principal, payload.summaries)


async def _ingest_usage(session, principal, days) -> dict:  # noqa: ANN001
    child = await _child_of(session, principal.device)
    outcome = await usage_service.ingest_daily_summaries(
        session,
        device=principal.device,
        child=child,
        days=[
            usage_service.SubmittedDay(
                local_date=day.local_date,
                timezone=day.timezone,
                total_screen_time_seconds=day.total_screen_time_seconds,
                unlock_count=day.unlock_count,
                category_totals={
                    category.value: seconds for category, seconds in day.category_totals.items()
                },
                app_summaries=[
                    (
                        item.package_identifier,
                        item.display_label,
                        item.category.value if item.category else None,
                        item.foreground_seconds,
                        item.launch_count,
                    )
                    for item in day.app_summaries
                ],
                source_app_version=day.source_app_version,
            )
            for day in days
        ],
    )
    return ok(
        UsageIngestResult(
            accepted=outcome.accepted,
            updated=outcome.updated,
            rejected=outcome.rejected,
            rejected_dates=outcome.rejected_dates,
            rejection_reasons=outcome.rejection_reasons,
        ),
        message="Usage recorded.",
    )


@router.post(
    "/events",
    response_model=ApiResponse[DeviceEventIngestResult],
    summary="Submit device events",
    dependencies=[Depends(RateLimit("device.events"))],
)
async def submit_events(
    payload: DeviceEventBatch, principal: ActiveDevice, session: DbSession
) -> dict:
    """Deduplicated by ``deduplication_key``, so a retried batch is a no-op.

    Payloads carrying message content, browsing history, media or coordinates
    are rejected: those are outside this product's collection scope.
    """
    outcome = await alert_service.ingest_events(
        session,
        device=principal.device,
        events=[
            (item.event_type, item.occurred_at, item.deduplication_key, item.payload)
            for item in payload.events
        ],
    )
    return ok(
        DeviceEventIngestResult(
            accepted=outcome.accepted,
            duplicates=outcome.duplicates,
            alerts_created=outcome.alerts_created,
            received_at=utcnow(),
        ),
        message="Events recorded.",
    )


@router.post(
    "/location",
    response_model=ApiResponse[LocationAcceptedOut],
    summary="Submit a location sample (gated)",
    dependencies=[Depends(RateLimit("device.location")), Depends(require_location_feature)],
)
async def submit_location(
    payload: LocationSubmit, principal: ActiveDevice, session: DbSession
) -> dict:
    """Accepted only when the feature is enabled, consent is on record, and the
    device reports the permission as granted.

    A rejected sample returns ``accepted: false`` with a ``rejection_code``;
    nothing is stored and no location is fabricated.
    """
    outcome = await location_service.submit_sample(
        session,
        device=principal.device,
        latitude=payload.latitude,
        longitude=payload.longitude,
        accuracy_meters=payload.accuracy_meters,
        source=payload.source,
        recorded_at=payload.recorded_at,
        deduplication_key=payload.deduplication_key,
        command_id=payload.command_id,
    )
    return ok(
        LocationAcceptedOut(
            accepted=outcome.accepted,
            sample_id=outcome.sample.id if outcome.sample else None,
            duplicate=outcome.duplicate,
            retention_expires_at=(outcome.sample.retention_expires_at if outcome.sample else None),
            rejection_code=outcome.rejection_code,
        ),
        message="Location recorded." if outcome.accepted else "Location not accepted.",
    )


# ---------------------------------------------------------------------------
# Push token
# ---------------------------------------------------------------------------
@router.post(
    "/push-token",
    response_model=ApiResponse[PushTokenOut],
    status_code=status.HTTP_201_CREATED,
    summary="Register this device's push token",
)
async def register_device_push_token(
    payload: PushTokenRegister, principal: ActiveDevice, session: DbSession
) -> dict:
    registration = await notification_service.register_push_token(
        session,
        raw_token=payload.token,
        platform=payload.platform,
        app_version=payload.app_version,
        device_id=principal.device.id,
    )
    row = registration.token
    return ok(
        PushTokenOut(
            id=row.id,
            platform=row.platform,
            active=row.active,
            app_version=row.app_version,
            created_at=row.created_at,
            updated_at=row.updated_at,
            token_suffix=notification_service.token_suffix(payload.token),
        ),
        message="Push token registered.",
    )


@router.delete(
    "/push-token",
    response_model=ApiResponse[GenericMessageOut],
    summary="Deregister this device's push token",
)
async def delete_device_push_token(
    payload: PushTokenDelete, principal: ActiveDevice, session: DbSession
) -> dict:
    removed = await notification_service.deactivate_push_token(
        session,
        raw_token=payload.token,
        device_id=principal.device.id,
        reason="device_request",
    )
    return ok(
        GenericMessageOut(detail="Push token removed." if removed else "Token not found."),
        message="Request processed.",
    )
