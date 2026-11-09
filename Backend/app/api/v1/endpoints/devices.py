"""Parent-facing device views, commands, and revocation."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import (
    ClientIp,
    CurrentParent,
    DbSession,
    IdempotencyKey,
    VerifiedParent,
    require_device_access,
)
from app.core.permissions import FamilyPermission
from app.core.response import ApiResponse, ok
from app.db.enums import PARENT_ISSUABLE_COMMANDS, AuditActorType
from app.db.models.device import Device
from app.schemas.command import (
    CommandCreateRequest,
    CommandDetailOut,
    CommandOut,
)
from app.schemas.device import (
    CapabilityOut,
    DeviceDetailOut,
    DeviceLabelUpdate,
    DeviceOut,
    DeviceRevokeRequest,
    DeviceRevokeResult,
    PermissionOut,
)
from app.services import (
    audit_service,
    command_service,
    device_service,
    family_service,
    idempotency_service,
)
from app.services.audit_service import AuditAction

router = APIRouter(tags=["devices"])

FamilyAccess = family_service.FamilyAccess
DeviceContext = tuple[FamilyAccess, Device]

DeviceRead = Annotated[DeviceContext, Depends(require_device_access(FamilyPermission.DEVICES_READ))]
DeviceManage = Annotated[
    DeviceContext, Depends(require_device_access(FamilyPermission.DEVICES_MANAGE))
]
CommandIssue = Annotated[
    DeviceContext, Depends(require_device_access(FamilyPermission.COMMANDS_ISSUE))
]


async def device_out(session, device: Device) -> DeviceOut:  # noqa: ANN001
    from app.db.models.family import ChildProfile

    child = await session.get(ChildProfile, device.child_profile_id)
    return DeviceOut(
        id=device.id,
        family_id=device.family_id,
        child_profile_id=device.child_profile_id,
        device_label=device.device_label,
        platform=device.platform,
        device_status=device.device_status,
        app_version=device.app_version,
        os_version=device.os_version,
        device_model=device.device_model,
        manufacturer=device.manufacturer,
        timezone=device.timezone,
        registered_at=device.registered_at,
        last_seen_at=device.last_seen_at,
        revoked_at=device.revoked_at,
        presence=device_service.presence_of(device),
        policy_version=child.policy_version if child else 0,
        applied_policy_version=device.applied_policy_version,
        policy_sync_status=device.policy_sync_status,
        policy_sync_detail=device.policy_sync_detail,
        policy_synced_at=device.policy_synced_at,
        created_at=device.created_at,
    )


@router.get(
    "/devices",
    response_model=ApiResponse[list[DeviceOut]],
    summary="List devices the caller may see",
)
async def list_devices(
    principal: CurrentParent,
    session: DbSession,
    child_profile_id: Annotated[uuid.UUID | None, Query()] = None,
    include_revoked: Annotated[bool, Query()] = False,
) -> dict:
    """Scoped to the families the caller belongs to *and* holds
    ``devices.read`` in."""
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    family_ids = [
        family.id
        for family, member in memberships
        if FamilyAccess(family=family, member=member).can(FamilyPermission.DEVICES_READ)
    ]
    devices = await device_service.list_devices(
        session,
        family_ids=family_ids,
        child_profile_id=child_profile_id,
        include_revoked=include_revoked,
    )
    return ok([await device_out(session, device) for device in devices])


@router.get(
    "/devices/{device_id}",
    response_model=ApiResponse[DeviceDetailOut],
    summary="Get one device with its reported capabilities",
)
async def get_device(session: DbSession, context: DeviceRead) -> dict:
    """``presence`` is derived from ``last_seen_at`` and is explicitly an
    inference. Capability and permission rows are device-reported facts."""
    _, device = context
    base = await device_out(session, device)
    capabilities = await device_service.list_capabilities(session, device_id=device.id)
    permissions = await device_service.list_permissions(session, device_id=device.id)
    pending = await command_service.count_pending(session, device_id=device.id)

    return ok(
        DeviceDetailOut(
            **base.model_dump(),
            capabilities=[
                CapabilityOut(
                    capability_key=row.capability_key,
                    support=row.support,
                    permission_state=row.permission_state,
                    reported_at=row.reported_at,
                    os_api_level=row.os_api_level,
                )
                for row in capabilities
            ],
            permissions=[
                PermissionOut(
                    permission_key=row.permission_key,
                    state=row.state,
                    reported_at=row.reported_at,
                )
                for row in permissions
            ],
            pending_command_count=pending,
        )
    )


@router.patch(
    "/devices/{device_id}/label",
    response_model=ApiResponse[DeviceOut],
    summary="Rename a device",
)
async def update_device_label(
    payload: DeviceLabelUpdate,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: DeviceManage,
) -> dict:
    _, device = context
    await device_service.update_label(
        session,
        device=device,
        label=payload.device_label,
        user_id=principal.id,
        client_ip=client_ip,
    )
    return ok(await device_out(session, device), message="Device renamed.")


@router.post(
    "/devices/{device_id}/revoke",
    response_model=ApiResponse[DeviceRevokeResult],
    summary="Unlink a device",
)
async def revoke_device(
    payload: DeviceRevokeRequest,
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: DeviceManage,
) -> dict:
    """Unlinking takes effect on the device's next API call, whether or not the
    device is currently reachable. Pending commands are cancelled so the parent
    is not shown work that will never run."""
    _, device = context
    outcome = await device_service.revoke_device(
        session,
        device=device,
        reason=payload.reason,
        actor_type=AuditActorType.parent_user,
        actor_id=principal.id,
        client_ip=client_ip,
    )
    return ok(
        DeviceRevokeResult(
            device_id=outcome.device.id,
            device_status=outcome.device.device_status,
            revoked_at=outcome.device.revoked_at,
            sessions_revoked=outcome.sessions_revoked,
            commands_cancelled=outcome.commands_cancelled,
            push_tokens_deactivated=outcome.push_tokens_deactivated,
        ),
        message="Device unlinked.",
    )


# ---------------------------------------------------------------------------
# Commands (parent view)
# ---------------------------------------------------------------------------
def command_out(command) -> CommandOut:  # noqa: ANN001
    return CommandOut(
        id=command.id,
        device_id=command.device_id,
        child_profile_id=command.child_profile_id,
        command_type=command.command_type,
        status=command.status,
        payload=dict(command.payload or {}),
        created_at=command.created_at,
        expires_at=command.expires_at,
        delivery_attempt_count=command.delivery_attempt_count,
        delivered_at=command.delivered_at,
        fetched_at=command.fetched_at,
        acknowledged_at=command.acknowledged_at,
        completed_at=command.completed_at,
        result=command.result,
        applied_policy_version=command.applied_policy_version,
        failure_code=command.failure_code,
        failure_message=command.failure_message,
    )


@router.get(
    "/devices/{device_id}/commands",
    response_model=ApiResponse[list[CommandOut]],
    summary="List a device's command history",
)
async def list_device_commands(
    session: DbSession,
    context: DeviceRead,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict:
    _, device = context
    rows = await command_service.list_for_device_parent_view(
        session, device_id=device.id, limit=limit
    )
    return ok([command_out(row) for row in rows])


@router.post(
    "/devices/{device_id}/commands",
    response_model=ApiResponse[CommandDetailOut],
    status_code=status.HTTP_201_CREATED,
    summary="Request a supported device action",
)
async def create_device_command(
    payload: CommandCreateRequest,
    principal: VerifiedParent,
    session: DbSession,
    idempotency_key: IdempotencyKey,
    context: CommandIssue,
    client_ip: ClientIp,
) -> dict:
    """Queue one of a fixed set of typed actions.

    Only these types can be requested through the API:
    ``sync_policies``, ``refresh_device_status``, ``request_usage_sync``,
    ``request_location_update``. There is no generic execute, shell, install or
    capture command, and the payload is validated against a per-type schema.

    The command is stored before any push is attempted, so it survives a lost
    notification. Supplying ``Idempotency-Key`` makes a retry return the
    original command rather than queueing a second one.
    """
    access, device = context
    command_type = payload.command.command_type

    if idempotency_key:
        replay = await idempotency_service.lookup(
            session,
            principal_type="parent_user",
            principal_id=principal.id,
            endpoint="POST /devices/{device_id}/commands",
            key=idempotency_key,
            request_payload=payload.model_dump(mode="json"),
        )
        if replay is not None:
            return replay.body

    created = await command_service.create_parent_command(
        session,
        device=device,
        command_type=command_type,
        payload=payload.command.model_dump(mode="json", exclude={"command_type"}),
        user_id=principal.id,
        idempotency_key=idempotency_key,
        expires_in_seconds=payload.expires_in_seconds,
    )
    await audit_service.record(
        session,
        action=AuditAction.COMMAND_CREATED,
        actor_type=AuditActorType.parent_user,
        actor_id=principal.id,
        target_type="device_command",
        target_id=created.command.id,
        family_id=access.family_id,
        client_ip=client_ip,
        metadata={
            "command_type": command_type.value,
            "device_id": device.id,
            "duplicate": not created.created,
        },
    )

    body = ok(
        CommandDetailOut(**command_out(created.command).model_dump(), attempts=[]),
        message=("Command queued." if created.created else "Command already queued (idempotent)."),
    )
    if idempotency_key:
        await idempotency_service.store(
            session,
            principal_type="parent_user",
            principal_id=principal.id,
            endpoint="POST /devices/{device_id}/commands",
            key=idempotency_key,
            request_payload=payload.model_dump(mode="json"),
            status_code=201,
            response_body=_jsonable(body),
        )
    return body


def _jsonable(body: dict) -> dict:
    from fastapi.encoders import jsonable_encoder

    return jsonable_encoder(body)


@router.get(
    "/commands/allowed-types",
    response_model=ApiResponse[list[str]],
    summary="The command types a parent may request",
)
async def allowed_command_types(principal: CurrentParent) -> dict:
    """Published so client teams build against the allow-list rather than
    guessing. Anything absent here is rejected server-side."""
    return ok(sorted(item.value for item in PARENT_ISSUABLE_COMMANDS))
