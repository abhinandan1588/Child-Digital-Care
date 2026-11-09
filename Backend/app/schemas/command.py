"""Device command schemas.

The payload of every command type has its own model, and
:data:`CommandPayloadUnion` is a discriminated union over ``command_type``.
That is what makes the allow-list real: a request whose ``command_type`` is not
in :class:`CommandType` fails validation before any code runs, and a payload
with unexpected fields is rejected (``extra="forbid"``).

There is intentionally no command that carries a script, shell string,
arbitrary URL, package to install, or media-capture instruction.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from app.db.enums import (
    CommandResult,
    CommandStatus,
    CommandType,
    DeliveryChannel,
    DeliveryOutcome,
)
from app.schemas.common import OutSchema, SchemaBase


# ---------------------------------------------------------------------------
# Payloads (one model per command type)
# ---------------------------------------------------------------------------
class SyncPoliciesPayload(SchemaBase):
    command_type: Literal[CommandType.sync_policies] = CommandType.sync_policies
    #: Version the device should converge on. Advisory: the device always
    #: fetches the current snapshot rather than trusting this number.
    target_policy_version: int | None = Field(default=None, ge=1)
    reason: str | None = Field(default=None, max_length=120)


class RefreshDeviceStatusPayload(SchemaBase):
    command_type: Literal[CommandType.refresh_device_status] = CommandType.refresh_device_status
    include_capabilities: bool = True
    include_permissions: bool = True


class RequestUsageSyncPayload(SchemaBase):
    command_type: Literal[CommandType.request_usage_sync] = CommandType.request_usage_sync
    #: How many days of daily summaries to re-send. Bounded to keep payload
    #: sizes and device work predictable.
    days: int = Field(default=1, ge=1, le=14)


class RequestLocationUpdatePayload(SchemaBase):
    """Only accepted when the location feature is enabled, consent is on record
    and the device reports the permission as granted. Rejected otherwise."""

    command_type: Literal[CommandType.request_location_update] = CommandType.request_location_update
    reason: str = Field(
        max_length=160,
        description="Shown to the child on the device and stored in the audit log.",
    )
    max_accuracy_meters: int | None = Field(default=None, ge=10, le=10_000)


class ApplySupportedPolicyPayload(SchemaBase):
    command_type: Literal[CommandType.apply_supported_policy] = CommandType.apply_supported_policy
    policy_version: int = Field(ge=1)


class RevokeDevicePayload(SchemaBase):
    """Server-generated only; a parent revokes via ``POST /devices/{id}/revoke``."""

    command_type: Literal[CommandType.revoke_device] = CommandType.revoke_device
    reason: str = Field(max_length=120)


CommandPayloadUnion = Annotated[
    SyncPoliciesPayload
    | RefreshDeviceStatusPayload
    | RequestUsageSyncPayload
    | RequestLocationUpdatePayload
    | ApplySupportedPolicyPayload
    | RevokeDevicePayload,
    Field(discriminator="command_type"),
]

#: Payload model for each command type, used by the service layer to re-validate
#: a stored payload before it is handed to a device.
PAYLOAD_MODELS: dict[CommandType, type[SchemaBase]] = {
    CommandType.sync_policies: SyncPoliciesPayload,
    CommandType.refresh_device_status: RefreshDeviceStatusPayload,
    CommandType.request_usage_sync: RequestUsageSyncPayload,
    CommandType.request_location_update: RequestLocationUpdatePayload,
    CommandType.apply_supported_policy: ApplySupportedPolicyPayload,
    CommandType.revoke_device: RevokeDevicePayload,
}


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
class CommandCreateRequest(SchemaBase):
    command: CommandPayloadUnion
    expires_in_seconds: int | None = Field(
        default=None,
        ge=60,
        le=604_800,
        description="Defaults to COMMAND_DEFAULT_TTL_SECONDS. A command never pends forever.",
    )


class CommandAcknowledgeRequest(SchemaBase):
    """Sent by the device when it has received a command and begun work."""

    received_at: datetime | None = Field(
        default=None, description="Device clock; the server records its own receipt time too."
    )
    app_version: str | None = Field(default=None, max_length=32)


class CommandResultRequest(SchemaBase):
    """Sent by the device when a command reaches a terminal outcome.

    ``unsupported`` and ``permission_denied`` are first-class results and are
    stored as-is. They are never translated into success.
    """

    result: CommandResult
    applied_policy_version: int | None = Field(default=None, ge=0)
    error_code: str | None = Field(default=None, max_length=64)
    message: str | None = Field(
        default=None,
        max_length=255,
        description="Safe, user-displayable explanation. No stack traces or PII.",
    )
    #: Per-item outcome for partial application, e.g.
    #: {"app_restrictions": "applied", "screen_time": "unsupported"}
    item_results: dict[str, str] | None = None


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
class CommandAttemptOut(OutSchema):
    attempt_number: int
    channel: DeliveryChannel
    outcome: DeliveryOutcome
    error_code: str | None
    attempted_at: datetime


class CommandOut(OutSchema):
    id: uuid.UUID
    device_id: uuid.UUID
    child_profile_id: uuid.UUID
    command_type: CommandType
    status: CommandStatus
    payload: dict
    created_at: datetime
    expires_at: datetime
    delivery_attempt_count: int
    delivered_at: datetime | None
    fetched_at: datetime | None
    acknowledged_at: datetime | None
    completed_at: datetime | None
    result: CommandResult | None
    applied_policy_version: int | None
    failure_code: str | None
    failure_message: str | None


class CommandDetailOut(CommandOut):
    attempts: list[CommandAttemptOut] = Field(default_factory=list)


class DeviceCommandOut(OutSchema):
    """Device-facing projection: no parent identity, no family metadata."""

    command_id: uuid.UUID
    command_type: CommandType
    payload: dict
    created_at: datetime
    expires_at: datetime
    requires_result: bool = True


class DeviceCommandListOut(OutSchema):
    commands: list[DeviceCommandOut] = Field(default_factory=list)
    policy_version: int
    server_time: datetime
    next_poll_after_seconds: int


class CommandStateChangeOut(OutSchema):
    command_id: uuid.UUID
    status: CommandStatus
    result: CommandResult | None = None
    #: True when the submission was a duplicate of one already processed.
    duplicate: bool = False
