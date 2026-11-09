"""Realtime event publication.

Events are *hints*: "something changed, re-fetch it". REST stays the source of
truth, so a client that misses a WebSocket frame recovers simply by polling.
That also keeps the payloads tiny and free of telemetry.

Fan-out goes through Redis Pub/Sub so multiple API instances can serve
connections for the same family.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.core.logging import get_logger
from app.core.redis import publish_json
from app.utils.time import utcnow

logger = get_logger(__name__)


class RealtimeEvent:
    """Event names shared with the client teams (docs/INTEGRATION_GUIDE.md)."""

    DEVICE_STATUS_CHANGED = "device.status_changed"
    DEVICE_LAST_SEEN = "device.last_seen"
    POLICY_SYNC_STATUS_CHANGED = "policy.sync_status_changed"
    COMMAND_STATUS_CHANGED = "command.status_changed"
    USAGE_SUMMARY_RECEIVED = "usage.summary_received"
    ALERT_CREATED = "alert.created"
    SUBSCRIPTION_STATUS_CHANGED = "subscription.status_changed"
    DEVICE_COMMANDS_PENDING = "device.commands_pending"


def family_channel(family_id: uuid.UUID) -> str:
    return f"cdc:family:{family_id}"


def device_channel(device_id: uuid.UUID) -> str:
    return f"cdc:device:{device_id}"


#: Anything that could carry content or identity is rejected before publish.
_FORBIDDEN_KEYS = frozenset(
    {
        "latitude",
        "longitude",
        "coordinates",
        "email",
        "display_name",
        "child_name",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "message_body",
        "app_list",
    }
)


def _safe(data: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in _FORBIDDEN_KEYS:
            raise ValueError(f"Realtime payload must not contain '{key}'.")
        cleaned[key] = str(value) if isinstance(value, uuid.UUID) else value
    return cleaned


def build_envelope(event: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": event,
        "data": _safe(data),
        "emitted_at": utcnow().isoformat(),
    }


async def publish_to_family(family_id: uuid.UUID, event: str, data: dict[str, Any]) -> bool:
    """Publish to every authorized subscriber of one family."""
    try:
        envelope = build_envelope(event, data)
    except ValueError as exc:
        logger.error("realtime_payload_rejected", event_name=event, error=str(exc))
        return False
    return await publish_json(family_channel(family_id), envelope)


async def publish_to_device(device_id: uuid.UUID, event: str, data: dict[str, Any]) -> bool:
    try:
        envelope = build_envelope(event, data)
    except ValueError as exc:
        logger.error("realtime_payload_rejected", event_name=event, error=str(exc))
        return False
    return await publish_json(device_channel(device_id), envelope)
