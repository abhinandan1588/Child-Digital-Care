"""Push provider interface.

A push notification in this product is a **wake-up signal**, never the payload.
``PushMessage.data`` carries at most a reason code and a hint of what to fetch;
the client then calls the API with its own credential to learn the details.

That design is a privacy requirement (no child telemetry in a notification that
may surface on a lock screen or pass through a third-party service) and a
reliability requirement (a dropped push loses nothing, because the durable
command still sits in PostgreSQL).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum


class PushSendOutcome(StrEnum):
    sent = "sent"
    token_invalid = "token_invalid"
    provider_error = "provider_error"
    not_configured = "not_configured"
    rate_limited = "rate_limited"


@dataclass(slots=True)
class PushMessage:
    token: str
    #: Short, non-identifying reason code, e.g. "commands_pending".
    reason: str
    #: Small map of safe hints. Validated by the provider to exclude anything
    #: that looks like content.
    data: dict[str, str] = field(default_factory=dict)
    #: Optional user-visible title/body. Only used for parent notifications,
    #: and kept deliberately generic ("New activity to review").
    title: str | None = None
    body: str | None = None
    #: FCM collapse key, so a backlog of wake-ups does not become a backlog of
    #: notifications on the device.
    collapse_key: str | None = None
    high_priority: bool = False
    ttl_seconds: int = 3600


@dataclass(frozen=True, slots=True)
class PushResult:
    outcome: PushSendOutcome
    provider: str
    provider_message_id: str | None = None
    error_code: str | None = None

    @property
    def sent(self) -> bool:
        return self.outcome is PushSendOutcome.sent


# Keys that must never appear in a push data payload.
FORBIDDEN_DATA_KEYS: frozenset[str] = frozenset(
    {
        "latitude",
        "longitude",
        "coordinates",
        "message",
        "message_body",
        "content",
        "transcript",
        "screenshot",
        "usage_detail",
        "app_list",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "email",
        "child_name",
        "display_name",
    }
)

MAX_DATA_VALUE_LENGTH = 128


def validate_push_data(data: dict[str, str]) -> dict[str, str]:
    """Reject payloads that would turn a wake-up signal into data exfiltration."""
    cleaned: dict[str, str] = {}
    for key, value in data.items():
        if key.lower() in FORBIDDEN_DATA_KEYS:
            raise ValueError(f"Push payload must not contain '{key}'.")
        text = str(value)
        if len(text) > MAX_DATA_VALUE_LENGTH:
            raise ValueError(f"Push payload value for '{key}' is too long.")
        cleaned[key] = text
    return cleaned


class PushProvider(ABC):
    name: str = "base"

    @property
    @abstractmethod
    def configured(self) -> bool: ...

    @abstractmethod
    async def send(self, message: PushMessage) -> PushResult: ...
