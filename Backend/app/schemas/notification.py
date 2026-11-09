"""Push token and notification preference schemas."""

from __future__ import annotations

import uuid
from datetime import datetime, time

from pydantic import Field, model_validator

from app.db.enums import DevicePlatform, NotificationType
from app.schemas.common import OutSchema, SchemaBase, validate_timezone


class QuietHours(SchemaBase):
    timezone: str = Field(max_length=64)
    start: time
    end: time

    @model_validator(mode="after")
    def _valid(self) -> QuietHours:
        validate_timezone(self.timezone)
        if self.start == self.end:
            raise ValueError("Quiet hours start and end must differ.")
        return self


class PushTokenRegister(SchemaBase):
    token: str = Field(min_length=20, max_length=4096)
    platform: DevicePlatform = DevicePlatform.android
    app_version: str | None = Field(default=None, max_length=32)


class PushTokenOut(OutSchema):
    id: uuid.UUID
    platform: DevicePlatform
    active: bool
    app_version: str | None
    created_at: datetime
    updated_at: datetime
    #: Last 6 characters only, so a parent can identify an install without the
    #: API ever returning a usable push credential.
    token_suffix: str


class PushTokenDelete(SchemaBase):
    token: str = Field(min_length=20, max_length=4096)


class NotificationPreferenceItem(SchemaBase):
    notification_type: NotificationType
    enabled: bool
    quiet_hours: QuietHours | None = None

    @model_validator(mode="after")
    def _security_always_on(self) -> NotificationPreferenceItem:
        if self.notification_type is NotificationType.security and not self.enabled:
            raise ValueError("Security notifications cannot be disabled.")
        return self


class NotificationPreferenceUpdate(SchemaBase):
    preferences: list[NotificationPreferenceItem] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def _unique(self) -> NotificationPreferenceUpdate:
        types = [item.notification_type for item in self.preferences]
        if len(types) != len(set(types)):
            raise ValueError("preferences contains duplicate notification_type values.")
        return self


class NotificationPreferenceOut(OutSchema):
    notification_type: NotificationType
    enabled: bool
    quiet_hours: dict | None = None
    #: True for types the product never suppresses.
    always_delivered: bool = False


class RealtimeTicketOut(OutSchema):
    """Short-lived ticket for the WebSocket handshake.

    Browsers cannot set an ``Authorization`` header on a WebSocket, so the
    client exchanges its access token for a single-purpose ticket (audience
    ``cdc:ws``, ~60s lifetime) and passes it as a query parameter.
    """

    ticket: str
    expires_in: int
    websocket_url: str
