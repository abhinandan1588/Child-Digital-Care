"""Admin dashboard schemas.

Admin responses use narrow projections. A support agent sees account and device
*metadata*; nothing here exposes child usage detail or location, which require
their own permissions (``child_usage.read`` / ``child_location.read``).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator

from app.db.enums import (
    AbuseReportCategory,
    AbuseReportStatus,
    AccountStatus,
    AuditActorType,
    AuditOutcome,
    DeviceStatus,
    SubscriptionStatus,
    TicketPriority,
    TicketStatus,
)
from app.schemas.common import OutSchema, SchemaBase


class AdminOverviewOut(OutSchema):
    """Aggregated counts only; no per-account data."""

    generated_at: datetime
    total_users: int
    active_users: int
    total_families: int
    total_children: int
    total_devices: int
    active_devices: int
    devices_offline_24h: int
    pending_commands: int
    expired_commands_24h: int
    open_alerts: int
    open_support_tickets: int
    open_abuse_reports: int
    outbox_backlog: int


class AdminUserListItem(OutSchema):
    id: uuid.UUID
    email: str
    display_name: str
    account_status: AccountStatus
    email_verified: bool
    created_at: datetime
    last_login_at: datetime | None
    family_count: int = 0


class AdminUserDetailOut(AdminUserListItem):
    families: list[AdminFamilySummary] = Field(default_factory=list)
    device_count: int = 0
    subscription_status: SubscriptionStatus | None = None
    open_ticket_count: int = 0
    #: Shown only to holders of ``users.pii.read``; otherwise omitted.
    timezone: str | None = None


class AdminFamilySummary(OutSchema):
    family_id: uuid.UUID
    name: str
    status: str
    is_owner: bool
    child_count: int = 0
    device_count: int = 0


class AdminUserStatusUpdate(SchemaBase):
    account_status: AccountStatus
    reason: str = Field(
        min_length=5,
        max_length=255,
        description="Mandatory. Written to the audit log with the actor identity.",
    )

    @field_validator("account_status")
    @classmethod
    def _allowed(cls, value: AccountStatus) -> AccountStatus:
        allowed = {
            AccountStatus.active,
            AccountStatus.suspended,
            AccountStatus.deactivated,
        }
        if value not in allowed:
            raise ValueError(
                "Only active, suspended and deactivated can be set from the admin API."
            )
        return value


class AdminFamilyListItem(OutSchema):
    id: uuid.UUID
    name: str
    status: str
    owner_email: str
    child_count: int
    device_count: int
    created_at: datetime


class AdminDeviceListItem(OutSchema):
    id: uuid.UUID
    family_id: uuid.UUID
    device_label: str
    platform: str
    device_status: DeviceStatus
    app_version: str | None
    os_version: str | None
    last_seen_at: datetime | None
    policy_sync_status: str
    registered_at: datetime | None


class AdminTicketListItem(OutSchema):
    id: uuid.UUID
    reference: str
    subject: str
    status: TicketStatus
    priority: TicketPriority
    contact_email: str
    assigned_admin_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    message_count: int = 0


class AdminTicketUpdate(SchemaBase):
    status: TicketStatus | None = None
    priority: TicketPriority | None = None
    assigned_admin_id: uuid.UUID | None = None
    internal_note: str | None = Field(default=None, max_length=4000)


class AdminAbuseReportListItem(OutSchema):
    id: uuid.UUID
    reference: str
    category: AbuseReportCategory
    status: AbuseReportStatus
    subject_family_id: uuid.UUID | None
    created_at: datetime
    reviewed_at: datetime | None
    action_taken: str | None


class AdminAbuseReportUpdate(SchemaBase):
    status: AbuseReportStatus
    action_taken: str | None = Field(default=None, max_length=64)
    resolution_notes: str = Field(
        min_length=5,
        max_length=4000,
        description="Mandatory record of the documented safety decision.",
    )


class AdminSubscriptionListItem(OutSchema):
    family_id: uuid.UUID
    plan_code: str | None
    status: SubscriptionStatus
    provider: str
    current_period_end: datetime | None
    cancel_at_period_end: bool
    updated_at: datetime


class AdminAuditLogItem(OutSchema):
    id: uuid.UUID
    actor_type: AuditActorType
    actor_id: uuid.UUID | None
    actor_label: str | None
    action: str
    outcome: AuditOutcome
    target_type: str | None
    target_id: uuid.UUID | None
    family_id: uuid.UUID | None
    request_id: str | None
    reason: str | None
    metadata: dict | None = Field(default=None, validation_alias="event_metadata")
    created_at: datetime


class AdminAnalyticsSummaryOut(OutSchema):
    """Aggregates only. Every number is a count over the whole platform."""

    generated_at: datetime
    window_days: int
    new_users: int
    new_families: int
    new_devices: int
    devices_reporting_usage: int
    commands_created: int
    commands_succeeded: int
    commands_failed: int
    commands_unsupported: int
    commands_expired: int
    policy_sync_failure_rate: float
    push_failure_rate: float


class AdminCreateRequest(SchemaBase):
    """Used by the bootstrap script and by ``admin_users.manage`` holders."""

    email: str = Field(max_length=320)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=16, max_length=128)
    roles: list[str] = Field(min_length=1, max_length=8)
