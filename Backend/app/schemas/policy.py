"""Policy, schedule and policy-snapshot schemas."""

from __future__ import annotations

import uuid
from datetime import datetime, time

from pydantic import Field, field_validator, model_validator

from app.db.enums import (
    RestrictionAction,
    ScheduleAction,
    SyncStatus,
    WebsiteRestrictionMode,
    Weekday,
)
from app.schemas.common import (
    OutSchema,
    SchemaBase,
    VersionedUpdate,
    validate_domain,
    validate_package_identifier,
    validate_timezone,
)

MAX_ALLOWLIST_PACKAGES = 50
MAX_SCHEDULES_PER_POLICY = 70  # 10 windows x 7 weekdays


# ---------------------------------------------------------------------------
# App restrictions
# ---------------------------------------------------------------------------
class AppRestrictionCreate(SchemaBase):
    package_identifier: str = Field(max_length=255, examples=["com.example.video"])
    display_label: str | None = Field(default=None, max_length=120)
    action: RestrictionAction
    daily_limit_seconds: int | None = Field(default=None, ge=60, le=86_400)
    enabled: bool = True
    device_id: uuid.UUID | None = Field(
        default=None,
        description="Scope to a single device. Omit to apply to every device of the child.",
    )

    @field_validator("package_identifier")
    @classmethod
    def _package(cls, value: str) -> str:
        return validate_package_identifier(value)

    @model_validator(mode="after")
    def _limit_required_for_time_limit(self) -> AppRestrictionCreate:
        if self.action is RestrictionAction.time_limit and self.daily_limit_seconds is None:
            raise ValueError("daily_limit_seconds is required when action is time_limit.")
        if self.action is not RestrictionAction.time_limit and self.daily_limit_seconds is not None:
            raise ValueError("daily_limit_seconds is only valid when action is time_limit.")
        return self


class AppRestrictionUpdate(VersionedUpdate):
    display_label: str | None = Field(default=None, max_length=120)
    action: RestrictionAction | None = None
    daily_limit_seconds: int | None = Field(default=None, ge=60, le=86_400)
    enabled: bool | None = None


class AppRestrictionOut(OutSchema):
    id: uuid.UUID
    child_profile_id: uuid.UUID
    device_id: uuid.UUID | None
    package_identifier: str
    display_label: str | None
    action: RestrictionAction
    daily_limit_seconds: int | None
    enabled: bool
    revision: int
    created_at: datetime
    updated_at: datetime


class PolicyMutationResult(OutSchema):
    """Returned by every policy mutation.

    ``sync_status`` is always ``pending_sync`` immediately after a change: the
    server has saved the intent and queued a sync, and it does not claim the
    device has applied anything until the device says so.
    """

    policy_version: int
    sync_status: SyncStatus = SyncStatus.pending_sync
    devices_notified: int = 0
    commands_queued: list[uuid.UUID] = Field(default_factory=list)


class AppRestrictionCreated(PolicyMutationResult):
    restriction_id: uuid.UUID
    restriction: AppRestrictionOut


# ---------------------------------------------------------------------------
# Screen-time policies and schedules
# ---------------------------------------------------------------------------
class ScreenTimeScheduleCreate(SchemaBase):
    weekday: Weekday
    start_local_time: time
    end_local_time: time
    action: ScheduleAction = ScheduleAction.block_all
    allowlisted_packages: list[str] = Field(default_factory=list, max_length=MAX_ALLOWLIST_PACKAGES)
    enabled: bool = True

    @field_validator("allowlisted_packages")
    @classmethod
    def _packages(cls, value: list[str]) -> list[str]:
        return sorted({validate_package_identifier(item) for item in value})

    @field_validator("start_local_time", "end_local_time")
    @classmethod
    def _whole_minutes(cls, value: time) -> time:
        # Sub-minute precision is not meaningful for a bedtime window and would
        # complicate device-side comparison.
        return value.replace(second=0, microsecond=0)

    @model_validator(mode="after")
    def _window_not_empty(self) -> ScreenTimeScheduleCreate:
        if self.start_local_time == self.end_local_time:
            raise ValueError(
                "start_local_time and end_local_time must differ. "
                "An end before the start means the window crosses midnight."
            )
        if self.action is ScheduleAction.allow_allowlisted_only and not self.allowlisted_packages:
            raise ValueError("allow_allowlisted_only requires at least one allowlisted package.")
        return self


class ScreenTimeScheduleUpdate(VersionedUpdate):
    weekday: Weekday | None = None
    start_local_time: time | None = None
    end_local_time: time | None = None
    action: ScheduleAction | None = None
    allowlisted_packages: list[str] | None = Field(default=None, max_length=MAX_ALLOWLIST_PACKAGES)
    enabled: bool | None = None

    @field_validator("allowlisted_packages")
    @classmethod
    def _packages(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return sorted({validate_package_identifier(item) for item in value})


class ScreenTimeScheduleOut(OutSchema):
    id: uuid.UUID
    policy_id: uuid.UUID
    weekday: Weekday
    start_local_time: time
    end_local_time: time
    action: ScheduleAction
    allowlisted_packages: list[str]
    enabled: bool
    crosses_midnight: bool = False


class ScreenTimePolicyCreate(SchemaBase):
    name: str = Field(min_length=1, max_length=80)
    daily_limit_seconds: int | None = Field(default=None, ge=0, le=86_400)
    timezone: str | None = Field(
        default=None, max_length=64, description="Defaults to the child's timezone."
    )
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=1000)
    device_id: uuid.UUID | None = None
    schedules: list[ScreenTimeScheduleCreate] = Field(
        default_factory=list, max_length=MAX_SCHEDULES_PER_POLICY
    )

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str | None) -> str | None:
        return validate_timezone(value) if value else value

    @model_validator(mode="after")
    def _something_to_enforce(self) -> ScreenTimePolicyCreate:
        if self.daily_limit_seconds is None and not self.schedules:
            raise ValueError(
                "A policy must set daily_limit_seconds, define at least one schedule, or both."
            )
        return self


class ScreenTimePolicyUpdate(VersionedUpdate):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    daily_limit_seconds: int | None = Field(default=None, ge=0, le=86_400)
    timezone: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=1000)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str | None) -> str | None:
        return validate_timezone(value) if value else value


class ScreenTimePolicyOut(OutSchema):
    id: uuid.UUID
    child_profile_id: uuid.UUID
    device_id: uuid.UUID | None
    name: str
    daily_limit_seconds: int | None
    timezone: str
    enabled: bool
    priority: int
    revision: int
    created_at: datetime
    updated_at: datetime
    schedules: list[ScreenTimeScheduleOut] = Field(default_factory=list)


class ScreenTimePolicyCreated(PolicyMutationResult):
    policy_id: uuid.UUID
    policy: ScreenTimePolicyOut


# ---------------------------------------------------------------------------
# Website restrictions (feature-gated)
# ---------------------------------------------------------------------------
class WebsiteRestrictionCreate(SchemaBase):
    domain: str = Field(max_length=253, examples=["example.com"])
    mode: WebsiteRestrictionMode = WebsiteRestrictionMode.blocklist
    enabled: bool = True

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        return validate_domain(value)


class WebsiteRestrictionOut(OutSchema):
    id: uuid.UUID
    child_profile_id: uuid.UUID
    domain: str
    mode: WebsiteRestrictionMode
    enabled: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Parent-facing policy bundle and device-facing snapshot
# ---------------------------------------------------------------------------
class DeviceSyncStateOut(OutSchema):
    device_id: uuid.UUID
    device_label: str
    policy_version: int
    applied_policy_version: int | None
    sync_status: SyncStatus
    detail: str | None = None
    reported_at: datetime | None = None


class PolicyBundleOut(OutSchema):
    """Everything the Parent App needs to render a child's policy screen."""

    child_profile_id: uuid.UUID
    policy_version: int
    app_restrictions: list[AppRestrictionOut] = Field(default_factory=list)
    screen_time_policies: list[ScreenTimePolicyOut] = Field(default_factory=list)
    website_restrictions: list[WebsiteRestrictionOut] = Field(default_factory=list)
    website_restrictions_enabled: bool = False
    #: Per-device truth about what has actually been applied.
    device_sync_states: list[DeviceSyncStateOut] = Field(default_factory=list)
    #: Human-readable notes, e.g. "app blocking unsupported on 1 device".
    capability_warnings: list[str] = Field(default_factory=list)


class PolicySnapshotRestriction(OutSchema):
    package_identifier: str
    action: RestrictionAction
    daily_limit_seconds: int | None = None


class PolicySnapshotSchedule(OutSchema):
    weekday: Weekday
    start_local_time: time
    end_local_time: time
    action: ScheduleAction
    allowlisted_packages: list[str] = Field(default_factory=list)
    crosses_midnight: bool = False


class PolicySnapshotScreenTime(OutSchema):
    policy_id: uuid.UUID
    name: str
    daily_limit_seconds: int | None
    timezone: str
    priority: int
    schedules: list[PolicySnapshotSchedule] = Field(default_factory=list)


class DevicePolicySnapshot(OutSchema):
    """The authoritative, device-scoped policy document.

    The Child App applies this and reports back with
    ``POST /device/commands/{id}/result`` including ``applied_policy_version``.
    Precedence is already resolved server-side, so the device does not have to
    reason about overlapping policies.
    """

    device_id: uuid.UUID
    child_profile_id: uuid.UUID
    policy_version: int
    generated_at: datetime
    timezone: str
    app_restrictions: list[PolicySnapshotRestriction] = Field(default_factory=list)
    screen_time_policies: list[PolicySnapshotScreenTime] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    #: Server-side notes for the device, e.g. which features are disabled.
    notes: list[str] = Field(default_factory=list)
