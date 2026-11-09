"""Usage-summary ingestion and parent-facing report schemas."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import Field, field_validator, model_validator

from app.db.enums import UsageCategory
from app.schemas.common import OutSchema, SchemaBase, validate_package_identifier, validate_timezone

MAX_APP_SUMMARIES_PER_DAY = 300
#: A day cannot contain more screen time than it has seconds; the server
#: rejects anything above this rather than storing an implausible total.
SECONDS_PER_DAY = 86_400
#: How far back a device may submit summaries. Older data is rejected so a
#: device with a badly wrong clock cannot rewrite history.
MAX_BACKFILL_DAYS = 30


class AppUsageItem(SchemaBase):
    package_identifier: str = Field(max_length=255)
    display_label: str | None = Field(default=None, max_length=120)
    category: UsageCategory | None = None
    foreground_seconds: int = Field(ge=0, le=SECONDS_PER_DAY)
    launch_count: int | None = Field(default=None, ge=0, le=5000)

    @field_validator("package_identifier")
    @classmethod
    def _package(cls, value: str) -> str:
        return validate_package_identifier(value)


class DailySummarySubmit(SchemaBase):
    """One day of aggregate usage, as computed on the device.

    This is *device-reported* data. It is validated for plausibility and
    labelled as reported throughout the API; the server cannot and does not
    claim it is cryptographically proven.
    """

    local_date: date
    timezone: str = Field(max_length=64)
    total_screen_time_seconds: int = Field(ge=0, le=SECONDS_PER_DAY)
    unlock_count: int | None = Field(default=None, ge=0, le=5000)
    category_totals: dict[UsageCategory, int] = Field(default_factory=dict)
    app_summaries: list[AppUsageItem] = Field(
        default_factory=list, max_length=MAX_APP_SUMMARIES_PER_DAY
    )
    source_app_version: str | None = Field(default=None, max_length=32)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        return validate_timezone(value)

    @field_validator("category_totals")
    @classmethod
    def _category_totals_sane(cls, value: dict[UsageCategory, int]) -> dict[UsageCategory, int]:
        for category, seconds in value.items():
            if seconds < 0 or seconds > SECONDS_PER_DAY:
                raise ValueError(f"category_totals[{category}] is out of range.")
        return value

    @model_validator(mode="after")
    def _totals_consistent(self) -> DailySummarySubmit:
        if sum(self.category_totals.values()) > SECONDS_PER_DAY:
            raise ValueError("category_totals sum exceeds one day.")
        if sum(item.foreground_seconds for item in self.app_summaries) > SECONDS_PER_DAY * 2:
            # Allowing 2x: concurrent foreground attribution differs per OEM, so
            # a small overlap is normal, a 2x overshoot is not.
            raise ValueError("app_summaries foreground time is implausible for one day.")
        packages = [item.package_identifier for item in self.app_summaries]
        if len(packages) != len(set(packages)):
            raise ValueError("app_summaries contains duplicate package identifiers.")
        return self


class DailySummaryBatchSubmit(SchemaBase):
    summaries: list[DailySummarySubmit] = Field(min_length=1, max_length=MAX_BACKFILL_DAYS)

    @model_validator(mode="after")
    def _unique_dates(self) -> DailySummaryBatchSubmit:
        dates = [item.local_date for item in self.summaries]
        if len(dates) != len(set(dates)):
            raise ValueError("summaries contains duplicate local_date values.")
        return self


class UsageIngestResult(OutSchema):
    accepted: int
    updated: int
    rejected: int = 0
    rejected_dates: list[date] = Field(default_factory=list)
    rejection_reasons: dict[str, str] = Field(default_factory=dict)


class AppUsageOut(OutSchema):
    package_identifier: str
    display_label: str | None
    category: str | None
    foreground_seconds: int
    launch_count: int | None


class DailySummaryOut(OutSchema):
    id: uuid.UUID
    device_id: uuid.UUID
    child_profile_id: uuid.UUID
    local_date: date
    timezone: str
    total_screen_time_seconds: int
    unlock_count: int | None
    category_totals: dict[str, int]
    received_at: datetime
    #: Always true. Present so client teams cannot forget that these numbers
    #: come from the device, not from server-side observation.
    device_reported: bool = True


class DailySummaryDetailOut(DailySummaryOut):
    app_summaries: list[AppUsageOut] = Field(default_factory=list)


class UsageOverviewOut(OutSchema):
    child_profile_id: uuid.UUID
    range_start: date
    range_end: date
    timezone: str
    total_screen_time_seconds: int
    average_daily_seconds: int
    days_with_data: int
    days_missing_data: list[date] = Field(default_factory=list)
    category_totals: dict[str, int] = Field(default_factory=dict)
    top_apps: list[AppUsageOut] = Field(default_factory=list)
    device_reported: bool = True
    #: Set when some devices have not reported for the period, so the Parent App
    #: can say "incomplete" instead of showing a misleadingly low total.
    data_completeness_note: str | None = None
