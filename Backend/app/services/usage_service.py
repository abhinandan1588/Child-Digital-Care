"""Usage-summary ingestion and parent-facing reports.

Everything here is **device-reported**. The server validates plausibility
(a day cannot hold more than 86 400 seconds, a date cannot be in the future
relative to the device's own timezone, a backfill cannot reach arbitrarily far
back) and then stores it, labelled as reported. It never presents these numbers
as independently verified.

Re-submitting a day is an upsert, which makes the Child App's retry logic
trivial: send the day again and the totals are replaced.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.logging import get_logger
from app.db.enums import NotificationType, UsageCategory
from app.db.models.device import Device
from app.db.models.family import ChildProfile
from app.db.models.usage import AppUsageSummary, UsageDailySummary
from app.schemas.usage import MAX_BACKFILL_DAYS
from app.services import notification_service, outbox_service
from app.services.outbox_service import OutboxTopic
from app.utils.time import local_date_for, utcnow

logger = get_logger(__name__)

#: Only this many app rows are kept per day. The tail is aggregated into
#: "other", which keeps the table bounded and is all a report needs.
MAX_STORED_APP_ROWS = 100
TOP_APPS_IN_OVERVIEW = 10


@dataclass(slots=True)
class SubmittedDay:
    local_date: date
    timezone: str
    total_screen_time_seconds: int
    unlock_count: int | None
    category_totals: dict[str, int]
    app_summaries: list[tuple[str, str | None, str | None, int, int | None]]
    source_app_version: str | None


@dataclass(slots=True)
class IngestOutcome:
    accepted: int = 0
    updated: int = 0
    rejected: int = 0
    rejected_dates: list[date] = field(default_factory=list)
    rejection_reasons: dict[str, str] = field(default_factory=dict)


def _validate_day(day: SubmittedDay, *, device_timezone: str) -> str | None:
    """Return a rejection reason, or ``None`` when the day is acceptable."""
    # Compare against the date in the *device's reported* timezone: a device in
    # Auckland legitimately reports a date that is "tomorrow" in UTC.
    today_local = local_date_for(day.timezone or device_timezone)
    if day.local_date > today_local:
        return "DATE_IN_FUTURE"
    if day.local_date < today_local - timedelta(days=MAX_BACKFILL_DAYS):
        return "DATE_TOO_OLD"
    if day.total_screen_time_seconds > 86_400:
        return "TOTAL_IMPLAUSIBLE"
    if sum(day.category_totals.values()) > 86_400:
        return "CATEGORY_TOTALS_IMPLAUSIBLE"
    return None


async def ingest_daily_summaries(
    session: AsyncSession,
    *,
    device: Device,
    child: ChildProfile,
    days: list[SubmittedDay],
) -> IngestOutcome:
    outcome = IngestOutcome()
    retention_cutoff = utcnow() + timedelta(days=settings.retention_usage_summaries_days)

    existing_rows = await session.execute(
        select(UsageDailySummary)
        .options(selectinload(UsageDailySummary.app_summaries))
        .where(
            UsageDailySummary.device_id == device.id,
            UsageDailySummary.local_date.in_([day.local_date for day in days]),
        )
    )
    existing = {row.local_date: row for row in existing_rows.scalars().unique().all()}

    for day in days:
        reason = _validate_day(day, device_timezone=device.timezone)
        if reason is not None:
            outcome.rejected += 1
            outcome.rejected_dates.append(day.local_date)
            outcome.rejection_reasons[day.local_date.isoformat()] = reason
            logger.info("usage_day_rejected", reason=reason, device_id=str(device.id))
            continue

        row = existing.get(day.local_date)
        if row is None:
            row = UsageDailySummary(
                family_id=device.family_id,
                child_profile_id=device.child_profile_id,
                device_id=device.id,
                local_date=day.local_date,
            )
            session.add(row)
            existing[day.local_date] = row
            outcome.accepted += 1
        else:
            outcome.updated += 1
            # Replace the previous breakdown rather than merging: the device
            # always sends a whole day, so merging would double-count.
            for app_row in list(row.app_summaries):
                await session.delete(app_row)

        row.timezone = day.timezone
        row.total_screen_time_seconds = day.total_screen_time_seconds
        row.unlock_count = day.unlock_count
        row.category_totals = dict(day.category_totals)
        row.source_app_version = day.source_app_version
        row.received_at = utcnow()
        row.updated_at = utcnow()
        row.retention_expires_at = retention_cutoff
        await session.flush()

        sorted_apps = sorted(day.app_summaries, key=lambda item: item[3], reverse=True)
        kept = sorted_apps[:MAX_STORED_APP_ROWS]
        overflow_seconds = sum(item[3] for item in sorted_apps[MAX_STORED_APP_ROWS:])

        for package, label, category, seconds, launches in kept:
            session.add(
                AppUsageSummary(
                    daily_summary_id=row.id,
                    package_identifier=package,
                    display_label=label,
                    category=category,
                    foreground_seconds=min(seconds, 86_400),
                    launch_count=launches,
                )
            )
        if overflow_seconds > 0:
            session.add(
                AppUsageSummary(
                    daily_summary_id=row.id,
                    package_identifier="other.aggregated",
                    display_label="Other apps",
                    category=UsageCategory.other.value,
                    foreground_seconds=min(overflow_seconds, 86_400),
                )
            )

    device.last_seen_at = utcnow()
    await session.flush()

    if outcome.accepted or outcome.updated:
        await outbox_service.enqueue(
            session,
            topic=OutboxTopic.USAGE_SUMMARY_RECEIVED,
            aggregate_type="device",
            aggregate_id=device.id,
            family_id=device.family_id,
            payload={
                "device_id": str(device.id),
                "child_profile_id": str(child.id),
                "days_accepted": outcome.accepted,
                "days_updated": outcome.updated,
            },
        )
    return outcome


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
async def list_daily_summaries(
    session: AsyncSession,
    *,
    child_profile_id: uuid.UUID,
    start: date,
    end: date,
    device_id: uuid.UUID | None = None,
) -> list[UsageDailySummary]:
    statement = select(UsageDailySummary).where(
        UsageDailySummary.child_profile_id == child_profile_id,
        UsageDailySummary.local_date >= start,
        UsageDailySummary.local_date <= end,
    )
    if device_id is not None:
        statement = statement.where(UsageDailySummary.device_id == device_id)
    result = await session.execute(statement.order_by(UsageDailySummary.local_date.desc()))
    return list(result.scalars().all())


async def get_daily_summary_detail(
    session: AsyncSession,
    *,
    child_profile_id: uuid.UUID,
    local_date: date,
    device_id: uuid.UUID | None = None,
) -> list[UsageDailySummary]:
    statement = (
        select(UsageDailySummary)
        .options(selectinload(UsageDailySummary.app_summaries))
        .where(
            UsageDailySummary.child_profile_id == child_profile_id,
            UsageDailySummary.local_date == local_date,
        )
    )
    if device_id is not None:
        statement = statement.where(UsageDailySummary.device_id == device_id)
    result = await session.execute(statement)
    return list(result.scalars().unique().all())


@dataclass(slots=True)
class UsageOverview:
    range_start: date
    range_end: date
    timezone: str
    total_screen_time_seconds: int
    average_daily_seconds: int
    days_with_data: int
    days_missing_data: list[date]
    category_totals: dict[str, int]
    top_apps: list[tuple[str, str | None, str | None, int, int | None]]
    data_completeness_note: str | None


async def build_overview(
    session: AsyncSession,
    *,
    child: ChildProfile,
    start: date,
    end: date,
    device_id: uuid.UUID | None = None,
) -> UsageOverview:
    """Aggregate a date range, and say plainly where data is missing.

    Summing only the days that happen to be present would understate usage and
    look like a fact. The missing dates are returned so the Parent App can show
    "incomplete" instead.
    """
    summaries = await list_daily_summaries(
        session, child_profile_id=child.id, start=start, end=end, device_id=device_id
    )

    per_day_totals: dict[date, int] = defaultdict(int)
    category_totals: dict[str, int] = defaultdict(int)
    for row in summaries:
        per_day_totals[row.local_date] += row.total_screen_time_seconds
        for category, seconds in (row.category_totals or {}).items():
            category_totals[str(category)] += int(seconds)

    all_dates = _date_range(start, end)
    missing = [day for day in all_dates if day not in per_day_totals]
    total = sum(per_day_totals.values())
    days_with_data = len(per_day_totals)

    app_result = await session.execute(
        select(
            AppUsageSummary.package_identifier,
            func.max(AppUsageSummary.display_label),
            func.max(AppUsageSummary.category),
            func.sum(AppUsageSummary.foreground_seconds),
            func.sum(AppUsageSummary.launch_count),
        )
        .join(
            UsageDailySummary,
            UsageDailySummary.id == AppUsageSummary.daily_summary_id,
        )
        .where(
            UsageDailySummary.child_profile_id == child.id,
            UsageDailySummary.local_date >= start,
            UsageDailySummary.local_date <= end,
            *([UsageDailySummary.device_id == device_id] if device_id else []),
        )
        .group_by(AppUsageSummary.package_identifier)
        .order_by(func.sum(AppUsageSummary.foreground_seconds).desc())
        .limit(TOP_APPS_IN_OVERVIEW)
    )
    top_apps = [
        (package, label, category, int(seconds or 0), int(launches) if launches else None)
        for package, label, category, seconds, launches in app_result.all()
    ]

    note: str | None = None
    if missing:
        note = (
            f"{len(missing)} of {len(all_dates)} day(s) in this range have not been reported "
            "by any device yet, so the totals are incomplete."
        )

    return UsageOverview(
        range_start=start,
        range_end=end,
        timezone=child.timezone,
        total_screen_time_seconds=total,
        average_daily_seconds=(total // days_with_data) if days_with_data else 0,
        days_with_data=days_with_data,
        days_missing_data=missing,
        category_totals=dict(category_totals),
        top_apps=top_apps,
        data_completeness_note=note,
    )


def _date_range(start: date, end: date) -> list[date]:
    if end < start:
        return []
    span = (end - start).days
    return [start + timedelta(days=offset) for offset in range(span + 1)]


async def purge_expired_summaries(session: AsyncSession, *, limit: int = 1000) -> int:
    """Delete summaries past their retention deadline. Run by the scheduler."""
    now = utcnow()
    result = await session.execute(
        select(UsageDailySummary.id)
        .where(
            UsageDailySummary.retention_expires_at.is_not(None),
            UsageDailySummary.retention_expires_at <= now,
        )
        .limit(limit)
    )
    ids = [row[0] for row in result.all()]
    if not ids:
        return 0
    from sqlalchemy import delete

    await session.execute(delete(UsageDailySummary).where(UsageDailySummary.id.in_(ids)))
    return len(ids)


async def notify_usage_received(session: AsyncSession, *, family_id: uuid.UUID) -> None:
    await notification_service.notify_family_guardians(
        session, family_id=family_id, notification_type=NotificationType.weekly_report
    )


def coerce_datetime(value: datetime | None) -> datetime:
    return value or utcnow()
