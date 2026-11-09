"""Timezone-aware time helpers.

Rules for this codebase:

* Every stored timestamp is timezone-aware UTC.
* Schedules are stored as *local wall-clock intent* (an IANA timezone plus a
  local time) and are only resolved to an instant when evaluated, so DST
  transitions behave the way a parent expects ("9pm bedtime" stays 9pm).
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Normalise a datetime to UTC, treating naive input as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def in_seconds(seconds: int) -> datetime:
    return utcnow() + timedelta(seconds=seconds)


def in_minutes(minutes: int) -> datetime:
    return utcnow() + timedelta(minutes=minutes)


def in_hours(hours: int) -> datetime:
    return utcnow() + timedelta(hours=hours)


def in_days(days: int) -> datetime:
    return utcnow() + timedelta(days=days)


def is_expired(expires_at: datetime | None, *, at: datetime | None = None) -> bool:
    if expires_at is None:
        return False
    return ensure_utc(expires_at) <= (at or utcnow())


def is_valid_timezone(name: str) -> bool:
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        return False
    return True


def timezone_names() -> set[str]:
    return available_timezones()


def local_date_for(tz_name: str, *, at: datetime | None = None) -> date:
    """The calendar date currently in effect in ``tz_name``."""
    moment = at or utcnow()
    return ensure_utc(moment).astimezone(ZoneInfo(tz_name)).date()


def local_window_to_utc(
    local_date: date, start: time, end: time, tz_name: str
) -> tuple[datetime, datetime]:
    """Resolve a local ``start``-``end`` window on ``local_date`` into UTC instants.

    A window whose end is at or before its start is treated as crossing
    midnight (e.g. a 21:00-07:00 bedtime) and ends on the following day.
    DST gaps/folds are resolved by ``zoneinfo``'s standard behaviour.
    """
    tz = ZoneInfo(tz_name)
    start_local = datetime.combine(local_date, start, tzinfo=tz)
    end_date = local_date if end > start else local_date + timedelta(days=1)
    end_local = datetime.combine(end_date, end, tzinfo=tz)
    return start_local.astimezone(UTC), end_local.astimezone(UTC)


def window_crosses_midnight(start: time, end: time) -> bool:
    return end <= start


def minutes_of_day(value: time) -> int:
    return value.hour * 60 + value.minute


__all__ = [
    "ensure_utc",
    "in_days",
    "in_hours",
    "in_minutes",
    "in_seconds",
    "is_expired",
    "is_valid_timezone",
    "local_date_for",
    "local_window_to_utc",
    "minutes_of_day",
    "timezone_names",
    "utcnow",
    "window_crosses_midnight",
]
