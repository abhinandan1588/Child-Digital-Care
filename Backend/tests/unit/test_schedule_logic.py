"""Schedule, timezone and DST handling."""

from __future__ import annotations

from datetime import UTC, datetime, time

import pytest

from app.core.errors import Conflict
from app.db.enums import Weekday
from app.services.policy_service import (
    MINUTES_PER_DAY,
    schedule_windows,
    validate_no_overlap,
)
from app.utils.time import (
    ensure_utc,
    is_valid_timezone,
    local_date_for,
    local_window_to_utc,
    window_crosses_midnight,
)

pytestmark = pytest.mark.unit


class TestWindows:
    def test_same_day_window(self) -> None:
        windows = schedule_windows(time(9, 0), time(17, 0))
        assert windows == [type(windows[0])(540, 1020)]

    def test_midnight_crossing_window_extends_past_the_day(self) -> None:
        """A 21:00-07:00 bedtime is one continuous range, not two pieces."""
        assert window_crosses_midnight(time(21, 0), time(7, 0)) is True
        windows = schedule_windows(time(21, 0), time(7, 0))
        assert len(windows) == 1
        assert windows[0].start == 21 * 60
        assert windows[0].end == 7 * 60 + MINUTES_PER_DAY

    def test_overlap_detection_within_a_weekday(self) -> None:
        with pytest.raises(Conflict) as exc:
            validate_no_overlap(
                [
                    (Weekday.monday, time(20, 0), time(22, 0)),
                    (Weekday.monday, time(21, 0), time(23, 0)),
                ]
            )
        assert "overlap" in str(exc.value).lower()

    def test_adjacent_windows_do_not_overlap(self) -> None:
        validate_no_overlap(
            [
                (Weekday.monday, time(18, 0), time(20, 0)),
                (Weekday.monday, time(20, 0), time(22, 0)),
            ]
        )

    def test_same_times_on_different_weekdays_are_fine(self) -> None:
        validate_no_overlap(
            [
                (Weekday.monday, time(21, 0), time(7, 0)),
                (Weekday.tuesday, time(21, 0), time(7, 0)),
            ]
        )

    def test_midnight_crossing_windows_on_the_same_day_overlap(self) -> None:
        with pytest.raises(Conflict):
            validate_no_overlap(
                [
                    (Weekday.friday, time(22, 0), time(6, 0)),
                    (Weekday.friday, time(23, 0), time(5, 0)),
                ]
            )


class TestTimezones:
    def test_iana_validation(self) -> None:
        assert is_valid_timezone("Europe/London")
        assert is_valid_timezone("Pacific/Auckland")
        assert not is_valid_timezone("Europe/Nowhere")
        assert not is_valid_timezone("BST")

    def test_bedtime_keeps_its_local_hour_across_dst(self) -> None:
        """21:00 local must stay 21:00 local, which means the UTC instant moves."""
        from datetime import date

        winter_start, _ = local_window_to_utc(
            date(2026, 1, 15), time(21, 0), time(7, 0), "Europe/London"
        )
        summer_start, _ = local_window_to_utc(
            date(2026, 7, 15), time(21, 0), time(7, 0), "Europe/London"
        )
        assert winter_start.hour == 21  # GMT
        assert summer_start.hour == 20  # BST is UTC+1

    def test_midnight_crossing_window_ends_next_day(self) -> None:
        from datetime import date

        start, end = local_window_to_utc(
            date(2026, 3, 10), time(21, 0), time(7, 0), "Europe/London"
        )
        assert end > start
        assert (end - start).total_seconds() == 10 * 3600

    def test_local_date_differs_from_utc_date_near_midnight(self) -> None:
        """A device in Auckland legitimately reports 'tomorrow' in UTC terms."""
        moment = datetime(2026, 6, 1, 23, 30, tzinfo=UTC)
        assert local_date_for("Pacific/Auckland", at=moment).day == 2
        assert local_date_for("UTC", at=moment).day == 1

    def test_naive_datetime_is_treated_as_utc(self) -> None:
        naive = datetime(2026, 6, 1, 12, 0)
        assert ensure_utc(naive).tzinfo is UTC
