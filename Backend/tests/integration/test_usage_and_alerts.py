"""Usage ingestion, reporting honesty, alerts, and notification preferences."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.utils.time import local_date_for, utcnow
from tests.conftest import API

pytestmark = pytest.mark.integration


def today_local() -> str:
    return local_date_for("Europe/London").isoformat()


def days_ago(count: int) -> str:
    return (local_date_for("Europe/London") - timedelta(days=count)).isoformat()


def summary_payload(local_date: str, total: int = 3600) -> dict:
    return {
        "local_date": local_date,
        "timezone": "Europe/London",
        "total_screen_time_seconds": total,
        "unlock_count": 42,
        "category_totals": {"social": 1200, "games": 900},
        "app_summaries": [
            {
                "package_identifier": "com.example.video",
                "display_label": "Example Video",
                "category": "video",
                "foreground_seconds": 1800,
                "launch_count": 9,
            },
            {
                "package_identifier": "com.example.game",
                "display_label": "Example Game",
                "category": "games",
                "foreground_seconds": 900,
            },
        ],
        "source_app_version": "1.0.0",
    }


async def test_usage_submission_and_report(client, family) -> None:
    submitted = await client.post(
        f"{API}/device/usage/daily-summary",
        json=summary_payload(today_local()),
        headers=family.device.headers,
    )
    assert submitted.status_code == 200
    assert submitted.json()["data"]["accepted"] == 1

    overview = await client.get(
        f"{API}/children/{family.child_id}/usage", headers=family.parent.headers
    )
    assert overview.status_code == 200
    data = overview.json()["data"]
    assert data["total_screen_time_seconds"] == 3600
    # The API always labels these numbers as device-reported.
    assert data["device_reported"] is True
    assert data["days_with_data"] == 1
    assert len(data["days_missing_data"]) == 6
    assert "incomplete" in data["data_completeness_note"]

    apps = await client.get(
        f"{API}/children/{family.child_id}/usage/apps?local_date={today_local()}",
        headers=family.parent.headers,
    )
    assert apps.status_code == 200
    breakdown = apps.json()["data"][0]["app_summaries"]
    assert breakdown[0]["package_identifier"] == "com.example.video"


async def test_resubmitting_a_day_replaces_rather_than_doubles(client, family) -> None:
    """Retry safety: the Child App can resend a day without inflating totals."""
    date = today_local()
    await client.post(
        f"{API}/device/usage/daily-summary",
        json=summary_payload(date, total=3600),
        headers=family.device.headers,
    )
    second = await client.post(
        f"{API}/device/usage/daily-summary",
        json=summary_payload(date, total=5400),
        headers=family.device.headers,
    )
    assert second.json()["data"]["updated"] == 1

    overview = await client.get(
        f"{API}/children/{family.child_id}/usage", headers=family.parent.headers
    )
    assert overview.json()["data"]["total_screen_time_seconds"] == 5400

    apps = await client.get(
        f"{API}/children/{family.child_id}/usage/apps?local_date={date}",
        headers=family.parent.headers,
    )
    packages = [item["package_identifier"] for item in apps.json()["data"][0]["app_summaries"]]
    assert len(packages) == len(set(packages))


async def test_backfill_batch_with_partial_rejection(client, family) -> None:
    response = await client.post(
        f"{API}/device/usage/app-summaries",
        json={
            "summaries": [
                summary_payload(days_ago(1)),
                summary_payload(days_ago(2)),
                summary_payload("2099-01-01"),
            ]
        },
        headers=family.device.headers,
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["accepted"] == 2
    assert data["rejected"] == 1
    assert data["rejection_reasons"]["2099-01-01"] == "DATE_IN_FUTURE"


async def test_duplicate_packages_in_one_day_are_rejected(client, family) -> None:
    payload = summary_payload(today_local())
    payload["app_summaries"].append(payload["app_summaries"][0])
    response = await client.post(
        f"{API}/device/usage/daily-summary", json=payload, headers=family.device.headers
    )
    assert response.status_code == 422


async def test_usage_range_is_bounded(client, family) -> None:
    response = await client.get(
        f"{API}/children/{family.child_id}/usage?start=2020-01-01&end=2026-01-01",
        headers=family.parent.headers,
    )
    assert response.status_code == 422


async def test_device_events_create_a_deduplicated_alert(client, family) -> None:
    occurred = utcnow().isoformat()
    payload = {
        "events": [
            {
                "event_type": "uninstall_attempted",
                "occurred_at": occurred,
                "deduplication_key": "uninstall-0000001",
                "payload": {"package_identifier": "com.childdigitalcare.child"},
            }
        ]
    }
    first = await client.post(f"{API}/device/events", json=payload, headers=family.device.headers)
    assert first.status_code == 200
    assert first.json()["data"]["accepted"] == 1
    assert first.json()["data"]["alerts_created"] == 1

    replay = await client.post(f"{API}/device/events", json=payload, headers=family.device.headers)
    assert replay.json()["data"]["duplicates"] == 1
    assert replay.json()["data"]["alerts_created"] == 0

    alerts = await client.get(f"{API}/alerts", headers=family.parent.headers)
    matching = [
        item
        for item in alerts.json()["data"]["items"]
        if item["alert_type"] == "uninstall_attempted"
    ]
    assert len(matching) == 1
    assert matching[0]["severity"] == "high"


async def test_alert_can_be_acknowledged_but_not_reopened(client, family) -> None:
    await client.post(
        f"{API}/device/events",
        json={
            "events": [
                {
                    "event_type": "policy_apply_failed",
                    "occurred_at": utcnow().isoformat(),
                    "deduplication_key": "apply-failed-0001",
                }
            ]
        },
        headers=family.device.headers,
    )
    alerts = await client.get(f"{API}/alerts", headers=family.parent.headers)
    alert_id = alerts.json()["data"]["items"][0]["id"]

    acknowledged = await client.patch(
        f"{API}/alerts/{alert_id}",
        json={"status": "acknowledged"},
        headers=family.parent.headers,
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["data"]["acknowledged_at"] is not None

    resolved = await client.patch(
        f"{API}/alerts/{alert_id}", json={"status": "resolved"}, headers=family.parent.headers
    )
    assert resolved.status_code == 200

    reopened = await client.patch(
        f"{API}/alerts/{alert_id}", json={"status": "open"}, headers=family.parent.headers
    )
    assert reopened.status_code == 422


async def test_alerts_are_cursor_paginated(client, family) -> None:
    events = [
        {
            "event_type": "blocked_app_launch_attempt",
            "occurred_at": (utcnow() - timedelta(days=offset)).isoformat(),
            "deduplication_key": f"blocked-{offset:06d}",
        }
        for offset in range(5)
    ]
    await client.post(
        f"{API}/device/events", json={"events": events}, headers=family.device.headers
    )

    first = await client.get(f"{API}/alerts?limit=2", headers=family.parent.headers)
    assert first.status_code == 200
    page = first.json()["data"]
    assert len(page["items"]) == 2
    assert page["page_info"]["has_more"] is True

    second = await client.get(
        f"{API}/alerts?limit=2&cursor={page['page_info']['next_cursor']}",
        headers=family.parent.headers,
    )
    assert second.status_code == 200
    first_ids = {item["id"] for item in page["items"]}
    second_ids = {item["id"] for item in second.json()["data"]["items"]}
    assert not (first_ids & second_ids)


async def test_malformed_cursor_is_a_validation_error(client, family) -> None:
    response = await client.get(f"{API}/alerts?cursor=not-a-cursor", headers=family.parent.headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_security_notifications_cannot_be_disabled(client, family) -> None:
    response = await client.patch(
        f"{API}/notification-preferences",
        json={"preferences": [{"notification_type": "security", "enabled": False}]},
        headers=family.parent.headers,
    )
    assert response.status_code == 422

    listed = await client.get(f"{API}/notification-preferences", headers=family.parent.headers)
    security = next(
        item for item in listed.json()["data"] if item["notification_type"] == "security"
    )
    assert security["always_delivered"] is True
    assert security["enabled"] is True


async def test_quiet_hours_round_trip(client, family) -> None:
    response = await client.patch(
        f"{API}/notification-preferences",
        json={
            "preferences": [
                {
                    "notification_type": "alert_raised",
                    "enabled": True,
                    "quiet_hours": {
                        "timezone": "Europe/London",
                        "start": "22:00:00",
                        "end": "07:00:00",
                    },
                }
            ]
        },
        headers=family.parent.headers,
    )
    assert response.status_code == 200
    updated = next(
        item for item in response.json()["data"] if item["notification_type"] == "alert_raised"
    )
    assert updated["quiet_hours"]["timezone"] == "Europe/London"
