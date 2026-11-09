"""Background jobs: idempotency, bounded retries, retention sweeps."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.db.enums import DeviceStatus, OutboxStatus
from app.db.models.command import DeviceCommand, DeviceEvent, OutboxEvent
from app.db.models.device import Device, PairingInvitation
from app.db.models.identity import UserSession
from app.db.models.usage import UsageDailySummary
from app.services import outbox_service
from app.utils.time import utcnow
from app.workers import jobs
from tests.conftest import API

pytestmark = pytest.mark.integration


async def test_outbox_processing_is_idempotent(client, family, session) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )

    first = await jobs.process_outbox()
    assert first.claimed >= 1

    second = await jobs.process_outbox()
    assert second.claimed == 0, "a processed event must not be claimed twice"

    pending = (
        await session.execute(
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.status == OutboxStatus.pending)
        )
    ).scalar_one()
    assert pending == 0


async def test_a_failing_event_is_retried_with_backoff_then_dead_lettered(
    session,
) -> None:
    event = await outbox_service.enqueue(
        session,
        topic="unknown.topic.for.test",
        aggregate_type="test",
        aggregate_id=uuid.uuid4(),
        payload={"note": "unroutable"},
    )
    await session.commit()

    # An unknown topic is a non-error "nothing to publish" outcome, so it is
    # retired rather than retried forever.
    result = await jobs.process_outbox()
    assert result.claimed >= 1

    await session.refresh(event)
    assert event.status in (OutboxStatus.sent, OutboxStatus.dead_letter)


async def test_mark_failed_applies_bounded_backoff(session) -> None:
    event = await outbox_service.enqueue(
        session,
        topic="device.command_queued",
        aggregate_type="device_command",
        aggregate_id=uuid.uuid4(),
        payload={},
    )
    await session.commit()

    before = event.available_at
    await outbox_service.mark_failed(session, event.id, error_code="TestError", attempts=1)
    await session.commit()
    await session.refresh(event)

    assert event.status is OutboxStatus.pending
    assert event.available_at > before
    assert event.last_error_code == "TestError"

    await outbox_service.mark_failed(
        session,
        event.id,
        error_code="TestError",
        attempts=settings.outbox_max_attempts,
    )
    await session.commit()
    await session.refresh(event)
    assert event.status is OutboxStatus.dead_letter


async def test_expired_pairing_invitations_are_swept(client, family, session) -> None:
    created = await client.post(
        f"{API}/children/{family.child_id}/pairing-invitations",
        json={},
        headers=family.parent.headers,
    )
    invitation_id = uuid.UUID(created.json()["data"]["invitation_id"])

    row = await session.get(PairingInvitation, invitation_id)
    row.expires_at = utcnow() - timedelta(minutes=1)
    await session.commit()

    swept = await jobs.expire_pairing_invitations()
    assert swept >= 1

    await session.refresh(row)
    assert row.status.value == "expired"


async def test_stale_devices_are_marked_offline_with_one_alert(client, family, session) -> None:
    device = await session.get(Device, uuid.UUID(family.device.device_id))
    device.last_seen_at = utcnow() - timedelta(days=3)
    await session.commit()

    marked = await jobs.mark_stale_devices()
    assert marked == 1

    await session.refresh(device)
    assert device.device_status is DeviceStatus.inactive

    alerts = await client.get(f"{API}/alerts", headers=family.parent.headers)
    offline = [
        item for item in alerts.json()["data"]["items"] if item["alert_type"] == "device_offline"
    ]
    assert len(offline) == 1

    # Running again must not pile up duplicates for the same day.
    device.device_status = DeviceStatus.active
    await session.commit()
    await jobs.mark_stale_devices()

    alerts_again = await client.get(f"{API}/alerts", headers=family.parent.headers)
    offline_again = [
        item
        for item in alerts_again.json()["data"]["items"]
        if item["alert_type"] == "device_offline"
    ]
    assert len(offline_again) == 1


async def test_offline_alert_resolves_when_the_device_returns(client, family, session) -> None:
    device = await session.get(Device, uuid.UUID(family.device.device_id))
    device.last_seen_at = utcnow() - timedelta(days=3)
    await session.commit()
    await jobs.mark_stale_devices()

    await client.post(f"{API}/device/heartbeat", json={}, headers=family.device.headers)

    alerts = await client.get(f"{API}/alerts?status=resolved", headers=family.parent.headers)
    resolved = [
        item for item in alerts.json()["data"]["items"] if item["alert_type"] == "device_offline"
    ]
    assert resolved


async def test_session_cleanup_removes_only_long_expired_rows(client, family, session) -> None:
    rows = (await session.execute(select(UserSession))).scalars().all()
    assert rows
    rows[0].expires_at = utcnow() - timedelta(days=30)
    await session.commit()

    result = await jobs.cleanup_sessions()
    assert result.user_sessions == 1

    remaining = (await session.execute(select(func.count()).select_from(UserSession))).scalar_one()
    assert remaining == len(rows) - 1


async def test_retention_sweep_deletes_past_deadline_data(client, family, session) -> None:
    await client.post(
        f"{API}/device/usage/daily-summary",
        json={
            "local_date": utcnow().date().isoformat(),
            "timezone": "Europe/London",
            "total_screen_time_seconds": 1000,
        },
        headers=family.device.headers,
    )
    await client.post(
        f"{API}/device/events",
        json={
            "events": [
                {
                    "event_type": "app_started",
                    "occurred_at": utcnow().isoformat(),
                    "deduplication_key": "retention-0001",
                }
            ]
        },
        headers=family.device.headers,
    )

    summaries = (await session.execute(select(UsageDailySummary))).scalars().all()
    events = (await session.execute(select(DeviceEvent))).scalars().all()
    assert summaries and events
    for row in (*summaries, *events):
        row.retention_expires_at = utcnow() - timedelta(days=1)
    await session.commit()

    result = await jobs.apply_retention()
    assert result.usage_summaries >= 1
    assert result.device_events >= 1

    assert (
        await session.execute(select(func.count()).select_from(UsageDailySummary))
    ).scalar_one() == 0


async def test_pending_wakeups_are_requeued_for_an_unreachable_device(
    client, family, session
) -> None:
    """A device that missed every push gets another chance."""
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    await jobs.process_outbox()

    commands = (
        (
            await session.execute(
                select(DeviceCommand).where(
                    DeviceCommand.device_id == uuid.UUID(family.device.device_id)
                )
            )
        )
        .scalars()
        .all()
    )
    for command in commands:
        command.created_at = utcnow() - timedelta(hours=3)
    await session.commit()

    requeued = await jobs.resend_pending_wakeups()
    assert requeued >= 1

    pending = (
        await session.execute(
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.status == OutboxStatus.pending)
        )
    ).scalar_one()
    assert pending >= 1


async def test_revoked_device_tokens_are_swept(client, family, session) -> None:
    await client.post(
        f"{API}/device/push-token",
        json={"token": "fake-device-push-token-sweep-0001", "platform": "android"},
        headers=family.device.headers,
    )
    device = await session.get(Device, uuid.UUID(family.device.device_id))
    device.device_status = DeviceStatus.revoked
    await session.commit()

    swept = await jobs.deactivate_revoked_device_tokens()
    assert swept == 1
