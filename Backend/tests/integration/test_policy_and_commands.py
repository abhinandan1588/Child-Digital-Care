"""Policies, versioning, the transactional outbox, and command lifecycle."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from app.db.enums import CommandStatus, CommandType, OutboxStatus, SyncStatus
from app.db.models.command import DeviceCommand, OutboxEvent
from app.db.models.policy import PolicyVersion
from app.workers import jobs
from tests.conftest import API

pytestmark = pytest.mark.integration


def command_for_version(payload: dict, version: int) -> str:
    """Pick the queued sync command that targets a specific policy version.

    A freshly paired device already has an initial `sync_policies` command for
    version 1, so a test must not assume the first command in the list is the
    one it just caused.
    """
    for item in payload["commands"]:
        if item["payload"].get("target_policy_version") == version:
            return item["command_id"]
    raise AssertionError(
        f"no queued command targets policy version {version}: {payload['commands']}"
    )


async def test_restriction_is_saved_versioned_and_queued(client, family, session) -> None:
    """One transaction: the policy row, the version row, the command, the outbox."""
    response = await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={
            "package_identifier": "com.example.video",
            "display_label": "Example Video",
            "action": "block",
            "enabled": True,
        },
        headers=family.parent.headers,
    )
    assert response.status_code == 201, response.text
    data = response.json()["data"]

    # The server does not claim the app is blocked yet.
    assert data["sync_status"] == "pending_sync"
    assert data["policy_version"] == 2
    assert data["devices_notified"] == 1
    assert len(data["commands_queued"]) == 1

    versions = (
        (
            await session.execute(
                select(PolicyVersion).where(
                    PolicyVersion.child_profile_id == uuid.UUID(family.child_id)
                )
            )
        )
        .scalars()
        .all()
    )
    assert [row.version for row in versions] == [2]
    assert versions[0].change_type == "app_restriction_created"

    command_id = uuid.UUID(data["commands_queued"][0])
    command = await session.get(DeviceCommand, command_id)
    assert command is not None
    assert command.command_type is CommandType.sync_policies
    assert command.status is CommandStatus.queued

    outbox = (
        (
            await session.execute(
                select(OutboxEvent).where(OutboxEvent.status == OutboxStatus.pending)
            )
        )
        .scalars()
        .all()
    )
    topics = {row.topic for row in outbox}
    assert "device.command_queued" in topics
    assert "policy.sync_requested" in topics


async def test_protected_packages_cannot_be_blocked(client, family) -> None:
    response = await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.android.dialer", "action": "block"},
        headers=family.parent.headers,
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "POLICY_CONFLICT"


async def test_time_limit_requires_a_limit(client, family) -> None:
    response = await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.game", "action": "time_limit"},
        headers=family.parent.headers,
    )
    assert response.status_code == 422


async def test_duplicate_restriction_is_rejected(client, family) -> None:
    payload = {"package_identifier": "com.example.video", "action": "block"}
    first = await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json=payload,
        headers=family.parent.headers,
    )
    assert first.status_code == 201
    second = await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json=payload,
        headers=family.parent.headers,
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "ALREADY_EXISTS"


async def test_optimistic_concurrency_on_update(client, family) -> None:
    created = await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    restriction = created.json()["data"]["restriction"]

    stale = await client.patch(
        f"{API}/children/{family.child_id}/app-restrictions/{restriction['id']}",
        json={"enabled": False, "if_revision": restriction["revision"] + 5},
        headers=family.parent.headers,
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "VERSION_CONFLICT"

    fresh = await client.patch(
        f"{API}/children/{family.child_id}/app-restrictions/{restriction['id']}",
        json={"enabled": False, "if_revision": restriction["revision"]},
        headers=family.parent.headers,
    )
    assert fresh.status_code == 200


async def test_screen_time_policy_with_overnight_schedule(client, family) -> None:
    response = await client.post(
        f"{API}/children/{family.child_id}/screen-time-policies",
        json={
            "name": "School nights",
            "daily_limit_seconds": 7200,
            "priority": 100,
            "schedules": [
                {
                    "weekday": "monday",
                    "start_local_time": "21:00:00",
                    "end_local_time": "07:00:00",
                    "action": "block_all",
                    "allowlisted_packages": ["com.google.android.apps.messaging"],
                }
            ],
        },
        headers=family.parent.headers,
    )
    assert response.status_code == 201, response.text
    policy = response.json()["data"]["policy"]
    assert policy["schedules"][0]["crosses_midnight"] is True


async def test_overlapping_schedules_within_a_policy_are_rejected(client, family) -> None:
    response = await client.post(
        f"{API}/children/{family.child_id}/screen-time-policies",
        json={
            "name": "Conflicting",
            "schedules": [
                {
                    "weekday": "monday",
                    "start_local_time": "20:00:00",
                    "end_local_time": "22:00:00",
                },
                {
                    "weekday": "monday",
                    "start_local_time": "21:00:00",
                    "end_local_time": "23:00:00",
                },
            ],
        },
        headers=family.parent.headers,
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SCHEDULE_INVALID"


async def test_device_snapshot_resolves_precedence(client, family) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={
            "package_identifier": "com.example.video",
            "action": "allow",
            "device_id": family.device.device_id,
        },
        headers=family.parent.headers,
    )

    snapshot = await client.get(f"{API}/device/policies/current", headers=family.device.headers)
    assert snapshot.status_code == 200
    data = snapshot.json()["data"]
    entries = [
        item
        for item in data["app_restrictions"]
        if item["package_identifier"] == "com.example.video"
    ]
    # One entry, and the device-scoped override wins.
    assert len(entries) == 1
    assert entries[0]["action"] == "allow"


async def test_command_lifecycle_through_the_device_api(client, family, session) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )

    fetched = await client.get(f"{API}/device/commands", headers=family.device.headers)
    assert fetched.status_code == 200
    commands = fetched.json()["data"]["commands"]
    assert commands, "the device should see the queued policy sync"
    command_id = command_for_version(fetched.json()["data"], 2)

    # Fetching is what marks the command delivered - not a push receipt.
    row = await session.get(DeviceCommand, uuid.UUID(command_id))
    await session.refresh(row)
    assert row.status is CommandStatus.delivered
    assert row.fetched_at is not None

    acknowledged = await client.post(
        f"{API}/device/commands/{command_id}/acknowledge",
        json={},
        headers=family.device.headers,
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["data"]["status"] == "acknowledged"

    result = await client.post(
        f"{API}/device/commands/{command_id}/result",
        json={"result": "succeeded", "applied_policy_version": 2},
        headers=family.device.headers,
    )
    assert result.status_code == 200
    assert result.json()["data"]["status"] == "succeeded"

    # Now, and only now, does the parent see the policy as applied.
    bundle = await client.get(
        f"{API}/children/{family.child_id}/policies", headers=family.parent.headers
    )
    states = bundle.json()["data"]["device_sync_states"]
    assert states[0]["sync_status"] == "synced"
    assert states[0]["applied_policy_version"] == 2


async def test_unsupported_result_is_never_turned_into_success(client, family) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    fetched = await client.get(f"{API}/device/commands", headers=family.device.headers)
    command_id = command_for_version(fetched.json()["data"], 2)

    reported = await client.post(
        f"{API}/device/commands/{command_id}/result",
        json={
            "result": "unsupported",
            "applied_policy_version": 1,
            "error_code": "REQUIRED_PERMISSION_NOT_GRANTED",
            "message": "The required permission is not enabled on this device.",
        },
        headers=family.device.headers,
    )
    assert reported.status_code == 200
    assert reported.json()["data"]["status"] == "unsupported"

    bundle = await client.get(
        f"{API}/children/{family.child_id}/policies", headers=family.parent.headers
    )
    state = bundle.json()["data"]["device_sync_states"][0]
    assert state["sync_status"] == SyncStatus.unsupported.value
    assert state["applied_policy_version"] == 1


async def test_duplicate_acknowledgement_and_late_result_are_safe(client, family) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    fetched = await client.get(f"{API}/device/commands", headers=family.device.headers)
    command_id = command_for_version(fetched.json()["data"], 2)

    await client.post(
        f"{API}/device/commands/{command_id}/acknowledge",
        json={},
        headers=family.device.headers,
    )
    duplicate = await client.post(
        f"{API}/device/commands/{command_id}/acknowledge",
        json={},
        headers=family.device.headers,
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["data"]["duplicate"] is True

    await client.post(
        f"{API}/device/commands/{command_id}/result",
        json={"result": "succeeded", "applied_policy_version": 2},
        headers=family.device.headers,
    )
    # A late, contradictory result must not overwrite the terminal state.
    late = await client.post(
        f"{API}/device/commands/{command_id}/result",
        json={"result": "failed", "error_code": "LATE"},
        headers=family.device.headers,
    )
    assert late.status_code == 200
    assert late.json()["data"]["duplicate"] is True
    assert late.json()["data"]["status"] == "succeeded"


async def test_parent_command_is_idempotent(client, family) -> None:
    payload = {"command": {"command_type": "refresh_device_status"}}
    headers = {**family.parent.headers, "Idempotency-Key": "parent-key-00000001"}

    first = await client.post(
        f"{API}/devices/{family.device.device_id}/commands", json=payload, headers=headers
    )
    assert first.status_code == 201
    second = await client.post(
        f"{API}/devices/{family.device.device_id}/commands", json=payload, headers=headers
    )
    assert second.status_code == 201
    assert second.json()["data"]["id"] == first.json()["data"]["id"]


async def test_idempotency_key_with_a_different_body_is_rejected(client, family) -> None:
    headers = {**family.parent.headers, "Idempotency-Key": "parent-key-00000002"}
    first = await client.post(
        f"{API}/devices/{family.device.device_id}/commands",
        json={"command": {"command_type": "refresh_device_status"}},
        headers=headers,
    )
    assert first.status_code == 201

    conflicting = await client.post(
        f"{API}/devices/{family.device.device_id}/commands",
        json={"command": {"command_type": "request_usage_sync", "days": 3}},
        headers=headers,
    )
    assert conflicting.status_code == 409
    assert conflicting.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"


async def test_outbox_worker_sends_a_content_free_wakeup(
    client, family, session, fake_push
) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    await client.post(
        f"{API}/device/push-token",
        json={"token": "fake-device-push-token-0000000001", "platform": "android"},
        headers=family.device.headers,
    )

    result = await jobs.process_outbox()
    assert result.claimed >= 1
    assert result.failed == 0

    wakeups = [item for item in fake_push.sent if item.reason == "commands_pending"]
    assert wakeups, "a wake-up should have been attempted"
    message = wakeups[0]
    # A wake-up carries a reason code and a count. Nothing else.
    assert message.title is None
    assert set(message.data) <= {"reason", "action", "pending"}

    remaining = (
        await session.execute(
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.status == OutboxStatus.pending)
        )
    ).scalar_one()
    assert remaining == 0


async def test_command_survives_a_push_failure(client, family, session, fake_push) -> None:
    """FCM is not the queue: a failed push must leave the command pending."""
    await client.post(
        f"{API}/device/push-token",
        json={"token": "fake-device-push-token-0000000002", "platform": "android"},
        headers=family.device.headers,
    )
    fake_push.fail_next = True

    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    await jobs.process_outbox()

    fetched = await client.get(f"{API}/device/commands", headers=family.device.headers)
    assert fetched.json()["data"]["commands"], "the command is still available to poll"


async def test_expired_commands_are_swept(client, family, session) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    rows = (
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
    for row in rows:
        row.expires_at = row.created_at.replace(year=2020)
    await session.commit()

    expired = await jobs.expire_commands()
    assert expired >= 1

    fetched = await client.get(f"{API}/device/commands", headers=family.device.headers)
    assert fetched.json()["data"]["commands"] == []


async def test_location_command_is_refused_while_the_feature_is_off(client, family) -> None:
    response = await client.post(
        f"{API}/devices/{family.device.device_id}/commands",
        json={
            "command": {
                "command_type": "request_location_update",
                "reason": "checking on the school run",
            }
        },
        headers=family.parent.headers,
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FEATURE_DISABLED"


async def test_usage_sync_command_needs_a_reported_capability(client, family) -> None:
    """A command the device cannot run is refused now, not queued to expire."""
    ok_response = await client.post(
        f"{API}/devices/{family.device.device_id}/commands",
        json={"command": {"command_type": "request_usage_sync", "days": 2}},
        headers=family.parent.headers,
    )
    assert ok_response.status_code == 201

    await client.post(
        f"{API}/device/capabilities",
        json={
            "capabilities": [
                {
                    "capability_key": "app_usage_stats",
                    "support": "unsupported",
                    "permission_state": "denied",
                }
            ]
        },
        headers=family.device.headers,
    )
    refused = await client.post(
        f"{API}/devices/{family.device.device_id}/commands",
        json={"command": {"command_type": "request_usage_sync", "days": 3}},
        headers=family.parent.headers,
    )
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] in (
        "CAPABILITY_UNSUPPORTED",
        "PERMISSION_STATE_BLOCKS_ACTION",
    )


async def test_capability_loss_is_surfaced_to_the_parent(client, family) -> None:
    await client.post(
        f"{API}/children/{family.child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=family.parent.headers,
    )
    await client.post(
        f"{API}/device/capabilities",
        json={
            "capabilities": [
                {
                    "capability_key": "app_blocking",
                    "support": "unsupported",
                    "permission_state": "denied",
                    "note": "Accessibility service disabled by the user.",
                }
            ]
        },
        headers=family.device.headers,
    )

    bundle = await client.get(
        f"{API}/children/{family.child_id}/policies", headers=family.parent.headers
    )
    warnings = bundle.json()["data"]["capability_warnings"]
    assert any("not supported" in warning for warning in warnings)

    alerts = await client.get(f"{API}/alerts", headers=family.parent.headers)
    types = {item["alert_type"] for item in alerts.json()["data"]["items"]}
    assert "capability_unsupported" in types
