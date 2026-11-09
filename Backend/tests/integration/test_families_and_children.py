"""Family creation, guardian invitations, child profile lifecycle."""

from __future__ import annotations

import pytest

from app.core.permissions import FamilyPermission
from tests.conftest import (
    API,
    create_child,
    create_family,
    pair_device,
    register_and_login,
)

pytestmark = pytest.mark.integration


async def test_creator_becomes_owner_with_full_permissions(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    response = await client.post(
        f"{API}/families",
        json={"name": "The Smiths", "timezone": "Europe/London"},
        headers=parent.headers,
    )
    assert response.status_code == 201
    data = response.json()["data"]
    assert data["my_role_is_owner"] is True
    assert set(data["my_permissions"]) == {perm.value for perm in FamilyPermission}


async def test_unverified_parent_cannot_create_a_family(client) -> None:
    """Setting up monitoring requires a proven email address."""
    from tests.conftest import TEST_PASSWORD, unique_email

    email = unique_email()
    await client.post(
        f"{API}/auth/register",
        json={
            "email": email,
            "password": TEST_PASSWORD,
            "display_name": "Unverified",
            "accepted_terms_version": "2026-01",
            "accepted_privacy_version": "2026-01",
        },
    )
    # Login is blocked before verification, so there is no token to misuse.
    login = await client.post(f"{API}/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert login.status_code == 403
    assert login.json()["error"]["code"] == "EMAIL_NOT_VERIFIED"


async def test_invalid_timezone_is_rejected(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    response = await client.post(
        f"{API}/families",
        json={"name": "Bad TZ", "timezone": "Mars/Olympus"},
        headers=parent.headers,
    )
    assert response.status_code == 422


async def test_guardian_invitation_round_trip(client, fake_email) -> None:
    owner = await register_and_login(client, fake_email)
    family_id = await create_family(client, owner)
    await create_child(client, owner, family_id)

    invited = await register_and_login(client, fake_email)
    fake_email.clear()

    invitation = await client.post(
        f"{API}/families/{family_id}/guardian-invitations",
        json={
            "invited_email": invited.email,
            "relationship_type": "guardian",
            "permissions": ["children.read", "devices.read", "family.members.manage"],
        },
        headers=owner.headers,
    )
    assert invitation.status_code == 201
    data = invitation.json()["data"]

    # The non-delegatable permission is stripped before storage.
    assert "family.members.manage" not in data["permissions"]
    assert "children.read" in data["permissions"]
    assert fake_email.last_for("guardian_invitation") is not None

    accepted = await client.post(
        f"{API}/guardian-invitations/accept",
        json={"token": data["invitation_token"]},
        headers=invited.headers,
    )
    assert accepted.status_code == 200
    assert accepted.json()["data"]["my_role_is_owner"] is False

    members = await client.get(f"{API}/families/{family_id}/members", headers=owner.headers)
    assert len(members.json()["data"]) == 2


async def test_invitation_is_bound_to_the_invited_address(client, fake_email) -> None:
    """A leaked invitation link must not be redeemable by anyone who finds it."""
    owner = await register_and_login(client, fake_email)
    family_id = await create_family(client, owner)
    invited = await register_and_login(client, fake_email)
    stranger = await register_and_login(client, fake_email)

    invitation = await client.post(
        f"{API}/families/{family_id}/guardian-invitations",
        json={"invited_email": invited.email},
        headers=owner.headers,
    )
    token = invitation.json()["data"]["invitation_token"]

    hijacked = await client.post(
        f"{API}/guardian-invitations/accept",
        json={"token": token},
        headers=stranger.headers,
    )
    assert hijacked.status_code == 403

    legitimate = await client.post(
        f"{API}/guardian-invitations/accept",
        json={"token": token},
        headers=invited.headers,
    )
    assert legitimate.status_code == 200


async def test_invitation_cannot_be_accepted_twice(client, fake_email) -> None:
    owner = await register_and_login(client, fake_email)
    family_id = await create_family(client, owner)
    invited = await register_and_login(client, fake_email)

    invitation = await client.post(
        f"{API}/families/{family_id}/guardian-invitations",
        json={"invited_email": invited.email},
        headers=owner.headers,
    )
    token = invitation.json()["data"]["invitation_token"]

    assert (
        await client.post(
            f"{API}/guardian-invitations/accept",
            json={"token": token},
            headers=invited.headers,
        )
    ).status_code == 200

    replay = await client.post(
        f"{API}/guardian-invitations/accept", json={"token": token}, headers=invited.headers
    )
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "INVITATION_ALREADY_CLAIMED"


async def test_limited_guardian_is_held_to_their_permissions(client, fake_email) -> None:
    owner = await register_and_login(client, fake_email)
    family_id = await create_family(client, owner)
    child_id = await create_child(client, owner, family_id)

    viewer = await register_and_login(client, fake_email)
    invitation = await client.post(
        f"{API}/families/{family_id}/guardian-invitations",
        json={
            "invited_email": viewer.email,
            "permissions": ["family.read", "children.read", "policies.read"],
        },
        headers=owner.headers,
    )
    await client.post(
        f"{API}/guardian-invitations/accept",
        json={"token": invitation.json()["data"]["invitation_token"]},
        headers=viewer.headers,
    )

    # Reading is allowed...
    assert (
        await client.get(f"{API}/children/{child_id}", headers=viewer.headers)
    ).status_code == 200
    assert (
        await client.get(f"{API}/children/{child_id}/policies", headers=viewer.headers)
    ).status_code == 200

    # ...changing is not.
    denied = await client.post(
        f"{API}/children/{child_id}/app-restrictions",
        json={"package_identifier": "com.example.video", "action": "block"},
        headers=viewer.headers,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"

    cannot_invite = await client.post(
        f"{API}/families/{family_id}/guardian-invitations",
        json={"invited_email": "someone@example.test"},
        headers=viewer.headers,
    )
    assert cannot_invite.status_code == 403


async def test_owner_cannot_be_removed(client, fake_email) -> None:
    owner = await register_and_login(client, fake_email)
    family_id = await create_family(client, owner)
    members = await client.get(f"{API}/families/{family_id}/members", headers=owner.headers)
    owner_member_id = members.json()["data"][0]["id"]

    response = await client.delete(
        f"{API}/families/{family_id}/members/{owner_member_id}", headers=owner.headers
    )
    assert response.status_code == 409


async def test_removed_guardian_loses_access_immediately(client, fake_email) -> None:
    owner = await register_and_login(client, fake_email)
    family_id = await create_family(client, owner)
    guest = await register_and_login(client, fake_email)

    invitation = await client.post(
        f"{API}/families/{family_id}/guardian-invitations",
        json={"invited_email": guest.email},
        headers=owner.headers,
    )
    await client.post(
        f"{API}/guardian-invitations/accept",
        json={"token": invitation.json()["data"]["invitation_token"]},
        headers=guest.headers,
    )
    assert (
        await client.get(f"{API}/families/{family_id}", headers=guest.headers)
    ).status_code == 200

    members = await client.get(f"{API}/families/{family_id}/members", headers=owner.headers)
    guest_member = next(item for item in members.json()["data"] if item["user_id"] == guest.user_id)
    await client.delete(
        f"{API}/families/{family_id}/members/{guest_member['id']}", headers=owner.headers
    )

    assert (
        await client.get(f"{API}/families/{family_id}", headers=guest.headers)
    ).status_code == 404


async def test_child_profile_crud_and_data_minimisation(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)

    created = await client.post(
        f"{API}/families/{family_id}/children",
        json={"display_name": "Sam", "age_band": "age_9_12"},
        headers=parent.headers,
    )
    assert created.status_code == 201
    child = created.json()["data"]
    assert child["age_band"] == "age_9_12"
    # No date of birth is collected or returned.
    assert "birth_year" not in child
    assert "date_of_birth" not in child

    updated = await client.patch(
        f"{API}/children/{child['id']}",
        json={"display_name": "Samantha", "timezone": "Europe/Dublin"},
        headers=parent.headers,
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["display_name"] == "Samantha"
    assert updated.json()["data"]["timezone"] == "Europe/Dublin"


async def test_a_date_of_birth_cannot_be_submitted(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    response = await client.post(
        f"{API}/families/{family_id}/children",
        json={"display_name": "Sam", "date_of_birth": "2015-04-01"},
        headers=parent.headers,
    )
    assert response.status_code == 422


async def test_deactivating_a_child_unlinks_its_devices(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    device = await pair_device(client, parent, child_id)

    response = await client.delete(f"{API}/children/{child_id}", headers=parent.headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["profile_status"] == "inactive"
    assert data["devices_revoked"] == 1
    assert "retention" in data["retention_note"].lower()

    # The device's credential stops working at once.
    assert (await client.get(f"{API}/device-auth/me", headers=device.headers)).status_code == 403


async def test_multiple_devices_per_child_are_supported(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)

    first = await pair_device(client, parent, child_id, "install-multi-0001")
    second = await pair_device(client, parent, child_id, "install-multi-0002")
    assert first.device_id != second.device_id

    devices = await client.get(f"{API}/devices?child_profile_id={child_id}", headers=parent.headers)
    assert len(devices.json()["data"]) == 2


async def test_device_heartbeat_and_presence(client, family) -> None:
    response = await client.post(
        f"{API}/device/heartbeat",
        json={"app_version": "1.0.1", "battery_percent": 72, "charging": False},
        headers=family.device.headers,
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["policy_version"] >= 1
    assert data["next_poll_after_seconds"] > 0

    view = await client.get(
        f"{API}/devices/{family.device.device_id}", headers=family.parent.headers
    )
    assert view.json()["data"]["presence"] == "online"
    assert view.json()["data"]["app_version"] == "1.0.1"
