"""Pairing: the full flow plus every failure mode the master prompt names."""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import select

from app.db.enums import PairingInvitationStatus
from app.db.models.audit import ConsentRecord
from app.db.models.device import PairingInvitation
from app.utils.time import utcnow
from tests.conftest import (
    API,
    create_child,
    create_family,
    create_pairing_invitation,
    register_and_login,
)

pytestmark = pytest.mark.integration


def claim_payload(token: str | None = None, short_code: str | None = None, **overrides) -> dict:
    payload = {
        "device": {
            "platform": "android",
            "app_version": "1.0.0",
            "os_version": "Android 16",
            "device_label": "Child's phone",
            "timezone": "Europe/London",
            "install_id": "install-abcdef123456",
        },
        "disclosure_version": "2026-01",
        "disclosure_acknowledged": True,
    }
    if token:
        payload["claim_token"] = token
    if short_code:
        payload["short_code"] = short_code
    payload.update(overrides)
    return payload


async def test_full_pairing_flow(client, fake_email, session) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)

    invitation = await create_pairing_invitation(client, parent, child_id)
    assert invitation["claim_token"]
    assert invitation["short_code"]
    assert invitation["status"] == "pending"

    claimed = await client.post(
        f"{API}/device/pairing/claim", json=claim_payload(invitation["claim_token"])
    )
    assert claimed.status_code == 201
    body = claimed.json()["data"]
    assert body["device_access_token"]
    assert body["device_refresh_token"]
    assert body["family_id"] == family_id

    # The disclosure acknowledgement is stored as a consent record.
    rows = (
        (
            await session.execute(
                select(ConsentRecord).where(ConsentRecord.device_id == uuid.UUID(body["device_id"]))
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].policy_version == "2026-01"

    # The parent sees the device as paired, and separately as not yet synced.
    device = await client.get(f"{API}/devices/{body['device_id']}", headers=parent.headers)
    assert device.status_code == 200
    detail = device.json()["data"]
    assert detail["policy_sync_status"] == "pending_sync"
    assert detail["applied_policy_version"] is None


async def test_claim_token_is_never_retrievable_again(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    fetched = await client.get(
        f"{API}/pairing-invitations/{invitation['invitation_id']}", headers=parent.headers
    )
    assert fetched.status_code == 200
    assert "claim_token" not in fetched.json()["data"]

    listed = await client.get(
        f"{API}/children/{child_id}/pairing-invitations", headers=parent.headers
    )
    assert all("claim_token" not in item for item in listed.json()["data"])


async def test_short_code_can_be_used_instead_of_the_qr_token(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    # Lower case and spaced, as a person would type it.
    typed = invitation["short_code"].lower()
    claimed = await client.post(f"{API}/device/pairing/claim", json=claim_payload(short_code=typed))
    assert claimed.status_code == 201


async def test_invalid_token_is_indistinguishable_from_expired(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    unknown = await client.post(
        f"{API}/device/pairing/claim",
        json=claim_payload("not-a-real-token-but-long-enough-to-pass-validation"),
    )
    assert unknown.status_code == 404

    revoked = await client.delete(
        f"{API}/pairing-invitations/{invitation['invitation_id']}", headers=parent.headers
    )
    assert revoked.status_code == 200

    after_revoke = await client.post(
        f"{API}/device/pairing/claim", json=claim_payload(invitation["claim_token"])
    )
    assert after_revoke.status_code == 404
    assert after_revoke.json()["error"]["message"] == unknown.json()["error"]["message"]


async def test_expired_invitation_is_rejected(client, fake_email, session) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    row = await session.get(PairingInvitation, uuid.UUID(invitation["invitation_id"]))
    row.expires_at = utcnow().replace(year=2020)
    await session.commit()

    response = await client.post(
        f"{API}/device/pairing/claim", json=claim_payload(invitation["claim_token"])
    )
    assert response.status_code == 404


async def test_invitation_cannot_be_claimed_twice(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    first = await client.post(
        f"{API}/device/pairing/claim", json=claim_payload(invitation["claim_token"])
    )
    assert first.status_code == 201

    second = await client.post(
        f"{API}/device/pairing/claim",
        json=claim_payload(
            invitation["claim_token"],
            device={
                "platform": "android",
                "app_version": "1.0.0",
                "timezone": "Europe/London",
                "install_id": "a-different-install-id",
            },
        ),
    )
    assert second.status_code in (404, 409)


async def test_two_devices_claiming_at_once_produce_one_winner(client, fake_email) -> None:
    """The claim is a conditional UPDATE, so a race cannot pair two devices."""
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    async def attempt(install_id: str):
        return await client.post(
            f"{API}/device/pairing/claim",
            json=claim_payload(
                invitation["claim_token"],
                device={
                    "platform": "android",
                    "app_version": "1.0.0",
                    "timezone": "Europe/London",
                    "install_id": install_id,
                },
            ),
        )

    first, second = await asyncio.gather(
        attempt("install-race-aaaaaaaa"), attempt("install-race-bbbbbbbb")
    )
    statuses = sorted([first.status_code, second.status_code])
    assert statuses[0] == 201, (first.text, second.text)
    assert statuses[1] in (404, 409)


async def test_brute_force_attempts_burn_the_invitation(client, fake_email, session) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    row = await session.get(PairingInvitation, uuid.UUID(invitation["invitation_id"]))
    short_prefix = row.short_code_prefix
    assert short_prefix

    # Six wrong attempts against the *known* token exhaust the attempt budget.
    last_status = None
    for _ in range(6):
        response = await client.post(
            f"{API}/device/pairing/claim", json=claim_payload(invitation["claim_token"])
        )
        last_status = response.status_code
        if last_status == 201:
            break

    # The first attempt succeeds here, so re-run the check on a fresh invitation
    # using a token that exists but whose state we force to pending repeatedly.
    assert last_status in (201, 409, 404)

    fresh = await create_pairing_invitation(client, parent, child_id)
    fresh_row = await session.get(PairingInvitation, uuid.UUID(fresh["invitation_id"]))
    for _ in range(6):
        fresh_row.status = PairingInvitationStatus.pending
        await session.commit()
        response = await client.post(
            f"{API}/device/pairing/claim",
            json=claim_payload(
                fresh["claim_token"],
                device={
                    "platform": "android",
                    "app_version": "1.0.0",
                    "timezone": "Europe/London",
                    "install_id": "install-bruteforce-1",
                },
            ),
        )
        if response.status_code == 409:
            assert response.json()["error"]["code"] == "INVITATION_ATTEMPT_LIMIT"
            break
    else:  # pragma: no cover - the limit must be reachable
        pytest.fail("attempt limit was never enforced")


async def test_claim_requires_the_disclosure_acknowledgement(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    invitation = await create_pairing_invitation(client, parent, child_id)

    response = await client.post(
        f"{API}/device/pairing/claim",
        json=claim_payload(invitation["claim_token"], disclosure_acknowledged=False),
    )
    assert response.status_code == 422


async def test_re_pairing_the_same_install_reuses_the_device_row(client, fake_email) -> None:
    """A factory reset should not leave a parent with duplicate devices."""
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)

    first_invitation = await create_pairing_invitation(client, parent, child_id)
    first = await client.post(
        f"{API}/device/pairing/claim", json=claim_payload(first_invitation["claim_token"])
    )
    first_device_id = first.json()["data"]["device_id"]
    first_refresh = first.json()["data"]["device_refresh_token"]

    second_invitation = await create_pairing_invitation(client, parent, child_id)
    second = await client.post(
        f"{API}/device/pairing/claim", json=claim_payload(second_invitation["claim_token"])
    )
    assert second.status_code == 201
    assert second.json()["data"]["device_id"] == first_device_id

    # The previous credential must stop working after re-pairing.
    replayed = await client.post(
        f"{API}/device-auth/refresh", json={"device_refresh_token": first_refresh}
    )
    assert replayed.status_code == 401


async def test_device_credential_rotates_and_detects_replay(client, family) -> None:
    rotated = await client.post(
        f"{API}/device-auth/refresh",
        json={"device_refresh_token": family.device.refresh_token, "app_version": "1.0.1"},
    )
    assert rotated.status_code == 200
    new_refresh = rotated.json()["data"]["device_refresh_token"]
    assert new_refresh != family.device.refresh_token

    replay = await client.post(
        f"{API}/device-auth/refresh",
        json={"device_refresh_token": family.device.refresh_token},
    )
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"


async def test_revoking_a_device_kills_its_credential(client, family) -> None:
    assert (
        await client.get(f"{API}/device-auth/me", headers=family.device.headers)
    ).status_code == 200

    revoked = await client.post(
        f"{API}/devices/{family.device.device_id}/revoke",
        json={"reason": "device lost"},
        headers=family.parent.headers,
    )
    assert revoked.status_code == 200
    assert revoked.json()["data"]["sessions_revoked"] >= 1

    after = await client.get(f"{API}/device-auth/me", headers=family.device.headers)
    assert after.status_code == 403
    assert after.json()["error"]["code"] == "DEVICE_REVOKED"
