"""Registration, verification, login, refresh rotation, reset, sessions."""

from __future__ import annotations

import pytest

from tests.conftest import API, TEST_PASSWORD, register_and_login, unique_email

pytestmark = pytest.mark.integration


async def test_register_verify_login(client, fake_email) -> None:
    email = unique_email()
    registered = await client.post(
        f"{API}/auth/register",
        json={
            "email": email,
            "password": TEST_PASSWORD,
            "display_name": "Alice",
            "timezone": "Europe/London",
            "locale": "en",
            "accepted_terms_version": "2026-01",
            "accepted_privacy_version": "2026-01",
        },
    )
    assert registered.status_code == 201
    body = registered.json()
    assert body["success"] is True
    assert body["meta"]["request_id"]
    assert body["data"]["account_status"] == "pending_verification"

    # An unverified account cannot sign in.
    blocked = await client.post(
        f"{API}/auth/login", json={"email": email, "password": TEST_PASSWORD}
    )
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "EMAIL_NOT_VERIFIED"

    verification = fake_email.last_for("email_verification")
    assert verification is not None
    assert verification.to == email

    token = body["data"]["dev_verification_token"]
    verified = await client.post(f"{API}/auth/verify-email", json={"token": token})
    assert verified.status_code == 200

    logged_in = await client.post(
        f"{API}/auth/login", json={"email": email, "password": TEST_PASSWORD}
    )
    assert logged_in.status_code == 200
    assert logged_in.json()["data"]["user"]["email_verified"] is True


async def test_verification_token_is_single_use(client, fake_email) -> None:
    email = unique_email()
    registered = await client.post(
        f"{API}/auth/register",
        json={
            "email": email,
            "password": TEST_PASSWORD,
            "display_name": "Alice",
            "accepted_terms_version": "2026-01",
            "accepted_privacy_version": "2026-01",
        },
    )
    token = registered.json()["data"]["dev_verification_token"]

    assert (await client.post(f"{API}/auth/verify-email", json={"token": token})).status_code == 200
    replay = await client.post(f"{API}/auth/verify-email", json={"token": token})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "TOKEN_INVALID"


async def test_duplicate_registration_does_not_reveal_the_account(client, fake_email) -> None:
    """Both responses must look the same to a client probing for accounts."""
    email = unique_email()
    payload = {
        "email": email,
        "password": TEST_PASSWORD,
        "display_name": "Alice",
        "accepted_terms_version": "2026-01",
        "accepted_privacy_version": "2026-01",
    }
    first = await client.post(f"{API}/auth/register", json=payload)
    second = await client.post(f"{API}/auth/register", json=payload)

    assert first.status_code == second.status_code == 201
    assert first.json()["message"] == second.json()["message"]
    assert second.json()["data"]["dev_verification_token"] is None


async def test_refresh_rotates_and_old_token_is_dead(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)

    rotated = await client.post(f"{API}/auth/refresh", json={"refresh_token": parent.refresh_token})
    assert rotated.status_code == 200
    new_refresh = rotated.json()["data"]["refresh_token"]
    assert new_refresh != parent.refresh_token

    replayed = await client.post(
        f"{API}/auth/refresh", json={"refresh_token": parent.refresh_token}
    )
    assert replayed.status_code == 401
    assert replayed.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"

    # Reuse detection revokes the whole family, including the newest token.
    after_reuse = await client.post(f"{API}/auth/refresh", json={"refresh_token": new_refresh})
    assert after_reuse.status_code == 401


async def test_logout_invalidates_the_access_token_immediately(client, fake_email) -> None:
    """Short-lived is not the same as revoked: the session row is checked."""
    parent = await register_and_login(client, fake_email)

    assert (await client.get(f"{API}/auth/me", headers=parent.headers)).status_code == 200

    logged_out = await client.post(
        f"{API}/auth/logout", json={"refresh_token": parent.refresh_token}, headers=parent.headers
    )
    assert logged_out.status_code == 200

    after = await client.get(f"{API}/auth/me", headers=parent.headers)
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "TOKEN_REVOKED"


async def test_password_reset_flow_revokes_sessions(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    fake_email.clear()

    requested = await client.post(f"{API}/auth/password/forgot", json={"email": parent.email})
    assert requested.status_code == 200

    message = fake_email.last_for("password_reset")
    assert message is not None
    token = message.text_body.split("token=")[1].split()[0]

    new_password = "brand-new-password-71x!"
    completed = await client.post(
        f"{API}/auth/password/reset", json={"token": token, "new_password": new_password}
    )
    assert completed.status_code == 200

    # The old session is gone and the old password no longer works.
    assert (await client.get(f"{API}/auth/me", headers=parent.headers)).status_code == 401
    assert (
        await client.post(
            f"{API}/auth/login", json={"email": parent.email, "password": TEST_PASSWORD}
        )
    ).status_code == 401
    assert (
        await client.post(
            f"{API}/auth/login", json={"email": parent.email, "password": new_password}
        )
    ).status_code == 200


async def test_password_reset_for_unknown_email_looks_identical(client) -> None:
    response = await client.post(
        f"{API}/auth/password/forgot", json={"email": "nobody@example.test"}
    )
    assert response.status_code == 200
    assert "If an account exists" in response.json()["data"]["detail"]


async def test_change_password_signs_out_other_sessions(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    second = await client.post(
        f"{API}/auth/login",
        json={"email": parent.email, "password": TEST_PASSWORD, "device_label": "Tablet"},
    )
    second_token = second.json()["data"]["access_token"]

    changed = await client.post(
        f"{API}/auth/password/change",
        json={
            "current_password": TEST_PASSWORD,
            "new_password": "another-good-password-4z!",
            "revoke_other_sessions": True,
        },
        headers={"Authorization": f"Bearer {second_token}"},
    )
    assert changed.status_code == 200

    # The session that performed the change survives; the other does not.
    assert (
        await client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {second_token}"})
    ).status_code == 200
    assert (await client.get(f"{API}/auth/me", headers=parent.headers)).status_code == 401


async def test_change_password_requires_the_current_password(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    response = await client.post(
        f"{API}/auth/password/change",
        json={
            "current_password": "not-the-password",
            "new_password": "another-good-password-4z!",
        },
        headers=parent.headers,
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"


async def test_sessions_can_be_listed_and_revoked(client, fake_email) -> None:
    parent = await register_and_login(client, fake_email)
    await client.post(
        f"{API}/auth/login",
        json={"email": parent.email, "password": TEST_PASSWORD, "device_label": "Tablet"},
    )

    listed = await client.get(f"{API}/auth/sessions", headers=parent.headers)
    assert listed.status_code == 200
    sessions = listed.json()["data"]
    assert len(sessions) == 2
    current = [item for item in sessions if item["current"]]
    assert len(current) == 1

    other = next(item for item in sessions if not item["current"])
    revoked = await client.delete(f"{API}/auth/sessions/{other['id']}", headers=parent.headers)
    assert revoked.status_code == 200

    remaining = await client.get(f"{API}/auth/sessions", headers=parent.headers)
    assert len(remaining.json()["data"]) == 1


async def test_weak_and_reused_passwords_are_rejected(client) -> None:
    short = await client.post(
        f"{API}/auth/register",
        json={
            "email": unique_email(),
            "password": "short",
            "display_name": "Alice",
            "accepted_terms_version": "2026-01",
            "accepted_privacy_version": "2026-01",
        },
    )
    assert short.status_code == 422
    assert short.json()["error"]["code"] == "VALIDATION_ERROR"

    common = await client.post(
        f"{API}/auth/register",
        json={
            "email": unique_email(),
            "password": "password123",
            "display_name": "Alice",
            "accepted_terms_version": "2026-01",
            "accepted_privacy_version": "2026-01",
        },
    )
    assert common.status_code == 422


async def test_password_may_not_contain_the_email_local_part(client) -> None:
    response = await client.post(
        f"{API}/auth/register",
        json={
            "email": "charlotte@example.test",
            "password": "charlotte-secret-1",
            "display_name": "Charlotte",
            "accepted_terms_version": "2026-01",
            "accepted_privacy_version": "2026-01",
        },
    )
    assert response.status_code == 422
