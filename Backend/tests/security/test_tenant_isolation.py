"""Cross-tenant and cross-principal access boundaries.

These are the tests that matter most in this product: a parental-control
backend that leaks one family's data into another's app is worse than no
product at all.
"""

from __future__ import annotations

import pytest

from tests.conftest import (
    API,
    create_child,
    create_family,
    pair_device,
    register_and_login,
)

pytestmark = pytest.mark.security


@pytest.fixture
async def two_families(client, fake_email):
    """Two unrelated parents, each with a family, child and paired device."""
    alice = await register_and_login(client, fake_email)
    alice_family = await create_family(client, alice, "Alice Family")
    alice_child = await create_child(client, alice, alice_family, "Alice Child")
    alice_device = await pair_device(client, alice, alice_child, "install-alice-0001")

    bob = await register_and_login(client, fake_email)
    bob_family = await create_family(client, bob, "Bob Family")
    bob_child = await create_child(client, bob, bob_family, "Bob Child")
    bob_device = await pair_device(client, bob, bob_child, "install-bob-0001")

    return {
        "alice": alice,
        "alice_family": alice_family,
        "alice_child": alice_child,
        "alice_device": alice_device,
        "bob": bob,
        "bob_family": bob_family,
        "bob_child": bob_child,
        "bob_device": bob_device,
    }


class TestParentCannotReachAnotherFamily:
    async def test_family_read(self, client, two_families) -> None:
        response = await client.get(
            f"{API}/families/{two_families['bob_family']}",
            headers=two_families["alice"].headers,
        )
        # 404, not 403: existence must not be confirmable by guessing ids.
        assert response.status_code == 404

    async def test_family_update(self, client, two_families) -> None:
        response = await client.patch(
            f"{API}/families/{two_families['bob_family']}",
            json={"name": "Taken Over"},
            headers=two_families["alice"].headers,
        )
        assert response.status_code == 404

    async def test_child_read(self, client, two_families) -> None:
        response = await client.get(
            f"{API}/children/{two_families['bob_child']}",
            headers=two_families["alice"].headers,
        )
        assert response.status_code == 404

    async def test_child_list_is_scoped(self, client, two_families) -> None:
        response = await client.get(
            f"{API}/families/{two_families['alice_family']}/children",
            headers=two_families["alice"].headers,
        )
        names = [item["display_name"] for item in response.json()["data"]]
        assert names == ["Alice Child"]

    async def test_device_read(self, client, two_families) -> None:
        response = await client.get(
            f"{API}/devices/{two_families['bob_device'].device_id}",
            headers=two_families["alice"].headers,
        )
        assert response.status_code == 404

    async def test_device_list_excludes_other_families(self, client, two_families) -> None:
        response = await client.get(f"{API}/devices", headers=two_families["alice"].headers)
        ids = {item["id"] for item in response.json()["data"]}
        assert two_families["bob_device"].device_id not in ids

    async def test_device_revoke(self, client, two_families) -> None:
        response = await client.post(
            f"{API}/devices/{two_families['bob_device'].device_id}/revoke",
            json={"reason": "malicious"},
            headers=two_families["alice"].headers,
        )
        assert response.status_code == 404

    async def test_policy_read_and_write(self, client, two_families) -> None:
        read = await client.get(
            f"{API}/children/{two_families['bob_child']}/policies",
            headers=two_families["alice"].headers,
        )
        assert read.status_code == 404

        write = await client.post(
            f"{API}/children/{two_families['bob_child']}/app-restrictions",
            json={"package_identifier": "com.example.video", "action": "block"},
            headers=two_families["alice"].headers,
        )
        assert write.status_code == 404

    async def test_usage_read(self, client, two_families) -> None:
        response = await client.get(
            f"{API}/children/{two_families['bob_child']}/usage",
            headers=two_families["alice"].headers,
        )
        assert response.status_code == 404

    async def test_pairing_invitation_for_another_child(self, client, two_families) -> None:
        response = await client.post(
            f"{API}/children/{two_families['bob_child']}/pairing-invitations",
            json={},
            headers=two_families["alice"].headers,
        )
        assert response.status_code == 404

    async def test_command_issue(self, client, two_families) -> None:
        response = await client.post(
            f"{API}/devices/{two_families['bob_device'].device_id}/commands",
            json={"command": {"command_type": "refresh_device_status"}},
            headers=two_families["alice"].headers,
        )
        assert response.status_code == 404

    async def test_alerts_are_scoped(self, client, two_families) -> None:
        response = await client.get(f"{API}/alerts", headers=two_families["alice"].headers)
        assert response.status_code == 200
        families = {item["family_id"] for item in response.json()["data"]["items"]}
        assert two_families["bob_family"] not in families

    async def test_client_supplied_ownership_ids_are_ignored(self, client, two_families) -> None:
        """A `family_id` in the body must never widen scope."""
        response = await client.post(
            f"{API}/families",
            json={
                "name": "Injected",
                "timezone": "Europe/London",
                "owner_user_id": two_families["bob"].user_id,
            },
            headers=two_families["alice"].headers,
        )
        # extra="forbid" rejects the unexpected field outright.
        assert response.status_code == 422


class TestDeviceScope:
    async def test_device_cannot_read_another_devices_commands(self, client, two_families) -> None:
        """A device's identity comes from its token, so it can only ever see
        its own queue - there is no parameter to tamper with."""
        alice_view = await client.get(
            f"{API}/device/commands", headers=two_families["alice_device"].headers
        )
        bob_view = await client.get(
            f"{API}/device/commands", headers=two_families["bob_device"].headers
        )
        assert alice_view.status_code == bob_view.status_code == 200

        alice_ids = {item["command_id"] for item in alice_view.json()["data"]["commands"]}
        bob_ids = {item["command_id"] for item in bob_view.json()["data"]["commands"]}
        assert alice_ids and bob_ids
        assert not (alice_ids & bob_ids)

    async def test_device_cannot_acknowledge_another_devices_command(
        self, client, two_families
    ) -> None:
        bob_commands = await client.get(
            f"{API}/device/commands", headers=two_families["bob_device"].headers
        )
        bob_command_id = bob_commands.json()["data"]["commands"][0]["command_id"]

        response = await client.post(
            f"{API}/device/commands/{bob_command_id}/acknowledge",
            json={},
            headers=two_families["alice_device"].headers,
        )
        assert response.status_code == 404

    async def test_device_cannot_report_a_result_for_another_device(
        self, client, two_families
    ) -> None:
        bob_commands = await client.get(
            f"{API}/device/commands", headers=two_families["bob_device"].headers
        )
        bob_command_id = bob_commands.json()["data"]["commands"][0]["command_id"]

        response = await client.post(
            f"{API}/device/commands/{bob_command_id}/result",
            json={"result": "succeeded"},
            headers=two_families["alice_device"].headers,
        )
        assert response.status_code == 404

    async def test_device_token_rejected_on_parent_routes(self, client, two_families) -> None:
        for method, path in (
            ("get", f"{API}/auth/me"),
            ("get", f"{API}/devices"),
            ("get", f"{API}/alerts"),
            ("get", f"{API}/families"),
        ):
            response = await getattr(client, method)(
                path, headers=two_families["alice_device"].headers
            )
            assert response.status_code == 401, path
            assert response.json()["error"]["code"] in ("TOKEN_INVALID", "AUTHENTICATION_REQUIRED")

    async def test_parent_token_rejected_on_device_routes(self, client, two_families) -> None:
        response = await client.get(f"{API}/device/commands", headers=two_families["alice"].headers)
        assert response.status_code == 401

    async def test_device_token_rejected_on_admin_routes(self, client, two_families) -> None:
        response = await client.get(
            f"{API}/admin/overview", headers=two_families["alice_device"].headers
        )
        assert response.status_code == 401

    async def test_parent_token_rejected_on_admin_routes(self, client, two_families) -> None:
        response = await client.get(f"{API}/admin/users", headers=two_families["alice"].headers)
        assert response.status_code == 401

    async def test_device_cannot_unlink_itself(self, client, two_families) -> None:
        """A child must not be able to end supervision from the device."""
        device = two_families["alice_device"]
        response = await client.post(
            f"{API}/devices/{device.device_id}/revoke",
            json={"reason": "I do not want this"},
            headers=device.headers,
        )
        assert response.status_code == 401

    async def test_device_cannot_submit_usage_for_another_child(self, client, two_families) -> None:
        """The child profile is derived from the token, so there is no field to
        point at someone else's child."""
        response = await client.post(
            f"{API}/device/usage/daily-summary",
            json={
                "local_date": "2026-01-01",
                "timezone": "Europe/London",
                "total_screen_time_seconds": 100,
                "child_profile_id": two_families["bob_child"],
            },
            headers=two_families["alice_device"].headers,
        )
        assert response.status_code == 422


class TestUnauthenticated:
    async def test_protected_routes_require_a_token(self, client) -> None:
        for method, path in (
            ("get", f"{API}/auth/me"),
            ("get", f"{API}/families"),
            ("get", f"{API}/devices"),
            ("get", f"{API}/alerts"),
            ("get", f"{API}/device/commands"),
            ("get", f"{API}/admin/overview"),
        ):
            response = await getattr(client, method)(path)
            assert response.status_code == 401, path
            body = response.json()
            assert body["success"] is False
            assert body["error"]["code"] in (
                "AUTHENTICATION_REQUIRED",
                "TOKEN_INVALID",
            )

    async def test_garbage_token_is_rejected(self, client) -> None:
        response = await client.get(f"{API}/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
        assert response.status_code == 401

    async def test_non_bearer_scheme_is_rejected(self, client) -> None:
        response = await client.get(
            f"{API}/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        assert response.status_code == 401
