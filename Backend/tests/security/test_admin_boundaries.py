"""Admin privilege boundaries and audit coverage."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.permissions import AdminPermission, AdminRoleName
from app.db.models.audit import AuditLog
from app.services import admin_service
from tests.conftest import API

pytestmark = pytest.mark.security

ADMIN_PASSWORD = "admin-password-long-enough-1"


async def make_admin(session, email: str, roles: list[str]):  # noqa: ANN001
    await admin_service.seed_rbac(session)
    admin = await admin_service.create_admin_user(
        session,
        email=email,
        display_name=email,
        password=ADMIN_PASSWORD,
        role_names=roles,
    )
    await session.commit()
    return admin


async def admin_login(client, email: str) -> dict[str, str]:
    response = await client.post(
        f"{API}/admin/auth/login",
        json={"email": email, "password": ADMIN_PASSWORD, "mfa_code": "000000"},
    )
    assert response.status_code == 200, response.text
    token = response.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def support_headers(client, session):
    await make_admin(session, "support@example.test", [AdminRoleName.support_admin.value])
    return await admin_login(client, "support@example.test")


@pytest.fixture
async def analyst_headers(client, session):
    await make_admin(session, "analyst@example.test", [AdminRoleName.read_only_analyst.value])
    return await admin_login(client, "analyst@example.test")


@pytest.fixture
async def super_headers(client, session):
    await make_admin(session, "root@example.test", [AdminRoleName.super_admin.value])
    return await admin_login(client, "root@example.test")


class TestLowPrivilegeAdmin:
    async def test_support_cannot_change_account_status(
        self, client, support_headers, family
    ) -> None:
        response = await client.patch(
            f"{API}/admin/users/{family.parent.user_id}/status",
            json={"account_status": "suspended", "reason": "no reason given"},
            headers=support_headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PERMISSION_DENIED"

    async def test_support_cannot_read_audit_logs(self, client, support_headers) -> None:
        response = await client.get(f"{API}/admin/audit-logs", headers=support_headers)
        assert response.status_code == 403

    async def test_support_cannot_revoke_a_device(self, client, support_headers, family) -> None:
        response = await client.post(
            f"{API}/admin/devices/{family.device.device_id}/revoke",
            headers=support_headers,
        )
        assert response.status_code == 403

    async def test_support_user_detail_withholds_profile_detail(
        self, client, support_headers, family
    ) -> None:
        """Support lacks users.pii.read, so extra profile fields stay empty."""
        response = await client.get(
            f"{API}/admin/users/{family.parent.user_id}", headers=support_headers
        )
        assert response.status_code == 200
        assert response.json()["data"]["timezone"] is None

    async def test_analyst_cannot_list_accounts(self, client, analyst_headers) -> None:
        for path in ("/admin/users", "/admin/families", "/admin/devices"):
            response = await client.get(f"{API}{path}", headers=analyst_headers)
            assert response.status_code == 403, path

    async def test_analyst_can_read_aggregates_only(self, client, analyst_headers) -> None:
        overview = await client.get(f"{API}/admin/overview", headers=analyst_headers)
        assert overview.status_code == 200
        analytics = await client.get(f"{API}/admin/analytics/summary", headers=analyst_headers)
        assert analytics.status_code == 200
        assert "total_users" in overview.json()["data"]

    async def test_me_reports_the_real_permission_set(self, client, support_headers) -> None:
        response = await client.get(f"{API}/admin/auth/me", headers=support_headers)
        permissions = set(response.json()["data"]["permissions"])
        assert AdminPermission.SUPPORT_TICKETS_WRITE.value in permissions
        assert AdminPermission.CHILD_LOCATION_READ.value not in permissions
        assert AdminPermission.USERS_STATUS_WRITE.value not in permissions


class TestSuperAdmin:
    async def test_can_change_account_status_with_a_reason(
        self, client, super_headers, family, session
    ) -> None:
        response = await client.patch(
            f"{API}/admin/users/{family.parent.user_id}/status",
            json={"account_status": "suspended", "reason": "confirmed abuse report 123"},
            headers=super_headers,
        )
        assert response.status_code == 200

        # The suspended parent is signed out everywhere.
        after = await client.get(f"{API}/auth/me", headers=family.parent.headers)
        assert after.status_code in (401, 403)

        logs = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == "admin.user_status_changed")
                )
            )
            .scalars()
            .all()
        )
        assert logs
        assert logs[0].reason == "confirmed abuse report 123"
        assert logs[0].actor_label == "root@example.test"

    async def test_status_change_requires_a_reason(self, client, super_headers, family) -> None:
        response = await client.patch(
            f"{API}/admin/users/{family.parent.user_id}/status",
            json={"account_status": "suspended"},
            headers=super_headers,
        )
        assert response.status_code == 422

    async def test_sensitive_reads_are_audited(
        self, client, super_headers, family, session
    ) -> None:
        await client.get(f"{API}/admin/users", headers=super_headers)
        await client.get(f"{API}/admin/users/{family.parent.user_id}", headers=super_headers)
        await client.get(f"{API}/admin/families", headers=super_headers)

        actions = {row.action for row in (await session.execute(select(AuditLog))).scalars().all()}
        assert "admin.user_list_read" in actions
        assert "admin.user_read" in actions
        assert "admin.family_read" in actions


class TestAdminAuthentication:
    async def test_wrong_password_is_generic(self, client, session) -> None:
        await make_admin(session, "ops@example.test", [AdminRoleName.support_admin.value])
        response = await client.post(
            f"{API}/admin/auth/login",
            json={"email": "ops@example.test", "password": "wrong", "mfa_code": "000000"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"

    async def test_unknown_admin_is_indistinguishable(self, client) -> None:
        response = await client.post(
            f"{API}/admin/auth/login",
            json={"email": "nobody@example.test", "password": "wrong", "mfa_code": "000000"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"

    async def test_mfa_code_is_required_outside_production(self, client, session) -> None:
        await make_admin(session, "mfa@example.test", [AdminRoleName.support_admin.value])
        response = await client.post(
            f"{API}/admin/auth/login",
            json={"email": "mfa@example.test", "password": ADMIN_PASSWORD},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "MFA_REQUIRED"

    async def test_admin_token_rejected_on_parent_routes(self, client, super_headers) -> None:
        response = await client.get(f"{API}/auth/me", headers=super_headers)
        assert response.status_code == 401

    async def test_admin_token_rejected_on_device_routes(self, client, super_headers) -> None:
        response = await client.get(f"{API}/device/commands", headers=super_headers)
        assert response.status_code == 401

    async def test_admin_session_rotation_detects_replay(self, client, session) -> None:
        await make_admin(session, "rot@example.test", [AdminRoleName.support_admin.value])
        login = await client.post(
            f"{API}/admin/auth/login",
            json={
                "email": "rot@example.test",
                "password": ADMIN_PASSWORD,
                "mfa_code": "000000",
            },
        )
        refresh_token = login.json()["data"]["refresh_token"]

        first = await client.post(
            f"{API}/admin/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert first.status_code == 200

        replay = await client.post(
            f"{API}/admin/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert replay.status_code == 401
        assert replay.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"
