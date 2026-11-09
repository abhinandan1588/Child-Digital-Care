"""Admin dashboard workflows: search, support, trust & safety, analytics."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.permissions import AdminRoleName
from app.db.enums import AbuseReportCategory, TicketStatus
from app.db.models.support import AbuseReport, SupportTicket, SupportTicketMessage
from app.services import admin_service
from tests.conftest import API

pytestmark = pytest.mark.integration

ADMIN_PASSWORD = "admin-password-long-enough-1"


@pytest.fixture
async def admin_headers(client, session):
    await admin_service.seed_rbac(session)
    await admin_service.create_admin_user(
        session,
        email="root@example.test",
        display_name="Root",
        password=ADMIN_PASSWORD,
        role_names=[AdminRoleName.super_admin.value],
    )
    await session.commit()

    response = await client.post(
        f"{API}/admin/auth/login",
        json={
            "email": "root@example.test",
            "password": ADMIN_PASSWORD,
            "mfa_code": "000000",
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['data']['access_token']}"}


async def test_rbac_seed_is_idempotent(session) -> None:
    first = await admin_service.seed_rbac(session)
    await session.commit()
    second = await admin_service.seed_rbac(session)
    await session.commit()
    assert first[0] > 0 and first[1] > 0 and first[2] > 0
    assert second == (0, 0, 0)


async def test_overview_counts_real_rows(client, admin_headers, family) -> None:
    response = await client.get(f"{API}/admin/overview", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["total_users"] >= 1
    assert data["total_families"] >= 1
    assert data["total_children"] >= 1
    assert data["total_devices"] >= 1
    assert data["pending_commands"] >= 1
    assert "outbox_backlog" in data


async def test_user_search_is_paginated(client, admin_headers, family) -> None:
    response = await client.get(f"{API}/admin/users?limit=1&offset=0", headers=admin_headers)
    assert response.status_code == 200
    page = response.json()["data"]
    assert len(page["items"]) == 1
    assert page["page_info"]["total"] >= 1

    by_email = await client.get(f"{API}/admin/users?q={family.parent.email}", headers=admin_headers)
    emails = [item["email"] for item in by_email.json()["data"]["items"]]
    assert family.parent.email in emails


async def test_user_detail_includes_family_rollup(client, admin_headers, family) -> None:
    response = await client.get(f"{API}/admin/users/{family.parent.user_id}", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["family_count"] == 1
    assert data["families"][0]["child_count"] == 1
    assert data["device_count"] == 1
    # super_admin holds users.pii.read, so the extra field is populated.
    assert data["timezone"] == "Europe/London"


async def test_family_and_device_search(client, admin_headers, family) -> None:
    families = await client.get(f"{API}/admin/families", headers=admin_headers)
    assert families.status_code == 200
    assert families.json()["data"]["items"][0]["owner_email"] == family.parent.email

    devices = await client.get(
        f"{API}/admin/devices?family_id={family.family_id}", headers=admin_headers
    )
    assert devices.status_code == 200
    item = devices.json()["data"]["items"][0]
    assert item["id"] == family.device.device_id
    # Device metadata only: no usage figures, no location.
    assert "total_screen_time_seconds" not in item
    assert "latitude" not in item


async def test_support_ticket_workflow(client, admin_headers, family, session) -> None:
    ticket = SupportTicket(
        reference="TKT-0001",
        user_id=None,
        family_id=None,
        contact_email=family.parent.email,
        subject="Device will not pair",
        category="pairing",
    )
    session.add(ticket)
    await session.commit()

    listed = await client.get(f"{API}/admin/support-tickets", headers=admin_headers)
    assert listed.status_code == 200
    assert listed.json()["data"]["items"][0]["reference"] == "TKT-0001"

    updated = await client.patch(
        f"{API}/admin/support-tickets/{ticket.id}",
        json={
            "status": "resolved",
            "priority": "high",
            "internal_note": "Walked the parent through re-pairing.",
        },
        headers=admin_headers,
    )
    assert updated.status_code == 200

    await session.refresh(ticket)
    assert ticket.status is TicketStatus.resolved
    assert ticket.resolved_at is not None

    notes = (
        (
            await session.execute(
                select(SupportTicketMessage).where(SupportTicketMessage.ticket_id == ticket.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(notes) == 1
    assert notes[0].is_internal_note is True


async def test_abuse_report_requires_documented_resolution(
    client, admin_headers, family, session
) -> None:
    report = AbuseReport(
        reference="ABR-0001",
        category=AbuseReportCategory.non_consensual_monitoring,
        description="The device owner says they did not agree to this.",
        subject_family_id=None,
    )
    session.add(report)
    await session.commit()

    listed = await client.get(f"{API}/admin/abuse-reports", headers=admin_headers)
    assert listed.status_code == 200
    assert listed.json()["data"]["items"][0]["category"] == ("non_consensual_monitoring")

    without_notes = await client.patch(
        f"{API}/admin/abuse-reports/{report.id}",
        json={"status": "action_taken"},
        headers=admin_headers,
    )
    assert without_notes.status_code == 422

    documented = await client.patch(
        f"{API}/admin/abuse-reports/{report.id}",
        json={
            "status": "action_taken",
            "action_taken": "devices_unlinked",
            "resolution_notes": "Confirmed with the device owner; devices unlinked.",
        },
        headers=admin_headers,
    )
    assert documented.status_code == 200

    await session.refresh(report)
    assert report.resolution_notes.startswith("Confirmed")
    assert report.reviewed_at is not None


async def test_admin_can_unlink_a_device(client, admin_headers, family) -> None:
    response = await client.post(
        f"{API}/admin/devices/{family.device.device_id}/revoke", headers=admin_headers
    )
    assert response.status_code == 200

    assert (
        await client.get(f"{API}/device-auth/me", headers=family.device.headers)
    ).status_code == 403


async def test_audit_log_is_readable_and_filterable(client, admin_headers, family) -> None:
    response = await client.get(f"{API}/admin/audit-logs?action=user.login", headers=admin_headers)
    assert response.status_code == 200
    items = response.json()["data"]["items"]
    assert items
    assert all(item["action"] == "user.login" for item in items)
    assert {"actor_type", "outcome", "created_at"} <= set(items[0])


async def test_analytics_reports_command_and_push_failure_rates(
    client, admin_headers, family
) -> None:
    response = await client.get(
        f"{API}/admin/analytics/summary?window_days=7", headers=admin_headers
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["window_days"] == 7
    assert data["new_users"] >= 1
    assert data["commands_created"] >= 1
    assert 0.0 <= data["policy_sync_failure_rate"] <= 1.0
    assert 0.0 <= data["push_failure_rate"] <= 1.0


async def test_permission_catalogue_is_published(client, admin_headers) -> None:
    response = await client.get(f"{API}/admin/permissions", headers=admin_headers)
    assert response.status_code == 200
    keys = {item["key"] for item in response.json()["data"]}
    assert "child_location.read" in keys
    sensitive = {item["key"] for item in response.json()["data"] if item["sensitive"] == "true"}
    assert "child_location.read" in sensitive


async def test_subscriptions_are_listed(client, admin_headers, family) -> None:
    # Reading the family's subscription creates the row.
    await client.get(
        f"{API}/billing/families/{family.family_id}/subscription",
        headers=family.parent.headers,
    )
    response = await client.get(f"{API}/admin/subscriptions", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["data"]["items"][0]["family_id"] == family.family_id
