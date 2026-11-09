"""The optional location module, exercised with the feature switched on.

The disabled path is covered in ``tests/security/test_input_and_disclosure.py``.
These tests enable the flag so the four gates, the precision reduction, the
audit trail and the consent-withdrawal purge are all actually executed.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.db.models.audit import AuditLog
from app.db.models.location import LocationSample
from app.schemas.location import LOCATION_COORDINATE_PRECISION
from app.utils.time import utcnow
from tests.conftest import API

pytestmark = pytest.mark.integration


@pytest.fixture
def location_enabled(monkeypatch):
    monkeypatch.setattr(settings, "feature_location_enabled", True)
    return True


async def grant_location_consent(client, family) -> str:
    response = await client.post(
        f"{API}/privacy/consents",
        json={
            "consent_type": "location_collection",
            "state": "granted",
            "policy_version": "2026-01",
            "method": "parent_app_acceptance",
        },
        headers=family.parent.headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]["id"]


async def report_location_capability(client, family, *, granted: bool = True) -> None:
    await client.post(
        f"{API}/device/capabilities",
        json={
            "capabilities": [
                {
                    "capability_key": "location_fine",
                    "support": "supported",
                    "permission_state": "granted" if granted else "denied",
                }
            ]
        },
        headers=family.device.headers,
    )
    await client.post(
        f"{API}/device/permissions/report",
        json={
            "permissions": [
                {
                    "permission_key": "location_fine",
                    "state": "granted" if granted else "denied",
                }
            ]
        },
        headers=family.device.headers,
    )


def sample_payload(**overrides) -> dict:
    payload = {
        "latitude": 51.5074456,
        "longitude": -0.1277653,
        "accuracy_meters": 25.0,
        "source": "fused",
        "recorded_at": utcnow().isoformat(),
        "deduplication_key": "loc-00000001",
    }
    payload.update(overrides)
    return payload


class TestGates:
    async def test_rejected_without_consent(self, client, family, location_enabled) -> None:
        await report_location_capability(client, family)
        response = await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        assert response.status_code == 200
        body = response.json()["data"]
        assert body["accepted"] is False
        assert body["rejection_code"] == "CONSENT_MISSING"
        assert body["sample_id"] is None

    async def test_rejected_without_a_reported_capability(
        self, client, family, location_enabled
    ) -> None:
        await grant_location_consent(client, family)
        response = await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        assert response.json()["data"]["rejection_code"] == "CAPABILITY_UNSUPPORTED"

    async def test_rejected_when_the_permission_is_denied(
        self, client, family, location_enabled
    ) -> None:
        await grant_location_consent(client, family)
        await report_location_capability(client, family, granted=False)
        response = await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        assert response.json()["data"]["rejection_code"] == "PERMISSION_NOT_GRANTED"

    async def test_nothing_is_stored_for_a_rejected_sample(
        self, client, family, location_enabled, session
    ) -> None:
        await report_location_capability(client, family)
        await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        count = (
            await session.execute(select(func.count()).select_from(LocationSample))
        ).scalar_one()
        assert count == 0


class TestAcceptedSamples:
    async def test_accepted_when_all_four_gates_pass(
        self, client, family, location_enabled, session
    ) -> None:
        await grant_location_consent(client, family)
        await report_location_capability(client, family)

        response = await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        assert response.status_code == 200
        body = response.json()["data"]
        assert body["accepted"] is True
        assert body["duplicate"] is False
        assert body["retention_expires_at"] is not None

        stored = (await session.execute(select(LocationSample))).scalars().one()
        # Precision is reduced before storage: ~110 m, not a doorstep.
        assert stored.latitude == round(51.5074456, LOCATION_COORDINATE_PRECISION)
        assert stored.longitude == round(-0.1277653, LOCATION_COORDINATE_PRECISION)
        assert stored.consent_record_id is not None

    async def test_resubmission_is_deduplicated(
        self, client, family, location_enabled, session
    ) -> None:
        await grant_location_consent(client, family)
        await report_location_capability(client, family)

        first = await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        second = await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        assert first.json()["data"]["accepted"] is True
        assert second.json()["data"]["duplicate"] is True

        count = (
            await session.execute(select(func.count()).select_from(LocationSample))
        ).scalar_one()
        assert count == 1

    async def test_stale_and_future_samples_are_refused(
        self, client, family, location_enabled
    ) -> None:
        await grant_location_consent(client, family)
        await report_location_capability(client, family)

        future = await client.post(
            f"{API}/device/location",
            json=sample_payload(recorded_at="2099-01-01T00:00:00+00:00"),
            headers=family.device.headers,
        )
        assert future.status_code == 422

        stale = await client.post(
            f"{API}/device/location",
            json=sample_payload(recorded_at="2020-01-01T00:00:00+00:00"),
            headers=family.device.headers,
        )
        assert stale.status_code == 422

    async def test_naive_timestamp_is_refused(self, client, family, location_enabled) -> None:
        response = await client.post(
            f"{API}/device/location",
            json=sample_payload(recorded_at="2026-01-01T10:00:00"),
            headers=family.device.headers,
        )
        assert response.status_code == 422


class TestParentReads:
    async def test_status_explains_availability_per_device(
        self, client, family, location_enabled
    ) -> None:
        await grant_location_consent(client, family)
        await report_location_capability(client, family)

        response = await client.get(
            f"{API}/children/{family.child_id}/location/status",
            headers=family.parent.headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["feature_enabled"] is True
        assert data["consent_state"] == "granted"
        assert data["availability"] == "available"
        assert data["devices"][0]["permission_state"] == "granted"

    async def test_latest_and_history_are_audited(
        self, client, family, location_enabled, session
    ) -> None:
        await grant_location_consent(client, family)
        await report_location_capability(client, family)
        await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )

        latest = await client.get(
            f"{API}/children/{family.child_id}/location/latest",
            headers=family.parent.headers,
        )
        assert latest.status_code == 200
        assert latest.json()["data"]["coordinate_precision_decimals"] == (
            LOCATION_COORDINATE_PRECISION
        )

        history = await client.get(
            f"{API}/children/{family.child_id}/location/history?hours=24&limit=10",
            headers=family.parent.headers,
        )
        assert history.status_code == 200
        assert len(history.json()["data"]) == 1

        reads = (
            (await session.execute(select(AuditLog).where(AuditLog.action == "location.read")))
            .scalars()
            .all()
        )
        assert len(reads) == 2
        # Coordinates must never appear in the audit metadata.
        for row in reads:
            blob = str(row.event_metadata or {})
            assert "51.5" not in blob
            assert "latitude" not in blob

    async def test_read_without_consent_is_refused(self, client, family, location_enabled) -> None:
        response = await client.get(
            f"{API}/children/{family.child_id}/location/latest",
            headers=family.parent.headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PERMISSION_STATE_BLOCKS_ACTION"

    async def test_a_guardian_without_location_read_is_refused(
        self, client, fake_email, family, location_enabled
    ) -> None:
        """`location.read` is non-delegatable, so an invited guardian never has it."""
        from tests.conftest import register_and_login

        await grant_location_consent(client, family)
        guest = await register_and_login(client, fake_email)
        invitation = await client.post(
            f"{API}/families/{family.family_id}/guardian-invitations",
            json={"invited_email": guest.email, "permissions": ["location.read"]},
            headers=family.parent.headers,
        )
        assert "location.read" not in invitation.json()["data"]["permissions"]

        await client.post(
            f"{API}/guardian-invitations/accept",
            json={"token": invitation.json()["data"]["invitation_token"]},
            headers=guest.headers,
        )
        response = await client.get(
            f"{API}/children/{family.child_id}/location/latest", headers=guest.headers
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PERMISSION_DENIED"


class TestConsentWithdrawalAndRetention:
    async def test_withdrawing_consent_deletes_the_samples(
        self, client, family, location_enabled, session
    ) -> None:
        consent_id = await grant_location_consent(client, family)
        await report_location_capability(client, family)
        await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )
        assert (
            await session.execute(select(func.count()).select_from(LocationSample))
        ).scalar_one() == 1

        withdrawn = await client.delete(
            f"{API}/privacy/consents/{consent_id}", headers=family.parent.headers
        )
        assert withdrawn.status_code == 200
        assert "deleted" in withdrawn.json()["data"]["detail"]

        assert (
            await session.execute(select(func.count()).select_from(LocationSample))
        ).scalar_one() == 0

    async def test_retention_sweep_removes_expired_samples(
        self, client, family, location_enabled, session
    ) -> None:
        from app.workers import jobs

        await grant_location_consent(client, family)
        await report_location_capability(client, family)
        await client.post(
            f"{API}/device/location", json=sample_payload(), headers=family.device.headers
        )

        stored = (await session.execute(select(LocationSample))).scalars().one()
        stored.retention_expires_at = utcnow().replace(year=2020)
        await session.commit()

        result = await jobs.apply_retention()
        assert result.location_samples == 1
        assert (
            await session.execute(select(func.count()).select_from(LocationSample))
        ).scalar_one() == 0


class TestLocationCommand:
    async def test_command_allowed_once_the_gates_pass(
        self, client, family, location_enabled
    ) -> None:
        await grant_location_consent(client, family)
        await report_location_capability(client, family)

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
        assert response.status_code == 201
        assert response.json()["data"]["command_type"] == "request_location_update"

    async def test_command_refused_without_consent(self, client, family, location_enabled) -> None:
        await report_location_capability(client, family)
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
        assert response.json()["error"]["code"] == "PERMISSION_STATE_BLOCKS_ACTION"

    async def test_command_requires_a_reason(self, client, family, location_enabled) -> None:
        response = await client.post(
            f"{API}/devices/{family.device.device_id}/commands",
            json={"command": {"command_type": "request_location_update"}},
            headers=family.parent.headers,
        )
        assert response.status_code == 422


async def test_sample_ids_are_uuids(client, family, location_enabled) -> None:
    await grant_location_consent(client, family)
    await report_location_capability(client, family)
    response = await client.post(
        f"{API}/device/location", json=sample_payload(), headers=family.device.headers
    )
    uuid.UUID(response.json()["data"]["sample_id"])
