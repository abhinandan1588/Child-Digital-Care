"""Consent, export, deletion, and the billing webhook path."""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.security import hmac_sha256_hex
from app.db.enums import PrivacyRequestStatus, PrivacyRequestType, SubscriptionStatus
from app.db.models.audit import PrivacyRequest
from app.db.models.billing import PaymentWebhookEvent, Plan, Subscription
from app.integrations.payments.provider import (
    GenericHmacPaymentProvider,
    set_payment_provider,
)
from app.services import privacy_service
from app.utils.time import utcnow
from tests.conftest import API, TEST_PASSWORD

pytestmark = pytest.mark.integration


class TestConsent:
    async def test_registration_records_terms_and_privacy_consent(self, client, family) -> None:
        response = await client.get(f"{API}/privacy/consents", headers=family.parent.headers)
        assert response.status_code == 200
        types = {item["consent_type"] for item in response.json()["data"]}
        assert {"parent_terms", "parent_privacy_policy"} <= types
        for item in response.json()["data"]:
            assert item["policy_version"]  # the exact version is pinned

    async def test_pairing_records_the_device_disclosure(self, client, family) -> None:
        response = await client.get(f"{API}/privacy/consents", headers=family.parent.headers)
        # The device disclosure is family-scoped, recorded by the device.
        device_consents = [
            item
            for item in response.json()["data"]
            if item["consent_type"] == "child_device_disclosure"
        ]
        assert device_consents
        assert device_consents[0]["device_id"] == family.device.device_id

    async def test_recording_and_withdrawing_location_consent(self, client, family) -> None:
        created = await client.post(
            f"{API}/privacy/consents",
            json={
                "consent_type": "location_collection",
                "state": "granted",
                "policy_version": "2026-01",
                "method": "parent_app_acceptance",
            },
            headers=family.parent.headers,
        )
        assert created.status_code == 201
        consent_id = created.json()["data"]["id"]

        withdrawn = await client.delete(
            f"{API}/privacy/consents/{consent_id}", headers=family.parent.headers
        )
        assert withdrawn.status_code == 200

        again = await client.delete(
            f"{API}/privacy/consents/{consent_id}", headers=family.parent.headers
        )
        assert again.status_code == 409


class TestExportAndDeletion:
    async def test_export_contains_the_account_and_omits_secrets(self, client, family) -> None:
        response = await client.get(f"{API}/privacy/export", headers=family.parent.headers)
        assert response.status_code == 200
        payload = response.json()["data"]

        assert payload["account"]["id"] == family.parent.user_id
        assert len(payload["families"]) == 1
        assert len(payload["children"]) == 1
        assert len(payload["devices"]) == 1
        assert "retention_exceptions" in payload["notes"]

        blob = json.dumps(payload).lower()
        for secret in ("password_hash", "refresh_token", "token_hash", "claim_token"):
            assert secret not in blob

    async def test_deletion_requires_password_and_phrase(self, client, family) -> None:
        wrong_phrase = await client.post(
            f"{API}/privacy/account/delete",
            json={"password": TEST_PASSWORD, "confirm_phrase": "delete"},
            headers=family.parent.headers,
        )
        assert wrong_phrase.status_code == 422

        wrong_password = await client.post(
            f"{API}/privacy/account/delete",
            json={"password": "not-the-password", "confirm_phrase": "DELETE MY ACCOUNT"},
            headers=family.parent.headers,
        )
        assert wrong_password.status_code == 403

    async def test_deletion_unlinks_devices_immediately(self, client, family) -> None:
        """Monitoring must stop now, not at the end of the grace period."""
        response = await client.post(
            f"{API}/privacy/account/delete",
            json={
                "password": TEST_PASSWORD,
                "confirm_phrase": "DELETE MY ACCOUNT",
                "reason": "no longer needed",
            },
            headers=family.parent.headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["devices_revoked"] == 1
        assert data["grace_period_days"] == privacy_service.DELETION_GRACE_PERIOD_DAYS

        assert (
            await client.get(f"{API}/device-auth/me", headers=family.device.headers)
        ).status_code == 403
        # Every parent session is revoked too.
        assert (
            await client.get(f"{API}/auth/me", headers=family.parent.headers)
        ).status_code == 401

    async def test_deletion_can_be_cancelled_within_the_grace_period(
        self, client, family, session
    ) -> None:
        await client.post(
            f"{API}/privacy/account/delete",
            json={"password": TEST_PASSWORD, "confirm_phrase": "DELETE MY ACCOUNT"},
            headers=family.parent.headers,
        )
        relogin = await client.post(
            f"{API}/auth/login",
            json={"email": family.parent.email, "password": TEST_PASSWORD},
        )
        # A pending-deletion account can still sign in, which is what makes the
        # cancellation route reachable.
        assert relogin.status_code == 200
        headers = {"Authorization": f"Bearer {relogin.json()['data']['access_token']}"}

        cancelled = await client.post(f"{API}/privacy/account/delete/cancel", headers=headers)
        assert cancelled.status_code == 200
        assert cancelled.json()["data"]["status"] == PrivacyRequestStatus.cancelled.value

    async def test_due_deletion_erases_personal_data(self, client, family, session) -> None:
        from app.db.models.family import Family
        from app.db.models.identity import User

        await client.post(
            f"{API}/privacy/account/delete",
            json={"password": TEST_PASSWORD, "confirm_phrase": "DELETE MY ACCOUNT"},
            headers=family.parent.headers,
        )

        request = (
            (
                await session.execute(
                    select(PrivacyRequest).where(
                        PrivacyRequest.request_type == PrivacyRequestType.deletion
                    )
                )
            )
            .scalars()
            .one()
        )
        request.requested_at = utcnow().replace(year=2020)
        await session.commit()

        outcomes = await privacy_service.execute_due_deletions(session)
        await session.commit()
        assert len(outcomes) == 1
        assert outcomes[0].families_deleted == 1

        user = await session.get(User, uuid.UUID(family.parent.user_id))
        await session.refresh(user)
        assert user.display_name == "[deleted]"
        assert user.email.startswith("deleted+")
        assert user.deleted_at is not None

        families = (await session.execute(select(Family))).scalars().all()
        assert families == []

        # The audit trail survives the deletion.
        from app.db.models.audit import AuditLog

        logs = (await session.execute(select(AuditLog))).scalars().all()
        assert any(row.action == "privacy.data_deleted" for row in logs)


class TestBilling:
    async def test_plans_and_subscription_report_billing_unavailable(self, client, family) -> None:
        plans = await client.get(f"{API}/billing/plans")
        assert plans.status_code == 200
        assert plans.json()["meta"]["billing_available"] is False

        subscription = await client.get(
            f"{API}/billing/families/{family.family_id}/subscription",
            headers=family.parent.headers,
        )
        assert subscription.status_code == 200
        data = subscription.json()["data"]
        assert data["status"] == SubscriptionStatus.none.value
        assert data["billing_available"] is False
        # With no provider configured the deployment is fully usable.
        assert data["entitlements"]["max_children"] is None

    async def test_checkout_fails_explicitly_rather_than_faking_success(
        self, client, family
    ) -> None:
        response = await client.post(
            f"{API}/billing/families/{family.family_id}/checkout",
            json={"plan_code": "family_monthly"},
            headers=family.parent.headers,
        )
        assert response.status_code in (501, 503)
        assert response.json()["error"]["code"] in (
            "NOT_IMPLEMENTED",
            "INTEGRATION_NOT_CONFIGURED",
        )

    async def test_unsigned_webhook_is_rejected(self, client) -> None:
        response = await client.post(
            f"{API}/billing/webhooks/generic_hmac",
            content=json.dumps({"id": "evt_1", "type": "subscription.activated"}),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "WEBHOOK_SIGNATURE_INVALID"

    async def test_signed_webhook_activates_and_is_idempotent(
        self, client, family, session, monkeypatch
    ) -> None:
        """Only a signature-verified webhook may change entitlement."""
        secret = "test-webhook-secret-value"
        monkeypatch.setattr(settings, "payment_provider", "generic_hmac")
        monkeypatch.setattr(settings, "payment_webhook_secret", secret)
        set_payment_provider(GenericHmacPaymentProvider())

        session.add(
            Plan(
                code="family_monthly",
                name="Family",
                price_minor_units=499,
                currency="GBP",
            )
        )
        await session.commit()

        body = json.dumps(
            {
                "id": "evt_signed_1",
                "type": "subscription.activated",
                "data": {
                    "family_id": family.family_id,
                    "plan_code": "family_monthly",
                    "subscription_ref": "sub_123",
                },
            }
        ).encode()
        timestamp = str(int(utcnow().timestamp()))
        signature = hmac_sha256_hex(secret, f"{timestamp}.".encode() + body)

        headers = {
            "content-type": "application/json",
            "x-webhook-signature": f"t={timestamp},v1={signature}",
        }
        first = await client.post(
            f"{API}/billing/webhooks/generic_hmac", content=body, headers=headers
        )
        assert first.status_code == 200, first.text
        assert first.json()["data"]["processed"] is True
        assert first.json()["data"]["duplicate"] is False

        replay = await client.post(
            f"{API}/billing/webhooks/generic_hmac", content=body, headers=headers
        )
        assert replay.status_code == 200
        assert replay.json()["data"]["duplicate"] is True

        stored = (
            (
                await session.execute(
                    select(Subscription).where(
                        Subscription.family_id == uuid.UUID(family.family_id)
                    )
                )
            )
            .scalars()
            .one()
        )
        await session.refresh(stored)
        assert stored.status is SubscriptionStatus.active
        assert stored.provider_subscription_ref == "sub_123"

        events = (await session.execute(select(PaymentWebhookEvent))).scalars().all()
        assert len(events) == 1
        assert events[0].signature_verified is True

        set_payment_provider(None)

    async def test_tampered_body_fails_verification(
        self, client, family, session, monkeypatch
    ) -> None:
        secret = "test-webhook-secret-value"
        monkeypatch.setattr(settings, "payment_provider", "generic_hmac")
        monkeypatch.setattr(settings, "payment_webhook_secret", secret)
        set_payment_provider(GenericHmacPaymentProvider())

        original = json.dumps({"id": "evt_t1", "type": "subscription.activated"}).encode()
        timestamp = str(int(utcnow().timestamp()))
        signature = hmac_sha256_hex(secret, f"{timestamp}.".encode() + original)

        tampered = json.dumps({"id": "evt_t1", "type": "subscription.cancelled"}).encode()
        response = await client.post(
            f"{API}/billing/webhooks/generic_hmac",
            content=tampered,
            headers={
                "content-type": "application/json",
                "x-webhook-signature": f"t={timestamp},v1={signature}",
            },
        )
        assert response.status_code == 400
        set_payment_provider(None)

    async def test_stale_timestamp_is_rejected(self, client, session, monkeypatch) -> None:
        """Replay protection: a captured delivery must not work days later."""
        secret = "test-webhook-secret-value"
        monkeypatch.setattr(settings, "payment_provider", "generic_hmac")
        monkeypatch.setattr(settings, "payment_webhook_secret", secret)
        set_payment_provider(GenericHmacPaymentProvider())

        body = json.dumps({"id": "evt_old", "type": "subscription.activated"}).encode()
        stale = str(int(utcnow().timestamp()) - 86_400)
        signature = hmac_sha256_hex(secret, f"{stale}.".encode() + body)

        response = await client.post(
            f"{API}/billing/webhooks/generic_hmac",
            content=body,
            headers={
                "content-type": "application/json",
                "x-webhook-signature": f"t={stale},v1={signature}",
            },
        )
        assert response.status_code == 400
        set_payment_provider(None)
