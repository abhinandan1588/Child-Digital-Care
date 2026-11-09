"""Input validation, command allow-listing, and what responses must not reveal."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.core.logging import SENSITIVE_KEYS, redact_processor
from app.db.models.audit import AuditLog
from app.db.models.notification import PushToken
from tests.conftest import API

pytestmark = pytest.mark.security


class TestCommandAllowList:
    @pytest.mark.parametrize(
        "command_type",
        [
            "execute",
            "shell",
            "run_script",
            "install_package",
            "capture_screen",
            "record_audio",
            "record_video",
            "read_messages",
        ],
    )
    async def test_arbitrary_command_types_are_rejected(self, client, family, command_type) -> None:
        response = await client.post(
            f"{API}/devices/{family.device.device_id}/commands",
            json={"command": {"command_type": command_type, "payload": "anything"}},
            headers=family.parent.headers,
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    async def test_unexpected_payload_fields_are_rejected(self, client, family) -> None:
        response = await client.post(
            f"{API}/devices/{family.device.device_id}/commands",
            json={
                "command": {
                    "command_type": "refresh_device_status",
                    "shell_command": "rm -rf /",
                }
            },
            headers=family.parent.headers,
        )
        assert response.status_code == 422

    async def test_server_only_command_cannot_be_requested(self, client, family) -> None:
        response = await client.post(
            f"{API}/devices/{family.device.device_id}/commands",
            json={"command": {"command_type": "revoke_device", "reason": "bypass"}},
            headers=family.parent.headers,
        )
        assert response.status_code in (403, 422)

    async def test_allowed_types_are_published(self, client, family) -> None:
        response = await client.get(f"{API}/commands/allowed-types", headers=family.parent.headers)
        assert response.status_code == 200
        types = set(response.json()["data"])
        assert types == {
            "sync_policies",
            "refresh_device_status",
            "request_usage_sync",
            "request_location_update",
        }


class TestTelemetryScope:
    @pytest.mark.parametrize(
        "forbidden_key",
        ["latitude", "message_body", "keystrokes", "screenshot", "browsing_history"],
    )
    async def test_out_of_scope_event_payloads_are_refused(
        self, client, family, forbidden_key
    ) -> None:
        """This product does not collect message content, media or coordinates
        through device events, and the API refuses to store them."""
        response = await client.post(
            f"{API}/device/events",
            json={
                "events": [
                    {
                        "event_type": "app_started",
                        "occurred_at": "2026-01-01T10:00:00+00:00",
                        "deduplication_key": "evt-00000001",
                        "payload": {forbidden_key: "something"},
                    }
                ]
            },
            headers=family.device.headers,
        )
        assert response.status_code == 409

    async def test_implausible_usage_is_rejected(self, client, family) -> None:
        response = await client.post(
            f"{API}/device/usage/daily-summary",
            json={
                "local_date": "2026-01-01",
                "timezone": "Europe/London",
                "total_screen_time_seconds": 999_999,
            },
            headers=family.device.headers,
        )
        assert response.status_code == 422

    async def test_future_dated_usage_is_rejected(self, client, family) -> None:
        response = await client.post(
            f"{API}/device/usage/daily-summary",
            json={
                "local_date": "2099-01-01",
                "timezone": "Europe/London",
                "total_screen_time_seconds": 100,
            },
            headers=family.device.headers,
        )
        assert response.status_code == 200
        body = response.json()["data"]
        assert body["rejected"] == 1
        assert body["rejection_reasons"]["2099-01-01"] == "DATE_IN_FUTURE"

    async def test_location_is_refused_while_the_feature_is_off(self, client, family) -> None:
        response = await client.post(
            f"{API}/device/location",
            json={
                "latitude": 51.5,
                "longitude": -0.12,
                "recorded_at": "2026-01-01T10:00:00+00:00",
            },
            headers=family.device.headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "FEATURE_DISABLED"

    async def test_parent_location_routes_are_refused_too(self, client, family) -> None:
        response = await client.get(
            f"{API}/children/{family.child_id}/location/latest",
            headers=family.parent.headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "FEATURE_DISABLED"


class TestResponseDisclosure:
    async def test_push_token_is_never_returned_in_full(self, client, family) -> None:
        raw = "fake-parent-push-token-abcdefghijklmnop"
        response = await client.post(
            f"{API}/push-token",
            json={"token": raw, "platform": "android"},
            headers=family.parent.headers,
        )
        assert response.status_code == 201
        body = response.text
        assert raw not in body
        assert response.json()["data"]["token_suffix"] == raw[-6:]

    async def test_stored_push_token_is_not_exposed_through_any_read(
        self, client, family, session
    ) -> None:
        raw = "fake-parent-push-token-0123456789abcdef"
        await client.post(
            f"{API}/push-token",
            json={"token": raw, "platform": "android"},
            headers=family.parent.headers,
        )
        stored = (await session.execute(select(PushToken))).scalars().all()
        assert any(row.token_value == raw for row in stored)

        preferences = await client.get(
            f"{API}/notification-preferences", headers=family.parent.headers
        )
        assert raw not in preferences.text

    async def test_errors_do_not_leak_internals(self, client) -> None:
        response = await client.get(f"{API}/families/not-a-uuid")
        assert response.status_code in (401, 422)
        body = response.text.lower()
        for leak in ("traceback", "sqlalchemy", "select ", "sqlite", "password_hash"):
            assert leak not in body

    async def test_404_body_is_the_standard_envelope(self, client) -> None:
        response = await client.get(f"{API}/does-not-exist")
        assert response.status_code == 404
        body = response.json()
        assert body["success"] is False
        assert body["error"]["code"] == "NOT_FOUND"
        assert "request_id" in body["meta"]

    async def test_request_id_is_echoed(self, client) -> None:
        response = await client.get("/health/live", headers={"X-Request-ID": "caller-supplied-id"})
        assert response.headers["X-Request-ID"] == "caller-supplied-id"

    async def test_security_headers_are_present(self, client) -> None:
        response = await client.get("/health/live")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers

    async def test_api_responses_get_the_strict_csp(self, client) -> None:
        """The JSON API loads nothing, so it should be allowed to load nothing."""
        for path in ("/health/live", f"{API}/billing/plans", f"{API}/auth/me"):
            csp = (await client.get(path)).headers["Content-Security-Policy"]
            assert csp.startswith("default-src 'none'"), path

    async def test_docs_page_csp_permits_its_own_assets(self, client) -> None:
        """Regression: `default-src 'none'` on /docs blocked Swagger UI's own
        stylesheet, script bundle and inline bootstrap, rendering a blank page.
        """
        response = await client.get("/docs")
        assert response.status_code == 200

        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'none'" not in csp
        # Everything the FastAPI-generated docs HTML actually needs.
        assert "https://cdn.jsdelivr.net" in csp
        assert "'unsafe-inline'" in csp  # the inline SwaggerUIBundle(...) call
        assert "connect-src 'self'" in csp  # fetching /openapi.json
        # Still an allow-list, not an opt-out.
        assert "frame-ancestors 'none'" in csp
        assert "default-src 'self'" in csp

        # Confirm the page really does reference those origins, so this test
        # fails if FastAPI changes how the docs are assembled.
        body = response.text
        assert "cdn.jsdelivr.net" in body
        assert "SwaggerUIBundle" in body

    async def test_redoc_gets_the_same_treatment(self, client) -> None:
        response = await client.get("/redoc")
        assert response.status_code == 200
        assert "default-src 'none'" not in response.headers["Content-Security-Policy"]


class TestAuditContent:
    async def test_audit_rows_never_store_secrets(self, client, family, session) -> None:
        await client.post(
            f"{API}/children/{family.child_id}/pairing-invitations",
            json={},
            headers=family.parent.headers,
        )
        rows = (await session.execute(select(AuditLog))).scalars().all()
        assert rows
        for row in rows:
            blob = json.dumps(row.event_metadata or {}).lower()
            for forbidden in ("token", "password", "latitude", "longitude", "secret"):
                assert forbidden not in blob, row.action

    async def test_audit_ip_is_truncated(self, client, family, session) -> None:
        rows = (await session.execute(select(AuditLog))).scalars().all()
        for row in rows:
            if row.ip_prefix:
                assert row.ip_prefix.endswith(("/24", "/48"))


class TestLogRedaction:
    def test_sensitive_keys_are_redacted(self) -> None:
        event = {
            "event": "test",
            "access_token": "secret-value",
            "password": "hunter2",
            "latitude": 51.5,
            "safe": "visible",
        }
        cleaned = redact_processor(None, "info", dict(event))
        assert cleaned["access_token"] == "[redacted]"
        assert cleaned["password"] == "[redacted]"
        assert cleaned["latitude"] == "[redacted]"
        assert cleaned["safe"] == "visible"

    def test_embedded_jwt_is_scrubbed(self) -> None:
        cleaned = redact_processor(
            None,
            "info",
            {"note": "header eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl tail"},
        )
        assert "eyJhbGciOi" not in cleaned["note"]

    def test_the_deny_list_covers_the_obvious_credentials(self) -> None:
        for key in ("password", "access_token", "refresh_token", "claim_token", "latitude"):
            assert key in SENSITIVE_KEYS
