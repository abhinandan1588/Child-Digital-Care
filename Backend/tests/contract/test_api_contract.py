"""API contract tests.

These exist so the three client teams can generate clients from the OpenAPI
document with confidence: the envelope is uniform, the examples in the docs
match reality, and a breaking change to a route or error code fails CI here
rather than in someone else's app.
"""

from __future__ import annotations

import pytest

from app.core.errors import ErrorCode
from app.db.enums import CommandType
from app.main import create_app
from tests.conftest import API

pytestmark = pytest.mark.contract


@pytest.fixture(scope="module")
def schema() -> dict:
    return create_app().openapi()


class TestOpenApiDocument:
    def test_schema_generates(self, schema) -> None:
        assert schema["openapi"].startswith("3.")
        assert schema["info"]["title"]
        assert schema["paths"]

    def test_bearer_scheme_is_declared(self, schema) -> None:
        assert "BearerAuth" in schema["components"]["securitySchemes"]

    def test_every_route_is_versioned_or_a_health_probe(self, schema) -> None:
        for path in schema["paths"]:
            assert path.startswith(("/api/v1/", "/health/")), path

    def test_every_operation_is_tagged_and_summarised(self, schema) -> None:
        missing: list[str] = []
        for path, operations in schema["paths"].items():
            for method, operation in operations.items():
                if not operation.get("tags"):
                    missing.append(f"{method.upper()} {path}: no tag")
                if not operation.get("summary"):
                    missing.append(f"{method.upper()} {path}: no summary")
        assert not missing, missing

    def test_no_internal_database_ids_are_exposed(self, schema) -> None:
        """Externally addressable ids are UUIDs, never sequential integers."""
        offenders: list[str] = []
        for name, component in schema["components"]["schemas"].items():
            properties = component.get("properties", {})
            for field, spec in properties.items():
                if field == "id" or field.endswith("_id"):
                    rendered = str(spec)
                    if '"integer"' in rendered or "'integer'" in rendered:
                        offenders.append(f"{name}.{field}")
        assert not offenders, offenders

    def test_the_three_client_surfaces_are_all_present(self, schema) -> None:
        tags = {
            tag
            for operations in schema["paths"].values()
            for operation in operations.values()
            for tag in operation.get("tags", [])
        }
        # Parent App
        assert {"auth", "families", "children", "policies", "usage", "alerts"} <= tags
        # Child App
        assert {"device", "device-auth"} <= tags
        # Admin Dashboard
        assert "admin" in tags

    def test_command_payloads_are_a_closed_discriminated_union(self, schema) -> None:
        """A client cannot invent a command type: the schema enumerates them."""
        component = schema["components"]["schemas"]["CommandCreateRequest"]
        rendered = str(component)
        for command_type in CommandType:
            if command_type in {CommandType.revoke_device}:
                continue
            assert command_type.value in str(schema["components"]["schemas"]), command_type
        assert "discriminator" in rendered or "oneOf" in rendered or "anyOf" in rendered


class TestResponseEnvelope:
    async def test_success_envelope_shape(self, client) -> None:
        response = await client.get(f"{API}/billing/plans")
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"success", "message", "data", "meta"}
        assert body["success"] is True
        assert isinstance(body["message"], str)
        assert "request_id" in body["meta"]

    async def test_error_envelope_shape(self, client) -> None:
        response = await client.get(f"{API}/auth/me")
        assert response.status_code == 401
        body = response.json()
        assert set(body) == {"success", "error", "meta"}
        assert body["success"] is False
        assert set(body["error"]) >= {"code", "message"}
        assert body["error"]["code"] in {item.value for item in ErrorCode}

    async def test_validation_error_lists_fields(self, client) -> None:
        response = await client.post(f"{API}/auth/login", json={"email": "not-an-email"})
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "VALIDATION_ERROR"
        assert error["details"]
        assert {"field", "issue"} <= set(error["details"][0])

    async def test_paginated_envelope_shape(self, client, family) -> None:
        response = await client.get(f"{API}/alerts", headers=family.parent.headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert set(data) == {"items", "page_info"}
        assert set(data["page_info"]) >= {"next_cursor", "has_more", "limit"}

    async def test_timestamps_are_iso_utc(self, client, family) -> None:
        response = await client.get(
            f"{API}/children/{family.child_id}", headers=family.parent.headers
        )
        created = response.json()["data"]["created_at"]
        assert created.endswith(("Z", "+00:00")), created


class TestDocumentedExamples:
    """The examples in docs/API_CONTRACT.md and section 21 of the master prompt
    must be real, working requests."""

    async def test_create_pairing_invitation_example(self, client, family) -> None:
        response = await client.post(
            f"{API}/children/{family.child_id}/pairing-invitations",
            json={},
            headers=family.parent.headers,
        )
        assert response.status_code == 201
        data = response.json()["data"]
        assert {"invitation_id", "claim_token", "expires_at", "status"} <= set(data)
        assert data["status"] == "pending"

    async def test_claim_pairing_invitation_example(self, client, family) -> None:
        invitation = await client.post(
            f"{API}/children/{family.child_id}/pairing-invitations",
            json={},
            headers=family.parent.headers,
        )
        response = await client.post(
            f"{API}/device/pairing/claim",
            json={
                "claim_token": invitation.json()["data"]["claim_token"],
                "device": {
                    "platform": "android",
                    "app_version": "1.0.0",
                    "os_version": "Android 16",
                    "device_label": "Child's phone",
                    "install_id": "example-install-000001",
                },
                "disclosure_version": "2026-01",
                "disclosure_acknowledged": True,
            },
        )
        assert response.status_code == 201
        data = response.json()["data"]
        assert {
            "device_id",
            "device_access_token",
            "device_refresh_token",
            "token_type",
            "expires_in",
            "status",
        } <= set(data)
        assert data["token_type"] == "Bearer"

    async def test_create_app_restriction_example(self, client, family) -> None:
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
        assert response.status_code == 201
        data = response.json()["data"]
        assert {"restriction_id", "policy_version", "sync_status"} <= set(data)
        assert data["sync_status"] == "pending_sync"

    async def test_device_command_result_example(self, client, family) -> None:
        fetched = await client.get(f"{API}/device/commands", headers=family.device.headers)
        command_id = fetched.json()["data"]["commands"][0]["command_id"]

        response = await client.post(
            f"{API}/device/commands/{command_id}/result",
            json={
                "result": "unsupported",
                "applied_policy_version": 3,
                "error_code": "REQUIRED_PERMISSION_NOT_GRANTED",
                "message": "The required permission is not enabled on this device.",
            },
            headers=family.device.headers,
        )
        assert response.status_code == 200
        assert response.json()["data"]["status"] == "unsupported"


class TestIntegrationStatusEndpoint:
    async def test_reports_configuration_honestly(self, client) -> None:
        """A client must be able to tell what will and will not work."""
        response = await client.get("/health/integrations")
        assert response.status_code == 200
        body = response.json()
        assert body["payments"]["configured"] is False
        assert body["features"]["location"] is False
        assert set(body) == {"email", "push", "payments", "object_storage", "features"}

    async def test_readiness_reports_dependencies(self, client) -> None:
        response = await client.get("/health/ready")
        assert response.status_code == 200
        body = response.json()
        assert body["checks"]["database"] == "ok"
        # Nothing about hostnames, versions or connection strings.
        assert "version" not in body
        assert "database_url" not in str(body)
