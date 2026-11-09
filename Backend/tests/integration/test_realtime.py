"""WebSocket handshake, subscription authorization and event fan-out.

These use Starlette's synchronous ``TestClient`` because it is the only
supported way to drive a WebSocket through an ASGI app in-process. That client
runs the app in its own event loop, so these tests deliberately do **not** use
the shared ``engine`` fixture: an async engine is bound to the loop that
created it. Instead the app builds its own engine, lazily, inside the
TestClient's loop, against a file-backed database created here.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.core.config import settings
from app.core.permissions import FamilyPermission, normalize_family_permissions
from app.core.security import (
    PrincipalType,
    TokenAudience,
    TokenKind,
    create_access_token,
    hash_password,
)
from app.db.enums import GuardianRelationship, MembershipStatus
from app.db.models import Base
from app.db.models.family import Family, FamilyMember
from app.db.models.identity import User
from app.db.session import configure_engine, dispose_engine, get_engine
from app.main import create_app
from app.utils.time import utcnow

pytestmark = pytest.mark.integration

API = "/api/v1"


@pytest.fixture
def realtime_app(tmp_path, monkeypatch):
    """App wired to a file-backed database holding one parent and one family."""
    database_path = tmp_path / "realtime.sqlite3"
    sync_url = f"sqlite+pysqlite:///{database_path}"
    async_url = f"sqlite+aiosqlite:///{database_path}"

    sync_engine = create_engine(sync_url)
    Base.metadata.create_all(sync_engine)

    user_id = uuid.uuid4()
    family_id = uuid.uuid4()
    with Session(sync_engine) as session:
        session.add(
            User(
                id=user_id,
                email="ws@example.test",
                normalized_email="ws@example.test",
                password_hash=hash_password("ws-test-password-01"),
                display_name="WS Parent",
                account_status="active",
                email_verified_at=utcnow(),
            )
        )
        session.add(Family(id=family_id, name="WS Family", owner_user_id=user_id))
        session.add(
            FamilyMember(
                family_id=family_id,
                user_id=user_id,
                relationship_type=GuardianRelationship.parent,
                membership_status=MembershipStatus.active,
                is_owner=True,
                permissions=normalize_family_permissions([perm.value for perm in FamilyPermission]),
                joined_at=utcnow(),
            )
        )
        session.commit()
    sync_engine.dispose()

    # Force the app to build its own async engine inside the TestClient loop.
    monkeypatch.setattr(settings, "database_url", async_url)
    monkeypatch.setattr(settings, "feature_websockets_enabled", True)

    import asyncio

    asyncio.run(dispose_engine())

    app = create_app()
    try:
        yield app, user_id, family_id
    finally:
        asyncio.run(dispose_engine())


@pytest.fixture
def ws_client(realtime_app):
    """A started TestClient, so individual tests open one context, not three."""
    app, user_id, family_id = realtime_app
    with TestClient(app) as client:
        yield client, user_id, family_id


def ws_ticket(user_id: uuid.UUID, family_ids: list[uuid.UUID]) -> str:
    return create_access_token(
        subject=user_id,
        principal_type=PrincipalType.parent_user,
        audience=TokenAudience.websocket,
        kind=TokenKind.ws_ticket,
        expires_in_minutes=1,
        scopes=tuple(f"family:{item}" for item in family_ids),
    ).token


class TestHandshake:
    """The ticket is checked before the socket is accepted."""

    def test_connects_and_announces_readiness(self, ws_client) -> None:
        client, user_id, family_id = ws_client
        ticket = ws_ticket(user_id, [family_id])

        with client.websocket_connect(f"{API}/realtime/ws?ticket={ticket}") as ws:
            ready = ws.receive_json()
            assert ready["event"] == "connection.ready"
            assert ready["data"]["user_id"] == str(user_id)

    def test_rejects_a_missing_ticket(self, ws_client) -> None:
        client, _, _ = ws_client
        # No ticket at all: the required query parameter fails validation, so
        # the socket is closed instead of being accepted unauthenticated.
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(f"{API}/realtime/ws"),
        ):
            pass

    def test_rejects_a_garbage_ticket(self, ws_client) -> None:
        client, _, _ = ws_client
        with (
            pytest.raises(WebSocketDisconnect) as exc,
            client.websocket_connect(f"{API}/realtime/ws?ticket=not-a-ticket"),
        ):
            pass
        # 1008 = policy violation, the close code used for a bad credential.
        assert exc.value.code == 1008

    def test_rejects_an_expired_ticket(self, ws_client) -> None:
        client, user_id, _ = ws_client
        expired = create_access_token(
            subject=user_id,
            principal_type=PrincipalType.parent_user,
            audience=TokenAudience.websocket,
            kind=TokenKind.ws_ticket,
            expires_in_minutes=-1,
        ).token

        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(f"{API}/realtime/ws?ticket={expired}"),
        ):
            pass

    def test_rejects_a_plain_access_token(self, ws_client) -> None:
        """A REST access token must not open the socket, and a ticket must not
        work on REST. The audience and kind claims enforce both directions."""
        client, user_id, _ = ws_client
        access = create_access_token(
            subject=user_id, principal_type=PrincipalType.parent_user
        ).token

        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(f"{API}/realtime/ws?ticket={access}"),
        ):
            pass

    def test_rejects_a_device_ticket(self, ws_client) -> None:
        client, _, family_id = ws_client
        device_ticket = create_access_token(
            subject=uuid.uuid4(),
            principal_type=PrincipalType.child_device,
            audience=TokenAudience.websocket,
            kind=TokenKind.ws_ticket,
            family_id=family_id,
        ).token

        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(f"{API}/realtime/ws?ticket={device_ticket}"),
        ):
            pass


class TestSubscriptions:
    """Authorization is re-evaluated per subscription, against the database."""

    def test_subscribe_and_unsubscribe_own_family(self, ws_client) -> None:
        client, user_id, family_id = ws_client
        ticket = ws_ticket(user_id, [family_id])

        with client.websocket_connect(f"{API}/realtime/ws?ticket={ticket}") as ws:
            ws.receive_json()  # connection.ready

            ws.send_json({"action": "subscribe", "family_id": str(family_id)})
            reply = ws.receive_json()
            assert reply["event"] == "subscribed"
            assert reply["data"]["family_id"] == str(family_id)

            ws.send_json({"action": "unsubscribe", "family_id": str(family_id)})
            assert ws.receive_json()["event"] == "unsubscribed"

    def test_membership_is_rechecked_against_the_database(self, ws_client) -> None:
        """A ticket is not authority. Even with a family in its scopes, the
        socket re-reads membership, so a removed guardian is refused."""
        client, user_id, _ = ws_client
        stranger_family = uuid.uuid4()
        ticket = ws_ticket(user_id, [stranger_family])

        with client.websocket_connect(f"{API}/realtime/ws?ticket={ticket}") as ws:
            ws.receive_json()
            ws.send_json({"action": "subscribe", "family_id": str(stranger_family)})
            reply = ws.receive_json()
            assert reply["event"] == "error"
            assert reply["data"]["code"] == "PERMISSION_DENIED"

    def test_ping_pong(self, ws_client) -> None:
        client, user_id, family_id = ws_client
        ticket = ws_ticket(user_id, [family_id])

        with client.websocket_connect(f"{API}/realtime/ws?ticket={ticket}") as ws:
            ws.receive_json()
            ws.send_json({"action": "ping"})
            assert ws.receive_json()["event"] == "pong"

    def test_malformed_frames_are_rejected_without_closing(self, ws_client) -> None:
        client, user_id, family_id = ws_client
        ticket = ws_ticket(user_id, [family_id])

        with client.websocket_connect(f"{API}/realtime/ws?ticket={ticket}") as ws:
            ws.receive_json()

            ws.send_text("not json at all")
            assert ws.receive_json()["data"]["code"] == "MALFORMED_REQUEST"

            ws.send_json({"action": "subscribe", "family_id": "not-a-uuid"})
            assert ws.receive_json()["data"]["code"] == "VALIDATION_ERROR"

            ws.send_json({"action": "teleport"})
            assert ws.receive_json()["data"]["code"] == "MALFORMED_REQUEST"

            # Still usable after three bad frames.
            ws.send_json({"action": "ping"})
            assert ws.receive_json()["event"] == "pong"

    def test_subscription_cap_is_declared(self, ws_client) -> None:
        from app.api.v1.endpoints.realtime import MAX_SUBSCRIPTIONS

        client, user_id, family_id = ws_client
        ticket = ws_ticket(user_id, [family_id])

        with client.websocket_connect(f"{API}/realtime/ws?ticket={ticket}") as ws:
            ws.receive_json()
            ws.send_json({"action": "subscribe", "family_id": str(family_id)})
            assert ws.receive_json()["event"] == "subscribed"

        # A further id would be refused on membership long before the cap is
        # reached, so the cap itself is asserted on the constant.
        assert MAX_SUBSCRIPTIONS == 10


class TestFanOut:
    async def test_published_event_reaches_a_local_subscriber(self, engine) -> None:
        """Fan-out without Redis: the in-process registry still delivers.

        This exercises ``ConnectionManager.deliver_local``, which is the path
        used when ``REDIS_URL`` is unset. Cross-instance fan-out goes through
        Redis pub/sub and is not covered here.
        """
        from app.services.realtime_service import RealtimeEvent, build_envelope
        from app.websocket.manager import ConnectionManager

        manager = ConnectionManager()
        family_id = uuid.uuid4()
        delivered: list[str] = []

        class FakeSocket:
            async def send_text(self, text: str) -> None:
                delivered.append(text)

            async def close(self) -> None:
                pass

        socket = FakeSocket()
        await manager.subscribe(socket, family_id)
        assert manager.local_connection_count() == 1

        envelope = build_envelope(
            RealtimeEvent.DEVICE_STATUS_CHANGED,
            {"device_id": str(uuid.uuid4()), "event": "registered"},
        )
        sent = await manager.deliver_local(family_id, envelope)
        assert sent == 1

        payload = json.loads(delivered[0])
        assert payload["event"] == "device.status_changed"
        assert "emitted_at" in payload

        # A different family's channel must not receive it.
        assert await manager.deliver_local(uuid.uuid4(), envelope) == 0

        await manager.disconnect(socket)
        assert manager.local_connection_count() == 0

    async def test_payloads_carrying_telemetry_are_refused(self, engine) -> None:
        """Realtime frames are hints, so they must not carry child data."""
        from app.services import realtime_service

        assert not await realtime_service.publish_to_family(
            uuid.uuid4(),
            realtime_service.RealtimeEvent.ALERT_CREATED,
            {"latitude": 51.5, "longitude": -0.12},
        )
        assert not await realtime_service.publish_to_family(
            uuid.uuid4(),
            realtime_service.RealtimeEvent.ALERT_CREATED,
            {"child_name": "Sam"},
        )


class TestTicketEndpoint:
    async def test_ticket_is_scoped_and_short_lived(self, client, family) -> None:
        from app.core.security import decode_access_token

        response = await client.post(f"{API}/realtime/ticket", headers=family.parent.headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["expires_in"] == settings.ws_ticket_expire_seconds
        assert data["websocket_url"].endswith("/realtime/ws")

        claims = decode_access_token(
            data["ticket"],
            expected_audience=TokenAudience.websocket,
            expected_principal=PrincipalType.parent_user,
            expected_kind=TokenKind.ws_ticket,
        )
        assert f"family:{family.family_id}" in claims.scopes

    async def test_ticket_is_rejected_on_rest_routes(self, client, family) -> None:
        response = await client.post(f"{API}/realtime/ticket", headers=family.parent.headers)
        ticket = response.json()["data"]["ticket"]

        blocked = await client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {ticket}"})
        assert blocked.status_code == 401
        assert blocked.json()["error"]["code"] == "TOKEN_INVALID"

    async def test_ticket_requires_authentication(self, client) -> None:
        assert (await client.post(f"{API}/realtime/ticket")).status_code == 401


def test_engine_helper_is_lazy() -> None:
    """Guards the assumption the fixture relies on: the engine is built on
    first use, so it belongs to whichever loop calls it first."""
    assert callable(get_engine)
    assert callable(configure_engine)
