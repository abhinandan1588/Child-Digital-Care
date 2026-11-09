"""WebSocket handshake and realtime subscription endpoint.

Two decisions shape this module:

* **Tickets, not query-string access tokens.** A browser cannot set an
  ``Authorization`` header on a WebSocket. Rather than let a long-lived access
  token sit in a URL (where it lands in proxy logs and browser history), the
  client exchanges it for a single-purpose ticket with a ~60 second lifetime and
  the ``cdc:ws`` audience, which is rejected on every REST route.

* **Authorization is re-evaluated at subscribe time.** A connection is not an
  identity: membership is re-read from the database when a subscription is
  requested, so a guardian removed from a family stops receiving its events.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from app.api.deps import (
    CurrentParent,
    DbSession,
    require_websocket_feature,
)
from app.core.config import settings
from app.core.errors import ErrorCode
from app.core.logging import get_logger
from app.core.rate_limit import RateLimit
from app.core.response import ApiResponse, ok
from app.core.security import (
    PrincipalType,
    TokenAudience,
    TokenKind,
    create_access_token,
    decode_access_token,
)
from app.db.session import get_sessionmaker
from app.schemas.notification import RealtimeTicketOut
from app.services import family_service
from app.websocket.manager import connection_manager

logger = get_logger(__name__)

router = APIRouter(tags=["realtime"])

# Guarded so a client cannot ask to subscribe to arbitrary channel strings.
MAX_SUBSCRIPTIONS = 10
PING_INTERVAL_SECONDS = 30


@router.post(
    "/realtime/ticket",
    response_model=ApiResponse[RealtimeTicketOut],
    summary="Mint a short-lived WebSocket ticket",
    dependencies=[Depends(RateLimit("ws.ticket")), Depends(require_websocket_feature)],
)
async def create_ticket(principal: CurrentParent, session: DbSession) -> dict:
    """Exchange an access token for a ticket usable only on the WebSocket route.

    The ticket carries the authorised family ids as scopes, so the socket does
    not have to trust anything the client sends after connecting.
    """
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    scopes = tuple(f"family:{family.id}" for family, _ in memberships)

    issued = create_access_token(
        subject=principal.id,
        principal_type=PrincipalType.parent_user,
        audience=TokenAudience.websocket,
        kind=TokenKind.ws_ticket,
        expires_in_minutes=max(1, settings.ws_ticket_expire_seconds // 60),
        session_id=principal.session_id,
        scopes=scopes,
    )
    return ok(
        RealtimeTicketOut(
            ticket=issued.token,
            expires_in=settings.ws_ticket_expire_seconds,
            websocket_url=f"{settings.api_v1_prefix}/realtime/ws",
        ),
        message="Ticket issued.",
    )


@router.websocket("/realtime/ws")
async def realtime_socket(
    websocket: WebSocket,
    ticket: str = Query(description="Ticket from POST /realtime/ticket."),
) -> None:
    """Authenticated event stream for the Parent App.

    Protocol:

    * client -> server: ``{"action": "subscribe", "family_id": "<uuid>"}``,
      ``{"action": "unsubscribe", "family_id": "<uuid>"}``, ``{"action": "ping"}``
    * server -> client: ``{"event": "<name>", "data": {...}, "emitted_at": "..."}``

    Events are hints only. A client that misses a frame recovers by calling
    REST, which remains the source of truth.
    """
    if not settings.feature_websockets_enabled:
        await websocket.close(code=1008, reason="Realtime updates are disabled.")
        return

    try:
        claims = decode_access_token(
            ticket,
            expected_audience=TokenAudience.websocket,
            expected_principal=PrincipalType.parent_user,
            expected_kind=TokenKind.ws_ticket,
        )
    except Exception:  # noqa: BLE001 - never leak why a handshake failed
        await websocket.close(code=1008, reason="Invalid or expired ticket.")
        return

    user_id = claims.subject_uuid
    await websocket.accept()

    subscriptions: set[uuid.UUID] = set()
    sessionmaker = get_sessionmaker()
    listener: asyncio.Task | None = None

    try:
        listener = asyncio.create_task(connection_manager.pump(websocket, subscriptions))
        await _send(websocket, {"event": "connection.ready", "data": {"user_id": str(user_id)}})

        while True:
            raw = await websocket.receive_text()
            try:
                message = json.loads(raw)
            except ValueError:
                await _send_error(websocket, ErrorCode.MALFORMED_REQUEST, "Expected JSON.")
                continue

            action = str(message.get("action", ""))

            if action == "ping":
                await _send(websocket, {"event": "pong", "data": {}})
                continue

            if action in ("subscribe", "unsubscribe"):
                family_id_raw = message.get("family_id")
                try:
                    family_id = uuid.UUID(str(family_id_raw))
                except (ValueError, TypeError):
                    await _send_error(
                        websocket, ErrorCode.VALIDATION_ERROR, "family_id must be a UUID."
                    )
                    continue

                if action == "unsubscribe":
                    subscriptions.discard(family_id)
                    await connection_manager.unsubscribe(websocket, family_id)
                    await _send(
                        websocket,
                        {"event": "unsubscribed", "data": {"family_id": str(family_id)}},
                    )
                    continue

                if len(subscriptions) >= MAX_SUBSCRIPTIONS:
                    await _send_error(
                        websocket, ErrorCode.QUOTA_EXCEEDED, "Too many subscriptions."
                    )
                    continue

                # Re-check membership against the database, not the ticket, so a
                # guardian removed since the ticket was issued is refused.
                async with sessionmaker() as db:
                    try:
                        await family_service.resolve_family_access(
                            db, user_id=user_id, family_id=family_id
                        )
                    except Exception:  # noqa: BLE001
                        logger.info(
                            "ws_subscription_denied",
                            user_id=str(user_id),
                            family_id=str(family_id),
                        )
                        await _send_error(
                            websocket,
                            ErrorCode.PERMISSION_DENIED,
                            "You do not have access to that family.",
                        )
                        continue

                subscriptions.add(family_id)
                await connection_manager.subscribe(websocket, family_id)
                await _send(
                    websocket, {"event": "subscribed", "data": {"family_id": str(family_id)}}
                )
                continue

            await _send_error(websocket, ErrorCode.MALFORMED_REQUEST, "Unknown action.")

    except WebSocketDisconnect:
        logger.info("ws_disconnected", user_id=str(user_id))
    except Exception as exc:  # noqa: BLE001
        logger.warning("ws_error", error=type(exc).__name__)
    finally:
        if listener is not None:
            listener.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await listener
        await connection_manager.disconnect(websocket)


async def _send(websocket: WebSocket, payload: dict) -> None:
    with contextlib.suppress(Exception):
        await websocket.send_text(json.dumps(payload, default=str))


async def _send_error(websocket: WebSocket, code: ErrorCode, message: str) -> None:
    await _send(
        websocket,
        {"event": "error", "data": {"code": code.value, "message": message}},
    )
