"""WebSocket connection registry and Redis fan-out.

A connection subscribes to family channels. Published events arrive over Redis
Pub/Sub, so any API instance can deliver an event for a family regardless of
which instance holds the socket. Without Redis the manager still works for a
single process, which is enough for local development.

Nothing here performs authorization: the endpoint checks family membership
against the database before calling :meth:`ConnectionManager.subscribe`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from collections import defaultdict

from fastapi import WebSocket

from app.core.logging import get_logger
from app.core.redis import get_redis
from app.services.realtime_service import family_channel

logger = get_logger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._subscribers: dict[uuid.UUID, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def subscribe(self, websocket: WebSocket, family_id: uuid.UUID) -> None:
        async with self._lock:
            self._subscribers[family_id].add(websocket)

    async def unsubscribe(self, websocket: WebSocket, family_id: uuid.UUID) -> None:
        async with self._lock:
            self._subscribers[family_id].discard(websocket)
            if not self._subscribers[family_id]:
                self._subscribers.pop(family_id, None)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            for family_id in list(self._subscribers):
                self._subscribers[family_id].discard(websocket)
                if not self._subscribers[family_id]:
                    self._subscribers.pop(family_id, None)
        with contextlib.suppress(Exception):
            await websocket.close()

    async def deliver_local(self, family_id: uuid.UUID, payload: dict) -> int:
        """Send to sockets attached to this process."""
        async with self._lock:
            targets = list(self._subscribers.get(family_id, ()))
        delivered = 0
        for socket in targets:
            try:
                await socket.send_text(json.dumps(payload, default=str))
                delivered += 1
            except Exception:  # noqa: BLE001 - a dead socket must not break fan-out
                await self.unsubscribe(socket, family_id)
        return delivered

    async def pump(self, websocket: WebSocket, subscriptions: set[uuid.UUID]) -> None:
        """Relay Redis messages for this socket's subscriptions.

        Runs as a task for the connection's lifetime. With Redis unavailable it
        idles, and the client still recovers state through REST.
        """
        client = get_redis()
        if client is None:
            # No fan-out backend: park the task until the connection closes and
            # the endpoint cancels it. An Event would need a second object to
            # own and set; cancellation already does the job.
            while True:  # noqa: ASYNC110
                await asyncio.sleep(30)

        pubsub = client.pubsub()
        known: set[uuid.UUID] = set()
        try:
            while True:
                new = subscriptions - known
                gone = known - subscriptions
                for family_id in new:
                    await pubsub.subscribe(family_channel(family_id))
                    known.add(family_id)
                for family_id in gone:
                    with contextlib.suppress(Exception):
                        await pubsub.unsubscribe(family_channel(family_id))
                    known.discard(family_id)

                if not known:
                    await asyncio.sleep(0.5)
                    continue

                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message is None:
                    continue
                data = message.get("data")
                if not data:
                    continue
                with contextlib.suppress(Exception):
                    await websocket.send_text(
                        data if isinstance(data, str) else json.dumps(data, default=str)
                    )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("ws_pump_failed", error=type(exc).__name__)
        finally:
            with contextlib.suppress(Exception):
                await pubsub.aclose()

    def local_connection_count(self) -> int:
        return sum(len(sockets) for sockets in self._subscribers.values())


connection_manager = ConnectionManager()
