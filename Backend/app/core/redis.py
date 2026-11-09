"""Shared async Redis client.

Redis is used for rate-limit counters, WebSocket fan-out, and the Celery
broker/result backend. The client is created lazily so the API can still boot
(and report ``not ready``) when Redis is down.
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as redis_asyncio
from redis.asyncio import Redis

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_client: Redis | None = None


def redis_enabled() -> bool:
    return bool(settings.redis_url)


def get_redis() -> Redis | None:
    """Return the process-wide Redis client, or ``None`` when not configured."""
    global _client
    if not settings.redis_url:
        return None
    if _client is None:
        _client = redis_asyncio.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
            retry_on_timeout=True,
        )
    return _client


async def ping_redis() -> bool:
    client = get_redis()
    if client is None:
        return False
    try:
        return bool(await client.ping())
    except Exception as exc:  # noqa: BLE001 - readiness probe must not raise
        logger.warning("redis_ping_failed", error=type(exc).__name__)
        return False


async def close_redis() -> None:
    global _client
    if _client is not None:
        try:
            await _client.aclose()
        finally:
            _client = None


async def publish_json(channel: str, payload: dict[str, Any]) -> bool:
    """Best-effort publish. Returns False when Redis is unavailable."""
    import json

    client = get_redis()
    if client is None:
        return False
    try:
        await client.publish(channel, json.dumps(payload, default=str))
    except Exception as exc:  # noqa: BLE001
        logger.warning("redis_publish_failed", channel=channel, error=type(exc).__name__)
        return False
    return True
