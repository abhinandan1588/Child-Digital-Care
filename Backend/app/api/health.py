"""Operational health endpoints.

``/health/live`` answers "is this process running" and touches nothing.
``/health/ready`` checks the dependencies a request actually needs. Neither
exposes version strings, hostnames, connection strings or dependency internals:
the readiness body names a dependency and whether it is reachable, nothing more.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.core.config import settings
from app.core.redis import ping_redis, redis_enabled
from app.db.session import check_database
from app.integrations.firebase import get_push_provider
from app.integrations.payments import get_payment_provider
from app.utils.time import utcnow

router = APIRouter(tags=["health"])


@router.get("/health/live", summary="Liveness probe")
async def live() -> dict:
    return {"status": "alive", "time": utcnow().isoformat()}


@router.get("/health/ready", summary="Readiness probe")
async def ready(response: Response) -> dict:
    """Not ready unless the database is reachable.

    Redis is reported but is not fatal on its own: with ``RATE_LIMIT_FAIL_OPEN``
    the API still serves requests, and the outbox simply drains later.
    """
    database_ok = await check_database()
    redis_ok = await ping_redis() if redis_enabled() else None

    checks: dict[str, str] = {
        "database": "ok" if database_ok else "unavailable",
        "redis": ("ok" if redis_ok else "unavailable") if redis_ok is not None else "disabled",
    }
    ready_state = database_ok
    if not ready_state:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if ready_state else "not_ready",
        "checks": checks,
        "time": utcnow().isoformat(),
    }


@router.get("/health/integrations", summary="Which optional integrations are configured")
async def integrations() -> dict:
    """Honest configuration report, so a client never has to guess whether a
    feature will work. ``not_configured`` means calls will fail explicitly
    rather than silently succeeding."""
    return {
        "email": {
            "provider": settings.email_provider,
            "configured": settings.email_provider != "disabled",
        },
        "push": {
            "provider": get_push_provider().name,
            "configured": get_push_provider().configured,
        },
        "payments": {
            "provider": get_payment_provider().name,
            "configured": get_payment_provider().configured,
        },
        "object_storage": {
            "provider": settings.object_storage_provider,
            "configured": settings.object_storage_configured,
        },
        "features": {
            "location": settings.feature_location_enabled,
            "website_restrictions": settings.feature_website_restrictions_enabled,
            "guardian_invitations": settings.feature_guardian_invitations_enabled,
            "websockets": settings.feature_websockets_enabled,
        },
    }
