"""FastAPI application factory.

Middleware order (outermost first) matters:

1. ``RequestContextMiddleware`` - assigns the correlation id before anything
   else can log.
2. ``SecurityHeadersMiddleware`` - headers on every response, including errors.
3. ``BodySizeLimitMiddleware`` - rejects oversized bodies before they are read.
4. ``TrustedHostMiddleware`` / ``CORSMiddleware`` - host and origin allow-lists.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.redis import close_redis, ping_redis, redis_enabled
from app.db.session import check_database, dispose_engine

logger = get_logger(__name__)

DESCRIPTION = """
Backend API for **Child Digital Care**: an Android-first parental-control and
family digital-wellbeing platform.

This API is the single source of truth for three separately developed clients
(Parent App, Child App, Admin Dashboard). The clients never talk to each other
or to the database directly.

### What the server does and does not claim

The server stores policy *intent*, distributes typed commands, and records what
devices report back. It cannot enforce anything on an Android device. A rule is
only ever reported as applied because a device acknowledged applying it;
`unsupported` and `permission_denied` are first-class outcomes and are never
translated into success.

### Principals

| Principal | Audience | Obtained via |
| --- | --- | --- |
| Parent / guardian | `cdc:parent` | `POST /auth/login` |
| Child device | `cdc:device` | `POST /device/pairing/claim` |
| Admin | `cdc:admin` | `POST /admin/auth/login` |

A credential for one principal is rejected on another's routes.

### Conventions

* Every success response uses the envelope
  `{"success": true, "message": ..., "data": ..., "meta": {"request_id": ...}}`.
* Errors use `{"success": false, "error": {"code", "message", "details"}, "meta": ...}`
  with a stable machine-readable `code`.
* Timestamps are ISO 8601 UTC; identifiers are UUIDs.
* Large collections use opaque cursor pagination.
* `Idempotency-Key` is honoured where a retry could otherwise duplicate work.
"""

TAGS_METADATA = [
    {"name": "health", "description": "Liveness, readiness and integration status."},
    {"name": "auth", "description": "Parent account authentication and sessions."},
    {"name": "families", "description": "Families and guardian membership."},
    {"name": "children", "description": "Child profiles."},
    {"name": "pairing", "description": "Pairing invitations and the device claim."},
    {"name": "devices", "description": "Device views and typed command requests."},
    {"name": "policies", "description": "App restrictions, screen time, schedules."},
    {"name": "usage", "description": "Device-reported usage reports."},
    {"name": "alerts", "description": "Parent-facing alerts."},
    {"name": "notifications", "description": "Push tokens and notification preferences."},
    {
        "name": "location",
        "description": (
            "Optional location module. Disabled by default; requires consent and a "
            "device-reported permission."
        ),
    },
    {"name": "billing", "description": "Plans, subscriptions and provider webhooks."},
    {"name": "privacy", "description": "Consent records, export and deletion."},
    {"name": "realtime", "description": "WebSocket tickets and the event stream."},
    {"name": "device-auth", "description": "Child App credential rotation."},
    {"name": "device", "description": "Child App: registration, sync, telemetry."},
    {"name": "admin", "description": "Admin Dashboard, permission-scoped."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    logger.info(
        "application_starting",
        version=__version__,
        env=settings.app_env.value,
        docs_enabled=settings.docs_enabled,
    )

    # Report dependency state at boot. The app still starts so that readiness
    # probes, not a crash loop, surface an unavailable database.
    if not await check_database():
        logger.error("database_unavailable_at_startup")
    if redis_enabled() and not await ping_redis():
        logger.warning("redis_unavailable_at_startup")

    try:
        yield
    finally:
        logger.info("application_stopping")
        await close_redis()
        await dispose_engine()


def create_app() -> FastAPI:
    configure_logging()

    app = FastAPI(
        title=settings.app_name,
        description=DESCRIPTION,
        version=__version__,
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
        # Interactive docs are off in production; the schema is still generated
        # for client codegen in CI.
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        swagger_ui_parameters={"persistAuthorization": True},
    )

    # Innermost added last: Starlette applies middleware in reverse order.
    if settings.trusted_hosts and "*" not in settings.trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            # Never a wildcard together with credentials.
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Idempotency-Key",
                "X-Request-ID",
            ],
            expose_headers=["X-Request-ID"],
            max_age=600,
        )

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    # Read the documentation paths off the app itself, so the relaxed CSP those
    # pages need always matches where they are actually served.
    app.add_middleware(
        SecurityHeadersMiddleware,
        documentation_paths=frozenset(
            path
            for path in (
                app.docs_url,
                app.redoc_url,
                app.swagger_ui_oauth2_redirect_url,
            )
            if path
        ),
    )
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    _install_openapi(app)
    return app


def _install_openapi(app: FastAPI) -> None:
    """Add the bearer security scheme and keep the schema cached."""

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
            tags=TAGS_METADATA,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["BearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "Access token from the matching login endpoint. Parent, device and "
                "admin tokens are not interchangeable."
            ),
        }
        schema["servers"] = [{"url": "/", "description": "This deployment"}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]


app = create_app()
