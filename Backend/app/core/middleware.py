"""HTTP middleware: correlation ids, access logging, body limits, security headers."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core import context
from app.core.config import settings
from app.core.errors import ErrorCode
from app.core.logging import get_logger

logger = get_logger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

# Paths excluded from access logging to keep health-probe noise out of logs.
_QUIET_PATHS = frozenset({"/health/live", "/health/ready", "/metrics"})

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}

#: The API serves JSON only, so it needs to load nothing at all.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

#: Swagger UI and ReDoc are real HTML pages: they pull a stylesheet and a
#: script bundle from jsDelivr, boot from an inline <script>, inject inline
#: styles, and fetch /openapi.json. Under ``default-src 'none'`` the browser
#: blocks all of that and renders a blank page, so the documentation routes get
#: their own policy. It is still an allow-list, and it applies only to the two
#: documentation paths - which are disabled entirely in production.
DOCS_CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'",
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'",
        "img-src 'self' data: https://fastapi.tiangolo.com",
        "font-src 'self' data: https://cdn.jsdelivr.net",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
    )
)


class RequestContextMiddleware:
    """Assign/propagate a request id and emit one structured access log line."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        incoming = headers.get(REQUEST_ID_HEADER.lower())
        request_id = incoming if incoming and len(incoming) <= 128 else context.new_request_id()
        context.set_request_id(request_id)
        context.set_principal(None)
        scope.setdefault("state", {})
        scope["state"]["request_id"] = request_id

        if scope["type"] == "websocket":
            try:
                await self.app(scope, receive, send)
            finally:
                context.reset()
            return

        started = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            path = scope.get("path", "")
            if path not in _QUIET_PATHS:
                duration_ms = round((time.perf_counter() - started) * 1000, 2)
                logger.info(
                    "http_request",
                    method=scope.get("method"),
                    path=path,
                    route=_route_template(scope),
                    status_code=status_holder["status"],
                    duration_ms=duration_ms,
                )
            context.reset()


def _route_template(scope: Scope) -> str | None:
    route = scope.get("route")
    return getattr(route, "path", None) if route else None


class BodySizeLimitMiddleware:
    """Reject oversized request bodies before they are buffered into memory."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(scope, send)
            return

        received = 0
        too_large = False

        async def guarded_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    # Truncate the stream so the handler sees a complete (empty) body
                    # and the 413 below is what the client receives.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        await self.app(scope, guarded_receive, send)
        if too_large:  # pragma: no cover - logged for observability
            logger.warning("request_body_truncated", path=scope.get("path"), received=received)

    async def _reject(self, scope: Scope, send: Send) -> None:
        request_id = scope.get("state", {}).get("request_id")
        response = JSONResponse(
            status_code=413,
            content={
                "success": False,
                "error": {
                    "code": ErrorCode.PAYLOAD_TOO_LARGE.value,
                    "message": f"Request body exceeds the {self.max_bytes} byte limit.",
                },
                "meta": {"request_id": request_id},
            },
        )
        await response(scope, _empty_receive, send)


async def _empty_receive() -> Message:  # pragma: no cover
    return {"type": "http.request", "body": b"", "more_body": False}


class SecurityHeadersMiddleware:
    """Defence-in-depth headers. A TLS-terminating proxy may also set these.

    ``documentation_paths`` is supplied from the app's own ``docs_url`` and
    ``redoc_url`` so the two cannot drift apart.
    """

    def __init__(self, app: ASGIApp, documentation_paths: frozenset[str] | None = None) -> None:
        self.app = app
        self.documentation_paths = documentation_paths or frozenset()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        csp = DOCS_CSP if scope.get("path") in self.documentation_paths else API_CSP

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in SECURITY_HEADERS.items():
                    headers.setdefault(key, value)
                headers.setdefault("Content-Security-Policy", csp)
                if settings.is_production:
                    headers.setdefault(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    )
            await send(message)

        await self.app(scope, receive, send_wrapper)


AsyncHandler = Callable[[Request], Awaitable[Response]]
