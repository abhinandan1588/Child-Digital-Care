"""Domain error types, stable error codes, and FastAPI exception handlers.

Every error the API returns carries a machine-readable ``code`` from
:class:`ErrorCode`. Client teams branch on the code, never on the message text.
Messages are human-readable and safe to display; internal detail (stack traces,
SQL, secrets) is logged but never serialised into the response.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings

logger = structlog.get_logger(__name__)


class ErrorCode(StrEnum):
    """Stable error codes. Adding values is backwards compatible; renaming is not."""

    # Validation / request shape
    VALIDATION_ERROR = "VALIDATION_ERROR"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"

    # Authentication
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    REFRESH_TOKEN_REUSED = "REFRESH_TOKEN_REUSED"
    WRONG_PRINCIPAL_TYPE = "WRONG_PRINCIPAL_TYPE"
    EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED"
    ACCOUNT_SUSPENDED = "ACCOUNT_SUSPENDED"
    ACCOUNT_NOT_ACTIVE = "ACCOUNT_NOT_ACTIVE"
    MFA_REQUIRED = "MFA_REQUIRED"

    # Authorization
    PERMISSION_DENIED = "PERMISSION_DENIED"
    NOT_FAMILY_MEMBER = "NOT_FAMILY_MEMBER"
    DEVICE_SCOPE_VIOLATION = "DEVICE_SCOPE_VIOLATION"

    # Resources
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    IDEMPOTENCY_KEY_REUSED = "IDEMPOTENCY_KEY_REUSED"

    # Domain rules
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    INVITATION_EXPIRED = "INVITATION_EXPIRED"
    INVITATION_ALREADY_CLAIMED = "INVITATION_ALREADY_CLAIMED"
    INVITATION_REVOKED = "INVITATION_REVOKED"
    INVITATION_ATTEMPT_LIMIT = "INVITATION_ATTEMPT_LIMIT"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    DEVICE_NOT_ACTIVE = "DEVICE_NOT_ACTIVE"
    COMMAND_NOT_SUPPORTED = "COMMAND_NOT_SUPPORTED"
    COMMAND_EXPIRED = "COMMAND_EXPIRED"
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    PERMISSION_STATE_BLOCKS_ACTION = "PERMISSION_STATE_BLOCKS_ACTION"
    POLICY_CONFLICT = "POLICY_CONFLICT"
    SCHEDULE_INVALID = "SCHEDULE_INVALID"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"

    # Platform / integration
    FEATURE_DISABLED = "FEATURE_DISABLED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    INTEGRATION_NOT_CONFIGURED = "INTEGRATION_NOT_CONFIGURED"
    INTEGRATION_FAILURE = "INTEGRATION_FAILURE"
    WEBHOOK_SIGNATURE_INVALID = "WEBHOOK_SIGNATURE_INVALID"

    # Infrastructure
    RATE_LIMITED = "RATE_LIMITED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ErrorDetail(dict):
    """Convenience constructor for the ``details`` entries in an error payload."""

    def __init__(self, field: str, issue: str) -> None:
        super().__init__(field=field, issue=issue)


class AppError(Exception):
    """Base class for every error that is safe to surface to an API client."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: ErrorCode = ErrorCode.INTERNAL_ERROR
    message: str = "The request could not be completed."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: ErrorCode | None = None,
        status_code: int | None = None,
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
        log_context: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.status_code = status_code or self.status_code
        self.details = details or []
        self.headers = headers or {}
        self.log_context = log_context or {}
        super().__init__(self.message)

    def to_payload(self, request_id: str | None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.details:
            error["details"] = self.details
        return {"success": False, "error": error, "meta": {"request_id": request_id}}


# ---------------------------------------------------------------------------
# Concrete errors
# ---------------------------------------------------------------------------
class ValidationFailed(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = ErrorCode.VALIDATION_ERROR
    message = "The request contains invalid fields."


class AuthenticationRequired(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = ErrorCode.AUTHENTICATION_REQUIRED
    message = "Authentication is required."

    def __init__(self, message: str | None = None, **kwargs: Any) -> None:
        kwargs.setdefault("headers", {"WWW-Authenticate": "Bearer"})
        super().__init__(message, **kwargs)


class InvalidToken(AuthenticationRequired):
    code = ErrorCode.TOKEN_INVALID
    message = "The supplied token is not valid."


class TokenExpired(AuthenticationRequired):
    code = ErrorCode.TOKEN_EXPIRED
    message = "The supplied token has expired."


class InvalidCredentials(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = ErrorCode.INVALID_CREDENTIALS
    # Deliberately generic: do not leak whether the account exists.
    message = "Email or password is incorrect."


class PermissionDenied(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = ErrorCode.PERMISSION_DENIED
    message = "You do not have permission to perform this action."


class NotFound(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = ErrorCode.NOT_FOUND
    message = "The requested resource was not found."


class Conflict(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = ErrorCode.CONFLICT
    message = "The request conflicts with the current state of the resource."


class RateLimited(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = ErrorCode.RATE_LIMITED
    message = "Too many requests. Please retry later."

    def __init__(self, retry_after_seconds: int = 60, **kwargs: Any) -> None:
        kwargs.setdefault("headers", {"Retry-After": str(retry_after_seconds)})
        super().__init__(kwargs.pop("message", None), **kwargs)


class FeatureDisabled(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = ErrorCode.FEATURE_DISABLED
    message = "This feature is not enabled for this deployment."


class NotImplementedYet(AppError):
    status_code = status.HTTP_501_NOT_IMPLEMENTED
    code = ErrorCode.NOT_IMPLEMENTED
    message = "This capability is not implemented."


class IntegrationNotConfigured(AppError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = ErrorCode.INTEGRATION_NOT_CONFIGURED
    message = "A required external integration is not configured."


class InvalidStateTransition(Conflict):
    code = ErrorCode.INVALID_STATE_TRANSITION
    message = "The requested state transition is not allowed."


class ServiceUnavailable(AppError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = ErrorCode.SERVICE_UNAVAILABLE
    message = "The service is temporarily unavailable."


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


_STATUS_CODE_MAP: dict[int, ErrorCode] = {
    400: ErrorCode.MALFORMED_REQUEST,
    401: ErrorCode.AUTHENTICATION_REQUIRED,
    403: ErrorCode.PERMISSION_DENIED,
    404: ErrorCode.NOT_FOUND,
    405: ErrorCode.MALFORMED_REQUEST,
    409: ErrorCode.CONFLICT,
    413: ErrorCode.PAYLOAD_TOO_LARGE,
    415: ErrorCode.UNSUPPORTED_MEDIA_TYPE,
    422: ErrorCode.VALIDATION_ERROR,
    429: ErrorCode.RATE_LIMITED,
    501: ErrorCode.NOT_IMPLEMENTED,
    503: ErrorCode.SERVICE_UNAVAILABLE,
}

_GENERIC_MESSAGES: dict[int, str] = {
    400: "The request could not be understood.",
    401: "Authentication is required.",
    403: "You do not have permission to perform this action.",
    404: "The requested resource was not found.",
    405: "That method is not allowed for this resource.",
    413: "The request body is too large.",
    415: "The request content type is not supported.",
    429: "Too many requests. Please retry later.",
    500: "An unexpected error occurred.",
    503: "The service is temporarily unavailable.",
}


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)  # noqa: S101 - handler registered for this type only
    log = logger.bind(
        request_id=_request_id(request),
        error_code=exc.code.value,
        status_code=exc.status_code,
        path=request.url.path,
        **exc.log_context,
    )
    if exc.status_code >= 500:
        log.error("request_failed", exc_info=exc)
    else:
        log.info("request_rejected")
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_payload(_request_id(request)),
        headers=exc.headers or None,
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    details: list[dict[str, str]] = []
    for error in exc.errors():
        location = [str(part) for part in error.get("loc", ()) if part != "body"]
        details.append(
            {
                "field": ".".join(location) or "body",
                "issue": str(error.get("msg", "Invalid value.")),
            }
        )
    wrapped = ValidationFailed(details=details)
    logger.bind(request_id=_request_id(request), path=request.url.path).info(
        "request_validation_failed", field_count=len(details)
    )
    return JSONResponse(
        status_code=wrapped.status_code,
        content=wrapped.to_payload(_request_id(request)),
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101
    code = _STATUS_CODE_MAP.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
    detail = exc.detail if isinstance(exc.detail, str) else None
    message = detail or _GENERIC_MESSAGES.get(
        exc.status_code, "The request could not be completed."
    )
    wrapped = AppError(message, code=code, status_code=exc.status_code)
    headers = dict(getattr(exc, "headers", None) or {})
    return JSONResponse(
        status_code=exc.status_code,
        content=wrapped.to_payload(_request_id(request)),
        headers=headers or None,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler. Never leaks exception text in production."""
    logger.bind(request_id=_request_id(request), path=request.url.path).error(
        "unhandled_exception", exc_info=exc
    )
    message = _GENERIC_MESSAGES[500]
    details: list[dict[str, Any]] = []
    if settings.debug and not settings.is_production:
        details = [{"field": "debug", "issue": f"{type(exc).__name__}: {exc}"}]
    wrapped = AppError(
        message,
        code=ErrorCode.INTERNAL_ERROR,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        details=details,
    )
    return JSONResponse(status_code=500, content=wrapped.to_payload(_request_id(request)))


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
