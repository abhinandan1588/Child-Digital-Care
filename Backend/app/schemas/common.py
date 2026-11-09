"""Shared schema building blocks: base config, pagination, validators."""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime
from typing import Annotated, Any

from email_validator import EmailNotValidError, validate_email
from fastapi import Query
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings
from app.core.errors import ErrorCode, ValidationFailed
from app.utils.time import is_valid_timezone

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


class SchemaBase(BaseModel):
    """Strict-by-default base.

    ``extra="forbid"`` on *request* models is deliberate: a client sending an
    unexpected field (for example ``family_id`` on a route where the server
    derives it) gets a clear 422 instead of having the field silently ignored.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=False,
    )


class OutSchema(BaseModel):
    """Response models allow ORM attribute reads and never forbid extras."""

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------
class CursorPage(SchemaBase):
    cursor: str | None = None
    limit: int = Field(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)


def cursor_params(
    cursor: Annotated[
        str | None,
        Query(description="Opaque cursor from a previous response's `page_info.next_cursor`."),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> CursorPage:
    return CursorPage(cursor=cursor, limit=limit)


def encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str | None) -> dict[str, Any]:
    """Decode an opaque cursor.

    A cursor is *not* a security boundary: it only carries sort keys, and every
    query it feeds is still scoped by the caller's authorization. It is
    validated so a malformed value produces a 422, not a 500.
    """
    if not cursor:
        return {}
    padding = "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(cursor + padding)
        value = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ValidationFailed(
            "The pagination cursor is not valid.",
            code=ErrorCode.VALIDATION_ERROR,
            details=[{"field": "cursor", "issue": "Malformed cursor."}],
        ) from exc
    if not isinstance(value, dict):
        raise ValidationFailed(
            "The pagination cursor is not valid.",
            details=[{"field": "cursor", "issue": "Malformed cursor."}],
        )
    return value


# ---------------------------------------------------------------------------
# Reusable field validators
# ---------------------------------------------------------------------------
def _validate_email_address(value: str) -> str:
    """Syntactic email validation, returning the normalised form.

    Two deliberate choices:

    * ``check_deliverability=False`` everywhere. A DNS/MX lookup inside request
      validation is a blocking network call on the request path and therefore a
      denial-of-service surface. Ownership of an address is proved by the
      verification email, not by its DNS records.
    * ``test_environment=True`` outside production, so RFC 2606 reserved
      domains (``example.test``) work in the seed script and the test suite.
      Production keeps the default rejection of reserved and special-use
      domains, so ``someone@localhost`` cannot be registered there.
    """
    try:
        result = validate_email(
            value,
            check_deliverability=False,
            test_environment=not settings.is_production,
        )
    except EmailNotValidError as exc:
        raise ValueError(str(exc)) from exc
    return result.normalized


#: Use in place of ``EmailStr`` across request schemas.
EmailAddress = Annotated[
    str, Field(min_length=3, max_length=320), AfterValidator(_validate_email_address)
]


_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def validate_package_identifier(value: str) -> str:
    """Android package names only: ``com.example.app``.

    Rejecting anything else keeps a restriction row from carrying a path, URL or
    shell fragment that a device might misinterpret.
    """
    candidate = value.strip()
    if not _PACKAGE_RE.match(candidate) or len(candidate) > 255:
        raise ValueError("Must be a valid Android package name, e.g. com.example.app")
    return candidate


def validate_domain(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("http://") or candidate.startswith("https://"):
        raise ValueError("Provide a bare domain, not a URL.")
    if "/" in candidate or "?" in candidate:
        raise ValueError("Provide a registrable domain without a path or query string.")
    if not _DOMAIN_RE.match(candidate) or len(candidate) > 253:
        raise ValueError("Must be a valid domain name, e.g. example.com")
    return candidate


def validate_timezone(value: str) -> str:
    candidate = value.strip()
    if not is_valid_timezone(candidate):
        raise ValueError("Must be a valid IANA timezone identifier, e.g. Europe/London")
    return candidate


class TimezoneMixin(SchemaBase):
    timezone: str = Field(default="UTC", max_length=64, examples=["Europe/London"])

    @field_validator("timezone")
    @classmethod
    def _check_tz(cls, value: str) -> str:
        return validate_timezone(value)


class VersionedUpdate(SchemaBase):
    """Optimistic concurrency for sensitive policy mutations.

    When ``if_revision`` is supplied it must match the stored revision, which
    stops two guardians editing the same policy from silently overwriting each
    other.
    """

    if_revision: int | None = Field(
        default=None,
        ge=1,
        description="Reject the update unless the stored revision matches.",
    )


class DeletedOut(OutSchema):
    id: Any
    deleted: bool = True


class AcknowledgedOut(OutSchema):
    acknowledged: bool = True
    received_at: datetime


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "AcknowledgedOut",
    "CursorPage",
    "EmailAddress",
    "DeletedOut",
    "OutSchema",
    "SchemaBase",
    "TimezoneMixin",
    "VersionedUpdate",
    "cursor_params",
    "decode_cursor",
    "encode_cursor",
    "validate_domain",
    "validate_package_identifier",
    "validate_timezone",
]
