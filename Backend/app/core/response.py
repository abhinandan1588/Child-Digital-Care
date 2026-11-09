"""The single success-response envelope used by every endpoint.

Shape (section 5.2 of the master prompt)::

    {"success": true, "message": "...", "data": {...}, "meta": {"request_id": "..."}}

Endpoints declare ``response_model=ApiResponse[SomeOut]`` so the generated
OpenAPI document shows the real envelope rather than a bare payload.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.core.context import get_request_id

T = TypeVar("T")


class ResponseMeta(BaseModel):
    model_config = ConfigDict(extra="allow")

    request_id: str | None = Field(default=None, description="Correlation id for this request.")


class PageInfo(BaseModel):
    """Cursor pagination metadata. Cursors are opaque and must not be parsed."""

    next_cursor: str | None = Field(default=None, description="Pass as `cursor` for the next page.")
    has_more: bool = False
    limit: int = 50
    total: int | None = Field(
        default=None,
        description="Only populated for endpoints where an exact count is cheap.",
    )


class ApiResponse(BaseModel, Generic[T]):
    success: bool = True
    message: str = "OK"
    data: T | None = None
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


class Page(BaseModel, Generic[T]):
    items: list[T] = Field(default_factory=list)
    page_info: PageInfo = Field(default_factory=PageInfo)


class ErrorDetailOut(BaseModel):
    field: str
    issue: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[ErrorDetailOut] = Field(default_factory=list)


class ApiErrorResponse(BaseModel):
    """Documented error envelope (used for OpenAPI ``responses=`` entries)."""

    success: bool = False
    error: ErrorBody
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


def ok(data: Any = None, message: str = "OK", **meta: Any) -> dict[str, Any]:
    """Build a success envelope as a plain dict.

    The correlation id is read from the request context, so handlers never need
    to accept the ``Request`` object just to echo it back.
    """
    meta.setdefault("request_id", get_request_id())
    return {"success": True, "message": message, "data": data, "meta": meta}


__all__ = [
    "ApiErrorResponse",
    "ApiResponse",
    "ErrorBody",
    "ErrorDetailOut",
    "Page",
    "PageInfo",
    "ResponseMeta",
    "ok",
]
