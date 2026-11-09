"""Request-scoped context.

A context variable carries the correlation id (and the resolved principal
label) for the lifetime of a request so that logging and the response envelope
can pick it up without threading ``Request`` through every function.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("cdc_request_id", default=None)
_principal: ContextVar[str | None] = ContextVar("cdc_principal", default=None)


def new_request_id() -> str:
    return str(uuid.uuid4())


def set_request_id(value: str | None) -> None:
    _request_id.set(value)


def get_request_id() -> str | None:
    return _request_id.get()


def set_principal(value: str | None) -> None:
    """Store a *safe* principal label, e.g. ``parent_user:<uuid>``."""
    _principal.set(value)


def get_principal() -> str | None:
    return _principal.get()


def reset() -> None:
    _request_id.set(None)
    _principal.set(None)
