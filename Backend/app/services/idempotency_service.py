"""``Idempotency-Key`` support.

Semantics:

* Same key **and** same request body -> the stored response is replayed.
* Same key, **different** body -> ``409 IDEMPOTENCY_KEY_REUSED``. Returning the
  first response would be worse than an error: the client would believe a
  different request succeeded.
* Keys are scoped by principal and endpoint, so two tenants cannot collide and
  a key reused on a different route is independent.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import Conflict, ErrorCode
from app.core.logging import get_logger
from app.db.models.audit import IdempotencyRecord
from app.repositories.base import rowcount_of
from app.utils.time import utcnow

logger = get_logger(__name__)


def digest_payload(payload: Any) -> str:
    serialised = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ReplayedResponse:
    status_code: int
    body: dict[str, Any]


async def lookup(
    session: AsyncSession,
    *,
    principal_type: str,
    principal_id: uuid.UUID,
    endpoint: str,
    key: str,
    request_payload: Any,
) -> ReplayedResponse | None:
    """Return a stored response for this key, or ``None`` to proceed."""
    result = await session.execute(
        select(IdempotencyRecord)
        .where(
            IdempotencyRecord.principal_type == principal_type,
            IdempotencyRecord.principal_id == principal_id,
            IdempotencyRecord.endpoint == endpoint,
            IdempotencyRecord.idempotency_key == key,
        )
        .limit(1)
    )
    row = result.scalars().first()
    if row is None:
        return None

    if row.expires_at <= utcnow():
        await session.delete(row)
        await session.flush()
        return None

    if row.request_digest != digest_payload(request_payload):
        logger.warning(
            "idempotency_key_reused_with_different_body",
            endpoint=endpoint,
            principal_type=principal_type,
        )
        raise Conflict(
            "This Idempotency-Key was already used with a different request body. "
            "Use a new key for a new request.",
            code=ErrorCode.IDEMPOTENCY_KEY_REUSED,
        )

    return ReplayedResponse(status_code=row.status_code, body=dict(row.response_body))


async def store(
    session: AsyncSession,
    *,
    principal_type: str,
    principal_id: uuid.UUID,
    endpoint: str,
    key: str,
    request_payload: Any,
    status_code: int,
    response_body: dict[str, Any],
) -> None:
    record = IdempotencyRecord(
        principal_type=principal_type[:24],
        principal_id=principal_id,
        endpoint=endpoint[:160],
        idempotency_key=key[:128],
        request_digest=digest_payload(request_payload),
        status_code=status_code,
        response_body=response_body,
        expires_at=utcnow() + timedelta(hours=settings.retention_idempotency_hours),
    )
    session.add(record)
    try:
        await session.flush()
    except IntegrityError:
        # Concurrent duplicate: the stored response is equivalent, so proceed.
        await session.rollback()
        logger.info("idempotency_record_race", endpoint=endpoint)


async def purge_expired(session: AsyncSession) -> int:
    result = await session.execute(
        delete(IdempotencyRecord).where(IdempotencyRecord.expires_at <= utcnow())
    )
    return rowcount_of(result)
