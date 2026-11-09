"""Shared persistence helpers: cursor pagination and safe single-row fetches."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any, TypeVar, cast

from sqlalchemy import CursorResult, Result, Select, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from app.db.base import Base
from app.schemas.common import decode_cursor, encode_cursor
from app.utils.time import ensure_utc

ModelT = TypeVar("ModelT", bound=Base)


async def get_by_id(
    session: AsyncSession, model: type[ModelT], identifier: uuid.UUID
) -> ModelT | None:
    return await session.get(model, identifier)


async def first_or_none(session: AsyncSession, statement: Select[Any]) -> Any:
    result = await session.execute(statement.limit(1))
    return result.scalars().first()


async def scalar_count(session: AsyncSession, statement: Select[Any]) -> int:
    from sqlalchemy import func

    subquery = statement.order_by(None).subquery()
    result = await session.execute(select(func.count()).select_from(subquery))
    return int(result.scalar_one())


class CursorPageResult:
    __slots__ = ("has_more", "items", "next_cursor")

    def __init__(self, items: Sequence[Any], next_cursor: str | None, has_more: bool) -> None:
        self.items = list(items)
        self.next_cursor = next_cursor
        self.has_more = has_more


async def paginate_by_timestamp(
    session: AsyncSession,
    statement: Select[Any],
    *,
    timestamp_column: InstrumentedAttribute[Any],
    id_column: InstrumentedAttribute[Any],
    cursor: str | None,
    limit: int,
    descending: bool = True,
) -> CursorPageResult:
    """Keyset pagination on ``(timestamp, id)``.

    The id tie-breaker is what makes the cursor stable: two rows written in the
    same microsecond would otherwise be able to swap places between pages, and
    a client could miss or repeat a row.
    """
    state = decode_cursor(cursor)
    after_ts = state.get("ts")
    after_id = state.get("id")

    if after_ts and after_id:
        boundary_ts = ensure_utc(datetime.fromisoformat(str(after_ts)))
        boundary_id = uuid.UUID(str(after_id))
        if descending:
            statement = statement.where(
                (timestamp_column < boundary_ts)
                | ((timestamp_column == boundary_ts) & (id_column < boundary_id))
            )
        else:
            statement = statement.where(
                (timestamp_column > boundary_ts)
                | ((timestamp_column == boundary_ts) & (id_column > boundary_id))
            )

    ordering = (
        (timestamp_column.desc(), id_column.desc())
        if descending
        else (timestamp_column.asc(), id_column.asc())
    )
    statement = statement.order_by(None).order_by(*ordering).limit(limit + 1)

    rows = (await session.execute(statement)).scalars().all()
    has_more = len(rows) > limit
    page = rows[:limit]

    next_cursor: str | None = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_cursor(
            {
                "ts": ensure_utc(getattr(last, timestamp_column.key)).isoformat(),
                "id": str(getattr(last, id_column.key)),
            }
        )
    return CursorPageResult(page, next_cursor, has_more)


__all__ = [
    "CursorPageResult",
    "first_or_none",
    "rowcount_of",
    "get_by_id",
    "paginate_by_timestamp",
    "scalar_count",
]


def rowcount_of(result: Result[Any]) -> int:
    """Affected-row count for an UPDATE or DELETE.

    ``AsyncSession.execute`` is typed as returning ``Result``, but ``rowcount``
    only exists on ``CursorResult``. Narrowing it once here keeps the cast out
    of every service and gives all callers the same ``int`` contract.
    """
    return int(cast("CursorResult[Any]", result).rowcount or 0)
