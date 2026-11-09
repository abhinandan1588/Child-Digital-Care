"""Declarative base, constraint naming convention, and common mixins."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.types import TZTimestamp, UUIDType
from app.utils.time import utcnow

# Deterministic constraint names keep Alembic autogenerate stable and make
# `DROP CONSTRAINT` possible in a downgrade.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = sa.MetaData(naming_convention=NAMING_CONVENTION)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        identifier = getattr(self, "id", None)
        return f"<{type(self).__name__} id={identifier}>"


class UUIDPrimaryKeyMixin:
    """UUID primary key, generated application-side.

    Externally exposed identifiers are always UUIDs; no table exposes a
    sequential integer id, so resource ids are not enumerable.

    Declared as a plain ``mapped_column`` rather than a ``declared_attr``:
    SQLAlchemy copies simple mixin columns onto each subclass, and the direct
    form is the one static type checkers resolve to ``uuid.UUID`` instead of
    ``Mapped[uuid.UUID]``.
    """

    id: Mapped[uuid.UUID] = mapped_column(UUIDType, primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp,
        nullable=False,
        default=utcnow,
        server_default=sa.func.now(),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        TZTimestamp,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=sa.func.now(),
    )


class SoftDeleteMixin:
    """Soft deletion.

    Queries must filter ``deleted_at IS NULL`` explicitly; there is no global
    query filter, so the intent is always visible at the call site.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(TZTimestamp, nullable=True, index=True)


__all__ = [
    "NAMING_CONVENTION",
    "Base",
    "SoftDeleteMixin",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
]
