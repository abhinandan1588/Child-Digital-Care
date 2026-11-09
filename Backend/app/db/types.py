"""Portable column types.

PostgreSQL is the production database. SQLite (via ``aiosqlite``) is supported
*for the test suite only*, which is why JSON columns are declared with a
PostgreSQL ``JSONB`` variant rather than using ``JSONB`` directly: the same
model metadata then emits correct DDL on both backends, and Alembic renders the
variant into the migration.
"""

from __future__ import annotations

import enum
from datetime import UTC
from typing import Any, TypeVar

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

#: UUID primary/foreign keys. Native ``uuid`` on PostgreSQL, CHAR(32) elsewhere.
UUIDType = sa.Uuid(as_uuid=True)


class UtcDateTime(sa.TypeDecorator):
    """``timestamptz`` that always reads and writes aware UTC datetimes.

    PostgreSQL returns an aware datetime for ``timestamptz``; SQLite returns a
    naive one. Without normalising, the same comparison
    (``row.expires_at <= utcnow()``) works in production and raises
    ``TypeError`` under the test backend - the sort of difference that hides a
    real bug. Coercing on the way in also stops a naive datetime from being
    stored and silently reinterpreted.
    """

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001, ANN201
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):  # noqa: ANN001, ANN201
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


#: Timezone-aware timestamp (``timestamptz`` on PostgreSQL).
TZTimestamp = UtcDateTime()

#: Variable-shaped metadata/payloads. ``jsonb`` on PostgreSQL, ``json`` on SQLite.
JSONBType: Any = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

#: Citext is avoided deliberately: emails are normalised in the application
#: (``normalized_email``) so uniqueness does not depend on a PG extension.
EmailText = sa.String(320)

EnumT = TypeVar("EnumT", bound=enum.Enum)


def enum_column(enum_cls: type[EnumT], name: str, length: int = 48) -> sa.Enum:
    """A VARCHAR + CHECK-constraint enum.

    ``native_enum=False`` is chosen over PostgreSQL native enums so that adding
    a new value is an ordinary CHECK-constraint migration instead of an
    ``ALTER TYPE`` that cannot run inside some transaction contexts. Values are
    persisted as the enum *value* (snake_case), not the member name.
    """
    return sa.Enum(
        enum_cls,
        name=name,
        native_enum=False,
        length=length,
        validate_strings=True,
        values_callable=lambda cls: [member.value for member in cls],
    )


__all__ = [
    "EmailText",
    "JSONBType",
    "TZTimestamp",
    "UUIDType",
    "UtcDateTime",
    "enum_column",
]
