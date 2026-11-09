"""Alembic environment.

The URL comes from ``DATABASE_URL`` (via pydantic-settings), so no connection
string is committed. Both async drivers (``asyncpg`` for PostgreSQL,
``aiosqlite`` for the test suite) are supported.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.core.config import settings

# Importing the model registry is what populates Base.metadata.
from app.db.models import Base  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata
# Alembic keeps options in a ConfigParser, where '%' starts an interpolation
# token. A generated database password containing '%' would otherwise fail the
# migration with an InterpolationSyntaxError, so escape it for storage.
config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))


def include_object(obj, name, type_, reflected, compare_to) -> bool:  # noqa: ANN001
    """Skip objects Alembic should not manage."""
    # SQLite's internal tables, if a dev points Alembic at the test database.
    return not (type_ == "table" and name.startswith("sqlite_"))


def render_item(type_, obj, autogen_context) -> str | bool:  # noqa: ANN001
    """Render PostgreSQL ``JSONB`` without its implicit ``astext_type``.

    Alembic's default rendering emits ``postgresql.JSONB(astext_type=Text())``,
    which references a name the generated module does not import. ``JSONB()``
    is equivalent (``Text`` is its default) and self-contained.
    """
    from sqlalchemy.dialects import postgresql

    from app.db.types import UtcDateTime

    if type_ == "type" and isinstance(obj, postgresql.JSONB):
        autogen_context.imports.add("from sqlalchemy.dialects import postgresql")
        return "postgresql.JSONB()"
    if type_ == "type" and isinstance(obj, UtcDateTime):
        # The decorator exists only to normalise timezone handling in Python;
        # the stored type is a plain timestamptz.
        return "sa.DateTime(timezone=True)"
    return False


def _configure(connection: Connection | None = None, **kwargs) -> None:  # noqa: ANN003
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_object=include_object,
        render_item=render_item,
        # Needed so a column type change is actually detected.
        compare_type=True,
        compare_server_default=True,
        # Portable batch mode so a future ALTER works on SQLite too.
        render_as_batch=settings.database_url.startswith("sqlite"),
        **kwargs,
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a database connection (``alembic ... --sql``)."""
    # The async URL is fine here: offline mode only needs the dialect to
    # compile DDL, it never opens a connection.
    _configure(
        url=settings.database_url,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
