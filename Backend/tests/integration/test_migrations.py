"""The Alembic migration and the ORM models must describe the same schema.

Rule 8 of the master prompt: ``create_all`` is not the schema strategy. These
tests prove the migration is the real source of truth by building a database
from it and comparing against the model metadata.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.db.models import Base

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
#: Columns an older migration may legitimately lack; empty for the initial one.
KNOWN_SCHEMA_EXCEPTIONS: dict[str, set[str]] = {}


def alembic_config(database_url: str) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def migrated_database(monkeypatch):
    """A database built purely by ``alembic upgrade head``."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "migrated.sqlite3"
        async_url = f"sqlite+aiosqlite:///{path}"
        monkeypatch.setenv("DATABASE_URL", async_url)

        from app.core import config as config_module

        config_module.get_settings.cache_clear()
        original_url = config_module.settings.database_url
        monkeypatch.setattr(config_module.settings, "database_url", async_url)

        command.upgrade(alembic_config(async_url), "head")
        yield f"sqlite:///{path}"

        monkeypatch.setattr(config_module.settings, "database_url", original_url)


def test_migration_creates_every_model_table(migrated_database) -> None:
    engine = create_engine(migrated_database)
    try:
        inspector = inspect(engine)
        migrated_tables = set(inspector.get_table_names()) - {"alembic_version"}
        model_tables = set(Base.metadata.tables)
        assert model_tables - migrated_tables == set(), "tables missing from the migration"
        assert migrated_tables - model_tables == set(), "tables not described by any model"
    finally:
        engine.dispose()


def test_migration_columns_match_the_models(migrated_database) -> None:
    engine = create_engine(migrated_database)
    try:
        inspector = inspect(engine)
        problems: list[str] = []
        for table_name, table in Base.metadata.tables.items():
            migrated_columns = {column["name"] for column in inspector.get_columns(table_name)}
            model_columns = {column.name for column in table.columns}
            allowed = KNOWN_SCHEMA_EXCEPTIONS.get(table_name, set())
            missing = model_columns - migrated_columns - allowed
            extra = migrated_columns - model_columns
            if missing:
                problems.append(f"{table_name}: missing {sorted(missing)}")
            if extra:
                problems.append(f"{table_name}: unexpected {sorted(extra)}")
        assert not problems, problems
    finally:
        engine.dispose()


def test_critical_uniqueness_is_enforced_by_the_database(migrated_database) -> None:
    """Pydantic validation is not the last line of defence."""
    engine = create_engine(migrated_database)
    try:
        inspector = inspect(engine)

        def constrained_columns(table: str) -> set[tuple[str, ...]]:
            found = {
                tuple(sorted(item["column_names"]))
                for item in inspector.get_unique_constraints(table)
            }
            found |= {
                tuple(sorted(item["column_names"]))
                for item in inspector.get_indexes(table)
                if item.get("unique")
            }
            return found

        assert ("normalized_email",) in constrained_columns("users")
        assert ("refresh_token_hash",) in constrained_columns("user_sessions")
        assert ("refresh_token_hash",) in constrained_columns("device_sessions")
        assert ("token_hash",) in constrained_columns("pairing_invitations")
        assert ("device_id", "idempotency_key") in constrained_columns("device_commands")
        assert ("device_id", "local_date") in constrained_columns("usage_daily_summaries")
        assert ("deduplication_key", "device_id") in constrained_columns("device_events")
        assert ("provider", "provider_event_id") in constrained_columns("payment_webhook_events")
    finally:
        engine.dispose()


def test_downgrade_removes_everything(migrated_database) -> None:
    """A migration that cannot be rolled back is not a migration."""
    async_url = migrated_database.replace("sqlite:///", "sqlite+aiosqlite:///")
    command.downgrade(alembic_config(async_url), "base")

    engine = create_engine(migrated_database)
    try:
        remaining = set(inspect(engine).get_table_names()) - {"alembic_version"}
        assert remaining == set()
    finally:
        engine.dispose()


def test_audit_log_has_no_foreign_keys(migrated_database) -> None:
    """Deleting a family must not be able to cascade its audit trail away."""
    engine = create_engine(migrated_database)
    try:
        assert inspect(engine).get_foreign_keys("audit_logs") == []
    finally:
        engine.dispose()
