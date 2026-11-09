"""Test fixtures.

The suite runs against an isolated SQLite database per test module and fake
integrations (no email leaves the process, no push is sent, no payment provider
is contacted). PostgreSQL remains the production database; the models declare
PostgreSQL variants for their JSON columns, so the same metadata produces
correct DDL on both.

``Base.metadata.create_all`` is used **only here**. Production and staging
schema management is Alembic, and ``tests/integration/test_migrations.py``
asserts the migration and the models agree.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest

# Configure the environment before app modules read settings.
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-characters-long")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("EMAIL_PROVIDER", "console")
os.environ.setdefault("PUSH_PROVIDER", "disabled")
os.environ.setdefault("PAYMENT_PROVIDER", "disabled")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("LOG_FORMAT", "console")
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("CORS_ORIGINS", "http://localhost:3000")
os.environ.setdefault("TRUSTED_HOSTS", "*")

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool, StaticPool  # noqa: E402

from app.core import rate_limit  # noqa: E402
from app.db.models import Base  # noqa: E402
from app.db.session import configure_engine, get_db  # noqa: E402
from app.integrations.email.base import EmailMessage, EmailProvider, SendResult  # noqa: E402
from app.integrations.email.provider import set_email_provider  # noqa: E402
from app.integrations.firebase.base import (  # noqa: E402
    PushMessage,
    PushProvider,
    PushResult,
    PushSendOutcome,
    validate_push_data,
)
from app.integrations.firebase.provider import set_push_provider  # noqa: E402
from app.main import create_app  # noqa: E402


# ---------------------------------------------------------------------------
# Fake integrations
# ---------------------------------------------------------------------------
@dataclass
class FakeEmailProvider(EmailProvider):
    """Captures messages so tests can assert a link was sent without parsing
    stdout, and so no token is ever printed during a test run."""

    name: str = "fake"
    sent: list[EmailMessage] = field(default_factory=list)

    @property
    def configured(self) -> bool:
        return True

    async def send(self, message: EmailMessage) -> SendResult:
        self.sent.append(message)
        return SendResult(sent=True, provider=self.name, provider_message_id="fake")

    def last_for(self, tag: str) -> EmailMessage | None:
        for message in reversed(self.sent):
            if message.tags.get("type") == tag:
                return message
        return None

    def clear(self) -> None:
        self.sent.clear()


@dataclass
class FakePushProvider(PushProvider):
    """Records every push and still enforces the payload deny-list, so a test
    that tries to smuggle telemetry into a notification fails."""

    name: str = "fake"
    sent: list[PushMessage] = field(default_factory=list)
    fail_next: bool = False
    invalid_tokens: set[str] = field(default_factory=set)

    @property
    def configured(self) -> bool:
        return True

    async def send(self, message: PushMessage) -> PushResult:
        validate_push_data({"reason": message.reason, **message.data})
        self.sent.append(message)
        if message.token in self.invalid_tokens:
            return PushResult(
                outcome=PushSendOutcome.token_invalid,
                provider=self.name,
                error_code="UnregisteredError",
            )
        if self.fail_next:
            self.fail_next = False
            return PushResult(
                outcome=PushSendOutcome.provider_error,
                provider=self.name,
                error_code="FakeError",
            )
        return PushResult(
            outcome=PushSendOutcome.sent, provider=self.name, provider_message_id="fake"
        )

    def clear(self) -> None:
        self.sent.clear()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
#: Point the suite at a real database to verify dialect-specific behaviour:
#:
#:     TEST_DATABASE_URL="postgresql+asyncpg://user@/db?host=/run/pg" pytest
#:
#: The schema must already exist there, created by ``alembic upgrade head`` —
#: which makes such a run a test of the *migration*, not of ``create_all``.
#: Tables are truncated between tests rather than dropped, because dropping 50
#: tables and 213 indexes per test would dominate the runtime.
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or ""


@pytest.fixture
async def engine() -> AsyncIterator:
    """A database per test.

    By default this is SQLite in-memory, so the suite is hermetic and fast;
    ``StaticPool`` keeps one connection alive so the in-memory schema survives
    across sessions within a test.
    """
    if TEST_DATABASE_URL:
        async for external in _external_engine():
            yield external
        return

    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with test_engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        # SQLite does not enforce foreign keys unless asked.
        await connection.exec_driver_sql("PRAGMA foreign_keys=ON")

    configure_engine(test_engine)
    try:
        yield test_engine
    finally:
        await test_engine.dispose()


async def _external_engine() -> AsyncIterator:
    """Engine bound to a real, already-migrated database, emptied per test."""
    from sqlalchemy import text

    test_engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)

    table_list = ", ".join(
        f'"{name}"' for name in Base.metadata.tables if name != "alembic_version"
    )
    async with test_engine.begin() as connection:
        # One statement, so foreign keys never block the reset.
        await connection.execute(text(f"TRUNCATE {table_list} RESTART IDENTITY CASCADE"))

    configure_engine(test_engine)
    try:
        yield test_engine
    finally:
        await test_engine.dispose()


@pytest.fixture
async def session(engine) -> AsyncIterator[AsyncSession]:  # noqa: ANN001
    maker = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with maker() as db:
        yield db
        await db.rollback()


@pytest.fixture
def fake_email() -> FakeEmailProvider:
    provider = FakeEmailProvider()
    set_email_provider(provider)
    yield provider
    set_email_provider(None)


@pytest.fixture
def fake_push() -> FakePushProvider:
    provider = FakePushProvider()
    set_push_provider(provider)
    yield provider
    set_push_provider(None)


@pytest.fixture(autouse=True)
def reset_rate_limits() -> None:
    rate_limit.reset_local_buckets()


@pytest.fixture
async def client(engine, fake_email, fake_push) -> AsyncIterator[AsyncClient]:  # noqa: ANN001
    """HTTP client bound to the app with the test database injected."""
    app = create_app()
    maker = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

    async def override_get_db() -> AsyncIterator[AsyncSession]:
        async with maker() as db:
            try:
                yield db
            except Exception:
                await db.rollback()
                raise
            else:
                if db.in_transaction():
                    await db.commit()

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver", timeout=30
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Account / family helpers
# ---------------------------------------------------------------------------
API = "/api/v1"
TEST_PASSWORD = "test-password-9f3a!"


@dataclass
class ParentContext:
    user_id: str
    email: str
    access_token: str
    refresh_token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


@dataclass
class DeviceContext:
    device_id: str
    child_profile_id: str
    family_id: str
    access_token: str
    refresh_token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


def unique_email(prefix: str = "parent") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.test"


async def register_and_login(
    client: AsyncClient, fake_email: FakeEmailProvider, email: str | None = None
) -> ParentContext:
    """Register, verify (via the captured email token) and sign in."""
    address = email or unique_email()
    response = await client.post(
        f"{API}/auth/register",
        json={
            "email": address,
            "password": TEST_PASSWORD,
            "display_name": "Test Parent",
            "timezone": "Europe/London",
            "locale": "en",
            "accepted_terms_version": "2026-01",
            "accepted_privacy_version": "2026-01",
        },
    )
    assert response.status_code == 201, response.text
    token = response.json()["data"]["dev_verification_token"]
    assert token, "the console email provider should surface a verification token"

    verified = await client.post(f"{API}/auth/verify-email", json={"token": token})
    assert verified.status_code == 200, verified.text

    logged_in = await client.post(
        f"{API}/auth/login", json={"email": address, "password": TEST_PASSWORD}
    )
    assert logged_in.status_code == 200, logged_in.text
    body = logged_in.json()["data"]
    return ParentContext(
        user_id=body["user"]["id"],
        email=address,
        access_token=body["access_token"],
        refresh_token=body["refresh_token"],
    )


async def create_family(
    client: AsyncClient, parent: ParentContext, name: str = "Test Family"
) -> str:
    response = await client.post(
        f"{API}/families",
        json={"name": name, "timezone": "Europe/London"},
        headers=parent.headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]["id"]


async def create_child(
    client: AsyncClient, parent: ParentContext, family_id: str, name: str = "Test Child"
) -> str:
    response = await client.post(
        f"{API}/families/{family_id}/children",
        json={"display_name": name, "age_band": "age_9_12"},
        headers=parent.headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]["id"]


async def create_pairing_invitation(
    client: AsyncClient, parent: ParentContext, child_id: str
) -> dict:
    response = await client.post(
        f"{API}/children/{child_id}/pairing-invitations",
        json={"include_short_code": True},
        headers=parent.headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


async def pair_device(
    client: AsyncClient,
    parent: ParentContext,
    child_id: str,
    install_id: str = "test-install-0001",
) -> DeviceContext:
    invitation = await create_pairing_invitation(client, parent, child_id)
    response = await client.post(
        f"{API}/device/pairing/claim",
        json={
            "claim_token": invitation["claim_token"],
            "device": {
                "platform": "android",
                "app_version": "1.0.0",
                "os_version": "Android 16",
                "device_label": "Test Phone",
                "timezone": "Europe/London",
                "install_id": install_id,
            },
            "disclosure_version": "2026-01",
            "disclosure_acknowledged": True,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()["data"]
    device = DeviceContext(
        device_id=body["device_id"],
        child_profile_id=body["child_profile_id"],
        family_id=body["family_id"],
        access_token=body["device_access_token"],
        refresh_token=body["device_refresh_token"],
    )

    registered = await client.post(
        f"{API}/device/register",
        json={
            "device": {
                "platform": "android",
                "app_version": "1.0.0",
                "os_version": "Android 16",
                "timezone": "Europe/London",
                "install_id": install_id,
            },
            "capabilities": [
                {
                    "capability_key": "app_usage_stats",
                    "support": "supported",
                    "permission_state": "granted",
                },
                {
                    "capability_key": "app_blocking",
                    "support": "supported",
                    "permission_state": "granted",
                },
            ],
            "permissions": [{"permission_key": "usage_stats", "state": "granted"}],
        },
        headers=device.headers,
    )
    assert registered.status_code == 200, registered.text
    return device


@dataclass
class FullFamily:
    parent: ParentContext
    family_id: str
    child_id: str
    device: DeviceContext


@pytest.fixture
async def family(client, fake_email) -> FullFamily:  # noqa: ANN001
    """A verified parent with one family, one child and one registered device."""
    parent = await register_and_login(client, fake_email)
    family_id = await create_family(client, parent)
    child_id = await create_child(client, parent, family_id)
    device = await pair_device(client, parent, child_id)
    return FullFamily(parent=parent, family_id=family_id, child_id=child_id, device=device)
