"""Rate limiting against a real Redis.

Skipped unless ``TEST_REDIS_URL`` is set:

    TEST_REDIS_URL=redis://127.0.0.1:6379/0 pytest tests/integration/test_rate_limit_redis.py

These exist because the in-process fallback hid a real defect. The limiter used
``INCRBY`` + ``EXPIRE key seconds NX`` in a pipeline; the ``NX`` flag needs
Redis 7.0, so against Redis 6.x the call raised ``ResponseError`` and — because
the limiter fails open by default — **every limit silently disappeared**. No
test caught it, because every test ran on the in-process fallback.

CI should set ``TEST_REDIS_URL`` against the oldest Redis the deployment
supports.
"""

from __future__ import annotations

import os

import pytest

from app.core import rate_limit
from app.core.errors import RateLimited

TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL") or ""

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not TEST_REDIS_URL, reason="TEST_REDIS_URL is not set"),
]


@pytest.fixture
async def redis_client(monkeypatch):
    """A Redis-backed limiter, with the in-process fallback disabled."""
    from app.core import redis as redis_module
    from app.core.config import settings

    monkeypatch.setattr(settings, "redis_url", TEST_REDIS_URL)
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_fail_open", True)
    await redis_module.close_redis()

    client = redis_module.get_redis()
    assert client is not None
    yield client

    await redis_module.close_redis()


async def exhaust(rule_name: str, identifier: str) -> tuple[int, RateLimited | None]:
    """Call until blocked. Returns how many calls were allowed."""
    rule = rate_limit.RULES[rule_name]
    allowed = 0
    for _ in range(rule.limit + 5):
        try:
            await rate_limit.check_rate_limit(rule_name, identifier)
            allowed += 1
        except RateLimited as exc:
            return allowed, exc
    return allowed, None


class TestEnforcement:
    @pytest.mark.parametrize(
        "rule_name",
        ["auth.register", "auth.login.ip", "auth.login.account", "pairing.claim.token"],
    )
    async def test_limit_is_enforced_exactly(self, redis_client, rule_name) -> None:
        rule = rate_limit.RULES[rule_name]
        identifier = rate_limit.hash_identifier(f"enforce-{rule_name}")
        await redis_client.delete(f"rl:{rule.name}:{identifier}")

        allowed, blocked = await exhaust(rule_name, identifier)

        assert allowed == rule.limit, f"{rule_name}: allowed {allowed}, expected {rule.limit}"
        assert blocked is not None, f"{rule_name}: never blocked — the limiter is not working"
        assert blocked.status_code == 429
        assert blocked.headers["Retry-After"] == str(rule.window_seconds)

    async def test_counter_carries_a_ttl(self, redis_client) -> None:
        """Without a TTL the counter never resets and the caller is locked out
        permanently — the failure mode the EXPIRE NX bug would have caused."""
        rule = rate_limit.RULES["auth.register"]
        identifier = rate_limit.hash_identifier("ttl-check")
        key = f"rl:{rule.name}:{identifier}"
        await redis_client.delete(key)

        await rate_limit.check_rate_limit("auth.register", identifier)

        assert int(await redis_client.get(key)) == 1
        ttl = await redis_client.ttl(key)
        assert 0 < ttl <= rule.window_seconds

    async def test_ttl_is_restored_if_it_is_ever_lost(self, redis_client) -> None:
        rule = rate_limit.RULES["auth.register"]
        identifier = rate_limit.hash_identifier("ttl-heal")
        key = f"rl:{rule.name}:{identifier}"
        await redis_client.delete(key)
        await redis_client.set(key, 1)  # no expiry
        assert await redis_client.ttl(key) == -1

        await rate_limit.check_rate_limit("auth.register", identifier)
        assert await redis_client.ttl(key) > 0

    async def test_buckets_are_independent(self, redis_client) -> None:
        """One account being throttled must not throttle a different one."""
        first = rate_limit.hash_identifier("victim@example.test")
        second = rate_limit.hash_identifier("bystander@example.test")
        for ident in (first, second):
            await redis_client.delete(f"rl:auth.login.account:{ident}")

        allowed, blocked = await exhaust("auth.login.account", first)
        assert blocked is not None

        # The bystander is unaffected.
        await rate_limit.check_rate_limit("auth.login.account", second)

    async def test_rules_do_not_share_a_bucket(self, redis_client) -> None:
        identifier = rate_limit.hash_identifier("shared-identity")
        for rule_name in ("auth.register", "auth.login.ip"):
            await redis_client.delete(f"rl:{rule_name}:{identifier}")

        _, blocked = await exhaust("auth.register", identifier)
        assert blocked is not None
        # A different rule with the same identifier still has its own budget.
        await rate_limit.check_rate_limit("auth.login.ip", identifier)

    async def test_keys_never_contain_the_raw_identifier(self, redis_client) -> None:
        email = "plaintext@example.test"
        identifier = rate_limit.hash_identifier(email)
        await rate_limit.check_rate_limit("auth.register", identifier)

        keys = [key async for key in redis_client.scan_iter(match="rl:*")]
        assert keys
        for key in keys:
            assert email not in key
            assert "plaintext" not in key

    async def test_cost_above_one_is_honoured(self, redis_client) -> None:
        rule = rate_limit.RULES["auth.register"]
        identifier = rate_limit.hash_identifier("cost-check")
        key = f"rl:{rule.name}:{identifier}"
        await redis_client.delete(key)

        await rate_limit.check_rate_limit("auth.register", identifier, cost=rule.limit)
        assert int(await redis_client.get(key)) == rule.limit

        with pytest.raises(RateLimited):
            await rate_limit.check_rate_limit("auth.register", identifier)


class TestDegradedRedis:
    async def test_fail_open_allows_traffic(self, monkeypatch) -> None:
        """An unreachable Redis must not take the API down with it."""
        from app.core import redis as redis_module
        from app.core.config import settings

        monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "rate_limit_fail_open", True)
        await redis_module.close_redis()

        await rate_limit.check_rate_limit("auth.register", "unreachable")
        await redis_module.close_redis()

    async def test_fail_closed_rejects_traffic(self, monkeypatch) -> None:
        from app.core import redis as redis_module
        from app.core.config import settings

        monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "rate_limit_fail_open", False)
        await redis_module.close_redis()

        with pytest.raises(RateLimited) as exc:
            await rate_limit.check_rate_limit("auth.register", "unreachable")
        assert "unavailable" in str(exc.value).lower()
        await redis_module.close_redis()


class TestPubSub:
    async def test_published_event_reaches_a_subscriber(self, redis_client) -> None:
        """The cross-instance fan-out path, which the single-process tests skip."""
        import asyncio
        import json
        import uuid

        from app.services import realtime_service

        family_id = uuid.uuid4()
        channel = realtime_service.family_channel(family_id)

        subscriber = redis_client.pubsub()
        await subscriber.subscribe(channel)
        await asyncio.sleep(0.2)
        while await subscriber.get_message(timeout=0.1):
            pass

        device_id = str(uuid.uuid4())
        assert await realtime_service.publish_to_family(
            family_id,
            realtime_service.RealtimeEvent.DEVICE_STATUS_CHANGED,
            {"device_id": device_id, "event": "registered"},
        )

        received = None
        for _ in range(40):
            message = await subscriber.get_message(ignore_subscribe_messages=True, timeout=0.2)
            if message:
                received = message
                break

        assert received is not None, "the subscriber never got the event"
        payload = json.loads(received["data"])
        assert payload["event"] == "device.status_changed"
        assert payload["data"]["device_id"] == device_id
        await subscriber.aclose()

    async def test_another_family_channel_is_not_delivered(self, redis_client) -> None:
        import asyncio
        import uuid

        from app.services import realtime_service

        mine = uuid.uuid4()
        theirs = uuid.uuid4()
        subscriber = redis_client.pubsub()
        await subscriber.subscribe(realtime_service.family_channel(mine))
        await asyncio.sleep(0.2)
        while await subscriber.get_message(timeout=0.1):
            pass

        await realtime_service.publish_to_family(
            theirs,
            realtime_service.RealtimeEvent.ALERT_CREATED,
            {"alert_id": str(uuid.uuid4())},
        )

        for _ in range(10):
            message = await subscriber.get_message(ignore_subscribe_messages=True, timeout=0.1)
            assert message is None, "received an event for a different family"
        await subscriber.aclose()
