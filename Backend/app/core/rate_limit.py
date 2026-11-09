"""Rate limiting.

A sliding-window counter in Redis, coordinated across API instances, with an
in-process fallback for single-node local development.

Two deliberate design points:

* **Victim-safe throttling.** Sensitive auth endpoints are limited per
  ``(identifier, ip)`` *and* per ip, never by account identifier alone, so an
  attacker cannot lock a victim out by hammering their email address.
* **Configurable fail mode.** If Redis is unreachable the limiter fails open by
  default (availability) but can be switched to fail closed via
  ``RATE_LIMIT_FAIL_OPEN=false``.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass

from fastapi import Request

from app.core.config import settings
from app.core.errors import RateLimited
from app.core.logging import get_logger
from app.core.redis import get_redis

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """``limit`` requests per ``window_seconds`` for a given bucket."""

    name: str
    limit: int
    window_seconds: int

    @property
    def retry_after(self) -> int:
        return self.window_seconds


# Central registry so limits are reviewable in one place.
RULES: dict[str, RateLimitRule] = {
    "auth.register": RateLimitRule("auth.register", limit=5, window_seconds=3600),
    "auth.login.ip": RateLimitRule("auth.login.ip", limit=30, window_seconds=900),
    "auth.login.account": RateLimitRule("auth.login.account", limit=10, window_seconds=900),
    "auth.password.forgot": RateLimitRule("auth.password.forgot", limit=5, window_seconds=3600),
    "auth.password.reset": RateLimitRule("auth.password.reset", limit=10, window_seconds=3600),
    "auth.verify_email": RateLimitRule("auth.verify_email", limit=10, window_seconds=3600),
    "auth.refresh": RateLimitRule("auth.refresh", limit=60, window_seconds=900),
    "admin.login.ip": RateLimitRule("admin.login.ip", limit=10, window_seconds=900),
    "admin.login.account": RateLimitRule("admin.login.account", limit=5, window_seconds=900),
    "pairing.claim.ip": RateLimitRule("pairing.claim.ip", limit=20, window_seconds=600),
    "pairing.claim.token": RateLimitRule("pairing.claim.token", limit=5, window_seconds=600),
    "pairing.create": RateLimitRule("pairing.create", limit=20, window_seconds=3600),
    "device.heartbeat": RateLimitRule("device.heartbeat", limit=120, window_seconds=3600),
    "device.usage_submit": RateLimitRule("device.usage_submit", limit=240, window_seconds=3600),
    "device.events": RateLimitRule("device.events", limit=600, window_seconds=3600),
    "device.location": RateLimitRule("device.location", limit=720, window_seconds=3600),
    "billing.webhook": RateLimitRule("billing.webhook", limit=600, window_seconds=60),
    "ws.ticket": RateLimitRule("ws.ticket", limit=60, window_seconds=300),
}


# ---------------------------------------------------------------------------
# In-process fallback (development / single node only)
# ---------------------------------------------------------------------------
_local_buckets: dict[str, list[float]] = defaultdict(list)


def _local_hit(key: str, rule: RateLimitRule) -> tuple[bool, int]:
    now = time.monotonic()
    cutoff = now - rule.window_seconds
    hits = [stamp for stamp in _local_buckets[key] if stamp > cutoff]
    hits.append(now)
    _local_buckets[key] = hits
    return len(hits) <= rule.limit, len(hits)


def reset_local_buckets() -> None:
    """Test helper: clear the in-process limiter state."""
    _local_buckets.clear()


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
def client_ip(request: Request) -> str:
    """Best-effort client address.

    ``X-Forwarded-For`` is only trusted when the deployment sits behind a proxy
    that is configured to overwrite it (see docs/DEPLOYMENT.md). We take the
    left-most entry and fall back to the socket peer.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def hash_identifier(value: str) -> str:
    """Limiter keys must not contain raw emails or tokens."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:32]


#: Increment a counter and make sure it has a TTL, atomically, in one round trip.
#:
#: Written as a script rather than ``INCRBY`` + ``EXPIRE ... NX`` in a pipeline
#: because the ``NX`` flag on ``EXPIRE`` requires Redis 7.0. Against Redis 6.x
#: that pipeline raises ``ResponseError``, and since the limiter fails open by
#: default, every limit silently disappeared. ``EVAL`` works on 2.6+.
#:
#: Checking the TTL (rather than assuming the first increment sets it) also
#: self-heals a key that somehow lost its expiry, which would otherwise block a
#: caller permanently.
_INCREMENT_AND_EXPIRE = """
local current = redis.call('INCRBY', KEYS[1], ARGV[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return current
"""


async def check_rate_limit(rule_name: str, identifier: str, *, cost: int = 1) -> None:
    """Consume ``cost`` from a bucket, raising :class:`RateLimited` when empty."""
    if not settings.rate_limit_enabled:
        return
    rule = RULES.get(rule_name)
    if rule is None:  # pragma: no cover - programming error
        raise KeyError(f"Unknown rate limit rule: {rule_name}")

    key = f"rl:{rule.name}:{identifier}"
    client = get_redis()

    if client is None:
        allowed, _ = _local_hit(key, rule)
        if not allowed:
            raise RateLimited(rule.retry_after, message="Too many requests. Please retry later.")
        return

    try:
        current = int(await client.eval(_INCREMENT_AND_EXPIRE, 1, key, cost, rule.window_seconds))
    except Exception as exc:  # noqa: BLE001 - Redis outage must not 500 the API
        logger.warning(
            "rate_limit_backend_unavailable",
            rule=rule.name,
            error=type(exc).__name__,
            fail_open=settings.rate_limit_fail_open,
        )
        if settings.rate_limit_fail_open:
            return
        raise RateLimited(rule.retry_after, message="Rate limiting is unavailable.") from exc

    if current > rule.limit:
        logger.info("rate_limited", rule=rule.name)
        raise RateLimited(rule.retry_after, message="Too many requests. Please retry later.")


class RateLimit:
    """FastAPI dependency: ``Depends(RateLimit("auth.login.ip"))``.

    Keys on the client IP. Use :func:`check_rate_limit` directly inside a
    handler when the bucket must include a request-body value (e.g. the email
    address being used, hashed).
    """

    def __init__(self, rule_name: str) -> None:
        if rule_name not in RULES:  # pragma: no cover - programming error
            raise KeyError(f"Unknown rate limit rule: {rule_name}")
        self.rule_name = rule_name

    async def __call__(self, request: Request) -> None:
        await check_rate_limit(self.rule_name, hash_identifier(client_ip(request)))


__all__ = [
    "RULES",
    "RateLimit",
    "RateLimitRule",
    "check_rate_limit",
    "client_ip",
    "hash_identifier",
    "reset_local_buckets",
]
