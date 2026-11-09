"""Payment provider interface.

No provider has been selected for this product, so this module defines the
*seam* only. Two rules are baked into the interface:

1. A subscription only becomes active from a **signature-verified webhook**.
   There is no code path where a client telling the API "I paid" changes
   entitlement.
2. Webhook handling is idempotent: the provider's own event id is the
   idempotency key, stored in ``payment_webhook_events``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class CheckoutSession:
    checkout_url: str
    provider: str
    expires_at: datetime | None = None
    provider_session_ref: str | None = None


@dataclass(frozen=True, slots=True)
class WebhookVerification:
    """Result of verifying a webhook delivery."""

    valid: bool
    provider_event_id: str | None = None
    event_type: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None


class PaymentProvider(ABC):
    name: str = "base"

    @property
    @abstractmethod
    def configured(self) -> bool: ...

    @abstractmethod
    async def create_checkout_session(
        self,
        *,
        family_id: str,
        plan_code: str,
        success_url: str | None,
        cancel_url: str | None,
    ) -> CheckoutSession: ...

    @abstractmethod
    def verify_webhook(
        self, *, raw_body: bytes, headers: dict[str, str]
    ) -> WebhookVerification: ...
