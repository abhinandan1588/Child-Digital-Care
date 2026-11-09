"""Payment provider implementations.

``disabled`` (the default) raises a documented 503 rather than fabricating a
checkout URL. ``generic_hmac`` is a concrete, provider-agnostic verifier for a
webhook signed as ``t=<unix>,v1=<hex hmac-sha256 of "<t>.<raw body>">`` - the
shape several providers use - so the whole webhook path (signature, timestamp
tolerance, replay rejection, idempotency) is implemented and testable before a
provider is chosen.
"""

from __future__ import annotations

import hmac
import json
from typing import Any

from app.core.config import settings
from app.core.errors import ErrorCode, IntegrationNotConfigured, NotImplementedYet
from app.core.logging import get_logger
from app.core.security import hmac_sha256_hex
from app.integrations.payments.base import (
    CheckoutSession,
    PaymentProvider,
    WebhookVerification,
)
from app.utils.time import utcnow

logger = get_logger(__name__)


class DisabledPaymentProvider(PaymentProvider):
    name = "disabled"

    @property
    def configured(self) -> bool:
        return False

    async def create_checkout_session(
        self, *, family_id: str, plan_code: str, success_url: str | None, cancel_url: str | None
    ) -> CheckoutSession:
        raise NotImplementedYet(
            "Checkout is not available: no payment provider is configured for this deployment.",
            code=ErrorCode.INTEGRATION_NOT_CONFIGURED,
        )

    def verify_webhook(self, *, raw_body: bytes, headers: dict[str, str]) -> WebhookVerification:
        return WebhookVerification(valid=False, error_code="PROVIDER_DISABLED")


class GenericHmacPaymentProvider(PaymentProvider):
    """Signature verification for an HMAC-signed webhook.

    Checkout itself still raises: creating a session needs a real provider API.
    This class exists so the *inbound* half - the half that moves money-backed
    entitlement - is real, verified, and covered by tests.
    """

    name = "generic_hmac"
    signature_header = "x-webhook-signature"

    @property
    def configured(self) -> bool:
        return bool(settings.payment_webhook_secret)

    async def create_checkout_session(
        self, *, family_id: str, plan_code: str, success_url: str | None, cancel_url: str | None
    ) -> CheckoutSession:
        raise IntegrationNotConfigured(
            "Checkout session creation requires a provider SDK that has not been selected yet. "
            "The webhook and subscription domain are implemented; see docs/API_CONTRACT.md."
        )

    def verify_webhook(self, *, raw_body: bytes, headers: dict[str, str]) -> WebhookVerification:
        if not self.configured:
            return WebhookVerification(valid=False, error_code="SECRET_NOT_CONFIGURED")

        header = headers.get(self.signature_header) or ""
        parts = dict(item.split("=", 1) for item in header.split(",") if "=" in item)
        timestamp = parts.get("t")
        signature = parts.get("v1")
        if not timestamp or not signature:
            return WebhookVerification(valid=False, error_code="SIGNATURE_HEADER_MALFORMED")

        if not timestamp.isdigit():
            return WebhookVerification(valid=False, error_code="SIGNATURE_TIMESTAMP_INVALID")

        age = abs(int(utcnow().timestamp()) - int(timestamp))
        if age > settings.payment_webhook_tolerance_seconds:
            # Rejecting stale timestamps is what stops a captured delivery from
            # being replayed days later with a still-valid signature.
            return WebhookVerification(valid=False, error_code="SIGNATURE_TIMESTAMP_EXPIRED")

        expected = hmac_sha256_hex(
            settings.payment_webhook_secret or "",
            f"{timestamp}.".encode() + raw_body,
        )
        if not hmac.compare_digest(expected, signature):
            logger.warning("payment_webhook_signature_invalid")
            return WebhookVerification(valid=False, error_code="SIGNATURE_MISMATCH")

        try:
            payload: dict[str, Any] = json.loads(raw_body)
        except ValueError:
            return WebhookVerification(valid=False, error_code="BODY_NOT_JSON")

        event_id = str(payload.get("id") or "")
        event_type = str(payload.get("type") or "")
        if not event_id or not event_type:
            return WebhookVerification(valid=False, error_code="EVENT_FIELDS_MISSING")

        return WebhookVerification(
            valid=True,
            provider_event_id=event_id,
            event_type=event_type,
            payload=payload,
        )


_provider: PaymentProvider | None = None


def get_payment_provider() -> PaymentProvider:
    global _provider
    if _provider is None:
        _provider = (
            GenericHmacPaymentProvider()
            if settings.payment_provider == "generic_hmac"
            else DisabledPaymentProvider()
        )
    return _provider


def set_payment_provider(provider: PaymentProvider | None) -> None:
    global _provider
    _provider = provider
