"""Subscription domain and webhook processing.

The rule that shapes this module: **only a signature-verified provider webhook
can change entitlement.** There is no API path where a client asserts a
purchase. With ``PAYMENT_PROVIDER=disabled`` the read endpoints still work and
report ``billing_available: false``, so the Parent App can hide purchase UI
instead of calling an endpoint that will 503.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.db.enums import (
    AuditActorType,
    AuditOutcome,
    SubscriptionStatus,
    WebhookProcessingStatus,
)
from app.db.models.billing import (
    PaymentWebhookEvent,
    Plan,
    Subscription,
    SubscriptionEvent,
)
from app.integrations.payments import get_payment_provider
from app.services import audit_service, outbox_service
from app.services.audit_service import AuditAction
from app.services.outbox_service import OutboxTopic
from app.utils.time import utcnow

logger = get_logger(__name__)

#: Provider event type -> target subscription status.
EVENT_STATUS_MAP: dict[str, SubscriptionStatus] = {
    "subscription.created": SubscriptionStatus.active,
    "subscription.activated": SubscriptionStatus.active,
    "subscription.renewed": SubscriptionStatus.active,
    "subscription.trial_started": SubscriptionStatus.trialing,
    "subscription.past_due": SubscriptionStatus.past_due,
    "subscription.payment_failed": SubscriptionStatus.past_due,
    "subscription.cancelled": SubscriptionStatus.cancelled,
    "subscription.expired": SubscriptionStatus.expired,
    "subscription.incomplete": SubscriptionStatus.incomplete,
}

#: Entitlements granted when no provider is configured. Deliberately generous:
#: a deployment without billing should be fully usable, not crippled.
UNMETERED_ENTITLEMENTS: dict[str, Any] = {
    "max_children": None,
    "max_devices": None,
    "location": False,
    "website_restrictions": False,
    "billing_configured": False,
}


async def list_plans(session: AsyncSession, *, include_inactive: bool = False) -> list[Plan]:
    statement = select(Plan)
    if not include_inactive:
        statement = statement.where(Plan.active.is_(True))
    result = await session.execute(statement.order_by(Plan.sort_order.asc()))
    return list(result.scalars().all())


async def get_or_create_subscription(
    session: AsyncSession, *, family_id: uuid.UUID
) -> Subscription:
    result = await session.execute(
        select(Subscription).where(Subscription.family_id == family_id).limit(1)
    )
    row = result.scalars().first()
    if row is not None:
        return row

    row = Subscription(
        family_id=family_id,
        status=SubscriptionStatus.none,
        provider=settings.payment_provider,
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        again = await session.execute(
            select(Subscription).where(Subscription.family_id == family_id).limit(1)
        )
        winner = again.scalars().first()
        if winner is None:  # pragma: no cover - defensive
            raise
        return winner
    return row


async def entitlements_for(session: AsyncSession, *, subscription: Subscription) -> dict[str, Any]:
    """What a family may currently use.

    With billing disabled this returns the unmetered set. Feature flags still
    win: an entitlement never turns on a feature the deployment has disabled.
    """
    if not settings.payments_configured:
        return {
            **UNMETERED_ENTITLEMENTS,
            "location": settings.feature_location_enabled,
            "website_restrictions": settings.feature_website_restrictions_enabled,
        }

    if subscription.plan_id is None or subscription.status not in (
        SubscriptionStatus.active,
        SubscriptionStatus.trialing,
    ):
        return {
            "max_children": 1,
            "max_devices": 1,
            "location": False,
            "website_restrictions": False,
            "billing_configured": True,
        }

    plan = await session.get(Plan, subscription.plan_id)
    flags = dict(plan.feature_flags or {}) if plan else {}
    return {
        "max_children": plan.max_children if plan else 1,
        "max_devices": plan.max_devices if plan else 1,
        "location": bool(flags.get("location")) and settings.feature_location_enabled,
        "website_restrictions": (
            bool(flags.get("website_restrictions"))
            and settings.feature_website_restrictions_enabled
        ),
        "billing_configured": True,
    }


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class WebhookOutcome:
    accepted: bool
    event_id: uuid.UUID | None
    duplicate: bool
    processed: bool
    error_code: str | None


async def process_webhook(
    session: AsyncSession,
    *,
    provider_name: str,
    raw_body: bytes,
    headers: dict[str, str],
) -> WebhookOutcome:
    """Verify, record, then process. In that order.

    Recording before processing means a provider retry is recognised as a
    duplicate even if the first attempt crashed mid-processing.
    """
    provider = get_payment_provider()
    digest = hashlib.sha256(raw_body).hexdigest()

    if provider_name != provider.name:
        await audit_service.record(
            session,
            action=AuditAction.WEBHOOK_REJECTED,
            actor_type=AuditActorType.system,
            outcome=AuditOutcome.denied,
            reason="provider_mismatch",
            metadata={"requested_provider": provider_name, "active_provider": provider.name},
        )
        return WebhookOutcome(False, None, False, False, "PROVIDER_MISMATCH")

    verification = provider.verify_webhook(raw_body=raw_body, headers=headers)
    if not verification.valid:
        # Still record the rejection, without the payload, so repeated invalid
        # deliveries are visible.
        session.add(
            PaymentWebhookEvent(
                provider=provider.name,
                provider_event_id=f"invalid-{digest[:32]}",
                event_type="unknown",
                status=WebhookProcessingStatus.signature_invalid,
                signature_verified=False,
                payload_digest=digest,
                error_code=(verification.error_code or "INVALID")[:64],
            )
        )
        await audit_service.record(
            session,
            action=AuditAction.WEBHOOK_REJECTED,
            actor_type=AuditActorType.system,
            outcome=AuditOutcome.denied,
            reason=verification.error_code,
        )
        logger.warning("payment_webhook_rejected", error_code=verification.error_code)
        return WebhookOutcome(False, None, False, False, verification.error_code)

    existing = await session.execute(
        select(PaymentWebhookEvent)
        .where(
            PaymentWebhookEvent.provider == provider.name,
            PaymentWebhookEvent.provider_event_id == verification.provider_event_id,
        )
        .limit(1)
    )
    duplicate = existing.scalars().first()
    if duplicate is not None:
        return WebhookOutcome(
            True,
            duplicate.id,
            True,
            duplicate.status is WebhookProcessingStatus.processed,
            None,
        )

    event = PaymentWebhookEvent(
        provider=provider.name,
        provider_event_id=str(verification.provider_event_id),
        event_type=str(verification.event_type)[:64],
        status=WebhookProcessingStatus.received,
        signature_verified=True,
        payload_digest=digest,
        payload=verification.payload,
    )
    session.add(event)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        return WebhookOutcome(True, None, True, False, None)

    processed = await _apply_webhook(session, event=event, payload=verification.payload)
    event.status = (
        WebhookProcessingStatus.processed if processed else WebhookProcessingStatus.ignored
    )
    event.processed_at = utcnow()

    await audit_service.record(
        session,
        action=AuditAction.WEBHOOK_RECEIVED,
        actor_type=AuditActorType.system,
        target_type="payment_webhook_event",
        target_id=event.id,
        metadata={"event_type": event.event_type, "processed": processed},
    )
    return WebhookOutcome(True, event.id, False, processed, None)


async def _apply_webhook(
    session: AsyncSession, *, event: PaymentWebhookEvent, payload: dict[str, Any]
) -> bool:
    target_status = EVENT_STATUS_MAP.get(event.event_type)
    if target_status is None:
        logger.info("payment_webhook_ignored", event_type=event.event_type)
        return False

    data = payload.get("data") or {}
    family_ref = data.get("family_id") or payload.get("family_id")
    if not family_ref:
        logger.warning("payment_webhook_missing_family", event_type=event.event_type)
        return False
    try:
        family_id = uuid.UUID(str(family_ref))
    except ValueError:
        logger.warning("payment_webhook_bad_family_ref")
        return False

    subscription = await get_or_create_subscription(session, family_id=family_id)
    previous = subscription.status

    plan_code = data.get("plan_code")
    if plan_code:
        plan_row = await session.execute(select(Plan).where(Plan.code == str(plan_code)).limit(1))
        plan = plan_row.scalars().first()
        if plan is not None:
            subscription.plan_id = plan.id

    subscription.status = target_status
    subscription.provider = event.provider
    if reference := data.get("subscription_ref"):
        subscription.provider_subscription_ref = str(reference)[:128]
    if customer := data.get("customer_ref"):
        subscription.provider_customer_ref = str(customer)[:128]
    if target_status is SubscriptionStatus.cancelled:
        subscription.cancelled_at = utcnow()

    session.add(
        SubscriptionEvent(
            subscription_id=subscription.id,
            family_id=family_id,
            event_type=event.event_type,
            from_status=previous,
            to_status=target_status,
            source="webhook",
            webhook_event_id=event.id,
            event_metadata={"provider_event_id": event.provider_event_id},
        )
    )
    await outbox_service.enqueue(
        session,
        topic=OutboxTopic.SUBSCRIPTION_STATUS_CHANGED,
        aggregate_type="subscription",
        aggregate_id=subscription.id,
        family_id=family_id,
        payload={"status": target_status.value, "previous_status": previous.value},
    )
    await audit_service.record(
        session,
        action=AuditAction.SUBSCRIPTION_CHANGED,
        actor_type=AuditActorType.system,
        target_type="subscription",
        target_id=subscription.id,
        family_id=family_id,
        metadata={"from": previous.value, "to": target_status.value},
    )
    return True


async def plan_code_for(session: AsyncSession, *, subscription: Subscription) -> str | None:
    if subscription.plan_id is None:
        return None
    plan = await session.get(Plan, subscription.plan_id)
    return plan.code if plan else None
