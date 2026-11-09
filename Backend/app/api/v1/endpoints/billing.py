"""Billing endpoints. Provider-neutral; no provider is selected."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import DbSession, VerifiedParent, require_family_membership
from app.core.config import settings
from app.core.errors import ErrorCode, IntegrationNotConfigured
from app.core.permissions import FamilyPermission
from app.core.rate_limit import RateLimit
from app.core.response import ApiResponse, ok
from app.integrations.payments import get_payment_provider
from app.schemas.billing import (
    CheckoutRequest,
    CheckoutSessionOut,
    PlanOut,
    SubscriptionOut,
    WebhookAcceptedOut,
)
from app.services import billing_service, family_service

router = APIRouter(prefix="/billing", tags=["billing"])

FamilyAccess = family_service.FamilyAccess
BillingManage = Annotated[
    FamilyAccess, Depends(require_family_membership(FamilyPermission.BILLING_MANAGE))
]

MAX_WEBHOOK_BODY_BYTES = 256 * 1024


@router.get(
    "/plans",
    response_model=ApiResponse[list[PlanOut]],
    summary="List available plans",
)
async def list_plans(session: DbSession) -> dict:
    """Readable without authentication-specific scope so a signed-out pricing
    screen can render; returns an empty list when no plans are configured."""
    plans = await billing_service.list_plans(session)
    return ok(
        [PlanOut.model_validate(plan) for plan in plans],
        message=(
            "Plans listed."
            if settings.payments_configured
            else "No payment provider is configured for this deployment."
        ),
        billing_available=settings.payments_configured,
    )


@router.get(
    "/families/{family_id}/subscription",
    response_model=ApiResponse[SubscriptionOut],
    summary="Get a family's subscription",
)
async def get_subscription(session: DbSession, access: BillingManage) -> dict:
    """``billing_available: false`` tells the client to hide purchase UI rather
    than call an endpoint that will return 503."""
    subscription = await billing_service.get_or_create_subscription(
        session, family_id=access.family_id
    )
    entitlements = await billing_service.entitlements_for(session, subscription=subscription)
    plan_code = await billing_service.plan_code_for(session, subscription=subscription)
    return ok(
        SubscriptionOut(
            family_id=access.family_id,
            plan_code=plan_code,
            status=subscription.status,
            provider=subscription.provider,
            trial_ends_at=subscription.trial_ends_at,
            current_period_start=subscription.current_period_start,
            current_period_end=subscription.current_period_end,
            cancel_at_period_end=subscription.cancel_at_period_end,
            billing_available=settings.payments_configured,
            entitlements=entitlements,
        )
    )


@router.post(
    "/families/{family_id}/checkout",
    response_model=ApiResponse[CheckoutSessionOut],
    status_code=status.HTTP_201_CREATED,
    summary="Start a checkout (requires a configured provider)",
)
async def create_checkout(
    payload: CheckoutRequest,
    principal: VerifiedParent,
    session: DbSession,
    access: BillingManage,
) -> dict:
    """Returns ``503 INTEGRATION_NOT_CONFIGURED`` until a payment provider is
    selected. It deliberately does not return a fake checkout URL."""
    provider = get_payment_provider()
    if not provider.configured:
        raise IntegrationNotConfigured(
            "Checkout is unavailable: no payment provider is configured for this deployment.",
            code=ErrorCode.INTEGRATION_NOT_CONFIGURED,
        )
    checkout = await provider.create_checkout_session(
        family_id=str(access.family_id),
        plan_code=payload.plan_code,
        success_url=payload.success_url,
        cancel_url=payload.cancel_url,
    )
    return ok(
        CheckoutSessionOut(
            checkout_url=checkout.checkout_url,
            provider=checkout.provider,
            expires_at=checkout.expires_at,
        ),
        message="Checkout session created.",
    )


@router.post(
    "/webhooks/{provider}",
    response_model=ApiResponse[WebhookAcceptedOut],
    summary="Payment provider webhook",
    dependencies=[Depends(RateLimit("billing.webhook"))],
)
async def payment_webhook(provider: str, request: Request, session: DbSession) -> dict:
    """The only path that can change entitlement.

    The raw body is read before parsing so the signature is verified over
    exactly the bytes the provider signed. Verification covers the HMAC and a
    timestamp tolerance (replay protection), and
    ``(provider, provider_event_id)`` is unique, so a retried delivery is
    recognised as a duplicate instead of being applied twice.
    """
    raw_body = await request.body()
    if len(raw_body) > MAX_WEBHOOK_BODY_BYTES:
        from app.core.errors import AppError

        raise AppError(
            "Webhook body is too large.",
            code=ErrorCode.PAYLOAD_TOO_LARGE,
            status_code=413,
        )

    headers = {key.lower(): value for key, value in request.headers.items()}
    outcome = await billing_service.process_webhook(
        session, provider_name=provider, raw_body=raw_body, headers=headers
    )

    if not outcome.accepted:
        # 400 with a stable code; the provider's retry is harmless because the
        # rejection is recorded and nothing was applied.
        from app.core.errors import AppError

        raise AppError(
            "Webhook signature verification failed.",
            code=ErrorCode.WEBHOOK_SIGNATURE_INVALID,
            status_code=400,
        )

    return ok(
        WebhookAcceptedOut(
            received=True,
            event_id=outcome.event_id,
            duplicate=outcome.duplicate,
            processed=outcome.processed,
        ),
        message="Webhook accepted.",
    )
