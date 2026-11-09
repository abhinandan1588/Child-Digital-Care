"""Billing schemas. Provider-neutral; no provider is selected."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.db.enums import BillingInterval, SubscriptionStatus
from app.schemas.common import OutSchema, SchemaBase


class PlanOut(OutSchema):
    id: uuid.UUID
    code: str
    name: str
    description: str
    price_minor_units: int
    currency: str
    interval: BillingInterval
    trial_days: int
    max_children: int | None
    max_devices: int | None
    feature_flags: dict
    active: bool


class SubscriptionOut(OutSchema):
    family_id: uuid.UUID
    plan_code: str | None = None
    status: SubscriptionStatus
    provider: str
    trial_ends_at: datetime | None = None
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    #: False whenever PAYMENT_PROVIDER=disabled, so clients can hide purchase UI
    #: instead of calling an endpoint that will return 503.
    billing_available: bool = False
    entitlements: dict = Field(default_factory=dict)


class CheckoutRequest(SchemaBase):
    plan_code: str = Field(min_length=1, max_length=48)
    success_url: str | None = Field(default=None, max_length=500)
    cancel_url: str | None = Field(default=None, max_length=500)


class CheckoutSessionOut(OutSchema):
    checkout_url: str
    provider: str
    expires_at: datetime | None = None


class WebhookAcceptedOut(OutSchema):
    received: bool = True
    event_id: uuid.UUID | None = None
    duplicate: bool = False
    processed: bool = False
