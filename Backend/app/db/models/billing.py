"""Provider-neutral billing domain.

No payment provider is selected. These tables model the *domain* (what a plan
is, what a subscription state is, which webhook events were seen) and the
integration seam lives in ``app/integrations/payments``. Nothing here ever
treats a client-reported purchase as proof of payment: only a signature-verified
provider webhook can move a subscription into ``active``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    BillingInterval,
    SubscriptionStatus,
    WebhookProcessingStatus,
)
from app.db.types import JSONBType, TZTimestamp, UUIDType, enum_column


class Plan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "plans"

    code: Mapped[str] = mapped_column(sa.String(48), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    description: Mapped[str] = mapped_column(sa.String(500), nullable=False, default="")
    #: Minor units (pence/cents) to avoid floating-point money.
    price_minor_units: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(sa.String(3), nullable=False, default="GBP")
    interval: Mapped[BillingInterval] = mapped_column(
        enum_column(BillingInterval, "billing_interval"),
        nullable=False,
        default=BillingInterval.month,
    )
    trial_days: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)

    max_children: Mapped[int | None] = mapped_column(sa.SmallInteger)
    max_devices: Mapped[int | None] = mapped_column(sa.SmallInteger)
    #: {"location": false, "website_restrictions": false, ...}
    feature_flags: Mapped[dict] = mapped_column(JSONBType, nullable=False, default=dict)

    active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)

    __table_args__ = (
        sa.UniqueConstraint("code", name="uq_plans_code"),
        sa.CheckConstraint("price_minor_units >= 0", name="price_non_negative"),
        sa.CheckConstraint("trial_days >= 0 AND trial_days <= 365", name="trial_days_in_range"),
    )


class Subscription(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One active subscription record per family."""

    __tablename__ = "subscriptions"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("plans.id", ondelete="RESTRICT")
    )
    status: Mapped[SubscriptionStatus] = mapped_column(
        enum_column(SubscriptionStatus, "subscription_status"),
        nullable=False,
        default=SubscriptionStatus.none,
    )

    provider: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="disabled")
    #: Opaque provider identifiers. Never a card number or any PAN data.
    provider_customer_ref: Mapped[str | None] = mapped_column(sa.String(128))
    provider_subscription_ref: Mapped[str | None] = mapped_column(sa.String(128))

    trial_ends_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    current_period_start: Mapped[datetime | None] = mapped_column(TZTimestamp)
    current_period_end: Mapped[datetime | None] = mapped_column(TZTimestamp)
    cancel_at_period_end: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    cancelled_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    __table_args__ = (
        sa.UniqueConstraint("family_id", name="uq_subscriptions_family_id"),
        sa.UniqueConstraint(
            "provider",
            "provider_subscription_ref",
            name="uq_subscriptions_provider_provider_subscription_ref",
        ),
        sa.Index("ix_subscriptions_status", "status"),
    )


class SubscriptionEvent(UUIDPrimaryKeyMixin, Base):
    """Append-only history of subscription state changes."""

    __tablename__ = "subscription_events"

    subscription_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False
    )
    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(sa.String(48), nullable=False)
    from_status: Mapped[SubscriptionStatus | None] = mapped_column(
        enum_column(SubscriptionStatus, "subscription_status")
    )
    to_status: Mapped[SubscriptionStatus] = mapped_column(
        enum_column(SubscriptionStatus, "subscription_status"), nullable=False
    )
    source: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="system")
    webhook_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("payment_webhook_events.id", ondelete="SET NULL")
    )
    event_metadata: Mapped[dict | None] = mapped_column(JSONBType)
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now(), index=True
    )

    __table_args__ = (
        sa.Index(
            "ix_subscription_events_subscription_id_created_at", "subscription_id", "created_at"
        ),
        sa.Index("ix_subscription_events_family_id", "family_id"),
    )


class PaymentWebhookEvent(UUIDPrimaryKeyMixin, Base):
    """Every webhook delivery, stored before processing.

    ``(provider, provider_event_id)`` is unique, which is what makes webhook
    processing idempotent under provider retries.
    """

    __tablename__ = "payment_webhook_events"

    provider: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    provider_event_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[WebhookProcessingStatus] = mapped_column(
        enum_column(WebhookProcessingStatus, "webhook_processing_status"),
        nullable=False,
        default=WebhookProcessingStatus.received,
    )
    signature_verified: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    #: SHA-256 of the raw body, so a replay with a mutated payload is detectable
    #: without retaining the full provider payload.
    payload_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSONBType)
    error_code: Mapped[str | None] = mapped_column(sa.String(64))

    received_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now(), index=True
    )
    processed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    __table_args__ = (
        sa.UniqueConstraint(
            "provider",
            "provider_event_id",
            name="uq_payment_webhook_events_provider_provider_event_id",
        ),
        sa.Index("ix_payment_webhook_events_status", "status"),
    )
