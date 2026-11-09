"""Audit log, consent records, privacy request workflows, idempotency store."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    AuditActorType,
    AuditOutcome,
    ConsentMethod,
    ConsentState,
    ConsentType,
    PrivacyRequestStatus,
    PrivacyRequestType,
)
from app.db.types import EmailText, JSONBType, TZTimestamp, UUIDType, enum_column


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Append-only audit trail.

    Append-only is enforced at two levels: the application never issues an
    UPDATE or DELETE against this table, and the deployment grants the
    application role ``INSERT, SELECT`` only (see docs/DEPLOYMENT.md). There
    is deliberately no ORM relationship or cascade into this table, so
    deleting a family cannot erase its audit history.
    """

    __tablename__ = "audit_logs"

    actor_type: Mapped[AuditActorType] = mapped_column(
        enum_column(AuditActorType, "audit_actor_type"), nullable=False
    )
    #: No foreign key: the record must survive deletion of the actor.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUIDType)
    actor_label: Mapped[str | None] = mapped_column(sa.String(120))

    action: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    outcome: Mapped[AuditOutcome] = mapped_column(
        enum_column(AuditOutcome, "audit_outcome"), nullable=False, default=AuditOutcome.success
    )
    target_type: Mapped[str | None] = mapped_column(sa.String(40))
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUIDType)
    family_id: Mapped[uuid.UUID | None] = mapped_column(UUIDType)

    request_id: Mapped[str | None] = mapped_column(sa.String(64))
    ip_prefix: Mapped[str | None] = mapped_column(sa.String(64))
    user_agent: Mapped[str | None] = mapped_column(sa.String(255))
    reason: Mapped[str | None] = mapped_column(sa.String(255))
    #: Safe metadata only: ids, counts, enum values. Never tokens, passwords,
    #: coordinates or child telemetry.
    event_metadata: Mapped[dict | None] = mapped_column(JSONBType)

    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now(), index=True
    )

    __table_args__ = (
        sa.Index("ix_audit_logs_actor_type_actor_id", "actor_type", "actor_id"),
        sa.Index("ix_audit_logs_family_id_created_at", "family_id", "created_at"),
        sa.Index("ix_audit_logs_action_created_at", "action", "created_at"),
        sa.Index("ix_audit_logs_target_type_target_id", "target_type", "target_id"),
    )


class ConsentRecord(UUIDPrimaryKeyMixin, Base):
    """A versioned consent/disclosure record.

    Each row pins the exact policy version that was presented, who recorded it,
    and how. Revocation is a state change on a new row, never a deletion, so
    the history of what was disclosed when stays intact.
    """

    __tablename__ = "consent_records"

    consent_type: Mapped[ConsentType] = mapped_column(
        enum_column(ConsentType, "consent_type"), nullable=False
    )
    state: Mapped[ConsentState] = mapped_column(
        enum_column(ConsentState, "consent_state"), nullable=False
    )
    policy_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    method: Mapped[ConsentMethod] = mapped_column(
        enum_column(ConsentMethod, "consent_method"), nullable=False
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    family_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="SET NULL")
    )
    child_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("child_profiles.id", ondelete="SET NULL")
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="SET NULL")
    )

    recorded_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    #: Surface shown to the person consenting, e.g. "parent_app", "child_app".
    surface: Mapped[str | None] = mapped_column(sa.String(32))
    consent_metadata: Mapped[dict | None] = mapped_column(JSONBType)

    __table_args__ = (
        sa.Index("ix_consent_records_family_id_consent_type", "family_id", "consent_type"),
        sa.Index("ix_consent_records_device_id_consent_type", "device_id", "consent_type"),
        sa.Index("ix_consent_records_user_id_consent_type", "user_id", "consent_type"),
    )


class PrivacyRequest(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A data export or deletion request.

    One table with a ``request_type`` discriminator rather than two nearly
    identical tables, because the workflow (receive -> verify -> process ->
    complete) and the SLA tracking are the same for both.
    """

    __tablename__ = "privacy_requests"

    request_type: Mapped[PrivacyRequestType] = mapped_column(
        enum_column(PrivacyRequestType, "privacy_request_type"), nullable=False
    )
    status: Mapped[PrivacyRequestStatus] = mapped_column(
        enum_column(PrivacyRequestStatus, "privacy_request_status"),
        nullable=False,
        default=PrivacyRequestStatus.pending,
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    family_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="SET NULL")
    )
    #: Retained so a request survives deletion of the account it refers to.
    requester_email: Mapped[str] = mapped_column(EmailText, nullable=False)

    requested_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    #: Regulatory deadline for responding.
    due_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    started_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    completed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    #: Short-lived object-storage key for an export bundle. Never a public URL.
    artifact_key: Mapped[str | None] = mapped_column(sa.String(255))
    artifact_expires_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    handled_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="SET NULL")
    )
    rejection_reason: Mapped[str | None] = mapped_column(sa.String(255))
    #: What was retained and why (e.g. billing records with a legal basis).
    retention_exceptions: Mapped[dict | None] = mapped_column(JSONBType)

    __table_args__ = (
        sa.Index("ix_privacy_requests_status_request_type", "status", "request_type"),
        sa.Index("ix_privacy_requests_user_id", "user_id"),
        sa.Index("ix_privacy_requests_due_at", "due_at"),
    )


class IdempotencyRecord(UUIDPrimaryKeyMixin, Base):
    """Stored result of a request that carried an ``Idempotency-Key``.

    A replay with the same key and the same body returns the stored response. A
    replay with the same key but a *different* body is a client bug and is
    rejected with ``IDEMPOTENCY_KEY_REUSED`` rather than silently returning the
    wrong result.
    """

    __tablename__ = "idempotency_records"

    #: Principal scope, so two tenants cannot collide on the same key.
    principal_type: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    principal_id: Mapped[uuid.UUID] = mapped_column(UUIDType, nullable=False)
    endpoint: Mapped[str] = mapped_column(sa.String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    status_code: Mapped[int] = mapped_column(sa.SmallInteger, nullable=False)
    response_body: Mapped[dict] = mapped_column(JSONBType, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(TZTimestamp, nullable=False, index=True)

    __table_args__ = (
        sa.UniqueConstraint(
            "principal_type",
            "principal_id",
            "endpoint",
            "idempotency_key",
            name="uq_idempotency_records_principal_endpoint_key",
        ),
    )
