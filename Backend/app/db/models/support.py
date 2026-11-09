"""Support tickets and abuse reports (trust & safety)."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.enums import (
    AbuseReportCategory,
    AbuseReportStatus,
    TicketPriority,
    TicketStatus,
)
from app.db.types import EmailText, JSONBType, TZTimestamp, UUIDType, enum_column


class SupportTicket(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "support_tickets"

    reference: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    family_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="SET NULL")
    )
    contact_email: Mapped[str] = mapped_column(EmailText, nullable=False)

    subject: Mapped[str] = mapped_column(sa.String(160), nullable=False)
    category: Mapped[str] = mapped_column(sa.String(48), nullable=False, default="general")
    status: Mapped[TicketStatus] = mapped_column(
        enum_column(TicketStatus, "ticket_status"), nullable=False, default=TicketStatus.open
    )
    priority: Mapped[TicketPriority] = mapped_column(
        enum_column(TicketPriority, "ticket_priority"),
        nullable=False,
        default=TicketPriority.normal,
    )
    assigned_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    closed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)

    messages: Mapped[list[SupportTicketMessage]] = relationship(
        back_populates="ticket", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        sa.UniqueConstraint("reference", name="uq_support_tickets_reference"),
        sa.Index("ix_support_tickets_status_priority", "status", "priority"),
        sa.Index("ix_support_tickets_user_id", "user_id"),
        sa.Index("ix_support_tickets_assigned_admin_id", "assigned_admin_id"),
    )


class SupportTicketMessage(UUIDPrimaryKeyMixin, Base):
    """A message on a ticket.

    Attachments are referenced by an object-storage key only; the content is
    never stored in the database and is served through short-lived signed URLs
    after an authorization check.
    """

    __tablename__ = "support_ticket_messages"

    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUIDType, sa.ForeignKey("support_tickets.id", ondelete="CASCADE"), nullable=False
    )
    author_type: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    author_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Visible only to staff.
    is_internal_note: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    #: [{"key": "...", "content_type": "image/png", "size_bytes": 1234}]
    attachments: Mapped[list | None] = mapped_column(JSONBType)
    created_at: Mapped[datetime] = mapped_column(
        TZTimestamp, nullable=False, server_default=sa.func.now(), index=True
    )

    ticket: Mapped[SupportTicket] = relationship(back_populates="messages")

    __table_args__ = (
        sa.Index("ix_support_ticket_messages_ticket_id_created_at", "ticket_id", "created_at"),
        sa.CheckConstraint(
            "author_type IN ('user', 'admin', 'system')", name="author_type_allowed"
        ),
        sa.CheckConstraint("length(body) >= 1", name="body_not_empty"),
    )


class AbuseReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A report that the product is being misused.

    Non-consensual monitoring is the central abuse risk for a parental-control
    product, so it is a first-class report category with its own review path.
    """

    __tablename__ = "abuse_reports"

    reference: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    category: Mapped[AbuseReportCategory] = mapped_column(
        enum_column(AbuseReportCategory, "abuse_report_category"), nullable=False
    )
    status: Mapped[AbuseReportStatus] = mapped_column(
        enum_column(AbuseReportStatus, "abuse_report_status"),
        nullable=False,
        default=AbuseReportStatus.received,
    )

    reporter_email: Mapped[str | None] = mapped_column(EmailText)
    reporter_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    #: Subject of the report; any of these may be null.
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    subject_family_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("families.id", ondelete="SET NULL")
    )
    subject_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("devices.id", ondelete="SET NULL")
    )

    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    reviewed_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDType, sa.ForeignKey("admin_users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(TZTimestamp)
    #: Free-text record of the documented safety action taken.
    resolution_notes: Mapped[str | None] = mapped_column(sa.Text)
    action_taken: Mapped[str | None] = mapped_column(sa.String(64))

    __table_args__ = (
        sa.UniqueConstraint("reference", name="uq_abuse_reports_reference"),
        sa.Index("ix_abuse_reports_status_category", "status", "category"),
        sa.Index("ix_abuse_reports_subject_family_id", "subject_family_id"),
        sa.CheckConstraint("length(description) >= 1", name="description_not_empty"),
    )
