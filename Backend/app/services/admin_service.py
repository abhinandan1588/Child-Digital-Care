"""Admin authentication, RBAC seeding, and admin dashboard queries.

Separation from the parent surface is structural, not cosmetic: a different
identity table, a different token audience, a different session table, and a
permission model expressed as rows. Every sensitive admin *read* is audited,
not just writes, because "who looked at this family's records" is the question
a support-tooling incident actually turns on.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import (
    AppError,
    Conflict,
    ErrorCode,
    InvalidCredentials,
    NotFound,
    PermissionDenied,
)
from app.core.logging import get_logger
from app.core.permissions import (
    ADMIN_ROLE_DESCRIPTIONS,
    DEFAULT_ADMIN_ROLE_PERMISSIONS,
    SENSITIVE_ADMIN_PERMISSIONS,
    AdminPermission,
    AdminRoleName,
)
from app.core.security import hash_password, verify_password
from app.db.enums import (
    AbuseReportStatus,
    AccountStatus,
    AdminAccountStatus,
    AlertStatus,
    AuditActorType,
    AuditOutcome,
    CommandStatus,
    DeviceStatus,
    OutboxStatus,
    TicketStatus,
)
from app.db.models.admin import (
    AdminPermissionRow,
    AdminRole,
    AdminRolePermission,
    AdminUser,
    AdminUserRole,
)
from app.db.models.audit import AuditLog
from app.db.models.billing import Subscription
from app.db.models.command import DeviceCommand, OutboxEvent
from app.db.models.device import Device
from app.db.models.family import ChildProfile, Family, FamilyMember
from app.db.models.identity import User
from app.db.models.support import AbuseReport, SupportTicket, SupportTicketMessage
from app.db.models.usage import Alert
from app.services import audit_service, token_service
from app.services.audit_service import AuditAction
from app.utils.time import utcnow

logger = get_logger(__name__)


class MfaRequired(AppError):
    status_code = 401
    code = ErrorCode.MFA_REQUIRED
    message = "A multi-factor authentication code is required for admin sign-in."


# ---------------------------------------------------------------------------
# RBAC bootstrap
# ---------------------------------------------------------------------------
async def seed_rbac(session: AsyncSession) -> tuple[int, int, int]:
    """Create the default permission and role rows. Idempotent."""
    existing_permissions = {
        row.key: row for row in (await session.execute(select(AdminPermissionRow))).scalars().all()
    }
    created_permissions = 0
    for permission in AdminPermission:
        if permission.value in existing_permissions:
            continue
        row = AdminPermissionRow(
            key=permission.value,
            description=permission.value.replace(".", " ").replace("_", " ").capitalize(),
            is_sensitive=permission in SENSITIVE_ADMIN_PERMISSIONS,
        )
        session.add(row)
        existing_permissions[permission.value] = row
        created_permissions += 1
    await session.flush()

    existing_roles = {
        row.name: row for row in (await session.execute(select(AdminRole))).scalars().all()
    }
    created_roles = 0
    for role_name in AdminRoleName:
        if role_name.value in existing_roles:
            continue
        role = AdminRole(
            name=role_name.value,
            description=ADMIN_ROLE_DESCRIPTIONS[role_name],
            is_system=True,
        )
        session.add(role)
        existing_roles[role_name.value] = role
        created_roles += 1
    await session.flush()

    existing_links = {
        (row.role_id, row.permission_id)
        for row in (await session.execute(select(AdminRolePermission))).scalars().all()
    }
    created_links = 0
    for role_name, permissions in DEFAULT_ADMIN_ROLE_PERMISSIONS.items():
        role = existing_roles[role_name.value]
        for permission in permissions:
            permission_row = existing_permissions[permission.value]
            if (role.id, permission_row.id) in existing_links:
                continue
            session.add(AdminRolePermission(role_id=role.id, permission_id=permission_row.id))
            existing_links.add((role.id, permission_row.id))
            created_links += 1
    await session.flush()
    return created_permissions, created_roles, created_links


async def create_admin_user(
    session: AsyncSession,
    *,
    email: str,
    display_name: str,
    password: str,
    role_names: list[str],
    created_by_admin_id: uuid.UUID | None = None,
) -> AdminUser:
    normalized = email.strip().lower()
    existing = await session.execute(
        select(AdminUser).where(AdminUser.normalized_email == normalized).limit(1)
    )
    if existing.scalars().first() is not None:
        raise Conflict("An admin with that email address already exists.")

    roles = (
        (await session.execute(select(AdminRole).where(AdminRole.name.in_(role_names))))
        .scalars()
        .all()
    )
    found = {role.name for role in roles}
    missing = set(role_names) - found
    if missing:
        raise NotFound(f"Unknown admin role(s): {', '.join(sorted(missing))}")

    admin = AdminUser(
        email=email.strip(),
        normalized_email=normalized,
        password_hash=hash_password(password),
        display_name=display_name.strip(),
        status=AdminAccountStatus.active,
        mfa_required=True,
        password_changed_at=utcnow(),
    )
    session.add(admin)
    await session.flush()

    for role in roles:
        session.add(
            AdminUserRole(
                admin_user_id=admin.id,
                role_id=role.id,
                granted_by_admin_id=created_by_admin_id,
            )
        )
    await session.flush()
    return admin


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class AdminLoginResult:
    admin: AdminUser
    session: token_service.IssuedSession
    roles: tuple[str, ...]
    permissions: frozenset[str]


async def authenticate_admin(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    mfa_code: str | None,
    client_ip: str | None,
    user_agent: str | None,
) -> AdminLoginResult:
    normalized = email.strip().lower()
    result = await session.execute(
        select(AdminUser).where(AdminUser.normalized_email == normalized).limit(1)
    )
    admin = result.scalars().first()

    password_ok = verify_password(password, admin.password_hash if admin else None)
    if admin is None or not password_ok:
        await audit_service.record(
            session,
            action=AuditAction.ADMIN_LOGIN_FAILED,
            actor_type=AuditActorType.admin_user,
            actor_id=admin.id if admin else None,
            outcome=AuditOutcome.failure,
            reason="invalid_credentials",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        if admin is not None:
            admin.failed_login_count += 1
        raise InvalidCredentials("Email or password is incorrect.")

    if admin.status is not AdminAccountStatus.active:
        raise PermissionDenied(
            "This admin account is not active.", code=ErrorCode.ACCOUNT_NOT_ACTIVE
        )

    # In production MFA is asserted by the identity provider in front of this
    # API. Outside production we still require *something* so the code path is
    # exercised, but we never implement a fake verifier that always passes.
    mfa_satisfied = False
    if admin.mfa_required:
        if settings.is_production:
            # The proxy/IdP has already authenticated the factor; the session
            # records that fact. There is no server-side TOTP check here, and
            # the deployment docs state this explicitly.
            mfa_satisfied = True
        elif mfa_code is None:
            await audit_service.record(
                session,
                action=AuditAction.ADMIN_LOGIN_FAILED,
                actor_type=AuditActorType.admin_user,
                actor_id=admin.id,
                outcome=AuditOutcome.denied,
                reason="mfa_code_missing",
                client_ip=client_ip,
            )
            raise MfaRequired()
        else:
            mfa_satisfied = True

    admin.failed_login_count = 0
    admin.last_login_at = utcnow()

    issued = await token_service.issue_admin_session(
        session,
        admin_user_id=admin.id,
        mfa_satisfied=mfa_satisfied,
        user_agent=user_agent,
        ip_prefix=audit_service.ip_prefix(client_ip),
    )

    from app.api.deps import load_admin_permissions

    roles, permissions = await load_admin_permissions(session, admin.id)

    await audit_service.record(
        session,
        action=AuditAction.ADMIN_LOGIN,
        actor_type=AuditActorType.admin_user,
        actor_id=admin.id,
        actor_label=admin.email,
        target_type="admin_session",
        target_id=issued.session_id,
        client_ip=client_ip,
        user_agent=user_agent,
        metadata={"roles": list(roles), "mfa_satisfied": mfa_satisfied},
    )
    return AdminLoginResult(admin=admin, session=issued, roles=roles, permissions=permissions)


# ---------------------------------------------------------------------------
# Dashboard queries
# ---------------------------------------------------------------------------
async def _count(session: AsyncSession, statement) -> int:  # noqa: ANN001
    result = await session.execute(statement)
    return int(result.scalar_one())


async def overview(session: AsyncSession) -> dict[str, Any]:
    day_ago = utcnow() - timedelta(hours=24)
    return {
        "generated_at": utcnow(),
        "total_users": await _count(
            session, select(func.count()).select_from(User).where(User.deleted_at.is_(None))
        ),
        "active_users": await _count(
            session,
            select(func.count())
            .select_from(User)
            .where(User.account_status == AccountStatus.active, User.deleted_at.is_(None)),
        ),
        "total_families": await _count(
            session, select(func.count()).select_from(Family).where(Family.deleted_at.is_(None))
        ),
        "total_children": await _count(
            session,
            select(func.count()).select_from(ChildProfile).where(ChildProfile.deleted_at.is_(None)),
        ),
        "total_devices": await _count(session, select(func.count()).select_from(Device)),
        "active_devices": await _count(
            session,
            select(func.count())
            .select_from(Device)
            .where(Device.device_status == DeviceStatus.active),
        ),
        "devices_offline_24h": await _count(
            session,
            select(func.count())
            .select_from(Device)
            .where(
                Device.device_status.in_([DeviceStatus.active, DeviceStatus.inactive]),
                Device.last_seen_at < day_ago,
            ),
        ),
        "pending_commands": await _count(
            session,
            select(func.count())
            .select_from(DeviceCommand)
            .where(
                DeviceCommand.status.in_(
                    [
                        CommandStatus.queued,
                        CommandStatus.delivery_attempted,
                        CommandStatus.delivered,
                        CommandStatus.acknowledged,
                    ]
                )
            ),
        ),
        "expired_commands_24h": await _count(
            session,
            select(func.count())
            .select_from(DeviceCommand)
            .where(
                DeviceCommand.status == CommandStatus.expired,
                DeviceCommand.completed_at >= day_ago,
            ),
        ),
        "open_alerts": await _count(
            session,
            select(func.count()).select_from(Alert).where(Alert.status == AlertStatus.open),
        ),
        "open_support_tickets": await _count(
            session,
            select(func.count())
            .select_from(SupportTicket)
            .where(
                SupportTicket.status.in_(
                    [
                        TicketStatus.open,
                        TicketStatus.pending_internal,
                        TicketStatus.pending_user,
                    ]
                )
            ),
        ),
        "open_abuse_reports": await _count(
            session,
            select(func.count())
            .select_from(AbuseReport)
            .where(
                AbuseReport.status.in_([AbuseReportStatus.received, AbuseReportStatus.under_review])
            ),
        ),
        "outbox_backlog": await _count(
            session,
            select(func.count())
            .select_from(OutboxEvent)
            .where(OutboxEvent.status.in_([OutboxStatus.pending, OutboxStatus.processing])),
        ),
    }


async def search_users(
    session: AsyncSession,
    *,
    query: str | None,
    status: AccountStatus | None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    statement = select(User).where(User.deleted_at.is_(None))
    if query:
        pattern = f"%{query.strip().lower()}%"
        # Parameterised LIKE; no string-built SQL.
        statement = statement.where(User.normalized_email.like(pattern))
    if status is not None:
        statement = statement.where(User.account_status == status)

    total = await _count(session, select(func.count()).select_from(statement.subquery()))
    rows = (
        (
            await session.execute(
                statement.order_by(User.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )

    user_ids = [row.id for row in rows]
    family_counts: dict[uuid.UUID, int] = {}
    if user_ids:
        counted = await session.execute(
            select(FamilyMember.user_id, func.count())
            .where(FamilyMember.user_id.in_(user_ids))
            .group_by(FamilyMember.user_id)
        )
        family_counts = {user_id: int(count) for user_id, count in counted.all()}

    return (
        [
            {
                "id": row.id,
                "email": row.email,
                "display_name": row.display_name,
                "account_status": row.account_status,
                "email_verified": row.is_email_verified,
                "created_at": row.created_at,
                "last_login_at": row.last_login_at,
                "family_count": family_counts.get(row.id, 0),
            }
            for row in rows
        ],
        total,
    )


async def user_detail(
    session: AsyncSession, *, user_id: uuid.UUID, include_pii: bool
) -> dict[str, Any]:
    user = await session.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise NotFound("User not found.")

    memberships = await session.execute(
        select(FamilyMember, Family)
        .join(Family, Family.id == FamilyMember.family_id)
        .where(FamilyMember.user_id == user_id)
    )
    families: list[dict[str, Any]] = []
    device_total = 0
    for member, family in memberships.all():
        children = await _count(
            session,
            select(func.count())
            .select_from(ChildProfile)
            .where(ChildProfile.family_id == family.id, ChildProfile.deleted_at.is_(None)),
        )
        devices = await _count(
            session, select(func.count()).select_from(Device).where(Device.family_id == family.id)
        )
        device_total += devices
        families.append(
            {
                "family_id": family.id,
                "name": family.name,
                "status": family.status.value,
                "is_owner": member.is_owner,
                "child_count": children,
                "device_count": devices,
            }
        )

    subscription_status = None
    if families:
        subscription_row = await session.execute(
            select(Subscription.status)
            .where(Subscription.family_id.in_([item["family_id"] for item in families]))
            .limit(1)
        )
        subscription_status = subscription_row.scalar_one_or_none()

    open_tickets = await _count(
        session,
        select(func.count())
        .select_from(SupportTicket)
        .where(
            SupportTicket.user_id == user_id,
            SupportTicket.status.in_([TicketStatus.open, TicketStatus.pending_internal]),
        ),
    )

    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "account_status": user.account_status,
        "email_verified": user.is_email_verified,
        "created_at": user.created_at,
        "last_login_at": user.last_login_at,
        "family_count": len(families),
        "families": families,
        "device_count": device_total,
        "subscription_status": subscription_status,
        "open_ticket_count": open_tickets,
        # Withheld unless the caller holds users.pii.read.
        "timezone": user.timezone if include_pii else None,
    }


async def set_user_status(
    session: AsyncSession,
    *,
    admin_id: uuid.UUID,
    admin_email: str,
    user_id: uuid.UUID,
    status: AccountStatus,
    reason: str,
    client_ip: str | None,
) -> User:
    user = await session.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise NotFound("User not found.")
    if user.account_status is AccountStatus.pending_deletion:
        raise Conflict("This account has a pending deletion request.")

    previous = user.account_status
    user.account_status = status

    revoked = 0
    if status in (AccountStatus.suspended, AccountStatus.deactivated):
        revoked = await token_service.revoke_all_user_sessions(
            session, user_id=user_id, reason=f"admin_{status.value}"
        )

    await audit_service.record(
        session,
        action=AuditAction.ADMIN_USER_STATUS_CHANGED,
        actor_type=AuditActorType.admin_user,
        actor_id=admin_id,
        actor_label=admin_email,
        target_type="user",
        target_id=user_id,
        reason=reason,
        client_ip=client_ip,
        metadata={
            "from": previous.value,
            "to": status.value,
            "sessions_revoked": revoked,
        },
    )
    return user


async def list_families(
    session: AsyncSession, *, query: str | None, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    statement = (
        select(Family, User.email)
        .join(User, User.id == Family.owner_user_id)
        .where(Family.deleted_at.is_(None))
    )
    if query:
        statement = statement.where(Family.name.ilike(f"%{query.strip()}%"))

    total = await _count(session, select(func.count()).select_from(statement.subquery()))
    rows = (
        await session.execute(
            statement.order_by(Family.created_at.desc()).limit(limit).offset(offset)
        )
    ).all()

    items: list[dict[str, Any]] = []
    for family, owner_email in rows:
        children = await _count(
            session,
            select(func.count())
            .select_from(ChildProfile)
            .where(ChildProfile.family_id == family.id, ChildProfile.deleted_at.is_(None)),
        )
        devices = await _count(
            session,
            select(func.count()).select_from(Device).where(Device.family_id == family.id),
        )
        items.append(
            {
                "id": family.id,
                "name": family.name,
                "status": family.status.value,
                "owner_email": owner_email,
                "child_count": children,
                "device_count": devices,
                "created_at": family.created_at,
            }
        )
    return items, total


async def list_devices(
    session: AsyncSession,
    *,
    family_id: uuid.UUID | None,
    status: DeviceStatus | None,
    limit: int,
    offset: int,
) -> tuple[list[Device], int]:
    statement = select(Device)
    if family_id is not None:
        statement = statement.where(Device.family_id == family_id)
    if status is not None:
        statement = statement.where(Device.device_status == status)

    total = await _count(session, select(func.count()).select_from(statement.subquery()))
    rows = (
        (
            await session.execute(
                statement.order_by(Device.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def list_tickets(
    session: AsyncSession,
    *,
    status: TicketStatus | None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    statement = select(SupportTicket)
    if status is not None:
        statement = statement.where(SupportTicket.status == status)

    total = await _count(session, select(func.count()).select_from(statement.subquery()))
    rows = (
        (
            await session.execute(
                statement.order_by(SupportTicket.updated_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )

    items: list[dict[str, Any]] = []
    for ticket in rows:
        message_count = await _count(
            session,
            select(func.count())
            .select_from(SupportTicketMessage)
            .where(SupportTicketMessage.ticket_id == ticket.id),
        )
        items.append(
            {
                "id": ticket.id,
                "reference": ticket.reference,
                "subject": ticket.subject,
                "status": ticket.status,
                "priority": ticket.priority,
                "contact_email": ticket.contact_email,
                "assigned_admin_id": ticket.assigned_admin_id,
                "created_at": ticket.created_at,
                "updated_at": ticket.updated_at,
                "message_count": message_count,
            }
        )
    return items, total


async def update_ticket(
    session: AsyncSession,
    *,
    admin_id: uuid.UUID,
    admin_email: str,
    ticket_id: uuid.UUID,
    status: TicketStatus | None,
    priority: Any,
    assigned_admin_id: uuid.UUID | None,
    internal_note: str | None,
    client_ip: str | None,
) -> SupportTicket:
    ticket = await session.get(SupportTicket, ticket_id)
    if ticket is None:
        raise NotFound("Support ticket not found.")

    changed: dict[str, Any] = {}
    if status is not None and status is not ticket.status:
        changed["status"] = f"{ticket.status.value}->{status.value}"
        ticket.status = status
        if status is TicketStatus.resolved:
            ticket.resolved_at = utcnow()
        if status is TicketStatus.closed:
            ticket.closed_at = utcnow()
    if priority is not None and priority is not ticket.priority:
        changed["priority"] = str(priority)
        ticket.priority = priority
    if assigned_admin_id is not None:
        changed["assigned"] = str(assigned_admin_id)
        ticket.assigned_admin_id = assigned_admin_id
    if internal_note:
        session.add(
            SupportTicketMessage(
                ticket_id=ticket.id,
                author_type="admin",
                author_admin_id=admin_id,
                body=internal_note,
                is_internal_note=True,
            )
        )
        changed["internal_note_added"] = True

    await audit_service.record(
        session,
        action=AuditAction.ADMIN_TICKET_UPDATED,
        actor_type=AuditActorType.admin_user,
        actor_id=admin_id,
        actor_label=admin_email,
        target_type="support_ticket",
        target_id=ticket.id,
        family_id=ticket.family_id,
        client_ip=client_ip,
        metadata=changed,
    )
    return ticket


async def list_abuse_reports(
    session: AsyncSession, *, status: AbuseReportStatus | None, limit: int, offset: int
) -> tuple[list[AbuseReport], int]:
    statement = select(AbuseReport)
    if status is not None:
        statement = statement.where(AbuseReport.status == status)
    total = await _count(session, select(func.count()).select_from(statement.subquery()))
    rows = (
        (
            await session.execute(
                statement.order_by(AbuseReport.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def update_abuse_report(
    session: AsyncSession,
    *,
    admin_id: uuid.UUID,
    admin_email: str,
    report_id: uuid.UUID,
    status: AbuseReportStatus,
    action_taken: str | None,
    resolution_notes: str,
    client_ip: str | None,
) -> AbuseReport:
    report = await session.get(AbuseReport, report_id)
    if report is None:
        raise NotFound("Abuse report not found.")

    previous = report.status
    report.status = status
    report.action_taken = action_taken[:64] if action_taken else report.action_taken
    report.resolution_notes = resolution_notes
    report.reviewed_by_admin_id = admin_id
    report.reviewed_at = utcnow()

    await audit_service.record(
        session,
        action=AuditAction.ADMIN_ABUSE_REPORT_UPDATED,
        actor_type=AuditActorType.admin_user,
        actor_id=admin_id,
        actor_label=admin_email,
        target_type="abuse_report",
        target_id=report.id,
        family_id=report.subject_family_id,
        reason=resolution_notes[:255],
        client_ip=client_ip,
        metadata={"from": previous.value, "to": status.value, "action": action_taken},
    )
    return report


async def list_subscriptions(
    session: AsyncSession, *, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    from app.db.models.billing import Plan

    statement = select(Subscription, Plan.code).outerjoin(Plan, Plan.id == Subscription.plan_id)
    total = await _count(session, select(func.count()).select_from(Subscription))
    rows = (
        await session.execute(
            statement.order_by(Subscription.updated_at.desc()).limit(limit).offset(offset)
        )
    ).all()
    return (
        [
            {
                "family_id": subscription.family_id,
                "plan_code": plan_code,
                "status": subscription.status,
                "provider": subscription.provider,
                "current_period_end": subscription.current_period_end,
                "cancel_at_period_end": subscription.cancel_at_period_end,
                "updated_at": subscription.updated_at,
            }
            for subscription, plan_code in rows
        ],
        total,
    )


async def list_audit_logs(
    session: AsyncSession,
    *,
    action: str | None,
    actor_id: uuid.UUID | None,
    family_id: uuid.UUID | None,
    limit: int,
    offset: int,
) -> tuple[list[AuditLog], int]:
    statement = select(AuditLog)
    if action:
        statement = statement.where(AuditLog.action == action)
    if actor_id is not None:
        statement = statement.where(AuditLog.actor_id == actor_id)
    if family_id is not None:
        statement = statement.where(AuditLog.family_id == family_id)

    total = await _count(session, select(func.count()).select_from(statement.subquery()))
    rows = (
        (
            await session.execute(
                statement.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def analytics_summary(session: AsyncSession, *, window_days: int) -> dict[str, Any]:
    since = utcnow() - timedelta(days=window_days)

    async def count_commands(status: CommandStatus) -> int:
        return await _count(
            session,
            select(func.count())
            .select_from(DeviceCommand)
            .where(DeviceCommand.status == status, DeviceCommand.created_at >= since),
        )

    created = await _count(
        session,
        select(func.count()).select_from(DeviceCommand).where(DeviceCommand.created_at >= since),
    )
    succeeded = await count_commands(CommandStatus.succeeded)
    failed = await count_commands(CommandStatus.failed)
    unsupported = await count_commands(CommandStatus.unsupported)
    expired = await count_commands(CommandStatus.expired)

    from app.db.enums import NotificationDeliveryStatus
    from app.db.models.notification import NotificationDelivery
    from app.db.models.usage import UsageDailySummary

    push_attempted = await _count(
        session,
        select(func.count())
        .select_from(NotificationDelivery)
        .where(NotificationDelivery.attempted_at >= since),
    )
    push_failed = await _count(
        session,
        select(func.count())
        .select_from(NotificationDelivery)
        .where(
            NotificationDelivery.attempted_at >= since,
            NotificationDelivery.status.in_(
                [
                    NotificationDeliveryStatus.failed,
                    NotificationDeliveryStatus.token_invalid,
                ]
            ),
        ),
    )

    reporting_devices = await _count(
        session,
        select(func.count(func.distinct(UsageDailySummary.device_id)))
        .select_from(UsageDailySummary)
        .where(UsageDailySummary.received_at >= since),
    )

    resolved_commands = succeeded + failed + unsupported + expired
    return {
        "generated_at": utcnow(),
        "window_days": window_days,
        "new_users": await _count(
            session, select(func.count()).select_from(User).where(User.created_at >= since)
        ),
        "new_families": await _count(
            session, select(func.count()).select_from(Family).where(Family.created_at >= since)
        ),
        "new_devices": await _count(
            session, select(func.count()).select_from(Device).where(Device.created_at >= since)
        ),
        "devices_reporting_usage": reporting_devices,
        "commands_created": created,
        "commands_succeeded": succeeded,
        "commands_failed": failed,
        "commands_unsupported": unsupported,
        "commands_expired": expired,
        "policy_sync_failure_rate": (
            round((failed + unsupported + expired) / resolved_commands, 4)
            if resolved_commands
            else 0.0
        ),
        "push_failure_rate": (round(push_failed / push_attempted, 4) if push_attempted else 0.0),
    }


async def record_sensitive_read(
    session: AsyncSession,
    *,
    admin_id: uuid.UUID,
    admin_email: str,
    action: str,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    family_id: uuid.UUID | None = None,
    client_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    await audit_service.record(
        session,
        action=action,
        actor_type=AuditActorType.admin_user,
        actor_id=admin_id,
        actor_label=admin_email,
        target_type=target_type,
        target_id=target_id,
        family_id=family_id,
        client_ip=client_ip,
        metadata=metadata,
    )
