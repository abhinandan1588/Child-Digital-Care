"""Audit logging.

Every privileged, security-relevant or sensitive-read action goes through
:func:`record`. The table is append-only: this module never issues UPDATE or
DELETE against it, and nothing else in the codebase writes to it.

Two guarantees matter:

* **Safe metadata only.** ``metadata`` is filtered through a deny-list so a
  caller cannot accidentally persist a token, password or coordinate pair.
* **Survives deletion.** ``audit_logs`` has no foreign keys into the tenant
  tables, so deleting a family or user cannot cascade its audit trail away.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import get_request_id
from app.core.logging import SENSITIVE_KEYS, get_logger
from app.db.enums import AuditActorType, AuditOutcome
from app.db.models.audit import AuditLog

logger = get_logger(__name__)

MAX_METADATA_KEYS = 25
MAX_METADATA_VALUE_LENGTH = 256


class AuditAction:
    """Canonical action names. Strings are part of the admin API contract."""

    # Authentication
    USER_REGISTERED = "user.registered"
    USER_EMAIL_VERIFIED = "user.email_verified"
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_LOGOUT = "user.logout"
    USER_LOGOUT_ALL = "user.logout_all"
    USER_TOKEN_REFRESHED = "user.token_refreshed"
    USER_REFRESH_REUSE_DETECTED = "user.refresh_reuse_detected"
    USER_PASSWORD_RESET_REQUESTED = "user.password_reset_requested"
    USER_PASSWORD_RESET_COMPLETED = "user.password_reset_completed"
    USER_PASSWORD_CHANGED = "user.password_changed"
    USER_SESSION_REVOKED = "user.session_revoked"

    # Family / children
    FAMILY_CREATED = "family.created"
    FAMILY_UPDATED = "family.updated"
    FAMILY_MEMBER_REMOVED = "family.member_removed"
    GUARDIAN_INVITED = "family.guardian_invited"
    GUARDIAN_INVITATION_ACCEPTED = "family.guardian_invitation_accepted"
    GUARDIAN_INVITATION_REVOKED = "family.guardian_invitation_revoked"
    CHILD_CREATED = "child.created"
    CHILD_UPDATED = "child.updated"
    CHILD_DEACTIVATED = "child.deactivated"

    # Pairing / devices
    PAIRING_INVITATION_CREATED = "pairing.invitation_created"
    PAIRING_INVITATION_REVOKED = "pairing.invitation_revoked"
    PAIRING_CLAIM_SUCCEEDED = "pairing.claim_succeeded"
    PAIRING_CLAIM_FAILED = "pairing.claim_failed"
    DEVICE_REGISTERED = "device.registered"
    DEVICE_LABEL_UPDATED = "device.label_updated"
    DEVICE_REVOKED = "device.revoked"
    DEVICE_TOKEN_REFRESHED = "device.token_refreshed"
    DEVICE_REFRESH_REUSE_DETECTED = "device.refresh_reuse_detected"
    DEVICE_CAPABILITIES_REPORTED = "device.capabilities_reported"
    DEVICE_PERMISSIONS_REPORTED = "device.permissions_reported"

    # Policies / commands
    POLICY_CHANGED = "policy.changed"
    POLICY_SYNC_REPORTED = "policy.sync_reported"
    COMMAND_CREATED = "command.created"
    COMMAND_CANCELLED = "command.cancelled"
    COMMAND_ACKNOWLEDGED = "command.acknowledged"
    COMMAND_RESULT_RECORDED = "command.result_recorded"

    # Sensitive reads
    LOCATION_READ = "location.read"
    LOCATION_SAMPLE_ACCEPTED = "location.sample_accepted"
    USAGE_READ = "usage.read"

    # Privacy
    CONSENT_RECORDED = "privacy.consent_recorded"
    CONSENT_REVOKED = "privacy.consent_revoked"
    EXPORT_REQUESTED = "privacy.export_requested"
    DELETION_REQUESTED = "privacy.deletion_requested"
    DELETION_CANCELLED = "privacy.deletion_cancelled"
    DATA_DELETED = "privacy.data_deleted"

    # Billing
    SUBSCRIPTION_CHANGED = "billing.subscription_changed"
    WEBHOOK_RECEIVED = "billing.webhook_received"
    WEBHOOK_REJECTED = "billing.webhook_rejected"

    # Admin
    ADMIN_LOGIN = "admin.login"
    ADMIN_LOGIN_FAILED = "admin.login_failed"
    ADMIN_LOGOUT = "admin.logout"
    ADMIN_USER_LIST_READ = "admin.user_list_read"
    ADMIN_USER_READ = "admin.user_read"
    ADMIN_USER_STATUS_CHANGED = "admin.user_status_changed"
    ADMIN_FAMILY_READ = "admin.family_read"
    ADMIN_DEVICE_READ = "admin.device_read"
    ADMIN_DEVICE_REVOKED = "admin.device_revoked"
    ADMIN_TICKET_UPDATED = "admin.ticket_updated"
    ADMIN_ABUSE_REPORT_UPDATED = "admin.abuse_report_updated"
    ADMIN_SUBSCRIPTION_READ = "admin.subscription_read"
    ADMIN_AUDIT_LOG_READ = "admin.audit_log_read"
    ADMIN_ANALYTICS_READ = "admin.analytics_read"
    ADMIN_PERMISSION_DENIED = "admin.permission_denied"

    # Authorization failures worth recording
    CROSS_TENANT_ACCESS_DENIED = "authz.cross_tenant_denied"


def sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop anything sensitive and bound the size of the stored blob."""
    if not metadata:
        return None
    cleaned: dict[str, Any] = {}
    for key, value in list(metadata.items())[:MAX_METADATA_KEYS]:
        if key.lower() in SENSITIVE_KEYS:
            continue
        if isinstance(value, uuid.UUID):
            cleaned[key] = str(value)
        elif isinstance(value, str):
            cleaned[key] = value[:MAX_METADATA_VALUE_LENGTH]
        elif isinstance(value, bool | int | float) or value is None:
            cleaned[key] = value
        elif isinstance(value, list | tuple):
            cleaned[key] = [str(item)[:64] for item in list(value)[:20]]
        elif isinstance(value, dict):
            cleaned[key] = {
                str(k)[:40]: str(v)[:64]
                for k, v in list(value.items())[:10]
                if str(k).lower() not in SENSITIVE_KEYS
            }
        else:
            cleaned[key] = str(value)[:MAX_METADATA_VALUE_LENGTH]
    return cleaned or None


def ip_prefix(ip: str | None) -> str | None:
    """Truncate an address so the audit trail is useful but not a tracker.

    IPv4 keeps the /24, IPv6 keeps the /48.
    """
    if not ip or ip == "unknown":
        return None
    if ":" in ip:
        groups = ip.split(":")
        return ":".join(groups[:3]) + "::/48"
    octets = ip.split(".")
    if len(octets) == 4:
        return ".".join(octets[:3]) + ".0/24"
    return None


async def record(
    session: AsyncSession,
    *,
    action: str,
    actor_type: AuditActorType,
    actor_id: uuid.UUID | None = None,
    actor_label: str | None = None,
    outcome: AuditOutcome = AuditOutcome.success,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    family_id: uuid.UUID | None = None,
    reason: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an audit entry to the current transaction.

    The entry commits with the action it describes, so there is no window in
    which a privileged change exists without its audit record.
    """
    entry = AuditLog(
        actor_type=actor_type,
        actor_id=actor_id,
        actor_label=(actor_label or None) and actor_label[:120],
        action=action[:80],
        outcome=outcome,
        target_type=target_type[:40] if target_type else None,
        target_id=target_id,
        family_id=family_id,
        request_id=(get_request_id() or None),
        ip_prefix=ip_prefix(client_ip),
        user_agent=user_agent[:255] if user_agent else None,
        reason=reason[:255] if reason else None,
        event_metadata=sanitize_metadata(metadata),
    )
    session.add(entry)
    logger.info(
        "audit",
        action=entry.action,
        actor_type=actor_type.value,
        outcome=outcome.value,
        target_type=entry.target_type,
    )
    return entry
