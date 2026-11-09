"""Permission vocabulary and evaluation.

Two independent permission systems, deliberately kept apart:

* **Family permissions** scope what a guardian may do *inside their own
  family*. They are stored per :class:`FamilyMember`.
* **Admin permissions** scope what internal staff may do across tenants. They
  are stored as rows (``admin_roles`` -> ``admin_permissions``) so a deployment
  can adjust them without a code change.

Checks always go through :func:`family_member_can` / :func:`admin_can`; no
module compares role-name strings inline.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Final


# ---------------------------------------------------------------------------
# Family (tenant-scoped) permissions
# ---------------------------------------------------------------------------
class FamilyPermission(StrEnum):
    FAMILY_READ = "family.read"
    FAMILY_UPDATE = "family.update"
    MEMBERS_MANAGE = "family.members.manage"
    CHILDREN_READ = "children.read"
    CHILDREN_MANAGE = "children.manage"
    DEVICES_READ = "devices.read"
    DEVICES_MANAGE = "devices.manage"
    PAIRING_MANAGE = "pairing.manage"
    POLICIES_READ = "policies.read"
    POLICIES_MANAGE = "policies.manage"
    COMMANDS_ISSUE = "commands.issue"
    USAGE_READ = "usage.read"
    ALERTS_READ = "alerts.read"
    ALERTS_MANAGE = "alerts.manage"
    LOCATION_READ = "location.read"
    BILLING_MANAGE = "billing.manage"
    PRIVACY_MANAGE = "privacy.manage"


#: Everything an owner holds implicitly.
FAMILY_OWNER_PERMISSIONS: Final[frozenset[FamilyPermission]] = frozenset(FamilyPermission)

#: Default grant for an invited co-guardian: full child-care control, but no
#: ability to restructure the family, change billing, or read location.
FAMILY_GUARDIAN_DEFAULT_PERMISSIONS: Final[tuple[FamilyPermission, ...]] = (
    FamilyPermission.FAMILY_READ,
    FamilyPermission.CHILDREN_READ,
    FamilyPermission.CHILDREN_MANAGE,
    FamilyPermission.DEVICES_READ,
    FamilyPermission.DEVICES_MANAGE,
    FamilyPermission.PAIRING_MANAGE,
    FamilyPermission.POLICIES_READ,
    FamilyPermission.POLICIES_MANAGE,
    FamilyPermission.COMMANDS_ISSUE,
    FamilyPermission.USAGE_READ,
    FamilyPermission.ALERTS_READ,
    FamilyPermission.ALERTS_MANAGE,
)

#: Read-only co-guardian (e.g. a grandparent who should see status only).
FAMILY_VIEWER_PERMISSIONS: Final[tuple[FamilyPermission, ...]] = (
    FamilyPermission.FAMILY_READ,
    FamilyPermission.CHILDREN_READ,
    FamilyPermission.DEVICES_READ,
    FamilyPermission.POLICIES_READ,
    FamilyPermission.USAGE_READ,
    FamilyPermission.ALERTS_READ,
)

#: Permissions that may never be delegated through an invitation.
#:
#: ``LOCATION_READ`` is in this set deliberately: reading a child's location is
#: the most invasive capability the product has, so it stays an owner-level
#: decision rather than something that arrives bundled with "help me manage the
#: kids". An invitation requesting it has it stripped before storage.
NON_DELEGATABLE_FAMILY_PERMISSIONS: Final[frozenset[FamilyPermission]] = frozenset(
    {
        FamilyPermission.FAMILY_UPDATE,
        FamilyPermission.MEMBERS_MANAGE,
        FamilyPermission.LOCATION_READ,
        FamilyPermission.BILLING_MANAGE,
        FamilyPermission.PRIVACY_MANAGE,
    }
)


def normalize_family_permissions(values: Iterable[str] | None) -> list[str]:
    """Keep only recognised permission strings, de-duplicated and sorted."""
    if not values:
        return []
    known = {perm.value for perm in FamilyPermission}
    return sorted({value for value in values if value in known})


def family_member_can(
    *,
    is_owner: bool,
    granted: Iterable[str] | None,
    required: FamilyPermission,
) -> bool:
    if is_owner:
        return True
    return required.value in set(granted or ())


# ---------------------------------------------------------------------------
# Admin permissions
# ---------------------------------------------------------------------------
class AdminPermission(StrEnum):
    OVERVIEW_READ = "overview.read"

    USERS_READ = "users.read"
    USERS_STATUS_WRITE = "users.status.write"
    USERS_PII_READ = "users.pii.read"

    FAMILIES_READ = "families.read"
    DEVICES_READ = "devices.read"
    DEVICES_REVOKE = "devices.revoke"

    # Deliberately separate from devices.read: usage and location are child
    # telemetry and must not ride along with ordinary support access.
    CHILD_USAGE_READ = "child_usage.read"
    CHILD_LOCATION_READ = "child_location.read"

    SUPPORT_TICKETS_READ = "support_tickets.read"
    SUPPORT_TICKETS_WRITE = "support_tickets.write"

    ABUSE_REPORTS_READ = "abuse_reports.read"
    ABUSE_REPORTS_WRITE = "abuse_reports.write"

    SUBSCRIPTIONS_READ = "subscriptions.read"
    SUBSCRIPTIONS_WRITE = "subscriptions.write"

    AUDIT_LOGS_READ = "audit_logs.read"
    ANALYTICS_READ = "analytics.read"

    PLATFORM_CONFIG_WRITE = "platform_config.write"
    ADMIN_USERS_MANAGE = "admin_users.manage"
    PRIVACY_REQUESTS_READ = "privacy_requests.read"
    PRIVACY_REQUESTS_WRITE = "privacy_requests.write"


class AdminRoleName(StrEnum):
    super_admin = "super_admin"
    support_admin = "support_admin"
    trust_safety_admin = "trust_safety_admin"
    billing_admin = "billing_admin"
    read_only_analyst = "read_only_analyst"


ADMIN_ROLE_DESCRIPTIONS: Final[dict[AdminRoleName, str]] = {
    AdminRoleName.super_admin: "Full platform access, including admin user management.",
    AdminRoleName.support_admin: "Account and device metadata plus support ticket handling.",
    AdminRoleName.trust_safety_admin: "Abuse report review and documented safety actions.",
    AdminRoleName.billing_admin: "Subscription and billing records only.",
    AdminRoleName.read_only_analyst: "Aggregated analytics; no per-account records.",
}

#: Default role -> permission mapping, seeded into the database by
#: ``app/scripts/seed_admin_rbac.py``. Rows are authoritative at runtime.
DEFAULT_ADMIN_ROLE_PERMISSIONS: Final[dict[AdminRoleName, tuple[AdminPermission, ...]]] = {
    AdminRoleName.super_admin: tuple(AdminPermission),
    AdminRoleName.support_admin: (
        AdminPermission.OVERVIEW_READ,
        AdminPermission.USERS_READ,
        AdminPermission.FAMILIES_READ,
        AdminPermission.DEVICES_READ,
        AdminPermission.SUPPORT_TICKETS_READ,
        AdminPermission.SUPPORT_TICKETS_WRITE,
        AdminPermission.SUBSCRIPTIONS_READ,
    ),
    AdminRoleName.trust_safety_admin: (
        AdminPermission.OVERVIEW_READ,
        AdminPermission.USERS_READ,
        AdminPermission.USERS_STATUS_WRITE,
        AdminPermission.FAMILIES_READ,
        AdminPermission.DEVICES_READ,
        AdminPermission.DEVICES_REVOKE,
        AdminPermission.ABUSE_REPORTS_READ,
        AdminPermission.ABUSE_REPORTS_WRITE,
        AdminPermission.SUPPORT_TICKETS_READ,
        AdminPermission.AUDIT_LOGS_READ,
    ),
    AdminRoleName.billing_admin: (
        AdminPermission.OVERVIEW_READ,
        AdminPermission.USERS_READ,
        AdminPermission.SUBSCRIPTIONS_READ,
        AdminPermission.SUBSCRIPTIONS_WRITE,
    ),
    AdminRoleName.read_only_analyst: (
        AdminPermission.OVERVIEW_READ,
        AdminPermission.ANALYTICS_READ,
    ),
}

#: Permissions that are never granted by default to any role other than
#: super_admin, and that must be assigned explicitly and audited.
SENSITIVE_ADMIN_PERMISSIONS: Final[frozenset[AdminPermission]] = frozenset(
    {
        AdminPermission.CHILD_LOCATION_READ,
        AdminPermission.CHILD_USAGE_READ,
        AdminPermission.USERS_PII_READ,
        AdminPermission.PLATFORM_CONFIG_WRITE,
        AdminPermission.ADMIN_USERS_MANAGE,
    }
)


def admin_can(granted: Iterable[str] | None, required: AdminPermission) -> bool:
    return required.value in set(granted or ())


def admin_permission_catalog() -> list[dict[str, str]]:
    return [
        {
            "key": perm.value,
            "sensitive": str(perm in SENSITIVE_ADMIN_PERMISSIONS).lower(),
        }
        for perm in AdminPermission
    ]


__all__ = [
    "ADMIN_ROLE_DESCRIPTIONS",
    "DEFAULT_ADMIN_ROLE_PERMISSIONS",
    "FAMILY_GUARDIAN_DEFAULT_PERMISSIONS",
    "FAMILY_OWNER_PERMISSIONS",
    "FAMILY_VIEWER_PERMISSIONS",
    "NON_DELEGATABLE_FAMILY_PERMISSIONS",
    "SENSITIVE_ADMIN_PERMISSIONS",
    "AdminPermission",
    "AdminRoleName",
    "FamilyPermission",
    "admin_can",
    "admin_permission_catalog",
    "family_member_can",
    "normalize_family_permissions",
]
