"""Permission evaluation for family and admin principals."""

from __future__ import annotations

import pytest

from app.core.permissions import (
    DEFAULT_ADMIN_ROLE_PERMISSIONS,
    FAMILY_GUARDIAN_DEFAULT_PERMISSIONS,
    NON_DELEGATABLE_FAMILY_PERMISSIONS,
    SENSITIVE_ADMIN_PERMISSIONS,
    AdminPermission,
    AdminRoleName,
    FamilyPermission,
    admin_can,
    family_member_can,
    normalize_family_permissions,
)
from app.services.family_service import filter_delegatable_permissions

pytestmark = pytest.mark.unit


class TestFamilyPermissions:
    def test_owner_holds_every_permission_implicitly(self) -> None:
        for permission in FamilyPermission:
            assert family_member_can(is_owner=True, granted=[], required=permission)

    def test_non_owner_needs_an_explicit_grant(self) -> None:
        granted = [FamilyPermission.CHILDREN_READ.value]
        assert family_member_can(
            is_owner=False, granted=granted, required=FamilyPermission.CHILDREN_READ
        )
        assert not family_member_can(
            is_owner=False, granted=granted, required=FamilyPermission.CHILDREN_MANAGE
        )

    def test_unknown_permission_strings_are_discarded(self) -> None:
        cleaned = normalize_family_permissions(
            ["children.read", "not.a.permission", "*", "children.read"]
        )
        assert cleaned == ["children.read"]

    def test_default_guardian_grant_excludes_location(self) -> None:
        """Reading a child's location needs a deliberate grant."""
        assert FamilyPermission.LOCATION_READ not in FAMILY_GUARDIAN_DEFAULT_PERMISSIONS

    def test_invitation_cannot_delegate_restructuring_or_billing(self) -> None:
        requested = [perm.value for perm in FamilyPermission]
        delegated = set(filter_delegatable_permissions(requested))
        for blocked in NON_DELEGATABLE_FAMILY_PERMISSIONS:
            assert blocked.value not in delegated

    def test_invitation_defaults_when_nothing_requested(self) -> None:
        delegated = filter_delegatable_permissions(None)
        assert "children.manage" in delegated
        assert "family.members.manage" not in delegated


class TestAdminPermissions:
    def test_admin_can_requires_exact_permission(self) -> None:
        granted = {AdminPermission.USERS_READ.value}
        assert admin_can(granted, AdminPermission.USERS_READ)
        assert not admin_can(granted, AdminPermission.USERS_STATUS_WRITE)
        assert not admin_can(None, AdminPermission.USERS_READ)

    def test_support_admin_cannot_read_child_telemetry(self) -> None:
        """Support access must not quietly include a child's usage or location."""
        support = set(DEFAULT_ADMIN_ROLE_PERMISSIONS[AdminRoleName.support_admin])
        assert AdminPermission.CHILD_LOCATION_READ not in support
        assert AdminPermission.CHILD_USAGE_READ not in support

    def test_billing_admin_sees_only_billing_and_identity(self) -> None:
        billing = set(DEFAULT_ADMIN_ROLE_PERMISSIONS[AdminRoleName.billing_admin])
        assert AdminPermission.SUBSCRIPTIONS_WRITE in billing
        assert AdminPermission.DEVICES_READ not in billing
        assert AdminPermission.CHILD_USAGE_READ not in billing

    def test_read_only_analyst_sees_no_per_account_records(self) -> None:
        analyst = set(DEFAULT_ADMIN_ROLE_PERMISSIONS[AdminRoleName.read_only_analyst])
        assert analyst == {AdminPermission.OVERVIEW_READ, AdminPermission.ANALYTICS_READ}

    def test_only_super_admin_holds_sensitive_permissions_by_default(self) -> None:
        for role, permissions in DEFAULT_ADMIN_ROLE_PERMISSIONS.items():
            if role is AdminRoleName.super_admin:
                continue
            assert not (SENSITIVE_ADMIN_PERMISSIONS & set(permissions)), role

    def test_suspension_is_not_a_support_capability(self) -> None:
        support = set(DEFAULT_ADMIN_ROLE_PERMISSIONS[AdminRoleName.support_admin])
        assert AdminPermission.USERS_STATUS_WRITE not in support
