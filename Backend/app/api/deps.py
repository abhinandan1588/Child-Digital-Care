"""Authentication and authorization dependencies.

Every protected route composes its guard from this module. The pattern is
always the same:

1. Verify the bearer token (signature, issuer, audience, expiry, principal type).
2. Confirm the backing **session row** is still live, so logout and device
   revocation take effect immediately rather than after the access token's TTL.
3. Load the principal from the database and confirm it is usable.
4. Resolve the resource *through* the principal's membership, never from a
   client-supplied scope.

Nothing here reads ``family_id``, ``role`` or ``device_id`` from a request body
or header.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Path, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import context
from app.core.config import settings
from app.core.errors import (
    AuthenticationRequired,
    ErrorCode,
    FeatureDisabled,
    InvalidToken,
    NotFound,
    PermissionDenied,
)
from app.core.logging import get_logger
from app.core.permissions import AdminPermission, FamilyPermission, admin_can
from app.core.rate_limit import client_ip
from app.core.security import (
    PrincipalType,
    TokenAudience,
    TokenClaims,
    decode_access_token,
)
from app.db.enums import AdminAccountStatus, DeviceStatus
from app.db.models.admin import (
    AdminPermissionRow,
    AdminRole,
    AdminRolePermission,
    AdminSession,
    AdminUser,
    AdminUserRole,
)
from app.db.models.device import Device, DeviceSession
from app.db.models.family import ChildProfile
from app.db.models.identity import User, UserSession
from app.db.session import get_db
from app.services import auth_service, family_service, token_service

logger = get_logger(__name__)

DbSession = Annotated[AsyncSession, Depends(get_db)]

# ``auto_error=False`` so a missing header produces our own envelope rather
# than FastAPI's default ``{"detail": ...}``.
_bearer = HTTPBearer(auto_error=False, scheme_name="BearerAuth")
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


def _require_bearer(credentials: HTTPAuthorizationCredentials | None) -> str:
    if credentials is None or not credentials.credentials:
        raise AuthenticationRequired()
    if credentials.scheme.lower() != "bearer":
        raise AuthenticationRequired("Use a Bearer token.", code=ErrorCode.TOKEN_INVALID)
    return credentials.credentials


# ---------------------------------------------------------------------------
# Request context helpers
# ---------------------------------------------------------------------------
def request_ip(request: Request) -> str:
    return client_ip(request)


def request_user_agent(request: Request) -> str | None:
    agent = request.headers.get("user-agent")
    return agent[:255] if agent else None


ClientIp = Annotated[str, Depends(request_ip)]
UserAgent = Annotated[str | None, Depends(request_user_agent)]


# ---------------------------------------------------------------------------
# Parent principal
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ParentPrincipal:
    user: User
    claims: TokenClaims

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    @property
    def session_id(self) -> uuid.UUID | None:
        return uuid.UUID(self.claims.session_id) if self.claims.session_id else None


async def get_current_parent(session: DbSession, credentials: BearerCredentials) -> ParentPrincipal:
    token = _require_bearer(credentials)
    claims = decode_access_token(
        token,
        expected_audience=TokenAudience.parent,
        expected_principal=PrincipalType.parent_user,
    )

    if claims.session_id:
        session_id = uuid.UUID(claims.session_id)
        if not await token_service.session_is_live(session, UserSession, session_id):
            raise AuthenticationRequired(
                "This session has been signed out.", code=ErrorCode.TOKEN_REVOKED
            )

    user = await session.get(User, claims.subject_uuid)
    if user is None or user.deleted_at is not None:
        raise AuthenticationRequired("Account not found.", code=ErrorCode.TOKEN_INVALID)

    auth_service.assert_usable_account(user)
    context.set_principal(f"parent_user:{user.id}")
    return ParentPrincipal(user=user, claims=claims)


CurrentParent = Annotated[ParentPrincipal, Depends(get_current_parent)]


async def get_verified_parent(principal: CurrentParent) -> ParentPrincipal:
    """Parent whose email is verified.

    Applied to family/device/policy mutations so an unverified address cannot
    be used to set up monitoring of a real device.
    """
    if settings.require_email_verification and not principal.user.is_email_verified:
        raise auth_service.EmailNotVerified()
    return principal


VerifiedParent = Annotated[ParentPrincipal, Depends(get_verified_parent)]


# ---------------------------------------------------------------------------
# Device principal
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class DevicePrincipal:
    device: Device
    claims: TokenClaims

    @property
    def id(self) -> uuid.UUID:
        return self.device.id

    @property
    def family_id(self) -> uuid.UUID:
        return self.device.family_id

    @property
    def child_profile_id(self) -> uuid.UUID:
        return self.device.child_profile_id

    @property
    def session_id(self) -> uuid.UUID | None:
        return uuid.UUID(self.claims.session_id) if self.claims.session_id else None

    def require_scope(self, scope: str) -> None:
        if scope not in self.claims.scopes:
            raise PermissionDenied(
                "This device credential does not carry the required scope.",
                code=ErrorCode.DEVICE_SCOPE_VIOLATION,
            )


async def get_current_device(session: DbSession, credentials: BearerCredentials) -> DevicePrincipal:
    token = _require_bearer(credentials)
    claims = decode_access_token(
        token,
        expected_audience=TokenAudience.device,
        expected_principal=PrincipalType.child_device,
    )

    device = await session.get(Device, claims.subject_uuid)
    if device is None:
        raise AuthenticationRequired("Device not found.", code=ErrorCode.TOKEN_INVALID)

    # Checked before the session, so an unlinked device gets the specific
    # DEVICE_REVOKED code it can act on rather than a generic token error.
    if device.device_status is DeviceStatus.revoked or device.revoked_at is not None:
        raise PermissionDenied(
            "This device has been unlinked by a parent.", code=ErrorCode.DEVICE_REVOKED
        )

    if claims.session_id:
        session_id = uuid.UUID(claims.session_id)
        if not await token_service.session_is_live(session, DeviceSession, session_id):
            raise AuthenticationRequired(
                "This device session has been revoked.", code=ErrorCode.TOKEN_REVOKED
            )

    # A token must not outlive a re-pairing: the family in the token has to
    # match the device's current family.
    if claims.family_id and str(device.family_id) != claims.family_id:
        raise InvalidToken("This credential no longer matches the device's family.")

    context.set_principal(f"child_device:{device.id}")
    return DevicePrincipal(device=device, claims=claims)


CurrentDevice = Annotated[DevicePrincipal, Depends(get_current_device)]


async def get_active_device(principal: CurrentDevice) -> DevicePrincipal:
    """Device that has completed registration.

    Pairing yields a credential immediately so the Child App can register, but
    telemetry and command endpoints require the registered state.
    """
    if principal.device.device_status not in (DeviceStatus.active, DeviceStatus.inactive):
        raise PermissionDenied(
            "Complete device registration before calling this endpoint.",
            code=ErrorCode.DEVICE_NOT_ACTIVE,
        )
    return principal


ActiveDevice = Annotated[DevicePrincipal, Depends(get_active_device)]


# ---------------------------------------------------------------------------
# Admin principal
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class AdminPrincipal:
    admin: AdminUser
    claims: TokenClaims
    roles: tuple[str, ...]
    permissions: frozenset[str]

    @property
    def id(self) -> uuid.UUID:
        return self.admin.id

    @property
    def session_id(self) -> uuid.UUID | None:
        return uuid.UUID(self.claims.session_id) if self.claims.session_id else None

    @property
    def mfa_satisfied(self) -> bool:
        return bool((self.claims.raw or {}).get("mfa"))

    def can(self, permission: AdminPermission) -> bool:
        return admin_can(self.permissions, permission)


async def load_admin_permissions(
    session: AsyncSession, admin_user_id: uuid.UUID
) -> tuple[tuple[str, ...], frozenset[str]]:
    """Resolve roles -> permissions from rows, not from role-name comparisons."""
    result = await session.execute(
        select(AdminRole.name, AdminPermissionRow.key)
        .join(AdminUserRole, AdminUserRole.role_id == AdminRole.id)
        .outerjoin(AdminRolePermission, AdminRolePermission.role_id == AdminRole.id)
        .outerjoin(AdminPermissionRow, AdminPermissionRow.id == AdminRolePermission.permission_id)
        .where(AdminUserRole.admin_user_id == admin_user_id)
    )
    roles: set[str] = set()
    permissions: set[str] = set()
    for role_name, permission_key in result.all():
        roles.add(role_name)
        if permission_key:
            permissions.add(permission_key)
    return tuple(sorted(roles)), frozenset(permissions)


async def get_current_admin(session: DbSession, credentials: BearerCredentials) -> AdminPrincipal:
    token = _require_bearer(credentials)
    claims = decode_access_token(
        token,
        expected_audience=TokenAudience.admin,
        expected_principal=PrincipalType.admin_user,
    )

    if claims.session_id:
        session_id = uuid.UUID(claims.session_id)
        if not await token_service.session_is_live(session, AdminSession, session_id):
            raise AuthenticationRequired(
                "This admin session has ended.", code=ErrorCode.TOKEN_REVOKED
            )

    admin = await session.get(AdminUser, claims.subject_uuid)
    if admin is None:
        raise AuthenticationRequired("Admin account not found.", code=ErrorCode.TOKEN_INVALID)
    if admin.status is not AdminAccountStatus.active:
        raise PermissionDenied(
            "This admin account is not active.", code=ErrorCode.ACCOUNT_NOT_ACTIVE
        )

    roles, permissions = await load_admin_permissions(session, admin.id)
    principal = AdminPrincipal(admin=admin, claims=claims, roles=roles, permissions=permissions)

    # In production MFA is enforced at the identity-provider/proxy layer; the
    # session still records whether it was satisfied, and we refuse a session
    # that claims otherwise for an account that requires it.
    if settings.is_production and admin.mfa_required and not principal.mfa_satisfied:
        raise PermissionDenied(
            "Multi-factor authentication is required for admin access.",
            code=ErrorCode.MFA_REQUIRED,
        )

    context.set_principal(f"admin_user:{admin.id}")
    return principal


CurrentAdmin = Annotated[AdminPrincipal, Depends(get_current_admin)]


def require_admin_permission(
    permission: AdminPermission,
) -> Callable[[AdminPrincipal], Awaitable[AdminPrincipal]]:
    """Dependency factory: ``Depends(require_admin_permission(AdminPermission.USERS_READ))``."""

    async def dependency(principal: CurrentAdmin) -> AdminPrincipal:
        if not principal.can(permission):
            logger.info(
                "admin_permission_denied",
                required=permission.value,
                admin_id=str(principal.id),
            )
            raise PermissionDenied(
                f"This action requires the '{permission.value}' admin permission."
            )
        return principal

    return dependency


# ---------------------------------------------------------------------------
# Family-scoped authorization
# ---------------------------------------------------------------------------
FamilyIdPath = Annotated[uuid.UUID, Path(description="Family identifier.")]
ChildIdPath = Annotated[uuid.UUID, Path(description="Child profile identifier.")]
DeviceIdPath = Annotated[uuid.UUID, Path(description="Device identifier.")]


def require_family_membership(
    permission: FamilyPermission,
) -> Callable[..., Awaitable[family_service.FamilyAccess]]:
    """Resolve ``{family_id}`` through the caller's membership and check a permission."""

    async def dependency(
        family_id: FamilyIdPath,
        session: DbSession,
        principal: CurrentParent,
    ) -> family_service.FamilyAccess:
        access = await family_service.resolve_family_access(
            session, user_id=principal.id, family_id=family_id
        )
        access.require(permission)
        return access

    return dependency


def require_child_access(
    permission: FamilyPermission,
) -> Callable[..., Awaitable[tuple[family_service.FamilyAccess, ChildProfile]]]:
    """Resolve ``{child_profile_id}`` -> its family -> the caller's permission."""

    async def dependency(
        child_profile_id: ChildIdPath,
        session: DbSession,
        principal: CurrentParent,
    ) -> tuple[family_service.FamilyAccess, ChildProfile]:
        access, child = await family_service.resolve_child_access(
            session, user_id=principal.id, child_profile_id=child_profile_id
        )
        access.require(permission)
        return access, child

    return dependency


def require_device_access(
    permission: FamilyPermission,
) -> Callable[..., Awaitable[tuple[family_service.FamilyAccess, Device]]]:
    """Resolve ``{device_id}`` -> its family -> the caller's permission."""

    async def dependency(
        device_id: DeviceIdPath,
        session: DbSession,
        principal: CurrentParent,
    ) -> tuple[family_service.FamilyAccess, Device]:
        access, device = await family_service.resolve_device_access(
            session, user_id=principal.id, device_id=device_id
        )
        access.require(permission)
        return access, device

    return dependency


# ---------------------------------------------------------------------------
# Feature gates
# ---------------------------------------------------------------------------
def require_feature(flag_name: str, human_name: str) -> Callable[[], None]:
    """Dependency factory that 403s a route when its feature flag is off."""

    def dependency() -> None:
        if not getattr(settings, flag_name, False):
            raise FeatureDisabled(
                f"{human_name} is not enabled for this deployment.",
            )

    return dependency


require_location_feature = require_feature("feature_location_enabled", "Location tracking")
require_website_restrictions_feature = require_feature(
    "feature_website_restrictions_enabled", "Website restrictions"
)
require_websocket_feature = require_feature("feature_websockets_enabled", "Realtime updates")


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
def idempotency_key(request: Request) -> str | None:
    key = request.headers.get("idempotency-key")
    if key is None:
        return None
    trimmed = key.strip()
    if not 8 <= len(trimmed) <= 128:
        raise PermissionDenied(
            "Idempotency-Key must be between 8 and 128 characters.",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=422,
        )
    return trimmed


IdempotencyKey = Annotated[str | None, Depends(idempotency_key)]


async def get_child_for_device(session: DbSession, principal: ActiveDevice) -> ChildProfile:
    child = await session.get(ChildProfile, principal.child_profile_id)
    if child is None:
        raise NotFound("Child profile not found.")
    return child
