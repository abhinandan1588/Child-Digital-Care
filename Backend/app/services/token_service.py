"""Refresh-session lifecycle for all three principal types.

One module owns rotation and reuse detection so the three principals cannot
drift apart. The rules are identical:

* The refresh token is opaque (256 bits) and only its SHA-256 hash is stored.
* Every use rotates it: the presented row is marked consumed and a new row is
  inserted in the same ``token_family_id``.
* Presenting an already-consumed or revoked token revokes **the entire family**
  and raises. That converts a stolen-token replay into a loud, contained event:
  the attacker and the victim both lose the session, and the audit log records it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal, cast

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import AppError, AuthenticationRequired, ErrorCode
from app.core.logging import get_logger
from app.core.security import (
    PrincipalType,
    create_access_token,
    generate_opaque_token,
    hash_opaque_token,
)
from app.db.models.admin import AdminSession
from app.db.models.device import DeviceSession
from app.db.models.identity import UserSession
from app.repositories.base import rowcount_of
from app.utils.time import utcnow

logger = get_logger(__name__)

SessionModel = UserSession | DeviceSession | AdminSession
PrincipalKind = Literal["user", "device", "admin"]


@dataclass(frozen=True, slots=True)
class IssuedSession:
    access_token: str
    refresh_token: str
    session_id: uuid.UUID
    expires_in: int
    refresh_expires_in: int


class RefreshTokenReused(AppError):
    status_code = 401
    code = ErrorCode.REFRESH_TOKEN_REUSED
    message = (
        "This session has been ended for your security because an old refresh token was "
        "presented. Please sign in again."
    )


def _refresh_days(kind: PrincipalKind) -> int:
    # Read from settings at call time so test overrides apply.
    return {
        "user": settings.refresh_token_expire_days,
        "device": settings.device_refresh_token_expire_days,
        "admin": settings.admin_refresh_token_expire_days,
    }[kind]


# ---------------------------------------------------------------------------
# Issue
# ---------------------------------------------------------------------------
async def issue_user_session(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    device_label: str | None = None,
    user_agent: str | None = None,
    ip_prefix: str | None = None,
    token_family_id: uuid.UUID | None = None,
    rotation_counter: int = 0,
) -> IssuedSession:
    raw_refresh = generate_opaque_token()
    family_id = token_family_id or uuid.uuid4()
    refresh_days = _refresh_days("user")
    row = UserSession(
        user_id=user_id,
        refresh_token_hash=hash_opaque_token(raw_refresh),
        token_family_id=family_id,
        rotation_counter=rotation_counter,
        device_label=device_label[:120] if device_label else None,
        user_agent=user_agent[:255] if user_agent else None,
        ip_prefix=ip_prefix,
        expires_at=utcnow() + timedelta(days=refresh_days),
    )
    session.add(row)
    await session.flush()

    access = create_access_token(
        subject=user_id,
        principal_type=PrincipalType.parent_user,
        session_id=row.id,
    )
    return IssuedSession(
        access_token=access.token,
        refresh_token=raw_refresh,
        session_id=row.id,
        expires_in=access.expires_in,
        refresh_expires_in=refresh_days * 86_400,
    )


async def issue_device_session(
    session: AsyncSession,
    *,
    device_id: uuid.UUID,
    family_id_claim: uuid.UUID,
    app_version: str | None = None,
    token_family_id: uuid.UUID | None = None,
    rotation_counter: int = 0,
) -> IssuedSession:
    raw_refresh = generate_opaque_token()
    family = token_family_id or uuid.uuid4()
    refresh_days = _refresh_days("device")
    row = DeviceSession(
        device_id=device_id,
        refresh_token_hash=hash_opaque_token(raw_refresh),
        token_family_id=family,
        rotation_counter=rotation_counter,
        app_version=app_version[:32] if app_version else None,
        expires_at=utcnow() + timedelta(days=refresh_days),
    )
    session.add(row)
    await session.flush()

    access = create_access_token(
        subject=device_id,
        principal_type=PrincipalType.child_device,
        session_id=row.id,
        family_id=family_id_claim,
        # Narrow scopes: a device token cannot be used for anything else even
        # if a future endpoint forgets its own check.
        scopes=(
            "device:self",
            "device:commands",
            "device:policies",
            "device:telemetry",
        ),
    )
    return IssuedSession(
        access_token=access.token,
        refresh_token=raw_refresh,
        session_id=row.id,
        expires_in=access.expires_in,
        refresh_expires_in=refresh_days * 86_400,
    )


async def issue_admin_session(
    session: AsyncSession,
    *,
    admin_user_id: uuid.UUID,
    mfa_satisfied: bool,
    user_agent: str | None = None,
    ip_prefix: str | None = None,
    token_family_id: uuid.UUID | None = None,
    rotation_counter: int = 0,
) -> IssuedSession:
    raw_refresh = generate_opaque_token()
    family = token_family_id or uuid.uuid4()
    refresh_days = _refresh_days("admin")
    row = AdminSession(
        admin_user_id=admin_user_id,
        refresh_token_hash=hash_opaque_token(raw_refresh),
        token_family_id=family,
        rotation_counter=rotation_counter,
        mfa_satisfied=mfa_satisfied,
        user_agent=user_agent[:255] if user_agent else None,
        ip_prefix=ip_prefix,
        expires_at=utcnow() + timedelta(days=refresh_days),
    )
    session.add(row)
    await session.flush()

    access = create_access_token(
        subject=admin_user_id,
        principal_type=PrincipalType.admin_user,
        session_id=row.id,
        extra_claims={"mfa": mfa_satisfied},
    )
    return IssuedSession(
        access_token=access.token,
        refresh_token=raw_refresh,
        session_id=row.id,
        expires_in=access.expires_in,
        refresh_expires_in=refresh_days * 86_400,
    )


# ---------------------------------------------------------------------------
# Rotate
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class RotationOutcome:
    issued: IssuedSession
    previous_session_id: uuid.UUID
    subject_id: uuid.UUID


async def _load_session_by_token(
    session: AsyncSession, model: type[SessionModel], raw_token: str
) -> SessionModel | None:
    token_hash = hash_opaque_token(raw_token)
    result = await session.execute(
        select(model).where(model.refresh_token_hash == token_hash).limit(1)
    )
    return cast("SessionModel | None", result.scalars().first())


async def _revoke_family(
    session: AsyncSession, model: type[SessionModel], token_family_id: uuid.UUID, reason: str
) -> int:
    result = await session.execute(
        update(model)
        .where(model.token_family_id == token_family_id, model.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoked_reason=reason)
    )
    return rowcount_of(result)


async def rotate_user_session(
    session: AsyncSession,
    *,
    raw_refresh_token: str,
    user_agent: str | None = None,
    ip_prefix: str | None = None,
) -> RotationOutcome:
    row = await _load_session_by_token(session, UserSession, raw_refresh_token)
    return await _rotate(
        session,
        kind="user",
        model=UserSession,
        row=row,
        issue=lambda r: issue_user_session(
            session,
            user_id=r.user_id,
            device_label=r.device_label,
            user_agent=user_agent or r.user_agent,
            ip_prefix=ip_prefix or r.ip_prefix,
            token_family_id=r.token_family_id,
            rotation_counter=r.rotation_counter + 1,
        ),
        subject_of=lambda r: r.user_id,
    )


async def rotate_device_session(
    session: AsyncSession,
    *,
    raw_refresh_token: str,
    family_id_claim: uuid.UUID,
    app_version: str | None = None,
) -> RotationOutcome:
    row = await _load_session_by_token(session, DeviceSession, raw_refresh_token)
    return await _rotate(
        session,
        kind="device",
        model=DeviceSession,
        row=row,
        issue=lambda r: issue_device_session(
            session,
            device_id=r.device_id,
            family_id_claim=family_id_claim,
            app_version=app_version or r.app_version,
            token_family_id=r.token_family_id,
            rotation_counter=r.rotation_counter + 1,
        ),
        subject_of=lambda r: r.device_id,
    )


async def rotate_admin_session(
    session: AsyncSession,
    *,
    raw_refresh_token: str,
    user_agent: str | None = None,
    ip_prefix: str | None = None,
) -> RotationOutcome:
    row = await _load_session_by_token(session, AdminSession, raw_refresh_token)
    return await _rotate(
        session,
        kind="admin",
        model=AdminSession,
        row=row,
        issue=lambda r: issue_admin_session(
            session,
            admin_user_id=r.admin_user_id,
            mfa_satisfied=r.mfa_satisfied,
            user_agent=user_agent or r.user_agent,
            ip_prefix=ip_prefix or r.ip_prefix,
            token_family_id=r.token_family_id,
            rotation_counter=r.rotation_counter + 1,
        ),
        subject_of=lambda r: r.admin_user_id,
    )


async def _rotate(
    session: AsyncSession,
    *,
    kind: PrincipalKind,
    model: type[SessionModel],
    row: SessionModel | None,
    issue,  # noqa: ANN001 - callable returning IssuedSession
    subject_of,  # noqa: ANN001
) -> RotationOutcome:
    if row is None:
        # Unknown token: no family to revoke, and no information to leak about
        # whether it ever existed.
        raise AuthenticationRequired(
            "The refresh token is not valid.", code=ErrorCode.TOKEN_INVALID
        )

    now = utcnow()

    if row.revoked_at is not None:
        # Either a replay of a rotated token or use of a deliberately revoked
        # session. Both warrant killing the family.
        revoked = await _revoke_family(session, model, row.token_family_id, "reuse_detected")
        # Commit before raising. The request-scoped session rolls back on an
        # exception, and a security response that disappears because the
        # request failed is no response at all.
        await session.commit()
        logger.warning(
            "refresh_token_reuse_detected",
            principal_kind=kind,
            token_family_id=str(row.token_family_id),
            sessions_revoked=revoked,
        )
        raise RefreshTokenReused(log_context={"principal_kind": kind})

    if row.expires_at <= now:
        row.revoked_at = now
        row.revoked_reason = "expired"
        await session.commit()
        raise AuthenticationRequired(
            "The refresh token has expired. Please sign in again.",
            code=ErrorCode.TOKEN_EXPIRED,
        )

    # Consume the presented token, then mint its successor.
    row.revoked_at = now
    row.revoked_reason = "rotated"
    row.last_used_at = now
    await session.flush()

    issued: IssuedSession = await issue(row)
    return RotationOutcome(issued=issued, previous_session_id=row.id, subject_id=subject_of(row))


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------
async def revoke_user_session_by_token(
    session: AsyncSession, *, raw_refresh_token: str, reason: str = "logout"
) -> bool:
    row = await _load_session_by_token(session, UserSession, raw_refresh_token)
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = utcnow()
    row.revoked_reason = reason
    return True


async def revoke_user_session_by_id(
    session: AsyncSession, *, user_id: uuid.UUID, session_id: uuid.UUID, reason: str = "revoked"
) -> bool:
    """Scoped by ``user_id`` so one parent cannot revoke another's session."""
    result = await session.execute(
        update(UserSession)
        .where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow(), revoked_reason=reason)
    )
    return rowcount_of(result) > 0


async def revoke_all_user_sessions(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    reason: str = "logout_all",
    keep_session_id: uuid.UUID | None = None,
) -> int:
    statement = update(UserSession).where(
        UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
    )
    if keep_session_id is not None:
        statement = statement.where(UserSession.id != keep_session_id)
    result = await session.execute(statement.values(revoked_at=utcnow(), revoked_reason=reason))
    return rowcount_of(result)


async def revoke_all_device_sessions(
    session: AsyncSession, *, device_id: uuid.UUID, reason: str = "device_revoked"
) -> int:
    result = await session.execute(
        update(DeviceSession)
        .where(DeviceSession.device_id == device_id, DeviceSession.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoked_reason=reason)
    )
    return rowcount_of(result)


async def revoke_device_session_by_token(
    session: AsyncSession, *, raw_refresh_token: str, reason: str = "device_logout"
) -> bool:
    row = await _load_session_by_token(session, DeviceSession, raw_refresh_token)
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = utcnow()
    row.revoked_reason = reason
    return True


async def revoke_all_admin_sessions(
    session: AsyncSession, *, admin_user_id: uuid.UUID, reason: str = "logout_all"
) -> int:
    result = await session.execute(
        update(AdminSession)
        .where(AdminSession.admin_user_id == admin_user_id, AdminSession.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoked_reason=reason)
    )
    return rowcount_of(result)


async def revoke_admin_session_by_token(
    session: AsyncSession, *, raw_refresh_token: str, reason: str = "logout"
) -> bool:
    row = await _load_session_by_token(session, AdminSession, raw_refresh_token)
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = utcnow()
    row.revoked_reason = reason
    return True


async def session_is_live(
    session: AsyncSession, model: type[SessionModel], session_id: uuid.UUID
) -> bool:
    """Used on every authenticated request so revocation takes effect at once.

    Access tokens are short-lived, but "short-lived" is not "revoked"; checking
    the session row is what makes logout and device revocation immediate.
    """
    row = cast("SessionModel | None", await session.get(model, session_id))
    if row is None or row.revoked_at is not None:
        return False
    return row.expires_at > utcnow()


async def touch_session(
    session: AsyncSession, model: type[SessionModel], session_id: uuid.UUID
) -> None:
    await session.execute(update(model).where(model.id == session_id).values(last_used_at=utcnow()))


__all__ = [
    "IssuedSession",
    "RefreshTokenReused",
    "RotationOutcome",
    "issue_admin_session",
    "issue_device_session",
    "issue_user_session",
    "revoke_admin_session_by_token",
    "revoke_all_admin_sessions",
    "revoke_all_device_sessions",
    "revoke_all_user_sessions",
    "revoke_device_session_by_token",
    "revoke_user_session_by_id",
    "revoke_user_session_by_token",
    "rotate_admin_session",
    "rotate_device_session",
    "rotate_user_session",
    "session_is_live",
    "touch_session",
]
