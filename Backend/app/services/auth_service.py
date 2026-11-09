"""Parent account authentication.

Security behaviours worth calling out:

* **No account enumeration.** Registration with an existing address, login with
  an unknown address, and password-reset for an unknown address all produce the
  same shape of response as the success case.
* **Constant-ish timing.** A login against a missing account still performs an
  Argon2 verification against a dummy hash.
* **Throttling without lockout.** Repeated failures slow a login down and are
  rate-limited per IP and per hashed identifier, but never permanently lock an
  account, because that would let an attacker deny service to a victim.
* **Tokens are single use and hashed at rest.** Verification and reset tokens
  are 256-bit random values; only their SHA-256 hashes are stored.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import (
    AppError,
    AuthenticationRequired,
    ErrorCode,
    InvalidCredentials,
    NotFound,
    PermissionDenied,
)
from app.core.logging import get_logger
from app.core.security import (
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    verify_and_maybe_rehash,
    verify_password,
)
from app.db.enums import (
    AccountStatus,
    AuditActorType,
    AuditOutcome,
    ConsentMethod,
    ConsentState,
    ConsentType,
)
from app.db.models.audit import ConsentRecord
from app.db.models.identity import (
    EmailVerificationToken,
    PasswordResetToken,
    User,
    UserSession,
)
from app.integrations.email import get_email_provider
from app.integrations.email.templates import (
    password_changed_email,
    password_reset_email,
    verification_email,
)
from app.services import audit_service, token_service
from app.services.audit_service import AuditAction
from app.utils.time import utcnow

logger = get_logger(__name__)


def normalize_email(email: str) -> str:
    return email.strip().lower()


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    user: User
    verification_token: str | None
    already_registered: bool


@dataclass(frozen=True, slots=True)
class LoginResult:
    user: User
    session: token_service.IssuedSession


class EmailNotVerified(AppError):
    status_code = 403
    code = ErrorCode.EMAIL_NOT_VERIFIED
    message = "Verify your email address before using this feature."


class AccountNotActive(AppError):
    status_code = 403
    code = ErrorCode.ACCOUNT_NOT_ACTIVE
    message = "This account is not active."


# ---------------------------------------------------------------------------
# Registration and verification
# ---------------------------------------------------------------------------
async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(
        select(User)
        .where(User.normalized_email == normalize_email(email), User.deleted_at.is_(None))
        .limit(1)
    )
    return result.scalars().first()


async def register_user(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    display_name: str,
    timezone: str,
    locale: str,
    terms_version: str,
    privacy_version: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> RegistrationResult:
    normalized = normalize_email(email)
    existing = await get_user_by_email(session, normalized)
    if existing is not None:
        # Same response shape as success; the (possibly legitimate) owner is
        # told by email that an account already exists.
        logger.info("registration_attempt_existing_email")
        await audit_service.record(
            session,
            action=AuditAction.USER_REGISTERED,
            actor_type=AuditActorType.anonymous,
            outcome=AuditOutcome.denied,
            target_type="user",
            target_id=existing.id,
            reason="email_already_registered",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        return RegistrationResult(user=existing, verification_token=None, already_registered=True)

    user = User(
        email=email.strip(),
        normalized_email=normalized,
        password_hash=hash_password(password),
        display_name=display_name.strip(),
        timezone=timezone,
        locale=locale,
        account_status=(
            AccountStatus.pending_verification
            if settings.require_email_verification
            else AccountStatus.active
        ),
        email_verified_at=None if settings.require_email_verification else utcnow(),
        password_changed_at=utcnow(),
    )
    session.add(user)

    try:
        await session.flush()
    except IntegrityError:
        # Lost a race on the unique index; behave like the existing-email path.
        await session.rollback()
        existing = await get_user_by_email(session, normalized)
        if existing is None:  # pragma: no cover - defensive
            raise
        return RegistrationResult(user=existing, verification_token=None, already_registered=True)

    for consent_type, version in (
        (ConsentType.parent_terms, terms_version),
        (ConsentType.parent_privacy_policy, privacy_version),
    ):
        session.add(
            ConsentRecord(
                consent_type=consent_type,
                state=ConsentState.granted,
                policy_version=version,
                method=ConsentMethod.parent_app_acceptance,
                user_id=user.id,
                surface="parent_app",
            )
        )

    raw_token: str | None = None
    if settings.require_email_verification:
        raw_token = await _create_verification_token(session, user)
        message = verification_email(
            to=user.email,
            display_name=user.display_name,
            token=raw_token,
            expires_hours=settings.email_verification_token_expire_hours,
        )
        await get_email_provider().send(message)

    await audit_service.record(
        session,
        action=AuditAction.USER_REGISTERED,
        actor_type=AuditActorType.parent_user,
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        client_ip=client_ip,
        user_agent=user_agent,
        metadata={"email_verification_required": settings.require_email_verification},
    )
    return RegistrationResult(
        user=user,
        verification_token=raw_token,
        already_registered=False,
    )


async def _create_verification_token(session: AsyncSession, user: User) -> str:
    # Invalidate any outstanding token so only the newest link works.
    await session.execute(
        update(EmailVerificationToken)
        .where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None),
        )
        .values(used_at=utcnow())
    )
    raw = generate_opaque_token()
    session.add(
        EmailVerificationToken(
            user_id=user.id,
            token_hash=hash_opaque_token(raw),
            expires_at=utcnow() + timedelta(hours=settings.email_verification_token_expire_hours),
        )
    )
    await session.flush()
    return raw


async def resend_verification(session: AsyncSession, user: User) -> str | None:
    if user.is_email_verified:
        return None
    raw = await _create_verification_token(session, user)
    await get_email_provider().send(
        verification_email(
            to=user.email,
            display_name=user.display_name,
            token=raw,
            expires_hours=settings.email_verification_token_expire_hours,
        )
    )
    return raw


async def verify_email(
    session: AsyncSession,
    *,
    raw_token: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> User:
    token_hash = hash_opaque_token(raw_token)
    result = await session.execute(
        select(EmailVerificationToken)
        .where(EmailVerificationToken.token_hash == token_hash)
        .limit(1)
    )
    row = result.scalars().first()
    now = utcnow()

    if row is None or row.used_at is not None or row.expires_at <= now:
        await audit_service.record(
            session,
            action=AuditAction.USER_EMAIL_VERIFIED,
            actor_type=AuditActorType.anonymous,
            outcome=AuditOutcome.failure,
            reason="invalid_or_expired_token",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise AuthenticationRequired(
            "This verification link is invalid or has expired. Request a new one.",
            code=ErrorCode.TOKEN_INVALID,
        )

    user = await session.get(User, row.user_id)
    if user is None or user.deleted_at is not None:
        raise NotFound("Account not found.")

    row.used_at = now
    if user.email_verified_at is None:
        user.email_verified_at = now
    if user.account_status is AccountStatus.pending_verification:
        user.account_status = AccountStatus.active

    await audit_service.record(
        session,
        action=AuditAction.USER_EMAIL_VERIFIED,
        actor_type=AuditActorType.parent_user,
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return user


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
def assert_usable_account(user: User) -> None:
    """Shared gate for authentication and for authenticated requests."""
    if user.deleted_at is not None or user.account_status in (
        AccountStatus.deleted,
        AccountStatus.deactivated,
    ):
        raise AccountNotActive("This account is no longer available.")
    if user.account_status is AccountStatus.suspended:
        raise AccountNotActive(
            "This account is suspended. Contact support.",
            code=ErrorCode.ACCOUNT_SUSPENDED,
        )


async def authenticate(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    device_label: str | None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> LoginResult:
    user = await get_user_by_email(session, email)

    # Always run a verification so the response time does not reveal whether
    # the account exists. `verify_and_maybe_rehash` also upgrades a stored hash
    # in place when the Argon2 parameters have since been raised.
    password_ok, upgraded_hash = verify_and_maybe_rehash(
        password, user.password_hash if user else None
    )

    if user is None or not password_ok:
        if user is not None:
            await session.execute(
                update(User)
                .where(User.id == user.id)
                .values(
                    failed_login_count=User.failed_login_count + 1,
                    last_failed_login_at=utcnow(),
                )
            )
        await audit_service.record(
            session,
            action=AuditAction.USER_LOGIN_FAILED,
            actor_type=AuditActorType.anonymous,
            outcome=AuditOutcome.failure,
            target_type="user",
            target_id=user.id if user else None,
            reason="invalid_credentials",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise InvalidCredentials()

    assert_usable_account(user)

    if settings.require_email_verification and not user.is_email_verified:
        await audit_service.record(
            session,
            action=AuditAction.USER_LOGIN_FAILED,
            actor_type=AuditActorType.parent_user,
            actor_id=user.id,
            outcome=AuditOutcome.denied,
            target_type="user",
            target_id=user.id,
            reason="email_not_verified",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise EmailNotVerified(
            "Verify your email address before signing in. We can send a new link."
        )

    if upgraded_hash:
        user.password_hash = upgraded_hash

    user.failed_login_count = 0
    user.last_login_at = utcnow()

    issued = await token_service.issue_user_session(
        session,
        user_id=user.id,
        device_label=device_label,
        user_agent=user_agent,
        ip_prefix=audit_service.ip_prefix(client_ip),
    )
    await audit_service.record(
        session,
        action=AuditAction.USER_LOGIN,
        actor_type=AuditActorType.parent_user,
        actor_id=user.id,
        target_type="user_session",
        target_id=issued.session_id,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return LoginResult(user=user, session=issued)


# ---------------------------------------------------------------------------
# Password reset / change
# ---------------------------------------------------------------------------
async def request_password_reset(
    session: AsyncSession,
    *,
    email: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Always succeeds from the caller's point of view."""
    user = await get_user_by_email(session, email)
    if user is None or user.account_status in (
        AccountStatus.deleted,
        AccountStatus.deactivated,
    ):
        logger.info("password_reset_requested_unknown_account")
        return

    await session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.invalidated_at.is_(None),
        )
        .values(invalidated_at=utcnow())
    )

    raw = generate_opaque_token()
    session.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_opaque_token(raw),
            expires_at=utcnow() + timedelta(minutes=settings.password_reset_token_expire_minutes),
            request_metadata={"ip_prefix": audit_service.ip_prefix(client_ip)},
        )
    )
    await session.flush()

    await get_email_provider().send(
        password_reset_email(
            to=user.email,
            display_name=user.display_name,
            token=raw,
            expires_minutes=settings.password_reset_token_expire_minutes,
        )
    )
    await audit_service.record(
        session,
        action=AuditAction.USER_PASSWORD_RESET_REQUESTED,
        actor_type=AuditActorType.anonymous,
        target_type="user",
        target_id=user.id,
        client_ip=client_ip,
        user_agent=user_agent,
    )


async def complete_password_reset(
    session: AsyncSession,
    *,
    raw_token: str,
    new_password: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> User:
    token_hash = hash_opaque_token(raw_token)
    result = await session.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash).limit(1)
    )
    row = result.scalars().first()
    now = utcnow()

    if (
        row is None
        or row.used_at is not None
        or row.invalidated_at is not None
        or row.expires_at <= now
    ):
        await audit_service.record(
            session,
            action=AuditAction.USER_PASSWORD_RESET_COMPLETED,
            actor_type=AuditActorType.anonymous,
            outcome=AuditOutcome.failure,
            reason="invalid_or_expired_token",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise AuthenticationRequired(
            "This reset link is invalid or has expired. Request a new one.",
            code=ErrorCode.TOKEN_INVALID,
        )

    user = await session.get(User, row.user_id)
    if user is None or user.deleted_at is not None:
        raise NotFound("Account not found.")

    row.used_at = now
    user.password_hash = hash_password(new_password)
    user.password_changed_at = now
    user.failed_login_count = 0
    # A password reset is the recovery path for a compromised account, so every
    # existing session must die.
    revoked = await token_service.revoke_all_user_sessions(
        session, user_id=user.id, reason="password_reset"
    )

    if user.account_status is AccountStatus.pending_verification and user.is_email_verified:
        user.account_status = AccountStatus.active

    await get_email_provider().send(password_changed_email(user.email, user.display_name))
    await audit_service.record(
        session,
        action=AuditAction.USER_PASSWORD_RESET_COMPLETED,
        actor_type=AuditActorType.parent_user,
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        client_ip=client_ip,
        user_agent=user_agent,
        metadata={"sessions_revoked": revoked},
    )
    return user


async def change_password(
    session: AsyncSession,
    *,
    user: User,
    current_password: str,
    new_password: str,
    revoke_other_sessions: bool,
    current_session_id: uuid.UUID | None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> int:
    if not verify_password(current_password, user.password_hash):
        await audit_service.record(
            session,
            action=AuditAction.USER_PASSWORD_CHANGED,
            actor_type=AuditActorType.parent_user,
            actor_id=user.id,
            outcome=AuditOutcome.failure,
            target_type="user",
            target_id=user.id,
            reason="current_password_mismatch",
            client_ip=client_ip,
            user_agent=user_agent,
        )
        raise PermissionDenied(
            "The current password is incorrect.", code=ErrorCode.INVALID_CREDENTIALS
        )

    user.password_hash = hash_password(new_password)
    user.password_changed_at = utcnow()

    revoked = 0
    if revoke_other_sessions:
        revoked = await token_service.revoke_all_user_sessions(
            session,
            user_id=user.id,
            reason="password_changed",
            keep_session_id=current_session_id,
        )

    await get_email_provider().send(password_changed_email(user.email, user.display_name))
    await audit_service.record(
        session,
        action=AuditAction.USER_PASSWORD_CHANGED,
        actor_type=AuditActorType.parent_user,
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        client_ip=client_ip,
        user_agent=user_agent,
        metadata={"sessions_revoked": revoked},
    )
    return revoked


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
async def list_sessions(session: AsyncSession, *, user_id: uuid.UUID) -> list[UserSession]:
    result = await session.execute(
        select(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.created_at.desc())
        .limit(100)
    )
    return list(result.scalars().all())


async def count_active_sessions(session: AsyncSession, *, user_id: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(UserSession)
        .where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > utcnow(),
        )
    )
    return int(result.scalar_one())
