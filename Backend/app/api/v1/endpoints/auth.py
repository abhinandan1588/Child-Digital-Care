"""Parent authentication endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from app.api.deps import (
    ClientIp,
    CurrentParent,
    DbSession,
    UserAgent,
)
from app.core.config import settings
from app.core.rate_limit import RateLimit, check_rate_limit, hash_identifier
from app.core.response import ApiResponse, ok
from app.db.enums import AuditActorType
from app.schemas.auth import (
    ChangePasswordRequest,
    FamilyMembershipSummary,
    ForgotPasswordRequest,
    GenericMessageOut,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MeOut,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResetPasswordRequest,
    SessionOut,
    TokenPair,
    UserOut,
    VerifyEmailRequest,
)
from app.services import audit_service, auth_service, family_service, token_service
from app.services.audit_service import AuditAction

router = APIRouter(prefix="/auth", tags=["auth"])


def user_out(user) -> UserOut:  # noqa: ANN001
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        account_status=user.account_status,
        email_verified=user.is_email_verified,
        timezone=user.timezone,
        locale=user.locale,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.post(
    "/register",
    response_model=ApiResponse[RegisterResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a parent account",
    dependencies=[Depends(RateLimit("auth.register"))],
)
async def register(
    payload: RegisterRequest,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    """Register a parent account and send a verification email.

    The response is identical whether or not the address was already
    registered, so this endpoint cannot be used to enumerate accounts.
    """
    await check_rate_limit("auth.register", hash_identifier(str(payload.email)))

    result = await auth_service.register_user(
        session,
        email=str(payload.email),
        password=payload.password,
        display_name=payload.display_name,
        timezone=payload.timezone,
        locale=payload.locale,
        terms_version=payload.accepted_terms_version,
        privacy_version=payload.accepted_privacy_version,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # The raw token is surfaced only by the local console mail sink, so a
    # developer can finish the flow without an inbox.
    dev_token = (
        result.verification_token
        if settings.email_provider == "console" and not settings.is_production
        else None
    )
    return ok(
        RegisterResponse(
            user_id=result.user.id,
            email=result.user.email,
            account_status=result.user.account_status,
            email_verification_required=settings.require_email_verification,
            dev_verification_token=dev_token if not result.already_registered else None,
        ),
        message=(
            "Account created. Check your email to verify the address."
            if settings.require_email_verification
            else "Account created."
        ),
    )


@router.post(
    "/verify-email",
    response_model=ApiResponse[GenericMessageOut],
    summary="Verify an email address",
    dependencies=[Depends(RateLimit("auth.verify_email"))],
)
async def verify_email(
    payload: VerifyEmailRequest,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    await auth_service.verify_email(
        session, raw_token=payload.token, client_ip=client_ip, user_agent=user_agent
    )
    return ok(
        GenericMessageOut(detail="Email address verified."),
        message="Email address verified.",
    )


@router.post(
    "/verify-email/resend",
    response_model=ApiResponse[GenericMessageOut],
    summary="Resend the verification email",
    dependencies=[Depends(RateLimit("auth.verify_email"))],
)
async def resend_verification(principal: CurrentParent, session: DbSession) -> dict:
    await auth_service.resend_verification(session, principal.user)
    return ok(
        GenericMessageOut(detail="If the address still needs verifying, a new link was sent."),
        message="Request processed.",
    )


@router.post(
    "/login",
    response_model=ApiResponse[LoginResponse],
    summary="Sign in",
    dependencies=[Depends(RateLimit("auth.login.ip"))],
)
async def login(
    payload: LoginRequest,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    """Exchange credentials for an access/refresh token pair.

    Limited per IP *and* per hashed email. The per-account bucket is generous
    and never locks the account, so an attacker cannot deny a victim access by
    hammering their address.
    """
    await check_rate_limit("auth.login.account", hash_identifier(str(payload.email)))

    result = await auth_service.authenticate(
        session,
        email=str(payload.email),
        password=payload.password,
        device_label=payload.device_label,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return ok(
        LoginResponse(
            access_token=result.session.access_token,
            refresh_token=result.session.refresh_token,
            expires_in=result.session.expires_in,
            refresh_expires_in=result.session.refresh_expires_in,
            user=user_out(result.user),
        ),
        message="Signed in.",
    )


@router.post(
    "/refresh",
    response_model=ApiResponse[TokenPair],
    summary="Rotate a refresh token",
    dependencies=[Depends(RateLimit("auth.refresh"))],
)
async def refresh(
    payload: RefreshRequest,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    """Rotate the session.

    The presented token is consumed. Presenting it again revokes the whole
    token family (reuse detection) and returns ``REFRESH_TOKEN_REUSED``.
    """
    outcome = await token_service.rotate_user_session(
        session,
        raw_refresh_token=payload.refresh_token,
        user_agent=user_agent,
        ip_prefix=audit_service.ip_prefix(client_ip),
    )
    await audit_service.record(
        session,
        action=AuditAction.USER_TOKEN_REFRESHED,
        actor_type=AuditActorType.parent_user,
        actor_id=outcome.subject_id,
        target_type="user_session",
        target_id=outcome.issued.session_id,
        client_ip=client_ip,
    )
    return ok(
        TokenPair(
            access_token=outcome.issued.access_token,
            refresh_token=outcome.issued.refresh_token,
            expires_in=outcome.issued.expires_in,
            refresh_expires_in=outcome.issued.refresh_expires_in,
        ),
        message="Session refreshed.",
    )


@router.post(
    "/logout",
    response_model=ApiResponse[GenericMessageOut],
    summary="Sign out of this session",
)
async def logout(
    payload: LogoutRequest,
    principal: CurrentParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    revoked = False
    if payload.refresh_token:
        revoked = await token_service.revoke_user_session_by_token(
            session, raw_refresh_token=payload.refresh_token
        )
    elif principal.session_id:
        revoked = await token_service.revoke_user_session_by_id(
            session,
            user_id=principal.id,
            session_id=principal.session_id,
            reason="logout",
        )

    await audit_service.record(
        session,
        action=AuditAction.USER_LOGOUT,
        actor_type=AuditActorType.parent_user,
        actor_id=principal.id,
        target_type="user_session",
        target_id=principal.session_id,
        client_ip=client_ip,
        metadata={"revoked": revoked},
    )
    return ok(GenericMessageOut(detail="Signed out."), message="Signed out.")


@router.post(
    "/logout-all",
    response_model=ApiResponse[GenericMessageOut],
    summary="Sign out of every session",
)
async def logout_all(principal: CurrentParent, session: DbSession, client_ip: ClientIp) -> dict:
    count = await token_service.revoke_all_user_sessions(
        session, user_id=principal.id, reason="logout_all"
    )
    await audit_service.record(
        session,
        action=AuditAction.USER_LOGOUT_ALL,
        actor_type=AuditActorType.parent_user,
        actor_id=principal.id,
        target_type="user",
        target_id=principal.id,
        client_ip=client_ip,
        metadata={"sessions_revoked": count},
    )
    return ok(
        GenericMessageOut(detail=f"{count} session(s) signed out."),
        message="All sessions signed out.",
    )


@router.post(
    "/password/forgot",
    response_model=ApiResponse[GenericMessageOut],
    summary="Request a password reset",
    dependencies=[Depends(RateLimit("auth.password.forgot"))],
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    """Always reports success, whether or not the address exists."""
    await check_rate_limit("auth.password.forgot", hash_identifier(str(payload.email)))
    await auth_service.request_password_reset(
        session, email=str(payload.email), client_ip=client_ip, user_agent=user_agent
    )
    return ok(
        GenericMessageOut(
            detail="If an account exists for that address, a reset link has been sent."
        ),
        message="Request processed.",
    )


@router.post(
    "/password/reset",
    response_model=ApiResponse[GenericMessageOut],
    summary="Complete a password reset",
    dependencies=[Depends(RateLimit("auth.password.reset"))],
)
async def reset_password(
    payload: ResetPasswordRequest,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    """Sets a new password and signs out every existing session."""
    await auth_service.complete_password_reset(
        session,
        raw_token=payload.token,
        new_password=payload.new_password,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return ok(
        GenericMessageOut(detail="Password updated. Sign in with your new password."),
        message="Password updated.",
    )


@router.post(
    "/password/change",
    response_model=ApiResponse[GenericMessageOut],
    summary="Change the password",
)
async def change_password(
    payload: ChangePasswordRequest,
    principal: CurrentParent,
    session: DbSession,
    client_ip: ClientIp,
    user_agent: UserAgent,
) -> dict:
    revoked = await auth_service.change_password(
        session,
        user=principal.user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        revoke_other_sessions=payload.revoke_other_sessions,
        current_session_id=principal.session_id,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return ok(
        GenericMessageOut(detail=f"Password changed. {revoked} other session(s) were signed out."),
        message="Password changed.",
    )


@router.get(
    "/me",
    response_model=ApiResponse[MeOut],
    summary="The signed-in parent and their families",
)
async def me(principal: CurrentParent, session: DbSession) -> dict:
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    return ok(
        MeOut(
            user=user_out(principal.user),
            families=[
                FamilyMembershipSummary(
                    family_id=family.id,
                    family_name=family.name,
                    is_owner=member.is_owner,
                    permissions=list(member.permissions or []),
                    membership_status=member.membership_status.value,
                )
                for family, member in memberships
            ],
        )
    )


@router.get(
    "/sessions",
    response_model=ApiResponse[list[SessionOut]],
    summary="List active sessions",
)
async def list_sessions(principal: CurrentParent, session: DbSession) -> dict:
    rows = await auth_service.list_sessions(session, user_id=principal.id)
    return ok(
        [
            SessionOut(
                id=row.id,
                device_label=row.device_label,
                created_at=row.created_at,
                last_used_at=row.last_used_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                current=row.id == principal.session_id,
            )
            for row in rows
        ]
    )


@router.delete(
    "/sessions/{session_id}",
    response_model=ApiResponse[GenericMessageOut],
    summary="Revoke one session",
)
async def revoke_session(
    session_id: uuid.UUID,
    principal: CurrentParent,
    session: DbSession,
    client_ip: ClientIp,
) -> dict:
    """Scoped to the caller's own sessions, so one parent cannot sign another out."""
    revoked = await token_service.revoke_user_session_by_id(
        session, user_id=principal.id, session_id=session_id, reason="revoked_by_user"
    )
    await audit_service.record(
        session,
        action=AuditAction.USER_SESSION_REVOKED,
        actor_type=AuditActorType.parent_user,
        actor_id=principal.id,
        target_type="user_session",
        target_id=session_id,
        client_ip=client_ip,
        metadata={"revoked": revoked},
    )
    return ok(
        GenericMessageOut(detail="Session revoked." if revoked else "Session already inactive."),
        message="Request processed.",
    )
