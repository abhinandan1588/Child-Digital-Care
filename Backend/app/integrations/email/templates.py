"""Transactional email bodies.

Links are built from ``FRONTEND_BASE_URL``. The token is in the URL, which is
why nothing in this module is ever logged and why the caller passes the token
in only at send time.
"""

from __future__ import annotations

from urllib.parse import quote

from app.core.config import settings
from app.integrations.email.base import EmailMessage


def _link(path: str, token: str) -> str:
    return f"{settings.frontend_base_url.rstrip('/')}{path}?token={quote(token)}"


def verification_email(to: str, display_name: str, token: str, expires_hours: int) -> EmailMessage:
    link = _link("/verify-email", token)
    return EmailMessage(
        to=to,
        subject=f"Verify your {settings.app_name} email address",
        text_body=(
            f"Hello {display_name},\n\n"
            "Confirm this email address to finish setting up your "
            f"{settings.app_name} account:\n\n{link}\n\n"
            f"The link expires in {expires_hours} hours and can be used once.\n\n"
            "If you did not create this account, you can ignore this message.\n"
        ),
        tags={"type": "email_verification"},
    )


def password_reset_email(
    to: str, display_name: str, token: str, expires_minutes: int
) -> EmailMessage:
    link = _link("/reset-password", token)
    return EmailMessage(
        to=to,
        subject=f"Reset your {settings.app_name} password",
        text_body=(
            f"Hello {display_name},\n\n"
            "Use this link to choose a new password:\n\n"
            f"{link}\n\n"
            f"The link expires in {expires_minutes} minutes and can be used once.\n\n"
            "If you did not request a password reset, no action is needed - your "
            "current password still works.\n"
        ),
        tags={"type": "password_reset"},
    )


def guardian_invitation_email(
    to: str, family_name: str, inviter_name: str, token: str, expires_hours: int
) -> EmailMessage:
    link = _link("/accept-invitation", token)
    return EmailMessage(
        to=to,
        subject=f"{inviter_name} invited you to help manage {family_name}",
        text_body=(
            f'{inviter_name} has invited you to join the family "{family_name}" on '
            f"{settings.app_name} as an additional guardian.\n\n"
            f"Accept the invitation:\n\n{link}\n\n"
            f"The invitation expires in {expires_hours} hours.\n\n"
            "You will need a Child Digital Care account with this email address.\n"
        ),
        tags={"type": "guardian_invitation"},
    )


def password_changed_email(to: str, display_name: str) -> EmailMessage:
    """Security notification. Carries no token, so it is safe to send widely."""
    return EmailMessage(
        to=to,
        subject=f"Your {settings.app_name} password was changed",
        text_body=(
            f"Hello {display_name},\n\n"
            "The password on your account was just changed. Other sessions were "
            "signed out.\n\n"
            "If this wasn't you, reset your password immediately and contact support.\n"
        ),
        tags={"type": "security"},
    )
