"""Email providers: console sink (development), SMTP, and explicitly disabled.

Verification and reset links contain single-use secrets. The console provider
prints the body so a developer can complete the flow locally, and that is
exactly why ``EMAIL_PROVIDER=console`` is rejected when ``APP_ENV=production``
(see :class:`app.core.config.Settings`).
"""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage as MimeMessage

from app.core.config import settings
from app.core.logging import get_logger
from app.integrations.email.base import EmailMessage, EmailProvider, SendResult

logger = get_logger(__name__)


class ConsoleEmailProvider(EmailProvider):
    """Writes the message to stdout. Local development only."""

    name = "console"

    @property
    def configured(self) -> bool:
        return True

    async def send(self, message: EmailMessage) -> SendResult:
        # Intentionally printed rather than logged: the body may contain a
        # one-time link, and the logging pipeline must never carry those.
        print(  # noqa: T201
            "\n=== [dev email sink] ===\n"
            f"To: {message.to}\n"
            f"Subject: {message.subject}\n"
            f"{message.text_body}\n"
            "========================\n",
            flush=True,
        )
        logger.info("email_sent", provider=self.name, to_domain=_domain_of(message.to))
        return SendResult(sent=True, provider=self.name, provider_message_id="console")


class SmtpEmailProvider(EmailProvider):
    name = "smtp"

    @property
    def configured(self) -> bool:
        return bool(settings.smtp_host and settings.smtp_port)

    async def send(self, message: EmailMessage) -> SendResult:
        if not self.configured:
            return SendResult(sent=False, provider=self.name, error_code="NOT_CONFIGURED")
        try:
            # smtplib is blocking; keep the event loop free.
            await asyncio.to_thread(self._send_sync, message)
        except Exception as exc:  # noqa: BLE001 - provider errors must not 500 a request
            logger.warning(
                "email_send_failed",
                provider=self.name,
                to_domain=_domain_of(message.to),
                error=type(exc).__name__,
            )
            return SendResult(sent=False, provider=self.name, error_code="SMTP_ERROR")
        logger.info("email_sent", provider=self.name, to_domain=_domain_of(message.to))
        return SendResult(sent=True, provider=self.name)

    def _send_sync(self, message: EmailMessage) -> None:
        mime = MimeMessage()
        mime["From"] = settings.email_from
        mime["To"] = message.to
        mime["Subject"] = message.subject
        mime.set_content(message.text_body)
        if message.html_body:
            mime.add_alternative(message.html_body, subtype="html")

        host = settings.smtp_host or ""
        port = settings.smtp_port or 587
        with smtplib.SMTP(host, port, timeout=15) as client:
            if settings.smtp_use_tls:
                client.starttls()
            if settings.smtp_username and settings.smtp_password:
                client.login(settings.smtp_username, settings.smtp_password)
            client.send_message(mime)


class DisabledEmailProvider(EmailProvider):
    """Reports failure honestly instead of pretending a message was sent."""

    name = "disabled"

    @property
    def configured(self) -> bool:
        return False

    async def send(self, message: EmailMessage) -> SendResult:
        logger.warning(
            "email_provider_disabled",
            to_domain=_domain_of(message.to),
            subject_tag=message.tags.get("type"),
        )
        return SendResult(sent=False, provider=self.name, error_code="PROVIDER_DISABLED")


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1] if "@" in address else "unknown"


_provider: EmailProvider | None = None

PROVIDERS: dict[str, type[EmailProvider]] = {
    "console": ConsoleEmailProvider,
    "smtp": SmtpEmailProvider,
    "disabled": DisabledEmailProvider,
}


def get_email_provider() -> EmailProvider:
    global _provider
    if _provider is None:
        provider_class = PROVIDERS[settings.email_provider]
        _provider = provider_class()
    return _provider


def set_email_provider(provider: EmailProvider | None) -> None:
    """Test hook for installing a fake provider."""
    global _provider
    _provider = provider
