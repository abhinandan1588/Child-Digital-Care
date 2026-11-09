"""Firebase Cloud Messaging adapter.

``firebase-admin`` is an *optional* dependency (``pip install '.[fcm]'``) and is
imported lazily. With ``PUSH_PROVIDER=disabled`` (the default) the API runs
normally and every send reports ``not_configured`` rather than pretending to
have delivered a notification.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.integrations.firebase.base import (
    PushMessage,
    PushProvider,
    PushResult,
    PushSendOutcome,
    validate_push_data,
)

logger = get_logger(__name__)

_init_lock = threading.Lock()


class DisabledPushProvider(PushProvider):
    name = "disabled"

    @property
    def configured(self) -> bool:
        return False

    async def send(self, message: PushMessage) -> PushResult:
        logger.info("push_provider_disabled", reason=message.reason)
        return PushResult(
            outcome=PushSendOutcome.not_configured,
            provider=self.name,
            error_code="PUSH_PROVIDER_DISABLED",
        )


class FcmPushProvider(PushProvider):
    """FCM via the Firebase Admin SDK.

    Credentials are read from a file path supplied by the environment
    (``FIREBASE_CREDENTIALS_PATH``), which in a deployment is a mounted secret.
    No service-account JSON is committed to the repository.
    """

    name = "fcm"

    def __init__(self) -> None:
        self._app: Any = None
        self._messaging: Any = None
        self._init_error: str | None = None

    @property
    def configured(self) -> bool:
        return bool(settings.firebase_credentials_path)

    def _ensure_initialised(self) -> bool:
        if self._messaging is not None:
            return True
        if self._init_error is not None:
            return False
        with _init_lock:
            if self._messaging is not None:
                return True
            try:
                import firebase_admin
                from firebase_admin import credentials, messaging
            except ImportError:
                self._init_error = "FIREBASE_SDK_NOT_INSTALLED"
                logger.error(
                    "push_sdk_missing",
                    hint="Install the optional extra: pip install '.[fcm]'",
                )
                return False

            path = Path(settings.firebase_credentials_path or "")
            if not path.is_file():
                self._init_error = "CREDENTIALS_FILE_MISSING"
                logger.error("push_credentials_missing", path=str(path))
                return False

            try:
                try:
                    self._app = firebase_admin.get_app("cdc")
                except ValueError:
                    self._app = firebase_admin.initialize_app(
                        credentials.Certificate(str(path)),
                        {"projectId": settings.firebase_project_id}
                        if settings.firebase_project_id
                        else None,
                        name="cdc",
                    )
                self._messaging = messaging
            except Exception as exc:  # noqa: BLE001
                self._init_error = "INITIALISATION_FAILED"
                logger.error("push_init_failed", error=type(exc).__name__)
                return False
        return True

    async def send(self, message: PushMessage) -> PushResult:
        if not self.configured:
            return PushResult(
                outcome=PushSendOutcome.not_configured,
                provider=self.name,
                error_code="PUSH_NOT_CONFIGURED",
            )
        try:
            data = validate_push_data({"reason": message.reason, **message.data})
        except ValueError as exc:
            # A programming error, not a provider failure: fail loudly.
            logger.error("push_payload_rejected", error=str(exc))
            return PushResult(
                outcome=PushSendOutcome.provider_error,
                provider=self.name,
                error_code="PAYLOAD_REJECTED",
            )

        if not await asyncio.to_thread(self._ensure_initialised):
            return PushResult(
                outcome=PushSendOutcome.not_configured,
                provider=self.name,
                error_code=self._init_error or "NOT_CONFIGURED",
            )

        return await asyncio.to_thread(self._send_sync, message, data)

    def _send_sync(self, message: PushMessage, data: dict[str, str]) -> PushResult:
        messaging = self._messaging
        assert messaging is not None  # noqa: S101 - guarded by _ensure_initialised

        notification = None
        if message.title and message.body:
            notification = messaging.Notification(title=message.title, body=message.body)

        android = messaging.AndroidConfig(
            priority="high" if message.high_priority else "normal",
            ttl=message.ttl_seconds,
            collapse_key=message.collapse_key,
        )
        payload = messaging.Message(
            token=message.token,
            data=data,
            notification=notification,
            android=android,
        )
        try:
            message_id = messaging.send(payload, app=self._app)
        except Exception as exc:  # noqa: BLE001
            error_name = type(exc).__name__
            if error_name in {
                "UnregisteredError",
                "SenderIdMismatchError",
                "InvalidArgumentError",
            }:
                logger.info("push_token_invalid", error=error_name)
                return PushResult(
                    outcome=PushSendOutcome.token_invalid,
                    provider=self.name,
                    error_code=error_name,
                )
            if error_name == "QuotaExceededError":
                return PushResult(
                    outcome=PushSendOutcome.rate_limited,
                    provider=self.name,
                    error_code=error_name,
                )
            logger.warning("push_send_failed", error=error_name)
            return PushResult(
                outcome=PushSendOutcome.provider_error,
                provider=self.name,
                error_code=error_name,
            )
        return PushResult(
            outcome=PushSendOutcome.sent,
            provider=self.name,
            provider_message_id=str(message_id),
        )


_provider: PushProvider | None = None


def get_push_provider() -> PushProvider:
    global _provider
    if _provider is None:
        _provider = FcmPushProvider() if settings.push_provider == "fcm" else DisabledPushProvider()
    return _provider


def set_push_provider(provider: PushProvider | None) -> None:
    """Test hook for installing a fake provider."""
    global _provider
    _provider = provider
