"""Structured logging configuration.

Logs are emitted as JSON in deployed environments and as coloured key/value
pairs locally. A redaction processor strips anything that looks like a
credential before the event leaves the process, so an accidental
``log.info("x", token=...)`` cannot leak a secret.
"""

from __future__ import annotations

import logging
import logging.config
import re
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

from app.core.config import settings
from app.core.context import get_principal, get_request_id

# Keys whose values must never be written to a log line.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "new_password",
        "current_password",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "refresh_token",
        "device_access_token",
        "device_refresh_token",
        "claim_token",
        "short_code",
        "pairing_code",
        "authorization",
        "api_key",
        "webhook_secret",
        "push_token",
        "fcm_token",
        "verification_token",
        "reset_token",
        "latitude",
        "longitude",
        "coordinates",
        "set-cookie",
        "cookie",
    }
)

REDACTED = "[redacted]"
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")


def _scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        value = _BEARER_RE.sub("Bearer " + REDACTED, value)
        return _JWT_RE.sub(REDACTED, value)
    if isinstance(value, dict):
        return {
            k: (REDACTED if k.lower() in SENSITIVE_KEYS else _scrub_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_scrub_value(item) for item in value]
    return value


def redact_processor(
    _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in list(event_dict.keys()):
        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _scrub_value(event_dict[key])
    return event_dict


def context_processor(
    _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    request_id = get_request_id()
    if request_id and "request_id" not in event_dict:
        event_dict["request_id"] = request_id
    principal = get_principal()
    if principal and "principal" not in event_dict:
        event_dict["principal"] = principal
    return event_dict


def service_processor(
    _logger: Any, _name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    event_dict.setdefault("service", "cdc-backend")
    event_dict.setdefault("env", settings.app_env.value)
    return event_dict


def configure_logging() -> None:
    """Idempotently configure stdlib logging + structlog."""
    level = getattr(logging, settings.log_level, logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        service_processor,
        context_processor,
        redact_processor,
        structlog.processors.StackInfoRenderer(),
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    # structlog events are handed to stdlib logging, which owns the single
    # stdout handler. That keeps uvicorn/sqlalchemy/celery output in the same
    # format and routed through the same redaction chain.
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    logging.getLogger().setLevel(level)

    # Route stdlib loggers (uvicorn, sqlalchemy, celery) through the same sink.
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "structured": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processors": [
                        structlog.processors.format_exc_info,
                        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                        redact_processor,
                        renderer,
                    ],
                    "foreign_pre_chain": shared_processors,
                }
            },
            "handlers": {
                "default": {
                    "class": "logging.StreamHandler",
                    "formatter": "structured",
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {"handlers": ["default"], "level": settings.log_level},
            "loggers": {
                "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
                "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
                # Access logging is handled by our own middleware (with request ids).
                "uvicorn.access": {"handlers": [], "level": "WARNING", "propagate": False},
                "sqlalchemy.engine": {
                    "handlers": ["default"],
                    "level": "INFO" if settings.database_echo else "WARNING",
                    "propagate": False,
                },
                "celery": {"handlers": ["default"], "level": "INFO", "propagate": False},
            },
        }
    )


def get_logger(name: str | None = None) -> Any:
    return structlog.get_logger(name)
