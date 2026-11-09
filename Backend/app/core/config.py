"""Application settings.

All configuration comes from the environment (or a local ``.env`` file). The
settings object additionally performs *fail-fast* validation: a production
deployment refuses to start with development placeholders, debug mode, wildcard
CORS, or missing secrets.
"""

from __future__ import annotations

import functools
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import parse_qsl, urlencode

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PLACEHOLDER_SECRET = "replace-this-for-local-development"  # noqa: S105 - sentinel, not a secret

# The local-development fallback. Deployed environments must set DATABASE_URL
# explicitly; validation below rejects this exact value so that an unset
# variable fails at startup with a clear message, rather than starting and then
# failing every request against a database that is not there.
LOCAL_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/child_digital_care"

# Shown alongside configuration errors, because the failure is almost always a
# missing environment variable on the hosting platform rather than a code bug.
CONFIG_HELP_URL = "docs/RENDER_DEPLOYMENT.md"


class AppEnv(StrEnum):
    development = "development"
    test = "test"
    staging = "staging"
    production = "production"


# ``NoDecode`` stops pydantic-settings from trying to JSON-decode the raw env
# value, so the comma-separated form below is handled by our own validator.
CsvList = Annotated[list[str], NoDecode, Field(default_factory=list)]


def _split_csv(value: object) -> object:
    """Allow ``A,B,C`` environment strings for list-typed settings."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):  # already JSON
            return value
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return value


def normalize_database_url(url: str) -> str:
    """Make a provider-supplied PostgreSQL URL usable by SQLAlchemy + asyncpg.

    Managed database providers (Render, Heroku, Neon, Railway, Supabase) hand
    out libpq connection strings: a ``postgres://`` or ``postgresql://`` scheme,
    often with ``sslmode`` in the query string. Neither part works here as
    given:

    * Without a driver in the scheme, SQLAlchemy loads its default synchronous
      psycopg driver, which this project does not install, so the engine fails
      with ``ModuleNotFoundError: No module named 'psycopg2'``.
    * SQLAlchemy's asyncpg dialect forwards every query parameter straight into
      ``asyncpg.connect()``, and asyncpg has no ``sslmode`` argument - it spells
      that setting ``ssl`` and accepts the same values. Left alone the
      connection raises
      ``TypeError: connect() got an unexpected keyword argument 'sslmode'``.

    Rewriting both here means a connection string copied out of a provider's
    dashboard can be pasted into ``DATABASE_URL`` unedited. Only these two
    known-incompatible forms are touched; any other query parameter is passed
    through untouched rather than guessed at.
    """
    if not url:
        return url

    scheme, separator, remainder = url.partition("://")
    if not separator or not scheme.startswith(("postgres", "postgresql")):
        return url  # sqlite (tests) or an explicitly chosen non-postgres driver

    if scheme in ("postgres", "postgresql"):
        scheme = "postgresql+asyncpg"
    if not scheme.endswith("+asyncpg"):
        # Somebody deliberately selected a different driver; respect it.
        return f"{scheme}://{remainder}"

    address, question_mark, query = remainder.partition("?")
    if not question_mark:
        return f"{scheme}://{address}"

    pairs = parse_qsl(query, keep_blank_values=True)
    already_has_ssl = any(key == "ssl" for key, _ in pairs)
    translated: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == "sslmode":
            if not already_has_ssl:
                translated.append(("ssl", value))
            continue
        if key == "channel_binding":
            continue  # libpq-only; asyncpg negotiates this itself
        translated.append((key, value))

    # ``safe="/"`` keeps Unix socket paths (``?host=/var/run/postgresql``)
    # readable, and keeps percent signs out of the URL - Alembic stores it in a
    # ConfigParser, where '%' is interpolation syntax.
    rebuilt = urlencode(translated, safe="/")
    return f"{scheme}://{address}?{rebuilt}" if rebuilt else f"{scheme}://{address}"


def _normalize_pem(value: str | None) -> str | None:
    """Accept PEM text pasted into a dashboard field as a single line.

    Web consoles and ``.env`` files frequently turn the newlines in a PEM block
    into the two characters ``\\n``. PyJWT then rejects the key as malformed,
    which reads like a wrong-key error rather than a formatting one.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if "\\n" in text and "\n" not in text:
        text = text.replace("\\n", "\n")
    return text


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ------------------------------------------------------
    app_name: str = "Child Digital Care API"
    app_env: AppEnv = AppEnv.development
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    host: str = "0.0.0.0"  # noqa: S104 - container binding; exposure is controlled by the deployment
    port: int = 8000

    # --- Crypto / tokens --------------------------------------------------
    secret_key: str = PLACEHOLDER_SECRET
    jwt_algorithm: Literal["HS256", "RS256"] = "HS256"
    # RS256 keys can arrive either as a file path (Kubernetes/Docker secret
    # mounts) or as inline PEM text (platforms whose only secret store is an
    # environment variable, such as Render). Inline wins when both are set.
    jwt_private_key: str | None = None
    jwt_public_key: str | None = None
    jwt_private_key_path: str | None = None
    jwt_public_key_path: str | None = None
    jwt_issuer: str = "child-digital-care"
    jwt_key_id: str = "local-dev-1"

    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    device_access_token_expire_minutes: int = 15
    device_refresh_token_expire_days: int = 180
    admin_access_token_expire_minutes: int = 15
    admin_refresh_token_expire_days: int = 1
    ws_ticket_expire_seconds: int = 60

    email_verification_token_expire_hours: int = 24
    password_reset_token_expire_minutes: int = 30
    pairing_invitation_expire_minutes: int = 15
    pairing_max_claim_attempts: int = 5

    # --- Datastores -------------------------------------------------------
    # Defaults describe a local development stack only. Every deployed
    # environment supplies DATABASE_URL and REDIS_URL from its own secret
    # store; no connection string belongs in this file.
    database_url: str = LOCAL_DATABASE_URL
    database_pool_size: int = 10
    database_max_overflow: int = 5
    database_pool_timeout_seconds: int = 30
    database_pool_recycle_seconds: int = 1800
    database_echo: bool = False

    redis_url: str | None = None

    # --- HTTP surface -----------------------------------------------------
    cors_origins: CsvList
    trusted_hosts: CsvList
    frontend_base_url: str = "http://localhost:3000"
    max_request_body_bytes: int = 1_048_576
    enable_docs: bool = True

    rate_limit_enabled: bool = True
    rate_limit_fail_open: bool = True

    # --- Email ------------------------------------------------------------
    email_provider: Literal["console", "smtp", "disabled"] = "console"
    email_from: str = "noreply@example.test"
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True

    # --- Push -------------------------------------------------------------
    push_provider: Literal["disabled", "fcm"] = "disabled"
    firebase_credentials_path: str | None = None
    firebase_project_id: str | None = None

    # --- Payments ---------------------------------------------------------
    payment_provider: Literal["disabled", "generic_hmac"] = "disabled"
    payment_webhook_secret: str | None = None
    payment_webhook_tolerance_seconds: int = 300

    # --- Object storage ---------------------------------------------------
    object_storage_provider: Literal["disabled", "s3_compatible"] = "disabled"
    object_storage_bucket: str | None = None
    object_storage_endpoint: str | None = None
    object_storage_access_key: str | None = None
    object_storage_secret_key: str | None = None
    object_storage_signed_url_ttl_seconds: int = 300

    # --- Feature gates ----------------------------------------------------
    feature_location_enabled: bool = False
    feature_website_restrictions_enabled: bool = False
    feature_guardian_invitations_enabled: bool = True
    feature_websockets_enabled: bool = True
    require_email_verification: bool = True

    # --- Retention --------------------------------------------------------
    retention_device_events_days: int = 90
    retention_usage_summaries_days: int = 400
    retention_location_samples_days: int = 30
    retention_audit_log_days: int = 730
    retention_command_history_days: int = 180
    retention_idempotency_hours: int = 24

    # --- Commands / outbox ------------------------------------------------
    command_default_ttl_seconds: int = 86_400
    command_max_delivery_attempts: int = 5
    outbox_batch_size: int = 100
    outbox_max_attempts: int = 8

    # --- Observability ----------------------------------------------------
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    sentry_dsn: str | None = None
    metrics_enabled: bool = True

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------
    @field_validator("cors_origins", "trusted_hosts", mode="before")
    @classmethod
    def _coerce_csv(cls, value: object) -> object:
        return _split_csv(value)

    @field_validator("database_url", mode="after")
    @classmethod
    def _normalize_database_url(cls, value: str) -> str:
        return normalize_database_url(value)

    @field_validator("jwt_private_key", "jwt_public_key", mode="after")
    @classmethod
    def _normalize_jwt_pem(cls, value: str | None) -> str | None:
        return _normalize_pem(value)

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError(f"Unsupported LOG_LEVEL: {value}")
        return level

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.app_env is AppEnv.production

    @property
    def is_testing(self) -> bool:
        return self.app_env is AppEnv.test

    @property
    def docs_enabled(self) -> bool:
        return self.enable_docs and not self.is_production

    @property
    def sync_database_url(self) -> str:
        """psycopg-free synchronous URL, used by Alembic's offline mode only."""
        return self.database_url.replace("+asyncpg", "").replace("+aiosqlite", "")

    @property
    def push_configured(self) -> bool:
        return self.push_provider == "fcm" and bool(self.firebase_credentials_path)

    @property
    def payments_configured(self) -> bool:
        return self.payment_provider != "disabled" and bool(self.payment_webhook_secret)

    @property
    def object_storage_configured(self) -> bool:
        return self.object_storage_provider != "disabled" and bool(self.object_storage_bucket)

    def jwt_signing_key(self) -> str:
        if self.jwt_algorithm == "HS256":
            return self.secret_key
        if self.jwt_private_key:
            return self.jwt_private_key
        if self.jwt_private_key_path:
            return Path(self.jwt_private_key_path).read_text(encoding="utf-8")
        raise RuntimeError(
            "JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH is required when JWT_ALGORITHM=RS256"
        )

    def jwt_verification_key(self) -> str:
        if self.jwt_algorithm == "HS256":
            return self.secret_key
        if self.jwt_public_key:
            return self.jwt_public_key
        if self.jwt_public_key_path:
            return Path(self.jwt_public_key_path).read_text(encoding="utf-8")
        raise RuntimeError(
            "JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_PATH is required when JWT_ALGORITHM=RS256"
        )

    # ------------------------------------------------------------------
    # Fail-fast production validation
    # ------------------------------------------------------------------
    @model_validator(mode="after")
    def _validate_environment(self) -> Settings:
        problems: list[str] = []

        if self.jwt_algorithm == "RS256":
            # Either form satisfies the requirement: inline PEM text, or a path
            # to a readable file. Only the path form can be checked eagerly.
            for inline_label, inline, path_label, path in (
                (
                    "JWT_PRIVATE_KEY",
                    self.jwt_private_key,
                    "JWT_PRIVATE_KEY_PATH",
                    self.jwt_private_key_path,
                ),
                (
                    "JWT_PUBLIC_KEY",
                    self.jwt_public_key,
                    "JWT_PUBLIC_KEY_PATH",
                    self.jwt_public_key_path,
                ),
            ):
                if inline:
                    continue
                if not path:
                    problems.append(
                        f"{inline_label} or {path_label} must be set when JWT_ALGORITHM=RS256."
                    )
                elif not Path(path).is_file():
                    problems.append(f"{path_label} points at a missing file: {path}")

        if self.app_env in (AppEnv.production, AppEnv.staging):
            if self.secret_key == PLACEHOLDER_SECRET:
                problems.append("SECRET_KEY still holds the example placeholder value.")
            if len(self.secret_key) < 32:
                problems.append("SECRET_KEY must be at least 32 characters.")
            if "*" in self.cors_origins:
                problems.append("CORS_ORIGINS must not contain '*'.")
            if not self.cors_origins:
                problems.append("CORS_ORIGINS must list at least one allowed origin.")
            if not self.redis_url:
                problems.append("REDIS_URL is required (rate limiting and outbox depend on it).")
            if self.database_url.startswith("sqlite"):
                problems.append("SQLite is not supported outside local development/tests.")
            if self.database_url == LOCAL_DATABASE_URL:
                problems.append(
                    "DATABASE_URL is not set; it still holds the local development default. "
                    "Use the managed database's internal connection string."
                )

        if self.app_env is AppEnv.production:
            if self.debug:
                problems.append("DEBUG must be false in production.")
            if self.email_provider == "console":
                problems.append("EMAIL_PROVIDER=console cannot be used in production.")
            if "*" in self.trusted_hosts:
                problems.append("TRUSTED_HOSTS must not be '*' in production.")
            if self.jwt_algorithm != "RS256":
                problems.append(
                    "JWT_ALGORITHM should be RS256 in production so verification keys can be "
                    "distributed without sharing the signing secret."
                )

        if self.payment_provider != "disabled" and not self.payment_webhook_secret:
            problems.append("PAYMENT_WEBHOOK_SECRET is required when a payment provider is set.")
        if self.push_provider == "fcm" and not self.firebase_credentials_path:
            problems.append("FIREBASE_CREDENTIALS_PATH is required when PUSH_PROVIDER=fcm.")
        if self.email_provider == "smtp" and not self.smtp_host:
            problems.append("SMTP_HOST is required when EMAIL_PROVIDER=smtp.")
        if self.object_storage_provider != "disabled" and not self.object_storage_bucket:
            problems.append("OBJECT_STORAGE_BUCKET is required when object storage is enabled.")

        if problems:
            bullet_list = "\n  - ".join(problems)
            raise ValueError(
                f"Invalid configuration for APP_ENV={self.app_env.value}:\n  - {bullet_list}\n"
                f"Each item above is an environment variable this environment must supply. "
                f"See {CONFIG_HELP_URL}."
            )
        return self


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor (import-safe, overridable in tests)."""
    return Settings()


settings = get_settings()

__all__ = [
    "AppEnv",
    "Settings",
    "get_settings",
    "normalize_database_url",
    "settings",
]
