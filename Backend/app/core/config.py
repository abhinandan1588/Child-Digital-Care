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

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PLACEHOLDER_SECRET = "replace-this-for-local-development"  # noqa: S105 - sentinel, not a secret


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
    jwt_private_key_path:/etc/secrets/jwt_private.pem
    jwt_public_key_path:/etc/secrets/jwt_public.pem
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
    database_url: str = "postgresql://child_digital_care_user:YandflqjbEeIBMi28fx554uid3ccdvcL@dpg-dboofv3bc2fs73coierg-a/child_digital_care+asyncpg://postgres:postgres@localhost:5432/child_digital_care"
    database_pool_size: int = 10
    database_max_overflow: int = 5
    database_pool_timeout_seconds: int = 30
    database_pool_recycle_seconds: int = 1800
    database_echo: bool = False

    redis_url: str | None = "redis://red-dbooi03m8hqs73eiluf0:6379"

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
        if not self.jwt_private_key_path:
            raise RuntimeError("JWT_PRIVATE_KEY_PATH is required when JWT_ALGORITHM=RS256")
        return Path(self.jwt_private_key_path).read_text(encoding="utf-8")

    def jwt_verification_key(self) -> str:
        if self.jwt_algorithm == "HS256":
            return self.secret_key
        if not self.jwt_public_key_path:
            raise RuntimeError("JWT_PUBLIC_KEY_PATH is required when JWT_ALGORITHM=RS256")
        return Path(self.jwt_public_key_path).read_text(encoding="utf-8")

    # ------------------------------------------------------------------
    # Fail-fast production validation
    # ------------------------------------------------------------------
    @model_validator(mode="after")
    def _validate_environment(self) -> Settings:
        problems: list[str] = []

        if self.jwt_algorithm == "RS256":
            for label, path in (
                ("JWT_PRIVATE_KEY_PATH", self.jwt_private_key_path),
                ("JWT_PUBLIC_KEY_PATH", self.jwt_public_key_path),
            ):
                if not path:
                    problems.append(f"{label} must be set when JWT_ALGORITHM=RS256.")
                elif not Path(path).is_file():
                    problems.append(f"{label} points at a missing file: {path}")

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
                f"Invalid configuration for APP_ENV={self.app_env.value}:\n  - {bullet_list}"
            )
        return self


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor (import-safe, overridable in tests)."""
    return Settings()


settings = get_settings()

__all__ = ["AppEnv", "Settings", "get_settings", "settings"]
