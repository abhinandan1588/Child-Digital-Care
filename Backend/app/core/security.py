"""Cryptographic primitives: password hashing, JWT access tokens, opaque secrets.

Design decisions (documented in docs/AUTH_AND_RBAC.md):

* **Access tokens are JWTs.** Short-lived, signed with a fixed algorithm
  allow-list, and carrying an explicit principal type so a device token can
  never be replayed against a parent endpoint.
* **Refresh tokens are opaque high-entropy strings**, never JWTs. Only a
  SHA-256 hash is stored, they rotate on every use, and reuse of a consumed
  token revokes the whole token family.
* **Pairing claim tokens are opaque too**, stored hashed, single use.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.config import settings
from app.core.errors import InvalidToken, TokenExpired
from app.utils.time import ensure_utc, utcnow

# ---------------------------------------------------------------------------
# Principals and audiences
# ---------------------------------------------------------------------------


class PrincipalType(StrEnum):
    parent_user = "parent_user"
    child_device = "child_device"
    admin_user = "admin_user"
    system = "system"


class TokenAudience(StrEnum):
    parent = "cdc:parent"
    device = "cdc:device"
    admin = "cdc:admin"
    websocket = "cdc:ws"


class TokenKind(StrEnum):
    access = "access"
    ws_ticket = "ws_ticket"


AUDIENCE_FOR_PRINCIPAL: Final[dict[PrincipalType, TokenAudience]] = {
    PrincipalType.parent_user: TokenAudience.parent,
    PrincipalType.child_device: TokenAudience.device,
    PrincipalType.admin_user: TokenAudience.admin,
}

# Never derive the algorithm from the token header.
ALLOWED_ALGORITHMS: Final[tuple[str, ...]] = ("HS256", "RS256")

# ---------------------------------------------------------------------------
# Password hashing (Argon2id)
# ---------------------------------------------------------------------------
# Parameters follow the OWASP "second recommended" Argon2id configuration
# (19 MiB memory, 2 iterations, 1 degree of parallelism).
_password_hash = PasswordHash(
    (
        Argon2Hasher(
            memory_cost=19 * 1024,
            time_cost=2,
            parallelism=1,
        ),
    )
)

# A hash of a throwaway value, used to equalise timing when the account is absent.
_DUMMY_HASH: Final[str] = _password_hash.hash(secrets.token_urlsafe(32))

MIN_PASSWORD_LENGTH: Final[int] = 12
MAX_PASSWORD_LENGTH: Final[int] = 128


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verify a password, spending comparable time when the hash is missing.

    Returning early for unknown accounts is an account-enumeration oracle, so
    an absent hash is checked against a dummy hash instead.
    """
    if not password_hash:
        _password_hash.verify(password, _DUMMY_HASH)
        return False
    try:
        return _password_hash.verify(password, password_hash)
    except Exception:  # noqa: BLE001 - malformed stored hash must not 500
        return False


def verify_and_maybe_rehash(password: str, password_hash: str | None) -> tuple[bool, str | None]:
    """Verify a password and return an upgraded hash when parameters moved on.

    Called on login so that raising the Argon2 cost later re-hashes accounts
    transparently as people sign in, instead of leaving old hashes in place
    forever or forcing a password reset.
    """
    if not password_hash:
        _password_hash.verify(password, _DUMMY_HASH)
        return False, None
    try:
        valid, updated = _password_hash.verify_and_update(password, password_hash)
    except Exception:  # noqa: BLE001 - a malformed stored hash must not 500
        return False, None
    return bool(valid), updated


# ---------------------------------------------------------------------------
# Opaque secrets (refresh tokens, pairing tokens, ws tickets)
# ---------------------------------------------------------------------------
OPAQUE_TOKEN_BYTES: Final[int] = 32  # 256 bits


def generate_opaque_token(num_bytes: int = OPAQUE_TOKEN_BYTES) -> str:
    return secrets.token_urlsafe(num_bytes)


def hash_opaque_token(token: str) -> str:
    """SHA-256 of a high-entropy token.

    A slow KDF buys nothing here: the input is already 256 bits of entropy, so
    there is no dictionary to search. Using a fast digest keeps refresh and
    pairing lookups indexable.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(token: str, token_hash: str) -> bool:
    return hmac.compare_digest(hash_opaque_token(token), token_hash)


_SHORT_CODE_ALPHABET: Final[str] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1


def generate_short_code(length: int = 8) -> str:
    """Human-transcribable pairing code.

    8 characters from a 32-symbol alphabet is 40 bits. That is only safe
    because the code is short-lived, single-use, attempt-limited and
    rate-limited; it is never a long-term credential.
    """
    return "".join(secrets.choice(_SHORT_CODE_ALPHABET) for _ in range(length))


def normalize_short_code(code: str) -> str:
    return code.strip().replace("-", "").replace(" ", "").upper()


def constant_time_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def hmac_sha256_hex(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# JWT access tokens
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenClaims:
    subject: str
    principal_type: PrincipalType
    jti: str
    issued_at: datetime
    expires_at: datetime
    audience: str
    session_id: str | None = None
    scopes: tuple[str, ...] = ()
    family_id: str | None = None
    kind: TokenKind = TokenKind.access
    raw: dict[str, Any] | None = None

    @property
    def subject_uuid(self) -> uuid.UUID:
        try:
            return uuid.UUID(self.subject)
        except ValueError as exc:  # pragma: no cover - defensive
            raise InvalidToken("Token subject is not a valid identifier.") from exc


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime
    expires_in: int


def create_access_token(
    *,
    subject: str | uuid.UUID,
    principal_type: PrincipalType,
    expires_in_minutes: int | None = None,
    session_id: str | uuid.UUID | None = None,
    scopes: list[str] | tuple[str, ...] | None = None,
    family_id: str | uuid.UUID | None = None,
    audience: TokenAudience | None = None,
    kind: TokenKind = TokenKind.access,
    extra_claims: dict[str, Any] | None = None,
) -> IssuedToken:
    """Mint a signed access token.

    ``typ`` (principal type) is what stops cross-principal replay: the
    dependency that guards parent routes requires ``typ == parent_user`` *and*
    ``aud == cdc:parent``.
    """
    if expires_in_minutes is None:
        expires_in_minutes = _default_expiry_minutes(principal_type)

    now = utcnow()
    expires_at = now + timedelta(minutes=expires_in_minutes)
    jti = str(uuid.uuid4())
    aud = (audience or AUDIENCE_FOR_PRINCIPAL[principal_type]).value

    payload: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": aud,
        "sub": str(subject),
        "typ": principal_type.value,
        "knd": kind.value,
        "jti": jti,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if session_id is not None:
        payload["sid"] = str(session_id)
    if scopes:
        payload["scp"] = list(scopes)
    if family_id is not None:
        payload["fam"] = str(family_id)
    if extra_claims:
        reserved = set(payload)
        payload.update({k: v for k, v in extra_claims.items() if k not in reserved})

    token = jwt.encode(
        payload,
        settings.jwt_signing_key(),
        algorithm=settings.jwt_algorithm,
        headers={"kid": settings.jwt_key_id},
    )
    return IssuedToken(
        token=token,
        jti=jti,
        expires_at=expires_at,
        expires_in=expires_in_minutes * 60,
    )


def _default_expiry_minutes(principal_type: PrincipalType) -> int:
    return {
        PrincipalType.parent_user: settings.access_token_expire_minutes,
        PrincipalType.child_device: settings.device_access_token_expire_minutes,
        PrincipalType.admin_user: settings.admin_access_token_expire_minutes,
        PrincipalType.system: settings.access_token_expire_minutes,
    }[principal_type]


def decode_access_token(
    token: str,
    *,
    expected_audience: TokenAudience,
    expected_principal: PrincipalType | None = None,
    expected_kind: TokenKind = TokenKind.access,
) -> TokenClaims:
    """Verify and decode a token, or raise an :class:`AppError` subclass."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_verification_key(),
            algorithms=[settings.jwt_algorithm],
            audience=expected_audience.value,
            issuer=settings.jwt_issuer,
            options={
                "require": ["exp", "iat", "sub", "aud", "iss", "jti"],
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_signature": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpired() from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidToken() from exc

    try:
        principal_type = PrincipalType(payload["typ"])
    except (KeyError, ValueError) as exc:
        raise InvalidToken("Token is missing a valid principal type.") from exc

    if expected_principal is not None and principal_type is not expected_principal:
        raise InvalidToken("This token cannot be used on this endpoint.")

    kind = TokenKind(payload.get("knd", TokenKind.access.value))
    if kind is not expected_kind:
        raise InvalidToken("This token cannot be used on this endpoint.")

    return TokenClaims(
        subject=str(payload["sub"]),
        principal_type=principal_type,
        jti=str(payload["jti"]),
        issued_at=ensure_utc(datetime.fromtimestamp(payload["iat"], tz=UTC)),
        expires_at=ensure_utc(datetime.fromtimestamp(payload["exp"], tz=UTC)),
        audience=str(payload["aud"]),
        session_id=payload.get("sid"),
        scopes=tuple(payload.get("scp", ())),
        family_id=payload.get("fam"),
        kind=kind,
        raw=payload,
    )


__all__ = [
    "ALLOWED_ALGORITHMS",
    "MAX_PASSWORD_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "IssuedToken",
    "PrincipalType",
    "TokenAudience",
    "TokenClaims",
    "TokenKind",
    "constant_time_compare",
    "create_access_token",
    "decode_access_token",
    "generate_opaque_token",
    "generate_short_code",
    "hash_opaque_token",
    "hash_password",
    "hmac_sha256_hex",
    "normalize_short_code",
    "tokens_match",
    "verify_and_maybe_rehash",
    "verify_password",
]
