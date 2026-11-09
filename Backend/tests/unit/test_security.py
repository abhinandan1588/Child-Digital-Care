"""Password hashing and token primitives."""

from __future__ import annotations

import time
import uuid

import pytest

from app.core.errors import InvalidToken, TokenExpired
from app.core.security import (
    PrincipalType,
    TokenAudience,
    TokenKind,
    create_access_token,
    decode_access_token,
    generate_opaque_token,
    generate_short_code,
    hash_opaque_token,
    hash_password,
    normalize_short_code,
    tokens_match,
    verify_password,
)

pytestmark = pytest.mark.unit


class TestPasswordHashing:
    def test_hash_is_argon2id_and_salted(self) -> None:
        first = hash_password("correct-horse-battery")
        second = hash_password("correct-horse-battery")
        assert first.startswith("$argon2id$")
        # Distinct salts mean identical passwords never share a hash.
        assert first != second

    def test_verify_round_trip(self) -> None:
        stored = hash_password("correct-horse-battery")
        assert verify_password("correct-horse-battery", stored) is True
        assert verify_password("wrong-password", stored) is False

    def test_missing_hash_still_spends_time(self) -> None:
        """An absent account must not be detectable by response time."""
        started = time.perf_counter()
        assert verify_password("anything", None) is False
        elapsed = time.perf_counter() - started
        # Argon2 with the configured cost takes meaningfully longer than a
        # bare `return False`.
        assert elapsed > 0.005

    def test_malformed_stored_hash_returns_false(self) -> None:
        assert verify_password("anything", "not-a-hash") is False


class TestOpaqueTokens:
    def test_tokens_are_high_entropy_and_unique(self) -> None:
        tokens = {generate_opaque_token() for _ in range(200)}
        assert len(tokens) == 200
        assert all(len(token) >= 40 for token in tokens)

    def test_hash_is_stable_and_comparison_is_constant_time(self) -> None:
        token = generate_opaque_token()
        digest = hash_opaque_token(token)
        assert hash_opaque_token(token) == digest
        assert tokens_match(token, digest) is True
        assert tokens_match(generate_opaque_token(), digest) is False

    def test_short_code_alphabet_excludes_ambiguous_characters(self) -> None:
        codes = "".join(generate_short_code(8) for _ in range(200))
        for ambiguous in ("I", "O", "0", "1"):
            assert ambiguous not in codes

    def test_short_code_normalisation_is_forgiving(self) -> None:
        assert normalize_short_code(" ab-cd ef ") == "ABCDEF"


class TestAccessTokens:
    def test_round_trip_carries_principal_and_session(self) -> None:
        subject = uuid.uuid4()
        session_id = uuid.uuid4()
        issued = create_access_token(
            subject=subject,
            principal_type=PrincipalType.parent_user,
            session_id=session_id,
        )
        claims = decode_access_token(
            issued.token,
            expected_audience=TokenAudience.parent,
            expected_principal=PrincipalType.parent_user,
        )
        assert claims.subject_uuid == subject
        assert claims.session_id == str(session_id)
        assert claims.jti == issued.jti

    def test_device_token_rejected_on_parent_audience(self) -> None:
        """Cross-principal replay is the attack this guards against."""
        issued = create_access_token(
            subject=uuid.uuid4(),
            principal_type=PrincipalType.child_device,
            family_id=uuid.uuid4(),
        )
        with pytest.raises(InvalidToken):
            decode_access_token(
                issued.token,
                expected_audience=TokenAudience.parent,
                expected_principal=PrincipalType.parent_user,
            )

    def test_parent_token_rejected_on_admin_audience(self) -> None:
        issued = create_access_token(subject=uuid.uuid4(), principal_type=PrincipalType.parent_user)
        with pytest.raises(InvalidToken):
            decode_access_token(
                issued.token,
                expected_audience=TokenAudience.admin,
                expected_principal=PrincipalType.admin_user,
            )

    def test_expired_token_is_rejected(self) -> None:
        issued = create_access_token(
            subject=uuid.uuid4(),
            principal_type=PrincipalType.parent_user,
            expires_in_minutes=-1,
        )
        with pytest.raises(TokenExpired):
            decode_access_token(issued.token, expected_audience=TokenAudience.parent)

    def test_tampered_signature_is_rejected(self) -> None:
        issued = create_access_token(subject=uuid.uuid4(), principal_type=PrincipalType.parent_user)
        header, payload, signature = issued.token.split(".")
        tampered = f"{header}.{payload}.{signature[:-4]}AAAA"
        with pytest.raises(InvalidToken):
            decode_access_token(tampered, expected_audience=TokenAudience.parent)

    def test_ws_ticket_cannot_be_used_as_access_token(self) -> None:
        """A ticket lives in a URL, so it must not open the REST API."""
        issued = create_access_token(
            subject=uuid.uuid4(),
            principal_type=PrincipalType.parent_user,
            audience=TokenAudience.websocket,
            kind=TokenKind.ws_ticket,
        )
        with pytest.raises(InvalidToken):
            decode_access_token(
                issued.token,
                expected_audience=TokenAudience.parent,
                expected_principal=PrincipalType.parent_user,
            )

    def test_access_token_cannot_be_used_as_ws_ticket(self) -> None:
        issued = create_access_token(subject=uuid.uuid4(), principal_type=PrincipalType.parent_user)
        with pytest.raises(InvalidToken):
            decode_access_token(
                issued.token,
                expected_audience=TokenAudience.parent,
                expected_kind=TokenKind.ws_ticket,
            )

    def test_algorithm_is_not_taken_from_the_header(self) -> None:
        """An ``alg: none`` token must never be accepted."""
        import base64
        import json

        def b64(data: dict) -> str:
            raw = json.dumps(data, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        forged = (
            f"{b64({'alg': 'none', 'typ': 'JWT'})}."
            f"{b64({'sub': str(uuid.uuid4()), 'aud': 'cdc:parent', 'typ': 'parent_user'})}."
        )
        with pytest.raises(InvalidToken):
            decode_access_token(forged, expected_audience=TokenAudience.parent)


class TestLoggingCallSafety:
    """``structlog``'s bound logger takes the message as a positional parameter
    named ``event``, so ``logger.info("x", event=...)`` raises ``TypeError``.

    A crash inside a log call is bad anywhere, but these are mostly on error
    and rejection paths, where it would convert a handled rejection into a 500.
    One such bug existed in ``realtime_service``; this guards the whole app.
    """

    def test_no_logger_call_passes_a_reserved_keyword(self) -> None:
        import ast
        import pathlib

        reserved = {"event", "level", "logger", "timestamp", "exc_info", "stack_info"}
        allowed = {"exc_info", "stack_info"}  # genuinely supported by structlog
        offenders: list[str] = []

        app_root = pathlib.Path(__file__).resolve().parents[2] / "app"
        for path in app_root.rglob("*.py"):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not isinstance(func, ast.Attribute):
                    continue
                if func.attr not in {"debug", "info", "warning", "error", "critical"}:
                    continue
                target = func.value
                name = getattr(target, "id", None) or getattr(target, "attr", None)
                if name not in {"logger", "log", "_logger"}:
                    continue
                for keyword in node.keywords:
                    if keyword.arg in reserved - allowed:
                        offenders.append(
                            f"{path.relative_to(app_root.parent)}:{node.lineno} "
                            f"passes {keyword.arg}="
                        )

        assert not offenders, "reserved structlog keyword passed to a logger: " + "; ".join(
            offenders
        )
