"""Command state transitions and policy precedence."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

import pytest

from app.core.errors import InvalidStateTransition
from app.db.enums import (
    PARENT_ISSUABLE_COMMANDS,
    TERMINAL_COMMAND_STATUSES,
    CommandResult,
    CommandStatus,
    CommandType,
    RestrictionAction,
)
from app.services.command_service import (
    ALLOWED_TRANSITIONS,
    RESULT_TO_STATUS,
    assert_transition,
    can_transition,
    derive_idempotency_key,
    is_terminal,
)
from app.services.policy_service import resolve_restrictions

pytestmark = pytest.mark.unit


class TestTransitions:
    def test_happy_path(self) -> None:
        path = [
            CommandStatus.queued,
            CommandStatus.delivery_attempted,
            CommandStatus.delivered,
            CommandStatus.acknowledged,
            CommandStatus.succeeded,
        ]
        for current, target in zip(path, path[1:], strict=False):
            assert can_transition(current, target), f"{current} -> {target}"

    def test_terminal_states_accept_nothing(self) -> None:
        for status in TERMINAL_COMMAND_STATUSES:
            assert ALLOWED_TRANSITIONS[status] == frozenset()
            assert is_terminal(status)

    def test_cannot_resurrect_a_finished_command(self) -> None:
        with pytest.raises(InvalidStateTransition):
            assert_transition(CommandStatus.succeeded, CommandStatus.acknowledged)
        with pytest.raises(InvalidStateTransition):
            assert_transition(CommandStatus.expired, CommandStatus.succeeded)

    def test_cannot_skip_straight_from_queued_to_succeeded(self) -> None:
        """Success requires the device to have actually received the command."""
        with pytest.raises(InvalidStateTransition):
            assert_transition(CommandStatus.queued, CommandStatus.succeeded)

    def test_expiry_and_cancellation_reachable_from_every_pending_state(self) -> None:
        for status in (
            CommandStatus.queued,
            CommandStatus.delivery_attempted,
            CommandStatus.delivered,
        ):
            assert can_transition(status, CommandStatus.expired)
            assert can_transition(status, CommandStatus.cancelled)

    def test_unsupported_and_permission_denied_are_not_success(self) -> None:
        assert RESULT_TO_STATUS[CommandResult.unsupported] is CommandStatus.unsupported
        assert RESULT_TO_STATUS[CommandResult.permission_denied] is CommandStatus.failed
        assert RESULT_TO_STATUS[CommandResult.succeeded] is CommandStatus.succeeded

    def test_every_status_has_a_transition_entry(self) -> None:
        for status in CommandStatus:
            assert status in ALLOWED_TRANSITIONS


class TestCommandAllowList:
    def test_no_arbitrary_execution_command_exists(self) -> None:
        """Rules 13 and 14: no remote shell, script or capture command."""
        forbidden = {
            "execute",
            "shell",
            "run_script",
            "install_package",
            "capture_screen",
            "record_audio",
            "record_video",
            "read_messages",
            "keylog",
        }
        declared = {item.value for item in CommandType}
        assert not (forbidden & declared)

    def test_parent_cannot_issue_server_only_commands(self) -> None:
        assert CommandType.revoke_device not in PARENT_ISSUABLE_COMMANDS
        assert CommandType.apply_supported_policy not in PARENT_ISSUABLE_COMMANDS
        assert CommandType.sync_policies in PARENT_ISSUABLE_COMMANDS


class TestIdempotencyKeys:
    def test_same_input_in_the_same_window_yields_one_key(self) -> None:
        device_id = uuid.uuid4()
        payload = {"target_policy_version": 3}
        first = derive_idempotency_key(
            device_id=device_id, command_type=CommandType.sync_policies, payload=payload
        )
        second = derive_idempotency_key(
            device_id=device_id, command_type=CommandType.sync_policies, payload=payload
        )
        assert first == second

    def test_different_devices_get_different_keys(self) -> None:
        payload = {"target_policy_version": 3}
        assert derive_idempotency_key(
            device_id=uuid.uuid4(),
            command_type=CommandType.sync_policies,
            payload=payload,
        ) != derive_idempotency_key(
            device_id=uuid.uuid4(),
            command_type=CommandType.sync_policies,
            payload=payload,
        )


@dataclass
class FakeRestriction:
    package_identifier: str
    action: RestrictionAction
    enabled: bool = True
    device_id: uuid.UUID | None = None
    daily_limit_seconds: int | None = None
    created_at: datetime = datetime(2026, 1, 1)


class TestPolicyPrecedence:
    def test_device_scoped_row_overrides_profile_wide(self) -> None:
        device_id = uuid.uuid4()
        resolved = resolve_restrictions(
            [
                FakeRestriction("com.example.app", RestrictionAction.block),
                FakeRestriction("com.example.app", RestrictionAction.allow, device_id=device_id),
            ],
            device_id=device_id,
        )
        assert len(resolved) == 1
        assert resolved[0].action is RestrictionAction.allow

    def test_other_devices_rows_are_ignored(self) -> None:
        resolved = resolve_restrictions(
            [FakeRestriction("com.example.app", RestrictionAction.allow, device_id=uuid.uuid4())],
            device_id=uuid.uuid4(),
        )
        assert resolved == []

    def test_stricter_action_wins_at_equal_scope(self) -> None:
        resolved = resolve_restrictions(
            [
                FakeRestriction("com.example.app", RestrictionAction.allow),
                FakeRestriction("com.example.app", RestrictionAction.block),
            ],
            device_id=uuid.uuid4(),
        )
        assert resolved[0].action is RestrictionAction.block

    def test_disabled_rows_are_dropped(self) -> None:
        resolved = resolve_restrictions(
            [FakeRestriction("com.example.app", RestrictionAction.block, enabled=False)],
            device_id=uuid.uuid4(),
        )
        assert resolved == []
