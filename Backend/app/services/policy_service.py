"""Policy intent, versioning, conflict resolution, and device snapshots.

Every mutation goes through :func:`bump_policy_version`, which in **one
transaction**:

1. increments ``child_profiles.policy_version``,
2. writes a ``policy_versions`` audit row,
3. inserts a ``pending_sync`` ``device_policy_states`` row per active device,
4. creates a durable ``sync_policies`` command per active device,
5. writes the outbox rows that will later become FCM wake-ups.

So a policy change and its synchronisation intent cannot diverge, and no push
is attempted while the transaction is open.

**Precedence** (documented in docs/API_CONTRACT.md and applied in
:func:`build_device_snapshot`):

* A device-scoped row beats a profile-wide row for the same package.
* ``block`` beats ``require_approval`` beats ``time_limit`` beats ``allow``.
* Among overlapping screen-time policies, the highest ``priority`` wins; ties
  break on the more restrictive action, then on the most recently updated.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.errors import Conflict, ErrorCode, NotFound
from app.core.logging import get_logger
from app.db.enums import (
    CapabilityKey,
    CapabilitySupport,
    CommandType,
    DeviceStatus,
    RestrictionAction,
    ScheduleAction,
    SyncStatus,
    WebsiteRestrictionMode,
    Weekday,
)
from app.db.models.device import Device, DeviceCapability
from app.db.models.family import ChildProfile
from app.db.models.policy import (
    AppRestriction,
    DevicePolicyState,
    PolicyVersion,
    ScreenTimePolicy,
    ScreenTimeSchedule,
    WebsiteRestriction,
)
from app.services import command_service, outbox_service
from app.services.outbox_service import OutboxTopic
from app.utils.time import minutes_of_day, utcnow, window_crosses_midnight

logger = get_logger(__name__)

MINUTES_PER_DAY = 1440

#: Lower number = more restrictive. Used to resolve precedence deterministically.
RESTRICTION_SEVERITY: dict[RestrictionAction, int] = {
    RestrictionAction.block: 0,
    RestrictionAction.require_approval: 1,
    RestrictionAction.time_limit: 2,
    RestrictionAction.allow: 3,
}

SCHEDULE_SEVERITY: dict[ScheduleAction, int] = {
    ScheduleAction.block_all: 0,
    ScheduleAction.allow_allowlisted_only: 1,
    ScheduleAction.warn_only: 2,
}

#: Packages the product refuses to restrict: blocking them can brick a device
#: or cut off emergency communication.
PROTECTED_PACKAGE_PREFIXES: tuple[str, ...] = (
    "com.android.dialer",
    "com.android.emergency",
    "com.android.server.telecom",
    "com.android.settings",
    "com.google.android.dialer",
    "com.google.android.apps.messaging",
    "com.childdigitalcare",
)


def assert_package_restrictable(package_identifier: str) -> None:
    lowered = package_identifier.lower()
    for prefix in PROTECTED_PACKAGE_PREFIXES:
        if lowered == prefix or lowered.startswith(prefix + "."):
            raise Conflict(
                f"'{package_identifier}' cannot be restricted: it is required for "
                "emergency calling, device settings, or this app itself.",
                code=ErrorCode.POLICY_CONFLICT,
            )


# ---------------------------------------------------------------------------
# Schedule validation
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class MinuteWindow:
    start: int
    end: int  # exclusive; may exceed MINUTES_PER_DAY when crossing midnight

    def overlaps(self, other: MinuteWindow) -> bool:
        return self.start < other.end and other.start < self.end


def schedule_windows(start: time, end: time) -> list[MinuteWindow]:
    """Express a local window as minute ranges on a 2-day line.

    A 21:00-07:00 bedtime becomes ``[1260, 1860)``: representing it as one
    continuous range (rather than two wrapped pieces) makes overlap checks a
    simple interval comparison.
    """
    start_minutes = minutes_of_day(start)
    end_minutes = minutes_of_day(end)
    if window_crosses_midnight(start, end):
        return [MinuteWindow(start_minutes, end_minutes + MINUTES_PER_DAY)]
    return [MinuteWindow(start_minutes, end_minutes)]


def validate_no_overlap(
    schedules: list[tuple[Weekday, time, time]], *, context: str = "policy"
) -> None:
    """Reject overlapping windows on the same weekday within one policy.

    Overlap inside a single policy is almost always a mistake (two bedtimes),
    and silently merging them would make the device's behaviour unexplainable.
    Overlap *between* policies is allowed and resolved by priority.
    """
    by_weekday: dict[Weekday, list[MinuteWindow]] = {}
    for weekday, start, end in schedules:
        windows = schedule_windows(start, end)
        existing = by_weekday.setdefault(weekday, [])
        for new_window in windows:
            for current in existing:
                if new_window.overlaps(current):
                    raise Conflict(
                        f"Two {weekday.value} windows in this {context} overlap. "
                        "Adjust the times so each covers a distinct period.",
                        code=ErrorCode.SCHEDULE_INVALID,
                    )
            existing.append(new_window)


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class PolicyChangeOutcome:
    policy_version: int
    commands_queued: list[uuid.UUID] = field(default_factory=list)
    devices_notified: int = 0
    sync_status: SyncStatus = SyncStatus.pending_sync


async def bump_policy_version(
    session: AsyncSession,
    *,
    child: ChildProfile,
    change_type: str,
    change_summary: str | None,
    changed_by_user_id: uuid.UUID | None,
) -> PolicyChangeOutcome:
    """Advance the policy version and queue synchronisation atomically."""
    child.policy_version += 1
    new_version = child.policy_version

    session.add(
        PolicyVersion(
            family_id=child.family_id,
            child_profile_id=child.id,
            version=new_version,
            changed_by_user_id=changed_by_user_id,
            change_type=change_type[:64],
            change_summary=(change_summary or None) and change_summary[:255],
        )
    )

    devices = await active_devices_for_child(session, child_profile_id=child.id)
    outcome = PolicyChangeOutcome(policy_version=new_version)

    for device in devices:
        session.add(
            DevicePolicyState(
                device_id=device.id,
                child_profile_id=child.id,
                policy_version=new_version,
                sync_status=SyncStatus.pending_sync,
            )
        )
        device.policy_sync_status = SyncStatus.pending_sync
        device.policy_sync_detail = None

        created = await command_service.create_command(
            session,
            device=device,
            command_type=CommandType.sync_policies,
            payload={
                "target_policy_version": new_version,
                "reason": change_type[:120],
            },
            created_by_user_id=changed_by_user_id,
        )
        outcome.commands_queued.append(created.command.id)

    outcome.devices_notified = len(devices)

    await outbox_service.enqueue(
        session,
        topic=OutboxTopic.POLICY_CHANGED,
        aggregate_type="child_profile",
        aggregate_id=child.id,
        family_id=child.family_id,
        payload={
            "child_profile_id": str(child.id),
            "policy_version": new_version,
            "change_type": change_type,
            "devices": len(devices),
        },
    )
    await session.flush()
    return outcome


async def active_devices_for_child(
    session: AsyncSession, *, child_profile_id: uuid.UUID
) -> list[Device]:
    result = await session.execute(
        select(Device).where(
            Device.child_profile_id == child_profile_id,
            Device.device_status.in_([DeviceStatus.active, DeviceStatus.inactive]),
            Device.revoked_at.is_(None),
        )
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# App restrictions
# ---------------------------------------------------------------------------
async def create_app_restriction(
    session: AsyncSession,
    *,
    child: ChildProfile,
    package_identifier: str,
    display_label: str | None,
    action: RestrictionAction,
    daily_limit_seconds: int | None,
    enabled: bool,
    device_id: uuid.UUID | None,
    user_id: uuid.UUID,
) -> tuple[AppRestriction, PolicyChangeOutcome]:
    assert_package_restrictable(package_identifier)

    if device_id is not None:
        await _assert_device_belongs_to_child(session, child=child, device_id=device_id)

    existing = await session.execute(
        select(AppRestriction)
        .where(
            AppRestriction.child_profile_id == child.id,
            AppRestriction.package_identifier == package_identifier,
            AppRestriction.device_id == device_id,
        )
        .limit(1)
    )
    row = existing.scalars().first()
    if row is not None:
        raise Conflict(
            "A restriction for that package already exists at this scope. Update it instead.",
            code=ErrorCode.ALREADY_EXISTS,
        )

    restriction = AppRestriction(
        family_id=child.family_id,
        child_profile_id=child.id,
        device_id=device_id,
        package_identifier=package_identifier,
        display_label=display_label,
        action=action,
        daily_limit_seconds=daily_limit_seconds,
        enabled=enabled,
        created_by_user_id=user_id,
        revision=1,
    )
    session.add(restriction)
    await session.flush()

    outcome = await bump_policy_version(
        session,
        child=child,
        change_type="app_restriction_created",
        change_summary=f"{action.value} {package_identifier}",
        changed_by_user_id=user_id,
    )
    return restriction, outcome


async def update_app_restriction(
    session: AsyncSession,
    *,
    child: ChildProfile,
    restriction: AppRestriction,
    display_label: str | None,
    action: RestrictionAction | None,
    daily_limit_seconds: int | None,
    enabled: bool | None,
    if_revision: int | None,
    user_id: uuid.UUID,
) -> tuple[AppRestriction, PolicyChangeOutcome]:
    _assert_revision(restriction.revision, if_revision)

    if action is not None:
        restriction.action = action
    if display_label is not None:
        restriction.display_label = display_label
    if enabled is not None:
        restriction.enabled = enabled
    if daily_limit_seconds is not None:
        restriction.daily_limit_seconds = daily_limit_seconds

    effective_action = restriction.action
    if effective_action is RestrictionAction.time_limit and not restriction.daily_limit_seconds:
        raise Conflict(
            "A time_limit restriction needs daily_limit_seconds.",
            code=ErrorCode.VALIDATION_ERROR,
        )
    if effective_action is not RestrictionAction.time_limit:
        restriction.daily_limit_seconds = None

    restriction.revision += 1
    await session.flush()

    outcome = await bump_policy_version(
        session,
        child=child,
        change_type="app_restriction_updated",
        change_summary=f"{restriction.action.value} {restriction.package_identifier}",
        changed_by_user_id=user_id,
    )
    return restriction, outcome


async def delete_app_restriction(
    session: AsyncSession,
    *,
    child: ChildProfile,
    restriction: AppRestriction,
    user_id: uuid.UUID,
) -> PolicyChangeOutcome:
    package = restriction.package_identifier
    await session.delete(restriction)
    await session.flush()
    return await bump_policy_version(
        session,
        child=child,
        change_type="app_restriction_deleted",
        change_summary=f"removed {package}",
        changed_by_user_id=user_id,
    )


async def get_app_restriction(
    session: AsyncSession, *, restriction_id: uuid.UUID
) -> AppRestriction:
    row = await session.get(AppRestriction, restriction_id)
    if row is None:
        raise NotFound("Restriction not found.")
    return row


async def list_app_restrictions(
    session: AsyncSession, *, child_profile_id: uuid.UUID
) -> list[AppRestriction]:
    result = await session.execute(
        select(AppRestriction)
        .where(AppRestriction.child_profile_id == child_profile_id)
        .order_by(AppRestriction.package_identifier.asc(), AppRestriction.device_id.asc())
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Screen-time policies
# ---------------------------------------------------------------------------
async def create_screen_time_policy(
    session: AsyncSession,
    *,
    child: ChildProfile,
    name: str,
    daily_limit_seconds: int | None,
    timezone: str | None,
    enabled: bool,
    priority: int,
    device_id: uuid.UUID | None,
    schedules: list[tuple[Weekday, time, time, ScheduleAction, list[str], bool]],
    user_id: uuid.UUID,
) -> tuple[ScreenTimePolicy, PolicyChangeOutcome]:
    if device_id is not None:
        await _assert_device_belongs_to_child(session, child=child, device_id=device_id)

    validate_no_overlap([(weekday, start, end) for weekday, start, end, *_ in schedules])
    # Allowlisted packages are exemptions, not restrictions, so the protected
    # package check deliberately does not apply to them.

    duplicate = await session.execute(
        select(ScreenTimePolicy)
        .where(
            ScreenTimePolicy.child_profile_id == child.id,
            ScreenTimePolicy.name == name.strip(),
        )
        .limit(1)
    )
    if duplicate.scalars().first() is not None:
        raise Conflict(
            "A screen-time policy with that name already exists for this child.",
            code=ErrorCode.ALREADY_EXISTS,
        )

    policy = ScreenTimePolicy(
        family_id=child.family_id,
        child_profile_id=child.id,
        device_id=device_id,
        name=name.strip(),
        daily_limit_seconds=daily_limit_seconds,
        timezone=timezone or child.timezone,
        enabled=enabled,
        priority=priority,
        created_by_user_id=user_id,
        revision=1,
    )
    session.add(policy)
    await session.flush()

    for weekday, start, end, action, allowlist, schedule_enabled in schedules:
        session.add(
            ScreenTimeSchedule(
                policy_id=policy.id,
                weekday=weekday,
                start_local_time=start,
                end_local_time=end,
                action=action,
                allowlisted_packages=allowlist,
                enabled=schedule_enabled,
            )
        )
    await session.flush()

    outcome = await bump_policy_version(
        session,
        child=child,
        change_type="screen_time_policy_created",
        change_summary=policy.name,
        changed_by_user_id=user_id,
    )
    return policy, outcome


async def update_screen_time_policy(
    session: AsyncSession,
    *,
    child: ChildProfile,
    policy: ScreenTimePolicy,
    name: str | None,
    daily_limit_seconds: int | None,
    timezone: str | None,
    enabled: bool | None,
    priority: int | None,
    if_revision: int | None,
    user_id: uuid.UUID,
) -> tuple[ScreenTimePolicy, PolicyChangeOutcome]:
    _assert_revision(policy.revision, if_revision)

    if name is not None:
        policy.name = name.strip()
    if daily_limit_seconds is not None:
        policy.daily_limit_seconds = daily_limit_seconds
    if timezone is not None:
        policy.timezone = timezone
    if enabled is not None:
        policy.enabled = enabled
    if priority is not None:
        policy.priority = priority

    policy.revision += 1
    await session.flush()

    outcome = await bump_policy_version(
        session,
        child=child,
        change_type="screen_time_policy_updated",
        change_summary=policy.name,
        changed_by_user_id=user_id,
    )
    return policy, outcome


async def delete_screen_time_policy(
    session: AsyncSession, *, child: ChildProfile, policy: ScreenTimePolicy, user_id: uuid.UUID
) -> PolicyChangeOutcome:
    name = policy.name
    await session.delete(policy)
    await session.flush()
    return await bump_policy_version(
        session,
        child=child,
        change_type="screen_time_policy_deleted",
        change_summary=f"removed {name}",
        changed_by_user_id=user_id,
    )


async def add_schedule(
    session: AsyncSession,
    *,
    child: ChildProfile,
    policy: ScreenTimePolicy,
    weekday: Weekday,
    start: time,
    end: time,
    action: ScheduleAction,
    allowlist: list[str],
    enabled: bool,
    user_id: uuid.UUID,
) -> tuple[ScreenTimeSchedule, PolicyChangeOutcome]:
    existing = await list_schedules(session, policy_id=policy.id)
    candidate = [(row.weekday, row.start_local_time, row.end_local_time) for row in existing] + [
        (weekday, start, end)
    ]
    validate_no_overlap(candidate)

    schedule = ScreenTimeSchedule(
        policy_id=policy.id,
        weekday=weekday,
        start_local_time=start,
        end_local_time=end,
        action=action,
        allowlisted_packages=allowlist,
        enabled=enabled,
    )
    session.add(schedule)
    policy.revision += 1
    await session.flush()

    outcome = await bump_policy_version(
        session,
        child=child,
        change_type="screen_time_schedule_created",
        change_summary=f"{policy.name} {weekday.value}",
        changed_by_user_id=user_id,
    )
    return schedule, outcome


async def update_schedule(
    session: AsyncSession,
    *,
    child: ChildProfile,
    schedule: ScreenTimeSchedule,
    policy: ScreenTimePolicy,
    weekday: Weekday | None,
    start: time | None,
    end: time | None,
    action: ScheduleAction | None,
    allowlist: list[str] | None,
    enabled: bool | None,
    user_id: uuid.UUID,
) -> tuple[ScreenTimeSchedule, PolicyChangeOutcome]:
    new_weekday = weekday or schedule.weekday
    new_start = start or schedule.start_local_time
    new_end = end or schedule.end_local_time
    if new_start == new_end:
        raise Conflict(
            "start_local_time and end_local_time must differ.", code=ErrorCode.SCHEDULE_INVALID
        )

    siblings = [
        (row.weekday, row.start_local_time, row.end_local_time)
        for row in await list_schedules(session, policy_id=policy.id)
        if row.id != schedule.id
    ]
    validate_no_overlap([*siblings, (new_weekday, new_start, new_end)])

    schedule.weekday = new_weekday
    schedule.start_local_time = new_start
    schedule.end_local_time = new_end
    if action is not None:
        schedule.action = action
    if allowlist is not None:
        schedule.allowlisted_packages = allowlist
    if enabled is not None:
        schedule.enabled = enabled

    if (
        schedule.action is ScheduleAction.allow_allowlisted_only
        and not schedule.allowlisted_packages
    ):
        raise Conflict(
            "allow_allowlisted_only needs at least one allowlisted package.",
            code=ErrorCode.SCHEDULE_INVALID,
        )

    policy.revision += 1
    await session.flush()

    outcome = await bump_policy_version(
        session,
        child=child,
        change_type="screen_time_schedule_updated",
        change_summary=f"{policy.name} {schedule.weekday.value}",
        changed_by_user_id=user_id,
    )
    return schedule, outcome


async def delete_schedule(
    session: AsyncSession,
    *,
    child: ChildProfile,
    schedule: ScreenTimeSchedule,
    policy: ScreenTimePolicy,
    user_id: uuid.UUID,
) -> PolicyChangeOutcome:
    weekday = schedule.weekday.value
    await session.delete(schedule)
    policy.revision += 1
    await session.flush()
    return await bump_policy_version(
        session,
        child=child,
        change_type="screen_time_schedule_deleted",
        change_summary=f"{policy.name} {weekday}",
        changed_by_user_id=user_id,
    )


async def list_schedules(
    session: AsyncSession, *, policy_id: uuid.UUID
) -> list[ScreenTimeSchedule]:
    result = await session.execute(
        select(ScreenTimeSchedule).where(ScreenTimeSchedule.policy_id == policy_id)
    )
    return list(result.scalars().all())


async def list_screen_time_policies(
    session: AsyncSession, *, child_profile_id: uuid.UUID
) -> list[ScreenTimePolicy]:
    result = await session.execute(
        select(ScreenTimePolicy)
        .options(selectinload(ScreenTimePolicy.schedules))
        .where(ScreenTimePolicy.child_profile_id == child_profile_id)
        .order_by(ScreenTimePolicy.priority.desc(), ScreenTimePolicy.created_at.asc())
    )
    return list(result.scalars().unique().all())


async def get_screen_time_policy(
    session: AsyncSession, *, policy_id: uuid.UUID
) -> ScreenTimePolicy:
    result = await session.execute(
        select(ScreenTimePolicy)
        .options(selectinload(ScreenTimePolicy.schedules))
        .where(ScreenTimePolicy.id == policy_id)
        .limit(1)
    )
    policy = result.scalars().first()
    if policy is None:
        raise NotFound("Screen-time policy not found.")
    return policy


async def get_schedule(session: AsyncSession, *, schedule_id: uuid.UUID) -> ScreenTimeSchedule:
    row = await session.get(ScreenTimeSchedule, schedule_id)
    if row is None:
        raise NotFound("Schedule not found.")
    return row


# ---------------------------------------------------------------------------
# Website restrictions (feature-gated)
# ---------------------------------------------------------------------------
async def list_website_restrictions(
    session: AsyncSession, *, child_profile_id: uuid.UUID
) -> list[WebsiteRestriction]:
    if not settings.feature_website_restrictions_enabled:
        return []
    result = await session.execute(
        select(WebsiteRestriction)
        .where(WebsiteRestriction.child_profile_id == child_profile_id)
        .order_by(WebsiteRestriction.domain.asc())
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Snapshots and bundles
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ResolvedRestriction:
    package_identifier: str
    action: RestrictionAction
    daily_limit_seconds: int | None


def resolve_restrictions(
    restrictions: list[AppRestriction], *, device_id: uuid.UUID
) -> list[ResolvedRestriction]:
    """Collapse profile-wide and device-scoped rows into one list per package."""
    by_package: dict[str, AppRestriction] = {}
    for row in restrictions:
        if not row.enabled:
            continue
        if row.device_id is not None and row.device_id != device_id:
            continue
        current = by_package.get(row.package_identifier)
        if current is None:
            by_package[row.package_identifier] = row
            continue
        # Device-scoped overrides profile-wide; otherwise the stricter wins.
        current_is_device = current.device_id is not None
        new_is_device = row.device_id is not None
        if (
            new_is_device
            and not current_is_device
            or new_is_device == current_is_device
            and (RESTRICTION_SEVERITY[row.action] < RESTRICTION_SEVERITY[current.action])
        ):
            by_package[row.package_identifier] = row

    return [
        ResolvedRestriction(
            package_identifier=row.package_identifier,
            action=row.action,
            daily_limit_seconds=row.daily_limit_seconds,
        )
        for row in sorted(by_package.values(), key=lambda r: r.package_identifier)
    ]


def applicable_policies(
    policies: list[ScreenTimePolicy], *, device_id: uuid.UUID
) -> list[ScreenTimePolicy]:
    """Enabled policies for this device, highest priority first."""
    selected = [
        policy
        for policy in policies
        if policy.enabled and (policy.device_id is None or policy.device_id == device_id)
    ]
    return sorted(
        selected,
        key=lambda p: (-p.priority, p.created_at),
    )


async def build_device_snapshot(
    session: AsyncSession, *, device: Device, child: ChildProfile
) -> dict:
    """The policy document a device applies.

    Precedence is resolved here, server-side, so the Child App never has to
    reason about conflicting rules - it applies what it is given and reports
    what it could not do.
    """
    restrictions = await list_app_restrictions(session, child_profile_id=child.id)
    policies = await list_screen_time_policies(session, child_profile_id=child.id)
    websites = await list_website_restrictions(session, child_profile_id=child.id)

    resolved = resolve_restrictions(restrictions, device_id=device.id)
    selected_policies = applicable_policies(policies, device_id=device.id)

    notes: list[str] = []
    if not settings.feature_website_restrictions_enabled and websites:
        notes.append("Website restrictions are disabled on this deployment and were not sent.")

    blocked_domains = [
        row.domain
        for row in websites
        if row.enabled and row.mode is WebsiteRestrictionMode.blocklist
    ]
    allowed_domains = [
        row.domain
        for row in websites
        if row.enabled and row.mode is WebsiteRestrictionMode.allowlist
    ]

    return {
        "device_id": device.id,
        "child_profile_id": child.id,
        "policy_version": child.policy_version,
        "generated_at": utcnow(),
        "timezone": child.timezone,
        "app_restrictions": [
            {
                "package_identifier": item.package_identifier,
                "action": item.action,
                "daily_limit_seconds": item.daily_limit_seconds,
            }
            for item in resolved
        ],
        "screen_time_policies": [
            {
                "policy_id": policy.id,
                "name": policy.name,
                "daily_limit_seconds": policy.daily_limit_seconds,
                "timezone": policy.timezone,
                "priority": policy.priority,
                "schedules": [
                    {
                        "weekday": schedule.weekday,
                        "start_local_time": schedule.start_local_time,
                        "end_local_time": schedule.end_local_time,
                        "action": schedule.action,
                        "allowlisted_packages": list(schedule.allowlisted_packages or []),
                        "crosses_midnight": window_crosses_midnight(
                            schedule.start_local_time, schedule.end_local_time
                        ),
                    }
                    for schedule in sorted(policy.schedules, key=lambda s: s.weekday.value)
                    if schedule.enabled
                ],
            }
            for policy in selected_policies
        ],
        "blocked_domains": blocked_domains,
        "allowed_domains": allowed_domains,
        "notes": notes,
    }


async def capability_warnings(
    session: AsyncSession, *, child_profile_id: uuid.UUID, has_restrictions: bool
) -> list[str]:
    """Explain, without guessing, which devices cannot enforce what is set.

    The server does not pretend a rule is active on a device that has reported
    the relevant capability as unsupported.
    """
    if not has_restrictions:
        return []
    devices = await active_devices_for_child(session, child_profile_id=child_profile_id)
    if not devices:
        return ["No active device is linked, so these rules are not being applied anywhere yet."]

    device_ids = [device.id for device in devices]
    result = await session.execute(
        select(DeviceCapability).where(
            DeviceCapability.device_id.in_(device_ids),
            DeviceCapability.capability_key.in_(
                [CapabilityKey.app_blocking, CapabilityKey.screen_time_enforcement]
            ),
        )
    )
    capabilities = list(result.scalars().all())
    reported_device_ids = {row.device_id for row in capabilities}

    warnings: list[str] = []
    unsupported = sum(1 for row in capabilities if row.support is CapabilitySupport.unsupported)
    if unsupported:
        warnings.append(
            f"{unsupported} device capability report(s) say app blocking or screen-time "
            "enforcement is not supported. Those rules will show as unsupported."
        )
    never_reported = len(set(device_ids) - reported_device_ids)
    if never_reported:
        warnings.append(
            f"{never_reported} device(s) have not reported their capabilities yet, so it is "
            "not yet known whether these rules can be enforced there."
        )
    return warnings


async def device_sync_states(
    session: AsyncSession, *, child_profile_id: uuid.UUID, policy_version: int
) -> list[dict]:
    devices = await active_devices_for_child(session, child_profile_id=child_profile_id)
    if not devices:
        return []

    result = await session.execute(
        select(DevicePolicyState).where(
            DevicePolicyState.child_profile_id == child_profile_id,
            DevicePolicyState.policy_version == policy_version,
        )
    )
    states = {row.device_id: row for row in result.scalars().all()}

    return [
        {
            "device_id": device.id,
            "device_label": device.device_label,
            "policy_version": policy_version,
            "applied_policy_version": device.applied_policy_version,
            "sync_status": (
                states[device.id].sync_status if device.id in states else device.policy_sync_status
            ),
            "detail": (
                states[device.id].detail if device.id in states else device.policy_sync_detail
            ),
            "reported_at": (
                states[device.id].reported_at if device.id in states else device.policy_synced_at
            ),
        }
        for device in devices
    ]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
def _assert_revision(current: int, expected: int | None) -> None:
    if expected is not None and expected != current:
        raise Conflict(
            "This policy was changed by someone else. Reload it and try again.",
            code=ErrorCode.VERSION_CONFLICT,
        )


async def _assert_device_belongs_to_child(
    session: AsyncSession, *, child: ChildProfile, device_id: uuid.UUID
) -> Device:
    result = await session.execute(
        select(Device)
        .where(
            Device.id == device_id,
            Device.child_profile_id == child.id,
            Device.family_id == child.family_id,
        )
        .limit(1)
    )
    device = result.scalars().first()
    if device is None:
        # A device id from another family must not be distinguishable from one
        # that does not exist.
        raise NotFound("Device not found for this child profile.")
    return device
