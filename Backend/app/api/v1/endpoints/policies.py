"""Policy and schedule endpoints (parent-facing).

Every mutation returns a :class:`PolicyMutationResult` whose ``sync_status`` is
``pending_sync``. That is deliberate: the server has saved the parent's intent
and queued a sync, and it does not claim the rule is in force until a device
reports back.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import (
    DbSession,
    VerifiedParent,
    require_child_access,
)
from app.core.config import settings
from app.core.errors import NotFound
from app.core.permissions import FamilyPermission
from app.core.response import ApiResponse, ok
from app.db.models.family import ChildProfile
from app.schemas.auth import GenericMessageOut
from app.schemas.policy import (
    AppRestrictionCreate,
    AppRestrictionCreated,
    AppRestrictionOut,
    AppRestrictionUpdate,
    DeviceSyncStateOut,
    PolicyBundleOut,
    PolicyMutationResult,
    ScreenTimePolicyCreate,
    ScreenTimePolicyCreated,
    ScreenTimePolicyOut,
    ScreenTimePolicyUpdate,
    ScreenTimeScheduleCreate,
    ScreenTimeScheduleOut,
    ScreenTimeScheduleUpdate,
    WebsiteRestrictionOut,
)
from app.services import family_service, policy_service
from app.utils.time import window_crosses_midnight

router = APIRouter(tags=["policies"])

FamilyAccess = family_service.FamilyAccess
ChildContext = tuple[FamilyAccess, ChildProfile]

PolicyRead = Annotated[ChildContext, Depends(require_child_access(FamilyPermission.POLICIES_READ))]
PolicyManage = Annotated[
    ChildContext, Depends(require_child_access(FamilyPermission.POLICIES_MANAGE))
]


def restriction_out(row) -> AppRestrictionOut:  # noqa: ANN001
    return AppRestrictionOut(
        id=row.id,
        child_profile_id=row.child_profile_id,
        device_id=row.device_id,
        package_identifier=row.package_identifier,
        display_label=row.display_label,
        action=row.action,
        daily_limit_seconds=row.daily_limit_seconds,
        enabled=row.enabled,
        revision=row.revision,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def schedule_out(row) -> ScreenTimeScheduleOut:  # noqa: ANN001
    return ScreenTimeScheduleOut(
        id=row.id,
        policy_id=row.policy_id,
        weekday=row.weekday,
        start_local_time=row.start_local_time,
        end_local_time=row.end_local_time,
        action=row.action,
        allowlisted_packages=list(row.allowlisted_packages or []),
        enabled=row.enabled,
        crosses_midnight=window_crosses_midnight(row.start_local_time, row.end_local_time),
    )


def policy_out(row) -> ScreenTimePolicyOut:  # noqa: ANN001
    return ScreenTimePolicyOut(
        id=row.id,
        child_profile_id=row.child_profile_id,
        device_id=row.device_id,
        name=row.name,
        daily_limit_seconds=row.daily_limit_seconds,
        timezone=row.timezone,
        enabled=row.enabled,
        priority=row.priority,
        revision=row.revision,
        created_at=row.created_at,
        updated_at=row.updated_at,
        schedules=[
            schedule_out(item) for item in sorted(row.schedules, key=lambda s: s.weekday.value)
        ],
    )


def mutation_result(outcome: policy_service.PolicyChangeOutcome) -> PolicyMutationResult:
    return PolicyMutationResult(
        policy_version=outcome.policy_version,
        sync_status=outcome.sync_status,
        devices_notified=outcome.devices_notified,
        commands_queued=outcome.commands_queued,
    )


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------
@router.get(
    "/children/{child_profile_id}/policies",
    response_model=ApiResponse[PolicyBundleOut],
    summary="Everything set for one child, plus real per-device sync state",
)
async def get_policy_bundle(session: DbSession, context: PolicyRead) -> dict:
    """``device_sync_states`` reflects device acknowledgements only.

    ``capability_warnings`` names the devices that have told us they cannot
    enforce what is configured, so the UI can say so instead of implying the
    rules are active everywhere.
    """
    _, child = context
    restrictions = await policy_service.list_app_restrictions(session, child_profile_id=child.id)
    policies = await policy_service.list_screen_time_policies(session, child_profile_id=child.id)
    websites = await policy_service.list_website_restrictions(session, child_profile_id=child.id)
    sync_states = await policy_service.device_sync_states(
        session, child_profile_id=child.id, policy_version=child.policy_version
    )
    warnings = await policy_service.capability_warnings(
        session,
        child_profile_id=child.id,
        has_restrictions=bool(restrictions or policies),
    )

    return ok(
        PolicyBundleOut(
            child_profile_id=child.id,
            policy_version=child.policy_version,
            app_restrictions=[restriction_out(row) for row in restrictions],
            screen_time_policies=[policy_out(row) for row in policies],
            website_restrictions=[
                WebsiteRestrictionOut(
                    id=row.id,
                    child_profile_id=row.child_profile_id,
                    domain=row.domain,
                    mode=row.mode,
                    enabled=row.enabled,
                    created_at=row.created_at,
                )
                for row in websites
            ],
            website_restrictions_enabled=settings.feature_website_restrictions_enabled,
            device_sync_states=[DeviceSyncStateOut(**state) for state in sync_states],
            capability_warnings=warnings,
        )
    )


# ---------------------------------------------------------------------------
# App restrictions
# ---------------------------------------------------------------------------
@router.post(
    "/children/{child_profile_id}/app-restrictions",
    response_model=ApiResponse[AppRestrictionCreated],
    status_code=status.HTTP_201_CREATED,
    summary="Create an app restriction",
)
async def create_app_restriction(
    payload: AppRestrictionCreate,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    """Saved and queued for synchronisation.

    Packages required for emergency calling, device settings, or this app
    itself are refused. The response says ``pending_sync``: it does not claim
    the app is blocked yet.
    """
    _, child = context
    restriction, outcome = await policy_service.create_app_restriction(
        session,
        child=child,
        package_identifier=payload.package_identifier,
        display_label=payload.display_label,
        action=payload.action,
        daily_limit_seconds=payload.daily_limit_seconds,
        enabled=payload.enabled,
        device_id=payload.device_id,
        user_id=principal.id,
    )
    return ok(
        AppRestrictionCreated(
            **mutation_result(outcome).model_dump(),
            restriction_id=restriction.id,
            restriction=restriction_out(restriction),
        ),
        message="Restriction saved and queued for synchronisation.",
    )


@router.get(
    "/children/{child_profile_id}/app-restrictions",
    response_model=ApiResponse[list[AppRestrictionOut]],
    summary="List app restrictions",
)
async def list_app_restrictions(session: DbSession, context: PolicyRead) -> dict:
    _, child = context
    rows = await policy_service.list_app_restrictions(session, child_profile_id=child.id)
    return ok([restriction_out(row) for row in rows])


async def _restriction_in_scope(session, child, restriction_id):  # noqa: ANN001
    restriction = await policy_service.get_app_restriction(session, restriction_id=restriction_id)
    if restriction.child_profile_id != child.id:
        # Never reveal that the id exists in another family.
        raise NotFound("Restriction not found.")
    return restriction


@router.patch(
    "/children/{child_profile_id}/app-restrictions/{restriction_id}",
    response_model=ApiResponse[AppRestrictionCreated],
    summary="Update an app restriction",
)
async def update_app_restriction(
    restriction_id: uuid.UUID,
    payload: AppRestrictionUpdate,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    """``if_revision`` gives optimistic concurrency: supply the revision you
    read and the update is rejected if another guardian changed it meanwhile."""
    _, child = context
    restriction = await _restriction_in_scope(session, child, restriction_id)
    restriction, outcome = await policy_service.update_app_restriction(
        session,
        child=child,
        restriction=restriction,
        display_label=payload.display_label,
        action=payload.action,
        daily_limit_seconds=payload.daily_limit_seconds,
        enabled=payload.enabled,
        if_revision=payload.if_revision,
        user_id=principal.id,
    )
    return ok(
        AppRestrictionCreated(
            **mutation_result(outcome).model_dump(),
            restriction_id=restriction.id,
            restriction=restriction_out(restriction),
        ),
        message="Restriction updated and queued for synchronisation.",
    )


@router.delete(
    "/children/{child_profile_id}/app-restrictions/{restriction_id}",
    response_model=ApiResponse[PolicyMutationResult],
    summary="Delete an app restriction",
)
async def delete_app_restriction(
    restriction_id: uuid.UUID,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    _, child = context
    restriction = await _restriction_in_scope(session, child, restriction_id)
    outcome = await policy_service.delete_app_restriction(
        session, child=child, restriction=restriction, user_id=principal.id
    )
    return ok(mutation_result(outcome), message="Restriction removed and queued for sync.")


# ---------------------------------------------------------------------------
# Screen-time policies
# ---------------------------------------------------------------------------
@router.post(
    "/children/{child_profile_id}/screen-time-policies",
    response_model=ApiResponse[ScreenTimePolicyCreated],
    status_code=status.HTTP_201_CREATED,
    summary="Create a screen-time policy",
)
async def create_screen_time_policy(
    payload: ScreenTimePolicyCreate,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    """Schedules carry local wall-clock intent plus an IANA timezone, so a 21:00
    bedtime stays 21:00 across a daylight-saving change. Two windows that
    overlap on the same weekday inside one policy are rejected."""
    _, child = context
    policy, outcome = await policy_service.create_screen_time_policy(
        session,
        child=child,
        name=payload.name,
        daily_limit_seconds=payload.daily_limit_seconds,
        timezone=payload.timezone,
        enabled=payload.enabled,
        priority=payload.priority,
        device_id=payload.device_id,
        schedules=[
            (
                item.weekday,
                item.start_local_time,
                item.end_local_time,
                item.action,
                item.allowlisted_packages,
                item.enabled,
            )
            for item in payload.schedules
        ],
        user_id=principal.id,
    )
    loaded = await policy_service.get_screen_time_policy(session, policy_id=policy.id)
    return ok(
        ScreenTimePolicyCreated(
            **mutation_result(outcome).model_dump(),
            policy_id=policy.id,
            policy=policy_out(loaded),
        ),
        message="Screen-time policy saved and queued for synchronisation.",
    )


@router.get(
    "/children/{child_profile_id}/screen-time-policies",
    response_model=ApiResponse[list[ScreenTimePolicyOut]],
    summary="List screen-time policies",
)
async def list_screen_time_policies(session: DbSession, context: PolicyRead) -> dict:
    _, child = context
    rows = await policy_service.list_screen_time_policies(session, child_profile_id=child.id)
    return ok([policy_out(row) for row in rows])


async def _policy_in_scope(session, child, policy_id):  # noqa: ANN001
    policy = await policy_service.get_screen_time_policy(session, policy_id=policy_id)
    if policy.child_profile_id != child.id:
        raise NotFound("Screen-time policy not found.")
    return policy


@router.patch(
    "/children/{child_profile_id}/screen-time-policies/{policy_id}",
    response_model=ApiResponse[ScreenTimePolicyCreated],
    summary="Update a screen-time policy",
)
async def update_screen_time_policy(
    policy_id: uuid.UUID,
    payload: ScreenTimePolicyUpdate,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    _, child = context
    policy = await _policy_in_scope(session, child, policy_id)
    policy, outcome = await policy_service.update_screen_time_policy(
        session,
        child=child,
        policy=policy,
        name=payload.name,
        daily_limit_seconds=payload.daily_limit_seconds,
        timezone=payload.timezone,
        enabled=payload.enabled,
        priority=payload.priority,
        if_revision=payload.if_revision,
        user_id=principal.id,
    )
    loaded = await policy_service.get_screen_time_policy(session, policy_id=policy.id)
    return ok(
        ScreenTimePolicyCreated(
            **mutation_result(outcome).model_dump(),
            policy_id=policy.id,
            policy=policy_out(loaded),
        ),
        message="Screen-time policy updated and queued for synchronisation.",
    )


@router.delete(
    "/children/{child_profile_id}/screen-time-policies/{policy_id}",
    response_model=ApiResponse[PolicyMutationResult],
    summary="Delete a screen-time policy",
)
async def delete_screen_time_policy(
    policy_id: uuid.UUID,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    _, child = context
    policy = await _policy_in_scope(session, child, policy_id)
    outcome = await policy_service.delete_screen_time_policy(
        session, child=child, policy=policy, user_id=principal.id
    )
    return ok(mutation_result(outcome), message="Policy removed and queued for sync.")


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------
@router.post(
    "/children/{child_profile_id}/screen-time-policies/{policy_id}/schedules",
    response_model=ApiResponse[ScreenTimeScheduleOut],
    status_code=status.HTTP_201_CREATED,
    summary="Add a schedule window",
)
async def add_schedule(
    policy_id: uuid.UUID,
    payload: ScreenTimeScheduleCreate,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    """An end time at or before the start means the window crosses midnight
    (a 21:00-07:00 bedtime)."""
    _, child = context
    policy = await _policy_in_scope(session, child, policy_id)
    schedule, outcome = await policy_service.add_schedule(
        session,
        child=child,
        policy=policy,
        weekday=payload.weekday,
        start=payload.start_local_time,
        end=payload.end_local_time,
        action=payload.action,
        allowlist=payload.allowlisted_packages,
        enabled=payload.enabled,
        user_id=principal.id,
    )
    return ok(
        schedule_out(schedule),
        message="Schedule added and queued for synchronisation.",
        policy_version=outcome.policy_version,
    )


async def _schedule_in_scope(session, child, policy_id, schedule_id):  # noqa: ANN001
    policy = await _policy_in_scope(session, child, policy_id)
    schedule = await policy_service.get_schedule(session, schedule_id=schedule_id)
    if schedule.policy_id != policy.id:
        raise NotFound("Schedule not found.")
    return policy, schedule


@router.patch(
    "/children/{child_profile_id}/screen-time-policies/{policy_id}/schedules/{schedule_id}",
    response_model=ApiResponse[ScreenTimeScheduleOut],
    summary="Update a schedule window",
)
async def update_schedule(
    policy_id: uuid.UUID,
    schedule_id: uuid.UUID,
    payload: ScreenTimeScheduleUpdate,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    _, child = context
    policy, schedule = await _schedule_in_scope(session, child, policy_id, schedule_id)
    schedule, outcome = await policy_service.update_schedule(
        session,
        child=child,
        schedule=schedule,
        policy=policy,
        weekday=payload.weekday,
        start=payload.start_local_time,
        end=payload.end_local_time,
        action=payload.action,
        allowlist=payload.allowlisted_packages,
        enabled=payload.enabled,
        user_id=principal.id,
    )
    return ok(
        schedule_out(schedule),
        message="Schedule updated and queued for synchronisation.",
        policy_version=outcome.policy_version,
    )


@router.delete(
    "/children/{child_profile_id}/screen-time-policies/{policy_id}/schedules/{schedule_id}",
    response_model=ApiResponse[PolicyMutationResult],
    summary="Delete a schedule window",
)
async def delete_schedule(
    policy_id: uuid.UUID,
    schedule_id: uuid.UUID,
    principal: VerifiedParent,
    session: DbSession,
    context: PolicyManage,
) -> dict:
    _, child = context
    policy, schedule = await _schedule_in_scope(session, child, policy_id, schedule_id)
    outcome = await policy_service.delete_schedule(
        session, child=child, schedule=schedule, policy=policy, user_id=principal.id
    )
    return ok(mutation_result(outcome), message="Schedule removed and queued for sync.")


# ---------------------------------------------------------------------------
# Website restrictions (feature-gated)
# ---------------------------------------------------------------------------
@router.get(
    "/children/{child_profile_id}/website-restrictions",
    response_model=ApiResponse[list[WebsiteRestrictionOut]],
    summary="List website restrictions",
)
async def list_website_restrictions(session: DbSession, context: PolicyRead) -> dict:
    """Returns an empty list while ``FEATURE_WEBSITE_RESTRICTIONS_ENABLED`` is
    false. On Android there is no general, policy-compliant way to filter web
    content across every browser, so the feature stays off until the Child App
    has a supported implementation. See docs/FEATURE_CAPABILITY_MATRIX.md."""
    _, child = context
    rows = await policy_service.list_website_restrictions(session, child_profile_id=child.id)
    return ok(
        [
            WebsiteRestrictionOut(
                id=row.id,
                child_profile_id=row.child_profile_id,
                domain=row.domain,
                mode=row.mode,
                enabled=row.enabled,
                created_at=row.created_at,
            )
            for row in rows
        ],
        message=(
            "Website restrictions are enabled."
            if settings.feature_website_restrictions_enabled
            else "Website restrictions are disabled for this deployment."
        ),
    )


@router.get(
    "/children/{child_profile_id}/policy-versions/current",
    response_model=ApiResponse[GenericMessageOut],
    summary="The current policy version number",
)
async def current_policy_version(session: DbSession, context: PolicyRead) -> dict:
    _, child = context
    return ok(
        GenericMessageOut(detail=str(child.policy_version)),
        message="Current policy version.",
        policy_version=child.policy_version,
    )
