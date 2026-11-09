"""Parent-facing usage reports."""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import ClientIp, DbSession, VerifiedParent, require_child_access
from app.core.errors import ValidationFailed
from app.core.permissions import FamilyPermission
from app.core.response import ApiResponse, ok
from app.db.enums import AuditActorType
from app.db.models.family import ChildProfile
from app.schemas.usage import (
    AppUsageOut,
    DailySummaryDetailOut,
    DailySummaryOut,
    UsageOverviewOut,
)
from app.services import audit_service, family_service, usage_service
from app.services.audit_service import AuditAction
from app.utils.time import local_date_for

router = APIRouter(tags=["usage"])

FamilyAccess = family_service.FamilyAccess
ChildContext = tuple[FamilyAccess, ChildProfile]
UsageRead = Annotated[ChildContext, Depends(require_child_access(FamilyPermission.USAGE_READ))]

MAX_RANGE_DAYS = 92


def _resolve_range(child: ChildProfile, start: date | None, end: date | None) -> tuple[date, date]:
    """Default to the last 7 days in the child's own timezone."""
    today = local_date_for(child.timezone)
    resolved_end = end or today
    resolved_start = start or (resolved_end - timedelta(days=6))
    if resolved_start > resolved_end:
        raise ValidationFailed(
            "The start date must not be after the end date.",
            details=[{"field": "start", "issue": "start is after end"}],
        )
    if (resolved_end - resolved_start).days + 1 > MAX_RANGE_DAYS:
        raise ValidationFailed(
            f"The requested range exceeds {MAX_RANGE_DAYS} days.",
            details=[{"field": "start", "issue": f"range limited to {MAX_RANGE_DAYS} days"}],
        )
    return resolved_start, resolved_end


def summary_out(row) -> DailySummaryOut:  # noqa: ANN001
    return DailySummaryOut(
        id=row.id,
        device_id=row.device_id,
        child_profile_id=row.child_profile_id,
        local_date=row.local_date,
        timezone=row.timezone,
        total_screen_time_seconds=row.total_screen_time_seconds,
        unlock_count=row.unlock_count,
        category_totals={str(k): int(v) for k, v in (row.category_totals or {}).items()},
        received_at=row.received_at,
    )


@router.get(
    "/children/{child_profile_id}/usage",
    response_model=ApiResponse[UsageOverviewOut],
    summary="Aggregated usage for a date range",
)
async def usage_overview(
    principal: VerifiedParent,
    session: DbSession,
    client_ip: ClientIp,
    context: UsageRead,
    start: Annotated[date | None, Query(description="Local start date (inclusive).")] = None,
    end: Annotated[date | None, Query(description="Local end date (inclusive).")] = None,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict:
    """All figures are device-reported.

    ``days_missing_data`` lists dates no device has reported, and
    ``data_completeness_note`` is set when the range is incomplete, so a partial
    total is never presented as the whole picture.
    """
    access, child = context
    range_start, range_end = _resolve_range(child, start, end)

    overview = await usage_service.build_overview(
        session, child=child, start=range_start, end=range_end, device_id=device_id
    )
    await audit_service.record(
        session,
        action=AuditAction.USAGE_READ,
        actor_type=AuditActorType.parent_user,
        actor_id=principal.id,
        target_type="child_profile",
        target_id=child.id,
        family_id=access.family_id,
        client_ip=client_ip,
        metadata={"days": (range_end - range_start).days + 1},
    )
    return ok(
        UsageOverviewOut(
            child_profile_id=child.id,
            range_start=overview.range_start,
            range_end=overview.range_end,
            timezone=overview.timezone,
            total_screen_time_seconds=overview.total_screen_time_seconds,
            average_daily_seconds=overview.average_daily_seconds,
            days_with_data=overview.days_with_data,
            days_missing_data=overview.days_missing_data,
            category_totals=overview.category_totals,
            top_apps=[
                AppUsageOut(
                    package_identifier=package,
                    display_label=label,
                    category=category,
                    foreground_seconds=seconds,
                    launch_count=launches,
                )
                for package, label, category, seconds, launches in overview.top_apps
            ],
            data_completeness_note=overview.data_completeness_note,
        )
    )


@router.get(
    "/children/{child_profile_id}/usage/daily",
    response_model=ApiResponse[list[DailySummaryOut]],
    summary="Per-day usage totals",
)
async def usage_daily(
    session: DbSession,
    context: UsageRead,
    start: Annotated[date | None, Query()] = None,
    end: Annotated[date | None, Query()] = None,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict:
    _, child = context
    range_start, range_end = _resolve_range(child, start, end)
    rows = await usage_service.list_daily_summaries(
        session,
        child_profile_id=child.id,
        start=range_start,
        end=range_end,
        device_id=device_id,
    )
    return ok([summary_out(row) for row in rows])


@router.get(
    "/children/{child_profile_id}/usage/apps",
    response_model=ApiResponse[list[DailySummaryDetailOut]],
    summary="Per-app breakdown for one day",
)
async def usage_apps(
    session: DbSession,
    context: UsageRead,
    local_date: Annotated[
        date | None, Query(description="Defaults to today in the child's timezone.")
    ] = None,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
) -> dict:
    """One entry per reporting device, so a child with two devices shows both
    rather than a silently merged total."""
    _, child = context
    target = local_date or local_date_for(child.timezone)
    rows = await usage_service.get_daily_summary_detail(
        session, child_profile_id=child.id, local_date=target, device_id=device_id
    )
    return ok(
        [
            DailySummaryDetailOut(
                **summary_out(row).model_dump(),
                app_summaries=[
                    AppUsageOut(
                        package_identifier=item.package_identifier,
                        display_label=item.display_label,
                        category=item.category,
                        foreground_seconds=item.foreground_seconds,
                        launch_count=item.launch_count,
                    )
                    for item in sorted(
                        row.app_summaries,
                        key=lambda item: item.foreground_seconds,
                        reverse=True,
                    )
                ],
            )
            for row in rows
        ]
    )
