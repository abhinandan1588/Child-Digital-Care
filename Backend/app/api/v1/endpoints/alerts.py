"""Alert endpoints (parent-facing)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import CurrentParent, DbSession, VerifiedParent
from app.core.permissions import FamilyPermission
from app.core.response import ApiResponse, Page, PageInfo, ok
from app.db.enums import AlertSeverity, AlertStatus
from app.db.models.usage import Alert
from app.repositories.base import paginate_by_timestamp
from app.schemas.alert import AlertOut, AlertUpdate
from app.schemas.common import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.services import alert_service, family_service

router = APIRouter(tags=["alerts"])

FamilyAccess = family_service.FamilyAccess


def alert_out(row: Alert) -> AlertOut:
    return AlertOut(
        id=row.id,
        family_id=row.family_id,
        child_profile_id=row.child_profile_id,
        device_id=row.device_id,
        alert_type=row.alert_type,
        severity=row.severity,
        status=row.status,
        title=row.title,
        message=row.message,
        occurred_at=row.occurred_at,
        acknowledged_at=row.acknowledged_at,
        resolved_at=row.resolved_at,
        created_at=row.created_at,
        alert_metadata=row.alert_metadata,
    )


async def _readable_family_ids(session, user_id: uuid.UUID) -> list[uuid.UUID]:  # noqa: ANN001
    memberships = await family_service.list_user_families(session, user_id=user_id)
    return [
        family.id
        for family, member in memberships
        if FamilyAccess(family=family, member=member).can(FamilyPermission.ALERTS_READ)
    ]


@router.get(
    "/alerts",
    response_model=ApiResponse[Page[AlertOut]],
    summary="List alerts",
)
async def list_alerts(
    principal: CurrentParent,
    session: DbSession,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Annotated[AlertSeverity | None, Query()] = None,
    child_profile_id: Annotated[uuid.UUID | None, Query()] = None,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> dict:
    """Cursor-paginated, newest first.

    Scoped to families where the caller holds ``alerts.read``; the cursor is
    opaque and carries only sort keys, so it cannot widen that scope.
    """
    family_ids = await _readable_family_ids(session, principal.id)
    if not family_ids:
        return ok(Page[AlertOut](items=[], page_info=PageInfo(limit=limit)))

    statement = select(Alert).where(Alert.family_id.in_(family_ids))
    if status_filter is not None:
        statement = statement.where(Alert.status == status_filter)
    if severity is not None:
        statement = statement.where(Alert.severity == severity)
    if child_profile_id is not None:
        statement = statement.where(Alert.child_profile_id == child_profile_id)
    if device_id is not None:
        statement = statement.where(Alert.device_id == device_id)

    page = await paginate_by_timestamp(
        session,
        statement,
        timestamp_column=Alert.occurred_at,
        id_column=Alert.id,
        cursor=cursor,
        limit=limit,
    )
    return ok(
        Page[AlertOut](
            items=[alert_out(row) for row in page.items],
            page_info=PageInfo(next_cursor=page.next_cursor, has_more=page.has_more, limit=limit),
        )
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=ApiResponse[AlertOut],
    summary="Get one alert",
)
async def get_alert(alert_id: uuid.UUID, principal: CurrentParent, session: DbSession) -> dict:
    family_ids = await _readable_family_ids(session, principal.id)
    alert = await alert_service.get_alert(session, alert_id=alert_id, family_ids=family_ids)
    return ok(alert_out(alert))


@router.patch(
    "/alerts/{alert_id}",
    response_model=ApiResponse[AlertOut],
    summary="Acknowledge, resolve or dismiss an alert",
)
async def update_alert(
    alert_id: uuid.UUID,
    payload: AlertUpdate,
    principal: VerifiedParent,
    session: DbSession,
) -> dict:
    """Requires ``alerts.manage``. An alert cannot be reopened, so the history
    of who closed what stays intact."""
    memberships = await family_service.list_user_families(session, user_id=principal.id)
    manageable = [
        family.id
        for family, member in memberships
        if FamilyAccess(family=family, member=member).can(FamilyPermission.ALERTS_MANAGE)
    ]
    alert = await alert_service.get_alert(session, alert_id=alert_id, family_ids=manageable)
    await alert_service.update_alert_status(
        session, alert=alert, status=payload.status, user_id=principal.id
    )
    return ok(alert_out(alert), message="Alert updated.")
