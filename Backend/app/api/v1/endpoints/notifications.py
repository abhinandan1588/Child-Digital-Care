"""Parent push tokens and notification preferences."""

from __future__ import annotations

from fastapi import APIRouter, status

from app.api.deps import CurrentParent, DbSession
from app.core.response import ApiResponse, ok
from app.db.enums import NotificationType
from app.schemas.auth import GenericMessageOut
from app.schemas.notification import (
    NotificationPreferenceOut,
    NotificationPreferenceUpdate,
    PushTokenDelete,
    PushTokenOut,
    PushTokenRegister,
)
from app.services import notification_service

router = APIRouter(tags=["notifications"])


@router.post(
    "/push-token",
    response_model=ApiResponse[PushTokenOut],
    status_code=status.HTTP_201_CREATED,
    summary="Register a parent push token",
)
async def register_push_token(
    payload: PushTokenRegister, principal: CurrentParent, session: DbSession
) -> dict:
    """Only the last six characters of the token are ever returned, so the API
    cannot be used to read back a usable push credential."""
    registration = await notification_service.register_push_token(
        session,
        raw_token=payload.token,
        platform=payload.platform,
        app_version=payload.app_version,
        user_id=principal.id,
    )
    row = registration.token
    return ok(
        PushTokenOut(
            id=row.id,
            platform=row.platform,
            active=row.active,
            app_version=row.app_version,
            created_at=row.created_at,
            updated_at=row.updated_at,
            token_suffix=notification_service.token_suffix(payload.token),
        ),
        message="Push token registered.",
    )


@router.delete(
    "/push-token",
    response_model=ApiResponse[GenericMessageOut],
    summary="Deregister a parent push token",
)
async def delete_push_token(
    payload: PushTokenDelete, principal: CurrentParent, session: DbSession
) -> dict:
    removed = await notification_service.deactivate_push_token(
        session, raw_token=payload.token, user_id=principal.id, reason="client_request"
    )
    return ok(
        GenericMessageOut(detail="Push token removed." if removed else "Token not found."),
        message="Request processed.",
    )


@router.get(
    "/notification-preferences",
    response_model=ApiResponse[list[NotificationPreferenceOut]],
    summary="Get notification preferences",
)
async def get_preferences(principal: CurrentParent, session: DbSession) -> dict:
    """Unset types default to enabled. Security notifications are listed with
    ``always_delivered: true`` and cannot be turned off."""
    stored = await notification_service.get_preferences(session, user_id=principal.id)
    return ok(
        [
            NotificationPreferenceOut(
                notification_type=notification_type,
                enabled=(
                    True
                    if notification_type in notification_service.ALWAYS_DELIVERED
                    else (
                        stored[notification_type].enabled if notification_type in stored else True
                    )
                ),
                quiet_hours=(
                    stored[notification_type].quiet_hours if notification_type in stored else None
                ),
                always_delivered=notification_type in notification_service.ALWAYS_DELIVERED,
            )
            for notification_type in NotificationType
        ]
    )


@router.patch(
    "/notification-preferences",
    response_model=ApiResponse[list[NotificationPreferenceOut]],
    summary="Update notification preferences",
)
async def update_preferences(
    payload: NotificationPreferenceUpdate, principal: CurrentParent, session: DbSession
) -> dict:
    rows = await notification_service.upsert_preferences(
        session,
        user_id=principal.id,
        items=[
            (
                item.notification_type,
                item.enabled,
                item.quiet_hours.model_dump(mode="json") if item.quiet_hours else None,
            )
            for item in payload.preferences
        ],
    )
    return ok(
        [
            NotificationPreferenceOut(
                notification_type=row.notification_type,
                enabled=row.enabled,
                quiet_hours=row.quiet_hours,
                always_delivered=row.notification_type in notification_service.ALWAYS_DELIVERED,
            )
            for row in rows
        ],
        message="Preferences updated.",
    )
