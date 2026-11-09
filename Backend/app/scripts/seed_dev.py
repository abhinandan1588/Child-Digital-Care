"""Seed obviously fake development data.

    python -m app.scripts.seed_dev

Refuses to run unless ``APP_ENV`` is ``development`` or ``test``. Every address
uses the reserved ``.test`` TLD and every password is the same well-known
string, so seeded data can never be mistaken for a real account.
"""

from __future__ import annotations

import asyncio
from datetime import time, timedelta

from app.core.config import AppEnv, settings
from app.core.logging import configure_logging
from app.db.enums import (
    AgeBand,
    BillingInterval,
    CapabilityKey,
    CapabilitySupport,
    DevicePlatform,
    PermissionKey,
    PermissionState,
    RestrictionAction,
    ScheduleAction,
    Weekday,
)
from app.db.models.billing import Plan
from app.db.session import dispose_engine, session_scope
from app.services import (
    auth_service,
    device_service,
    family_service,
    pairing_service,
    policy_service,
    usage_service,
)
from app.utils.time import local_date_for, utcnow

DEV_PASSWORD = "dev-password-not-secret"  # noqa: S105 - deliberately fake
PARENT_EMAIL = "parent@example.test"
SECOND_PARENT_EMAIL = "coparent@example.test"


async def main() -> None:  # noqa: PLR0915 - a linear seed script reads better flat
    configure_logging()

    if settings.app_env not in (AppEnv.development, AppEnv.test):
        raise SystemExit(
            f"Refusing to seed: APP_ENV is '{settings.app_env.value}'. "
            "Seeding is only permitted in development or test."
        )

    try:
        async with session_scope() as session:
            existing = await auth_service.get_user_by_email(session, PARENT_EMAIL)
            if existing is not None:
                print("Development data already present. Nothing to do.")
                return

            # --- Plans (billing stays 'disabled'; these are catalogue rows) ---

            session.add(
                Plan(
                    code="family_monthly",
                    name="Family (monthly)",
                    description="Example plan. No payment provider is configured.",
                    price_minor_units=499,
                    currency="GBP",
                    interval=BillingInterval.month,
                    trial_days=14,
                    max_children=5,
                    max_devices=10,
                    feature_flags={"location": False, "website_restrictions": False},
                    sort_order=1,
                )
            )

            # --- Parent accounts -------------------------------------------
            registration = await auth_service.register_user(
                session,
                email=PARENT_EMAIL,
                password=DEV_PASSWORD,
                display_name="Dev Parent",
                timezone="Europe/London",
                locale="en",
                terms_version="dev-2026-01",
                privacy_version="dev-2026-01",
            )
            parent = registration.user
            if registration.verification_token:
                await auth_service.verify_email(session, raw_token=registration.verification_token)

            second = await auth_service.register_user(
                session,
                email=SECOND_PARENT_EMAIL,
                password=DEV_PASSWORD,
                display_name="Dev Co-parent",
                timezone="Europe/London",
                locale="en",
                terms_version="dev-2026-01",
                privacy_version="dev-2026-01",
            )
            if second.verification_token:
                await auth_service.verify_email(session, raw_token=second.verification_token)

            # --- Family and child ------------------------------------------
            access = await family_service.create_family(
                session, owner=parent, name="Dev Family", timezone="Europe/London"
            )
            child = await family_service.create_child_profile(
                session,
                access=access,
                actor=parent,
                display_name="Dev Child",
                age_band=AgeBand.age_9_12,
                timezone="Europe/London",
                avatar_key=None,
            )

            # --- Paired device ---------------------------------------------
            invitation = await pairing_service.create_invitation(
                session,
                child=child,
                created_by_user_id=parent.id,
                expires_in_minutes=60,
                include_short_code=True,
                device_label="Dev Child Phone",
            )
            claim = await pairing_service.claim_invitation(
                session,
                claim_token=invitation.claim_token,
                short_code=None,
                platform=DevicePlatform.android,
                app_version="1.0.0-dev",
                os_version="Android 16",
                device_label="Dev Child Phone",
                device_model="Pixel 8",
                manufacturer="Google",
                timezone="Europe/London",
                install_id="dev-install-0000000001",
                disclosure_version="dev-2026-01",
            )
            device = claim.device

            await device_service.register_device(
                session,
                device=device,
                app_version="1.0.0-dev",
                os_version="Android 16",
                device_label="Dev Child Phone",
                device_model="Pixel 8",
                manufacturer="Google",
                timezone="Europe/London",
                install_id="dev-install-0000000001",
            )
            await device_service.report_capabilities(
                session,
                device=device,
                app_version="1.0.0-dev",
                items=[
                    (
                        CapabilityKey.app_usage_stats,
                        CapabilitySupport.supported,
                        PermissionState.granted,
                        35,
                        None,
                    ),
                    (
                        CapabilityKey.app_blocking,
                        CapabilitySupport.supported,
                        PermissionState.granted,
                        35,
                        None,
                    ),
                    (
                        CapabilityKey.location_fine,
                        CapabilitySupport.unsupported,
                        PermissionState.not_requested,
                        35,
                        "Location is disabled on this deployment.",
                    ),
                ],
            )
            await device_service.report_permissions(
                session,
                device=device,
                app_version="1.0.0-dev",
                items=[
                    (PermissionKey.usage_stats, PermissionState.granted, None),
                    (PermissionKey.post_notifications, PermissionState.granted, None),
                ],
            )

            # --- Policies ---------------------------------------------------
            await policy_service.create_app_restriction(
                session,
                child=child,
                package_identifier="com.example.video",
                display_label="Example Video",
                action=RestrictionAction.block,
                daily_limit_seconds=None,
                enabled=True,
                device_id=None,
                user_id=parent.id,
            )
            await policy_service.create_screen_time_policy(
                session,
                child=child,
                name="School nights",
                daily_limit_seconds=7200,
                timezone="Europe/London",
                enabled=True,
                priority=100,
                device_id=None,
                schedules=[
                    (
                        weekday,
                        time(21, 0),
                        time(7, 0),
                        ScheduleAction.block_all,
                        ["com.google.android.apps.messaging"],
                        True,
                    )
                    for weekday in (
                        Weekday.monday,
                        Weekday.tuesday,
                        Weekday.wednesday,
                        Weekday.thursday,
                        Weekday.sunday,
                    )
                ],
                user_id=parent.id,
            )

            # --- Reported usage --------------------------------------------
            # The device's own timezone decides what "today" is; using the
            # host's local date would be rejected as a future date whenever the
            # two disagree.
            today = local_date_for("Europe/London")
            await usage_service.ingest_daily_summaries(
                session,
                device=device,
                child=child,
                days=[
                    usage_service.SubmittedDay(
                        local_date=today - timedelta(days=offset),
                        timezone="Europe/London",
                        total_screen_time_seconds=3600 + offset * 900,
                        unlock_count=40 + offset,
                        category_totals={"social": 1200, "games": 900, "education": 600},
                        app_summaries=[
                            ("com.example.video", "Example Video", "video", 1800, 12),
                            ("com.example.game", "Example Game", "games", 900, 6),
                        ],
                        source_app_version="1.0.0-dev",
                    )
                    for offset in range(3)
                ],
            )

        print("Development data seeded.")
        print(f"  Parent:    {PARENT_EMAIL} / {DEV_PASSWORD}")
        print(f"  Co-parent: {SECOND_PARENT_EMAIL} / {DEV_PASSWORD}")
        print(f"  Family:    Dev Family    Child: Dev Child    Device: {device.id}")
        print(f"  Seeded at: {utcnow().isoformat()}")
        print("  Create an admin with: python -m app.scripts.create_admin --email ...")
    finally:
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())
