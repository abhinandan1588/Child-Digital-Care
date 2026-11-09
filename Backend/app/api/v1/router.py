"""Assembly of the versioned API.

Route groups are mounted in a fixed order so the generated OpenAPI document is
stable, and tags map onto the three client surfaces documented in
``docs/INTEGRATION_GUIDE.md``:

* ``auth``, ``families``, ``children``, ``pairing``, ``devices``, ``policies``,
  ``usage``, ``alerts``, ``notifications``, ``location``, ``billing``,
  ``privacy``, ``realtime`` - Parent App.
* ``device``, ``device-auth`` - Child App.
* ``admin`` - Admin Dashboard.

The location group is mounted unconditionally so that the API answers
``403 FEATURE_DISABLED`` when the feature is off, rather than ``404``, which a
client could not distinguish from a bad path.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import (
    admin,
    alerts,
    auth,
    billing,
    children,
    device_api,
    devices,
    families,
    location,
    notifications,
    pairing,
    policies,
    privacy,
    realtime,
    usage,
)

api_router = APIRouter()

# --- Parent App ------------------------------------------------------------
api_router.include_router(auth.router)
api_router.include_router(families.router)
api_router.include_router(children.router)
api_router.include_router(pairing.router)
api_router.include_router(devices.router)
api_router.include_router(policies.router)
api_router.include_router(usage.router)
api_router.include_router(alerts.router)
api_router.include_router(notifications.router)
api_router.include_router(location.router)
api_router.include_router(billing.router)
api_router.include_router(privacy.router)
api_router.include_router(realtime.router)

# --- Child App -------------------------------------------------------------
api_router.include_router(device_api.auth_router)
api_router.include_router(device_api.router)

# --- Admin Dashboard -------------------------------------------------------
api_router.include_router(admin.router)

__all__ = ["api_router"]
