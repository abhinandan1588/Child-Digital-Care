"""ORM model registry.

Importing this package registers every mapped class on ``Base.metadata``.
Alembic's ``env.py`` and the test fixtures both rely on that, so new model
modules must be imported here.
"""

from __future__ import annotations

from app.db.base import Base
from app.db.models.admin import (
    AdminPermissionRow,
    AdminRole,
    AdminRolePermission,
    AdminSession,
    AdminUser,
    AdminUserRole,
)
from app.db.models.audit import (
    AuditLog,
    ConsentRecord,
    IdempotencyRecord,
    PrivacyRequest,
)
from app.db.models.billing import (
    PaymentWebhookEvent,
    Plan,
    Subscription,
    SubscriptionEvent,
)
from app.db.models.command import (
    DeviceCommand,
    DeviceCommandAttempt,
    DeviceEvent,
    DeviceSyncCursor,
    OutboxEvent,
)
from app.db.models.device import (
    Device,
    DeviceCapability,
    DevicePermissionReport,
    DeviceSession,
    PairingInvitation,
)
from app.db.models.family import (
    ChildProfile,
    Family,
    FamilyMember,
    GuardianInvitation,
)
from app.db.models.identity import (
    EmailVerificationToken,
    PasswordResetToken,
    User,
    UserSession,
)
from app.db.models.location import LocationSample
from app.db.models.notification import (
    NotificationDelivery,
    NotificationPreference,
    PushToken,
    WebSocketConnection,
)
from app.db.models.policy import (
    AppCatalogEntry,
    AppRestriction,
    DevicePolicyState,
    PolicyVersion,
    ScreenTimePolicy,
    ScreenTimeSchedule,
    WebsiteRestriction,
)
from app.db.models.support import (
    AbuseReport,
    SupportTicket,
    SupportTicketMessage,
)
from app.db.models.usage import (
    Alert,
    AppUsageSummary,
    UsageDailySummary,
)

__all__ = [
    "AbuseReport",
    "AdminPermissionRow",
    "AdminRole",
    "AdminRolePermission",
    "AdminSession",
    "AdminUser",
    "AdminUserRole",
    "Alert",
    "AppCatalogEntry",
    "AppRestriction",
    "AppUsageSummary",
    "AuditLog",
    "Base",
    "ChildProfile",
    "ConsentRecord",
    "Device",
    "DeviceCapability",
    "DeviceCommand",
    "DeviceCommandAttempt",
    "DeviceEvent",
    "DevicePermissionReport",
    "DevicePolicyState",
    "DeviceSession",
    "DeviceSyncCursor",
    "EmailVerificationToken",
    "Family",
    "FamilyMember",
    "GuardianInvitation",
    "IdempotencyRecord",
    "LocationSample",
    "NotificationDelivery",
    "NotificationPreference",
    "OutboxEvent",
    "PairingInvitation",
    "PasswordResetToken",
    "PaymentWebhookEvent",
    "Plan",
    "PolicyVersion",
    "PrivacyRequest",
    "PushToken",
    "ScreenTimePolicy",
    "ScreenTimeSchedule",
    "Subscription",
    "SubscriptionEvent",
    "SupportTicket",
    "SupportTicketMessage",
    "UsageDailySummary",
    "User",
    "UserSession",
    "WebSocketConnection",
    "WebsiteRestriction",
]
