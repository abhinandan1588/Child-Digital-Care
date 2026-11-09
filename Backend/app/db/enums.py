"""Domain enumerations shared by ORM models and Pydantic schemas.

Values are snake_case and are part of the public API contract: adding a value
is backwards compatible, renaming one is a breaking change that requires an API
version bump and an entry in ``docs/CHANGELOG_API.md``.
"""

from __future__ import annotations

from enum import StrEnum


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
class AccountStatus(StrEnum):
    pending_verification = "pending_verification"
    active = "active"
    suspended = "suspended"
    deactivated = "deactivated"
    pending_deletion = "pending_deletion"
    deleted = "deleted"


class AdminAccountStatus(StrEnum):
    active = "active"
    suspended = "suspended"
    disabled = "disabled"


# ---------------------------------------------------------------------------
# Family
# ---------------------------------------------------------------------------
class FamilyStatus(StrEnum):
    active = "active"
    suspended = "suspended"
    pending_deletion = "pending_deletion"
    deleted = "deleted"


class GuardianRelationship(StrEnum):
    parent = "parent"
    guardian = "guardian"
    caregiver = "caregiver"
    other = "other"


class MembershipStatus(StrEnum):
    invited = "invited"
    active = "active"
    removed = "removed"


class InvitationStatus(StrEnum):
    pending = "pending"
    accepted = "accepted"
    expired = "expired"
    revoked = "revoked"


class ProfileStatus(StrEnum):
    active = "active"
    inactive = "inactive"
    pending_deletion = "pending_deletion"
    deleted = "deleted"


class AgeBand(StrEnum):
    """Coarse age bands. Full dates of birth are deliberately not collected."""

    under_6 = "under_6"
    age_6_8 = "age_6_8"
    age_9_12 = "age_9_12"
    age_13_15 = "age_13_15"
    age_16_17 = "age_16_17"
    undisclosed = "undisclosed"


# ---------------------------------------------------------------------------
# Devices and pairing
# ---------------------------------------------------------------------------
class DevicePlatform(StrEnum):
    android = "android"
    ios = "ios"
    other = "other"


class DeviceStatus(StrEnum):
    pending_registration = "pending_registration"
    active = "active"
    inactive = "inactive"
    revoked = "revoked"
    replaced = "replaced"


class PairingInvitationStatus(StrEnum):
    pending = "pending"
    claimed = "claimed"
    expired = "expired"
    revoked = "revoked"


class CapabilitySupport(StrEnum):
    """Whether the *device* reports it can perform a capability at all."""

    supported = "supported"
    unsupported = "unsupported"
    unknown = "unknown"


class PermissionState(StrEnum):
    """Android runtime/special permission state, as reported by the device."""

    granted = "granted"
    denied = "denied"
    permanently_denied = "permanently_denied"
    restricted = "restricted"
    not_requested = "not_requested"
    not_applicable = "not_applicable"
    unknown = "unknown"


class CapabilityKey(StrEnum):
    """Capabilities the Child App may report. Server-side vocabulary only;
    the Android team validates each against current platform/Play policy.
    See docs/FEATURE_CAPABILITY_MATRIX.md."""

    app_usage_stats = "app_usage_stats"
    app_blocking = "app_blocking"
    screen_time_enforcement = "screen_time_enforcement"
    device_admin_lock = "device_admin_lock"
    background_execution = "background_execution"
    foreground_service = "foreground_service"
    location_coarse = "location_coarse"
    location_fine = "location_fine"
    notification_post = "notification_post"
    boot_completed = "boot_completed"
    battery_optimisation_exempt = "battery_optimisation_exempt"
    web_content_filtering = "web_content_filtering"


class PermissionKey(StrEnum):
    usage_stats = "usage_stats"
    accessibility_service = "accessibility_service"
    device_admin = "device_admin"
    post_notifications = "post_notifications"
    location_coarse = "location_coarse"
    location_fine = "location_fine"
    location_background = "location_background"
    ignore_battery_optimisations = "ignore_battery_optimisations"
    query_all_packages = "query_all_packages"
    vpn_service = "vpn_service"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
class RestrictionAction(StrEnum):
    block = "block"
    allow = "allow"
    require_approval = "require_approval"
    time_limit = "time_limit"


class ScheduleAction(StrEnum):
    block_all = "block_all"
    allow_allowlisted_only = "allow_allowlisted_only"
    warn_only = "warn_only"


class Weekday(StrEnum):
    monday = "monday"
    tuesday = "tuesday"
    wednesday = "wednesday"
    thursday = "thursday"
    friday = "friday"
    saturday = "saturday"
    sunday = "sunday"


WEEKDAY_ORDER: tuple[Weekday, ...] = (
    Weekday.monday,
    Weekday.tuesday,
    Weekday.wednesday,
    Weekday.thursday,
    Weekday.friday,
    Weekday.saturday,
    Weekday.sunday,
)


class PolicyScope(StrEnum):
    child_profile = "child_profile"
    device = "device"


class SyncStatus(StrEnum):
    """What the *server knows* about device application of a policy set.

    Never inferred: only moved forward by a device acknowledgement/result.
    """

    pending_sync = "pending_sync"
    delivered = "delivered"
    synced = "synced"
    partially_applied = "partially_applied"
    failed = "failed"
    unsupported = "unsupported"


class WebsiteRestrictionMode(StrEnum):
    blocklist = "blocklist"
    allowlist = "allowlist"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
class CommandType(StrEnum):
    """Strict allow-list. No generic execute/shell/capture command exists, and
    none may be added: see rule 13/14 in the master prompt."""

    sync_policies = "sync_policies"
    refresh_device_status = "refresh_device_status"
    request_usage_sync = "request_usage_sync"
    request_location_update = "request_location_update"
    apply_supported_policy = "apply_supported_policy"
    revoke_device = "revoke_device"


#: Commands a parent may create directly through the API.
PARENT_ISSUABLE_COMMANDS: frozenset[CommandType] = frozenset(
    {
        CommandType.sync_policies,
        CommandType.refresh_device_status,
        CommandType.request_usage_sync,
        CommandType.request_location_update,
    }
)


class CommandStatus(StrEnum):
    queued = "queued"
    delivery_attempted = "delivery_attempted"
    delivered = "delivered"
    acknowledged = "acknowledged"
    succeeded = "succeeded"
    failed = "failed"
    expired = "expired"
    cancelled = "cancelled"
    unsupported = "unsupported"


TERMINAL_COMMAND_STATUSES: frozenset[CommandStatus] = frozenset(
    {
        CommandStatus.succeeded,
        CommandStatus.failed,
        CommandStatus.expired,
        CommandStatus.cancelled,
        CommandStatus.unsupported,
    }
)


class CommandResult(StrEnum):
    """What a device reports after attempting a command."""

    succeeded = "succeeded"
    failed = "failed"
    unsupported = "unsupported"
    permission_denied = "permission_denied"
    partially_applied = "partially_applied"


class DeliveryChannel(StrEnum):
    fcm = "fcm"
    websocket = "websocket"
    device_poll = "device_poll"


class DeliveryOutcome(StrEnum):
    sent = "sent"
    no_active_token = "no_active_token"
    provider_error = "provider_error"
    token_invalid = "token_invalid"
    provider_not_configured = "provider_not_configured"
    skipped = "skipped"


class OutboxStatus(StrEnum):
    pending = "pending"
    processing = "processing"
    sent = "sent"
    failed = "failed"
    dead_letter = "dead_letter"


class DeviceEventType(StrEnum):
    app_started = "app_started"
    app_stopped = "app_stopped"
    policy_applied = "policy_applied"
    policy_apply_failed = "policy_apply_failed"
    permission_changed = "permission_changed"
    capability_changed = "capability_changed"
    uninstall_attempted = "uninstall_attempted"
    device_rebooted = "device_rebooted"
    time_changed = "time_changed"
    network_changed = "network_changed"
    screen_time_limit_reached = "screen_time_limit_reached"
    blocked_app_launch_attempt = "blocked_app_launch_attempt"


# ---------------------------------------------------------------------------
# Usage, alerts, location
# ---------------------------------------------------------------------------
class UsageCategory(StrEnum):
    social = "social"
    games = "games"
    education = "education"
    video = "video"
    communication = "communication"
    productivity = "productivity"
    browser = "browser"
    other = "other"
    uncategorised = "uncategorised"


class AlertType(StrEnum):
    device_offline = "device_offline"
    device_revoked = "device_revoked"
    policy_sync_failed = "policy_sync_failed"
    permission_revoked_on_device = "permission_revoked_on_device"
    capability_unsupported = "capability_unsupported"
    screen_time_limit_reached = "screen_time_limit_reached"
    blocked_app_launch_attempt = "blocked_app_launch_attempt"
    uninstall_attempted = "uninstall_attempted"
    new_device_paired = "new_device_paired"
    subscription_issue = "subscription_issue"


class AlertSeverity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


class AlertStatus(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    dismissed = "dismissed"


class LocationSource(StrEnum):
    gps = "gps"
    network = "network"
    fused = "fused"
    unknown = "unknown"


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
class NotificationType(StrEnum):
    device_paired = "device_paired"
    device_offline = "device_offline"
    policy_sync_failed = "policy_sync_failed"
    alert_raised = "alert_raised"
    weekly_report = "weekly_report"
    subscription = "subscription"
    security = "security"
    device_wakeup = "device_wakeup"


class NotificationDeliveryStatus(StrEnum):
    queued = "queued"
    sent = "sent"
    failed = "failed"
    token_invalid = "token_invalid"
    suppressed_by_preference = "suppressed_by_preference"
    provider_not_configured = "provider_not_configured"


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------
class BillingInterval(StrEnum):
    month = "month"
    year = "year"
    lifetime = "lifetime"


class SubscriptionStatus(StrEnum):
    none = "none"
    trialing = "trialing"
    active = "active"
    past_due = "past_due"
    cancelled = "cancelled"
    expired = "expired"
    incomplete = "incomplete"


class WebhookProcessingStatus(StrEnum):
    received = "received"
    processed = "processed"
    ignored = "ignored"
    signature_invalid = "signature_invalid"
    failed = "failed"


# ---------------------------------------------------------------------------
# Support / trust & safety
# ---------------------------------------------------------------------------
class TicketStatus(StrEnum):
    open = "open"
    pending_user = "pending_user"
    pending_internal = "pending_internal"
    resolved = "resolved"
    closed = "closed"


class TicketPriority(StrEnum):
    low = "low"
    normal = "normal"
    high = "high"
    urgent = "urgent"


class AbuseReportStatus(StrEnum):
    received = "received"
    under_review = "under_review"
    action_taken = "action_taken"
    dismissed = "dismissed"


class AbuseReportCategory(StrEnum):
    non_consensual_monitoring = "non_consensual_monitoring"
    account_takeover = "account_takeover"
    child_safety = "child_safety"
    privacy_complaint = "privacy_complaint"
    other = "other"


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------
class ConsentType(StrEnum):
    parent_terms = "parent_terms"
    parent_privacy_policy = "parent_privacy_policy"
    child_device_disclosure = "child_device_disclosure"
    location_collection = "location_collection"
    usage_collection = "usage_collection"


class ConsentState(StrEnum):
    granted = "granted"
    declined = "declined"
    revoked = "revoked"


class ConsentMethod(StrEnum):
    parent_app_acceptance = "parent_app_acceptance"
    child_device_acknowledgement = "child_device_acknowledgement"
    support_assisted = "support_assisted"


class PrivacyRequestStatus(StrEnum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    rejected = "rejected"
    cancelled = "cancelled"


class PrivacyRequestType(StrEnum):
    export = "export"
    deletion = "deletion"


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
class AuditActorType(StrEnum):
    parent_user = "parent_user"
    child_device = "child_device"
    admin_user = "admin_user"
    system = "system"
    anonymous = "anonymous"


class AuditOutcome(StrEnum):
    success = "success"
    failure = "failure"
    denied = "denied"


__all__ = [name for name in dir() if not name.startswith("_")]
