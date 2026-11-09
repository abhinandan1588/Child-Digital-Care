# API contract

Base path `/api/v1`. The generated OpenAPI document at `/openapi.json` is
authoritative; this file explains the parts a schema cannot express.

**119 operations across 99 paths.** Health probes live outside the version
prefix at `/health/*`.

## Conventions

### Success envelope

```json
{
  "success": true,
  "message": "Policy created successfully",
  "data": { "id": "uuid", "status": "pending" },
  "meta": { "request_id": "request-id" }
}
```

### Error envelope

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request contains invalid fields.",
    "details": [{ "field": "name", "issue": "Field is required." }]
  },
  "meta": { "request_id": "request-id" }
}
```

Branch on `error.code`. Messages are human-readable and may be reworded without
an API version bump; codes may not.

### Headers

| Header | Direction | Purpose |
| --- | --- | --- |
| `Authorization: Bearer <token>` | request | Principal-specific access token |
| `Idempotency-Key` | request | 8–128 chars; replays the stored response |
| `X-Request-ID` | both | Correlation; generated if absent, always echoed |

### Pagination

Cursor-based for large histories (alerts, audit logs):

```json
{
  "data": {
    "items": [],
    "page_info": { "next_cursor": "opaque", "has_more": true, "limit": 50, "total": null }
  }
}
```

Keyset pagination on `(timestamp, id)` — the id tie-breaker is what makes the
cursor stable when two rows share a timestamp. The cursor is opaque and carries
only sort keys; every query it feeds is still scoped by the caller's
authorization, so a forged cursor cannot widen access. A malformed cursor is a
`422`, not a `500`.

Admin list endpoints use `limit`/`offset` with a `total`, because an admin
console needs page numbers.

### Types

- Timestamps: ISO 8601 UTC (`2026-11-07T12:30:00Z`).
- Identifiers: UUID v4. No endpoint exposes an integer id.
- Enums: snake_case. New values may be added; renaming one is breaking.
- Durations: seconds, as integers.
- Money: minor units plus an ISO 4217 currency code. Never a float.
- Local times: `HH:MM:SS` paired with an IANA timezone.

### Error codes

| Code | HTTP | Meaning |
| --- | --- | --- |
| `VALIDATION_ERROR` | 422 | Field-level failure; see `details` |
| `MALFORMED_REQUEST` | 400 | Unparseable request |
| `PAYLOAD_TOO_LARGE` | 413 | Body exceeds `MAX_REQUEST_BODY_BYTES` |
| `AUTHENTICATION_REQUIRED` | 401 | Missing or unusable credential |
| `INVALID_CREDENTIALS` | 401 | Wrong email/password (deliberately generic) |
| `TOKEN_EXPIRED` | 401 | Access token past `exp` |
| `TOKEN_INVALID` | 401 | Bad signature, wrong audience, or wrong principal type |
| `TOKEN_REVOKED` | 401 | Session was signed out |
| `REFRESH_TOKEN_REUSED` | 401 | Replay detected; whole token family revoked |
| `EMAIL_NOT_VERIFIED` | 403 | Verify the address first |
| `ACCOUNT_SUSPENDED` / `ACCOUNT_NOT_ACTIVE` | 403 | Account state blocks the action |
| `MFA_REQUIRED` | 401 | Admin sign-in needs a second factor |
| `PERMISSION_DENIED` | 403 | Authenticated but not authorised |
| `DEVICE_SCOPE_VIOLATION` | 403 | Device credential lacks the scope |
| `DEVICE_REVOKED` | 403 | Device was unlinked by a parent |
| `DEVICE_NOT_ACTIVE` | 409 | Registration not complete |
| `NOT_FOUND` | 404 | Absent, or outside the caller's scope |
| `CONFLICT` | 409 | Conflicts with current state |
| `ALREADY_EXISTS` | 409 | Uniqueness violation |
| `VERSION_CONFLICT` | 409 | `if_revision` did not match |
| `IDEMPOTENCY_KEY_REUSED` | 409 | Same key, different body |
| `INVALID_STATE_TRANSITION` | 409 | Not allowed by the state machine |
| `INVITATION_EXPIRED` / `_ALREADY_CLAIMED` / `_REVOKED` / `_ATTEMPT_LIMIT` | 409 | Pairing or guardian invitation |
| `COMMAND_NOT_SUPPORTED` | 403 | Not in the parent-issuable allow-list |
| `COMMAND_EXPIRED` | 409 | Past its TTL |
| `CAPABILITY_UNSUPPORTED` | 409 | Device reported it cannot do this |
| `PERMISSION_STATE_BLOCKS_ACTION` | 409 | Android permission not granted, or consent missing |
| `POLICY_CONFLICT` | 409 | e.g. a protected package |
| `SCHEDULE_INVALID` | 409 | Overlapping or empty window |
| `QUOTA_EXCEEDED` | 409 | Per-family/child limit |
| `FEATURE_DISABLED` | 403 | Gate off for this deployment |
| `NOT_IMPLEMENTED` | 501 | Documented as not built |
| `INTEGRATION_NOT_CONFIGURED` | 503 | Required integration absent |
| `WEBHOOK_SIGNATURE_INVALID` | 400 | Signature, timestamp or body mismatch |
| `RATE_LIMITED` | 429 | With `Retry-After` |
| `SERVICE_UNAVAILABLE` | 503 | Dependency down |
| `INTERNAL_ERROR` | 500 | Logged with the request id; no internals in the body |

## Parent App endpoints

### Authentication

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/auth/register` | Identical response whether or not the address exists |
| POST | `/auth/verify-email` | Single-use token |
| POST | `/auth/verify-email/resend` | Authenticated |
| POST | `/auth/login` | Rate-limited per IP and per hashed email |
| POST | `/auth/refresh` | Rotates; replay revokes the token family |
| POST | `/auth/logout` | This session |
| POST | `/auth/logout-all` | Every session |
| POST | `/auth/password/forgot` | Always `200` |
| POST | `/auth/password/reset` | Revokes **all** sessions |
| POST | `/auth/password/change` | Optionally keeps the current session |
| GET | `/auth/me` | User plus family memberships and effective permissions |
| GET | `/auth/sessions` | Active sessions, current one flagged |
| DELETE | `/auth/sessions/{session_id}` | Scoped to the caller's own sessions |

### Families and guardians

| Method | Path | Permission |
| --- | --- | --- |
| POST | `/families` | verified email |
| GET | `/families` | membership |
| GET | `/families/{family_id}` | `family.read` |
| PATCH | `/families/{family_id}` | `family.update` |
| GET | `/families/{family_id}/members` | `family.read` |
| DELETE | `/families/{family_id}/members/{member_id}` | `family.members.manage` |
| POST | `/families/{family_id}/guardian-invitations` | `family.members.manage` |
| GET | `/families/{family_id}/guardian-invitations` | `family.members.manage` |
| DELETE | `/families/{family_id}/guardian-invitations/{invitation_id}` | `family.members.manage` |
| POST | `/guardian-invitations/accept` | verified email; bound to the invited address |

### Children

| Method | Path | Permission |
| --- | --- | --- |
| POST | `/families/{family_id}/children` | `children.manage` |
| GET | `/families/{family_id}/children` | `children.read` |
| GET | `/children/{child_profile_id}` | `children.read` |
| PATCH | `/children/{child_profile_id}` | `children.manage` |
| DELETE | `/children/{child_profile_id}` | `children.manage` — deactivates, unlinks devices, returns a retention note |

An `age_band` is collected, never a date of birth. Submitting
`date_of_birth` is a `422`.

### Pairing

| Method | Path | Auth |
| --- | --- | --- |
| POST | `/children/{child_profile_id}/pairing-invitations` | `pairing.manage` |
| GET | `/children/{child_profile_id}/pairing-invitations` | `pairing.manage` |
| GET | `/pairing-invitations/{invitation_id}` | `pairing.manage` |
| DELETE | `/pairing-invitations/{invitation_id}` | `pairing.manage` |
| POST | `/device/pairing/claim` | **none** — the claim token is the credential |

### Devices and commands

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/devices` | `devices.read` (scoped to the caller's families) |
| GET | `/devices/{device_id}` | `devices.read` — includes reported capabilities and permissions |
| PATCH | `/devices/{device_id}/label` | `devices.manage` |
| POST | `/devices/{device_id}/revoke` | `devices.manage` |
| GET | `/devices/{device_id}/commands` | `devices.read` |
| POST | `/devices/{device_id}/commands` | `commands.issue`; honours `Idempotency-Key` |
| GET | `/commands/allowed-types` | authenticated |

### Policies

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/children/{id}/policies` | `policies.read` — the full bundle plus real per-device sync state |
| GET/POST | `/children/{id}/app-restrictions` | read / manage |
| PATCH/DELETE | `/children/{id}/app-restrictions/{restriction_id}` | `policies.manage` |
| GET/POST | `/children/{id}/screen-time-policies` | read / manage |
| PATCH/DELETE | `/children/{id}/screen-time-policies/{policy_id}` | `policies.manage` |
| POST | `/children/{id}/screen-time-policies/{policy_id}/schedules` | `policies.manage` |
| PATCH/DELETE | `.../schedules/{schedule_id}` | `policies.manage` |
| GET | `/children/{id}/website-restrictions` | `policies.read` — empty while gated off |
| GET | `/children/{id}/policy-versions/current` | `policies.read` |

### Usage, alerts, notifications

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/children/{id}/usage` | `usage.read` — aggregate plus `days_missing_data` |
| GET | `/children/{id}/usage/daily` | `usage.read` |
| GET | `/children/{id}/usage/apps` | `usage.read` |
| GET | `/alerts` | `alerts.read` — cursor-paginated |
| GET | `/alerts/{alert_id}` | `alerts.read` |
| PATCH | `/alerts/{alert_id}` | `alerts.manage` — cannot reopen |
| POST/DELETE | `/push-token` | authenticated |
| GET/PATCH | `/notification-preferences` | authenticated |
| POST | `/realtime/ticket` | authenticated — short-lived WebSocket ticket |

### Location (gated)

All three return `403 FEATURE_DISABLED` unless `FEATURE_LOCATION_ENABLED=true`,
and require the non-delegatable `location.read` permission. Every read is
audited.

| Method | Path |
| --- | --- |
| GET | `/children/{id}/location/status` |
| GET | `/children/{id}/location/latest` |
| GET | `/children/{id}/location/history` |

### Billing and privacy

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/billing/plans` | `meta.billing_available` says whether purchase is possible |
| GET | `/billing/families/{family_id}/subscription` | `billing.manage` |
| POST | `/billing/families/{family_id}/checkout` | `503` until a provider is configured |
| POST | `/billing/webhooks/{provider}` | signature-verified; the only path that changes entitlement |
| GET/POST | `/privacy/consents` | versioned consent records |
| DELETE | `/privacy/consents/{consent_id}` | withdrawing location consent deletes the samples |
| GET/POST | `/privacy/requests` | export / deletion requests |
| GET | `/privacy/export` | inline export bundle |
| POST | `/privacy/account/delete` | password + `"DELETE MY ACCOUNT"` |
| POST | `/privacy/account/delete/cancel` | within the grace period |

## Child App endpoints

Every route authenticates as a device. The device id comes from the token, so
there is no parameter a device could tamper with to reach another device.

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/device/pairing/claim` | unauthenticated; see [PAIRING_FLOW.md](PAIRING_FLOW.md) |
| POST | `/device-auth/refresh` | rotates; replay revokes the family |
| POST | `/device-auth/logout` | ends this session only |
| GET | `/device-auth/me` | identity, policy version, sync status, server time |
| POST | `/device/register` | idempotent; safe on every app start |
| POST | `/device/heartbeat` | returns whether to fetch policies or commands |
| POST | `/device/capabilities` | what the device can do |
| POST | `/device/permissions/report` | Android permission states |
| GET | `/device/policies/current` | precedence already resolved server-side |
| GET | `/device/commands` | fetching marks commands `delivered` |
| POST | `/device/commands/{id}/acknowledge` | safe to retry |
| POST | `/device/commands/{id}/result` | `unsupported` is stored verbatim |
| POST | `/device/usage/daily-summary` | upsert: re-sending replaces |
| POST | `/device/usage/app-summaries` | batch backfill, max 30 days |
| POST | `/device/events` | deduplicated by key |
| POST | `/device/location` | gated; returns `accepted: false` with a reason |
| POST/DELETE | `/device/push-token` | |

A device **cannot** unlink itself, read another device's data, call a parent or
admin route, or submit data for a different child.

## Admin endpoints

All under `/admin`. Each requires one `AdminPermission`; see
[AUTH_AND_RBAC.md](AUTH_AND_RBAC.md).

| Method | Path | Permission |
| --- | --- | --- |
| POST | `/admin/auth/login` | — |
| POST | `/admin/auth/refresh` | — |
| POST | `/admin/auth/logout` | authenticated |
| GET | `/admin/auth/me` | authenticated |
| GET | `/admin/permissions` | authenticated |
| GET | `/admin/overview` | `overview.read` |
| GET | `/admin/users` | `users.read` (audited) |
| GET | `/admin/users/{user_id}` | `users.read`; profile detail needs `users.pii.read` |
| PATCH | `/admin/users/{user_id}/status` | `users.status.write`; reason mandatory |
| GET | `/admin/families` | `families.read` (audited) |
| GET | `/admin/devices` | `devices.read` (audited) |
| POST | `/admin/devices/{device_id}/revoke` | `devices.revoke` |
| GET | `/admin/support-tickets` | `support_tickets.read` |
| PATCH | `/admin/support-tickets/{ticket_id}` | `support_tickets.write` |
| GET | `/admin/abuse-reports` | `abuse_reports.read` |
| PATCH | `/admin/abuse-reports/{report_id}` | `abuse_reports.write`; notes mandatory |
| GET | `/admin/subscriptions` | `subscriptions.read` |
| GET | `/admin/audit-logs` | `audit_logs.read` (itself audited) |
| GET | `/admin/analytics/summary` | `analytics.read` |

## Policy precedence

Resolved server-side, so the Child App never reconciles conflicting rules.

**App restrictions**

1. A device-scoped row beats a profile-wide row for the same package.
2. At equal scope, the stricter action wins:
   `block` > `require_approval` > `time_limit` > `allow`.
3. Disabled rows are ignored.
4. Protected packages (dialer, emergency, settings, this app) cannot be
   restricted at all — `409 POLICY_CONFLICT`.

**Screen-time policies**

1. Only enabled policies for this device (or profile-wide) apply.
2. Higher `priority` wins; ties break on creation order.
3. Within one policy, two windows overlapping on the same weekday are rejected
   (`409 SCHEDULE_INVALID`). Overlap *between* policies is allowed and resolved
   by priority.
4. `end_local_time <= start_local_time` means the window crosses midnight.
5. Windows are local wall-clock intent plus an IANA zone, so a 21:00 bedtime
   stays 21:00 across a DST change.

## Worked examples

### Create a pairing invitation

`POST /api/v1/children/{child_profile_id}/pairing-invitations`

```json
{ "include_short_code": true, "expires_in_minutes": 15 }
```

```json
{
  "success": true,
  "message": "Pairing invitation created.",
  "data": {
    "invitation_id": "9a8b7c6d-1234-4567-8901-123456789012",
    "family_id": "11111111-1111-4111-8111-111111111111",
    "child_profile_id": "22222222-2222-4222-8222-222222222222",
    "claim_token": "example-only-high-entropy-token",
    "short_code": "K7M2QX4P",
    "short_code_prefix": "K7M2",
    "status": "pending",
    "expires_at": "2026-11-07T12:30:00Z",
    "attempt_count": 0
  },
  "meta": { "request_id": "example-request-id" }
}
```

`claim_token` is returned **once**. Only its SHA-256 hash is stored, it is never
logged, and it cannot be retrieved again. Encode this token in the QR code —
never a parent JWT or account details.

### Claim a pairing invitation

`POST /api/v1/device/pairing/claim`

```json
{
  "claim_token": "example-only-high-entropy-token",
  "device": {
    "platform": "android",
    "app_version": "1.0.0",
    "os_version": "Android 16",
    "device_label": "Child's phone",
    "install_id": "random-per-install-id"
  },
  "disclosure_version": "2026-01",
  "disclosure_acknowledged": true
}
```

```json
{
  "success": true,
  "message": "Device paired. Complete registration next.",
  "data": {
    "device_id": "c2d2b1a0-1234-4567-8901-123456789012",
    "child_profile_id": "22222222-2222-4222-8222-222222222222",
    "family_id": "11111111-1111-4111-8111-111111111111",
    "device_access_token": "example-short-lived-device-token",
    "device_refresh_token": "example-one-time-refresh-secret",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_expires_in": 15552000,
    "status": "pending_registration",
    "policy_version": 1
  },
  "meta": { "request_id": "example-request-id" }
}
```

The refresh token is an **opaque** server-side-hashed secret, not a JWT.

### Create an app restriction

`POST /api/v1/children/{child_profile_id}/app-restrictions`

```json
{
  "package_identifier": "com.example.video",
  "display_label": "Example Video",
  "action": "block",
  "enabled": true
}
```

```json
{
  "success": true,
  "message": "Restriction saved and queued for synchronisation.",
  "data": {
    "restriction_id": "e1e2e3e4-1234-4567-8901-123456789012",
    "policy_version": 4,
    "sync_status": "pending_sync",
    "devices_notified": 1,
    "commands_queued": ["aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"],
    "restriction": {
      "id": "e1e2e3e4-1234-4567-8901-123456789012",
      "package_identifier": "com.example.video",
      "action": "block",
      "enabled": true,
      "revision": 1
    }
  },
  "meta": { "request_id": "example-request-id" }
}
```

`pending_sync`, not "blocked". The app is not blocked until a device says so.

### Device command result

`POST /api/v1/device/commands/{command_id}/result`

```json
{
  "result": "unsupported",
  "applied_policy_version": 3,
  "error_code": "REQUIRED_PERMISSION_NOT_GRANTED",
  "message": "The required permission is not enabled on this device."
}
```

```json
{
  "success": true,
  "message": "Result recorded.",
  "data": {
    "command_id": "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
    "status": "unsupported",
    "result": "unsupported",
    "duplicate": false
  },
  "meta": { "request_id": "example-request-id" }
}
```

The parent's policy bundle then shows `sync_status: "unsupported"` for that
device, with the device still honestly reported on `applied_policy_version: 3`.

## Versioning policy

Backwards compatible: new endpoints, new optional request fields, new response
fields, new enum values, new error codes.

Breaking, requiring `/api/v2` and a [CHANGELOG_API.md](CHANGELOG_API.md) entry:
removing or renaming a field or endpoint, changing a type, making an optional
field required, removing an enum value or error code, or changing the envelope.
Response shapes are never changed silently.
