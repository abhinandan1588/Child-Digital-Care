# API changelog

Contract changes to `/api/v1`. Client teams should watch this file and
regenerate their clients when it gains an entry.

## Compatibility rules

**Backwards compatible** — no entry required, but noted here anyway:

- a new endpoint
- a new optional request field
- a new response field
- a new enum value
- a new error code
- a reworded `error.message`

**Breaking** — requires a new version prefix (`/api/v2`) and an entry here:

- removing or renaming any field or endpoint
- changing a field's type
- making an optional request field required
- removing an enum value or an error code
- changing the response envelope
- changing the meaning of an existing value

Response shapes are never changed silently. Clients must branch on
`error.code`, never on `error.message`, which is why rewording a message is not
breaking.

---

## [1.0.0] — 2026-11-07

Initial contract. 119 operations across 99 paths.

### Added — Parent App

- **Authentication** (13 operations): registration with email verification,
  login, refresh with rotation, logout, logout-all, password forgot/reset/change,
  `/auth/me`, session list and revoke.
- **Families and guardians** (10): family CRUD, member list and removal,
  guardian invitation create/list/revoke/accept.
- **Children** (5): CRUD plus a deactivation endpoint that unlinks devices and
  returns a retention note.
- **Pairing** (5): invitation create/list/get/revoke, and the unauthenticated
  device claim.
- **Devices and commands** (7): device list and detail with reported
  capabilities and permissions, rename, revoke, command history, typed command
  request, and a published allow-list.
- **Policies** (14): the full policy bundle with per-device sync state,
  app restrictions, screen-time policies, schedules, gated website
  restrictions, current policy version.
- **Usage** (3): aggregate overview, per-day totals, per-app breakdown.
- **Alerts** (3): cursor-paginated list, detail, acknowledge/resolve/dismiss.
- **Notifications** (4): push token register/deregister, preference get/update.
- **Location** (3, gated): status, latest, history.
- **Billing** (4): plans, subscription, checkout, provider webhook.
- **Privacy** (8): consent list/create/withdraw, request list/create, inline
  export, account deletion schedule and cancel.
- **Realtime** (1): WebSocket ticket, plus the `/realtime/ws` socket.

### Added — Child App

- **Device auth** (3): refresh with rotation, logout, identity.
- **Device API** (14): register, heartbeat, capability report, permission
  report, current policy snapshot, command fetch, acknowledge, result, daily
  usage submit, batch usage submit, events, gated location submit, push token
  register and deregister.

### Added — Admin Dashboard

- **Admin** (19): login, refresh, logout, identity, permission catalogue,
  overview, user search and detail, status change, family search, device search
  and revoke, support tickets, abuse reports, subscriptions, audit logs,
  analytics summary.

### Added — Operations

- `GET /health/live`, `GET /health/ready`, `GET /health/integrations`.

### Contract decisions established in this version

These are the conventions clients should build against. Changing any of them
later would be a breaking change.

| Decision | Detail |
| --- | --- |
| Response envelope | `{success, message, data, meta.request_id}` on every response, success and error |
| Error codes | A documented, stable enum. Branch on `code`, never on `message` |
| Identifiers | UUID everywhere; no integer id is exposed |
| Timestamps | ISO 8601 UTC |
| Enums | snake_case |
| Money | Minor units plus an ISO 4217 code; never a float |
| Pagination | Cursor (keyset on `timestamp, id`) for parent-facing histories; `limit`/`offset` with `total` for admin lists |
| Idempotency | `Idempotency-Key` on retryable writes; same key with a different body returns `409 IDEMPOTENCY_KEY_REUSED` |
| Correlation | `X-Request-ID` accepted and always echoed |
| Optimistic concurrency | `if_revision` on policy mutations; mismatch returns `409 VERSION_CONFLICT` |
| Cross-tenant access | `404`, not `403`, so resource existence is not discoverable |
| Policy mutations | Always return `sync_status: "pending_sync"`; never claim a rule is in force |
| Device results | `unsupported` and `permission_denied` are preserved verbatim, never mapped to success |
| Telemetry labelling | Usage responses carry `device_reported: true` and report missing days |
| Disabled features | `403 FEATURE_DISABLED`; disabled integrations `503 INTEGRATION_NOT_CONFIGURED`. Nothing fakes success |
| Secrets in responses | A pairing claim token is returned exactly once; push tokens only ever as a 6-character suffix |
| Principals | Parent, device and admin tokens are not interchangeable; each has its own audience |

### Known not-implemented surfaces

Documented rather than hidden, and returning explicit errors:

| Surface | Behaviour |
| --- | --- |
| `POST /billing/.../checkout` | `503 INTEGRATION_NOT_CONFIGURED` — no payment provider selected |
| Object storage (avatars, attachments, export artifacts) | `503` — interface defined, no provider implemented |
| Website restrictions | `FEATURE_WEBSITE_RESTRICTIONS_ENABLED=false`; read endpoint returns an empty list with an explanatory message |
| Location module | `FEATURE_LOCATION_ENABLED=false`; all three endpoints `403 FEATURE_DISABLED` |
| Admin MFA verification | Delegated to the identity provider; no server-side TOTP verifier exists |

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

---

## Template for future entries

```markdown
## [1.1.0] — YYYY-MM-DD

### Added
- `POST /api/v1/...` — what it does, which permission it needs.

### Changed (backwards compatible)
- `GET /api/v1/...` now returns `new_field`. Existing fields unchanged.

### Deprecated
- `field_x` on `...Out`. Replaced by `field_y`. Removal no earlier than
  YYYY-MM-DD, and in `/api/v2`.

### Fixed
- `...` returned `500` instead of `422` for `...`.

### Client action required
- Regenerate clients. Dart/Kotlin/TypeScript: no change needed unless using
  `field_x`.
```
