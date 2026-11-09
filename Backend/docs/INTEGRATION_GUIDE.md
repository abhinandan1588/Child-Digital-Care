# Integration guide for the client teams

The backend owns the API contract. Clients consume it; they do not invent
payloads. The generated OpenAPI document at `/openapi.json` is authoritative.

## Generate a client, do not hand-write one

```bash
make openapi        # writes openapi.json
```

| Client | Suggested generator |
| --- | --- |
| Parent App (Flutter/Dart) | `openapi-generator-cli generate -i openapi.json -g dart-dio -o lib/api` |
| Child App (Kotlin) | `openapi-generator-cli generate -i openapi.json -g kotlin -o src/main/kotlin/api` |
| Admin Dashboard (TypeScript) | `npx openapi-typescript openapi.json -o src/api/schema.d.ts` |

Regenerate whenever `docs/CHANGELOG_API.md` gains an entry. Pin the schema
version you built against.

## Rules for every client

1. **Branch on `error.code`, never on `message`.** Messages may be reworded;
   codes are contract.
2. **Never trust local state over the server.** Entitlement, permissions, policy
   versions and sync status come from the API.
3. **Send `Idempotency-Key` on retryable writes.** Reuse the same key for a
   retry of the same request; use a new key for a new request.
4. **Send `X-Request-ID`** and log it. It is the fastest route to a server-side
   diagnosis.
5. **Treat `403 FEATURE_DISABLED` as "hide this feature"**, not as an error to
   retry. Call `GET /health/integrations` at startup to learn what is on.
6. **Store refresh tokens in platform secure storage.** Keychain/Keystore, never
   plain preferences, never a log line.
7. **Handle `401` by rotating once**, then signing out. Do not loop.

## Parent App (Flutter)

### Startup

```text
1. GET /health/integrations      → which features exist in this deployment
2. have a refresh token?  → POST /auth/refresh   else → login screen
3. GET /auth/me                  → user + families + effective permissions
4. GET /devices                  → device list with presence and sync status
5. POST /realtime/ticket         → then open the WebSocket (optional)
```

Drive the UI from `my_permissions` in each family object rather than from an
assumed role. A co-guardian legitimately has fewer capabilities than an owner,
and `location.read` in particular is never in the default guardian grant.

### Showing policy state honestly

This is the one place where a misleading UI does real harm. The server gives
you per-device truth in `device_sync_states`; use it.

| `sync_status` | Say | Do not say |
| --- | --- | --- |
| `pending_sync` | "Saved. Waiting for the device." | "Blocked" |
| `delivered` / `acknowledged` | "Sent to the device." | "Active" |
| `synced` | "Active on this device." | |
| `partially_applied` | "Partly active — tap for detail." (`item_results`) | "Active" |
| `unsupported` | "This device cannot apply this rule." | "Active" |
| `failed` | show `detail` | "Active" |

Also surface `capability_warnings` from the policy bundle, and
`data_completeness_note` plus `days_missing_data` on usage reports. A total that
silently omits four unreported days looks like a fact and is not one.

### Pairing

```text
POST /children/{id}/pairing-invitations
  → render claim_token as a QR code; display short_code as a fallback
  → show expires_at as a countdown
  → poll GET /devices (or watch device.status_changed) until the device appears
  → then show "paired" and "waiting to sync" as two separate states
```

Encode **only** the `claim_token` in the QR payload. Never a parent JWT, never
an email address, never a family id. The token is returned exactly once and
cannot be fetched again; if the parent loses it, create a new invitation.

### Commands

```text
GET  /commands/allowed-types                  → build the UI from this
POST /devices/{id}/commands                   → Idempotency-Key required in practice
GET  /devices/{id}/commands                   → poll, or watch command.status_changed
```

A `409 CAPABILITY_UNSUPPORTED` or `409 PERMISSION_STATE_BLOCKS_ACTION` is not a
bug: the device has told the server it cannot do this. Show the user what to
re-enable on the device.

### WebSocket

```text
POST /api/v1/realtime/ticket   → { ticket, expires_in: 60, websocket_url }
WS   /api/v1/realtime/ws?ticket=<ticket>
  → send    {"action": "subscribe",   "family_id": "<uuid>"}
  → send    {"action": "unsubscribe", "family_id": "<uuid>"}
  → send    {"action": "ping"}        every 30 s
  ← receive {"event": "...", "data": {...}, "emitted_at": "..."}
```

Events: `device.status_changed`, `device.last_seen`,
`policy.sync_status_changed`, `command.status_changed`,
`usage.summary_received`, `alert.created`, `subscription.status_changed`,
`device.commands_pending`.

Events are **hints**. They carry ids and status, never telemetry. On any event,
re-fetch the relevant REST resource. Reconnect with exponential backoff
(1s, 2s, 4s… capped at 60s, jittered), mint a fresh ticket each time, and
re-subscribe. A ticket lives about 60 seconds, so fetch it immediately before
connecting. Tickets are rejected on REST routes by design.

## Child App (Kotlin / Android)

### Lifecycle

```text
First run
  1. scan QR or accept a typed code
  2. show the disclosure; obtain acknowledgement
  3. POST /device/pairing/claim      { claim_token, device, disclosure_* }
  4. store device_refresh_token in Android Keystore-backed storage
  5. POST /device/register           + capabilities + permissions
  6. GET  /device/policies/current   → apply
  7. POST /device/commands/{id}/result
  8. POST /device/push-token

Every start
  POST /device/register              (idempotent)
  POST /device/heartbeat             → tells you whether to fetch
  POST /device/capabilities          whenever capability or permission changes

On FCM wake-up (data-only, {"reason": "commands_pending"})
  GET  /device/commands
  for each: acknowledge → act → report result

Periodic (WorkManager, respecting Doze)
  POST /device/heartbeat
  POST /device/usage/daily-summary   (or app-summaries for a backfill)
  POST /device/events                (batched, deduplicated)
```

`heartbeat` returns `policy_sync_required`, `pending_command_count` and
`next_poll_after_seconds` — one call tells you whether anything needs doing, so
you do not need to poll several endpoints speculatively.

### Report the truth

This is the single most important rule for this client.

```json
{ "result": "unsupported",
  "applied_policy_version": 3,
  "error_code": "REQUIRED_PERMISSION_NOT_GRANTED",
  "message": "The required permission is not enabled on this device." }
```

Never report `succeeded` for something the device could not do. The server
stores `unsupported` and `permission_denied` verbatim and shows the parent the
truth. A false success means a parent believes a child is protected when they
are not.

`applied_policy_version` is the version the device **currently has applied** —
not the version it was asked to apply. The server keeps the two apart.

### Telemetry scope

Send: daily aggregate screen time, per-category totals, per-package foreground
seconds, launch counts, allow-listed event types with safe payloads.

Do not send, and the API will reject: message content, SMS, contacts,
keystrokes, clipboard, screenshots, URLs, browsing history, audio, photos,
coordinates in an event payload.

### Retry and failure handling

| Response | Action |
| --- | --- |
| `401` | `POST /device-auth/refresh` once, then retry; on failure, re-pair |
| `403 DEVICE_REVOKED` | Stop all work, clear local credentials, tell the user supervision ended |
| `403 FEATURE_DISABLED` | Stop attempting that feature |
| `409 COMMAND_EXPIRED` | Drop the command |
| `422` | A client bug. Log it; do not retry unchanged |
| `429` | Honour `Retry-After` |
| `5xx` | Exponential backoff with jitter |

Usage submission is an upsert and events are deduplicated by key, so retrying a
batch is always safe. Never replay a refresh token: a replay revokes the whole
token family, and the device will have to be re-paired.

### Secure storage

`device_refresh_token` goes in `EncryptedSharedPreferences` or an equivalent
hardware-backed keystore. Not plain `SharedPreferences`, not a file, not a log.
Access tokens may live in memory only.

## Admin Dashboard (Next.js)

### Permission-aware UI

```text
POST /admin/auth/login     { email, password, mfa_code }
GET  /admin/auth/me        → { roles, permissions }
GET  /admin/permissions    → the full catalogue, with `sensitive` flags
```

Build navigation from `permissions`, never from role names. A `403
PERMISSION_DENIED` reaching the user is a UI bug — the capability should not
have been offered.

### What a role can see

| Surface | Permission |
| --- | --- |
| Overview counters | `overview.read` |
| User search and detail | `users.read` (profile detail needs `users.pii.read`) |
| Suspend / reactivate | `users.status.write` + a written reason |
| Family and device search | `families.read` / `devices.read` |
| Unlink a device | `devices.revoke` |
| Support tickets | `support_tickets.read` / `.write` |
| Abuse reports | `abuse_reports.read` / `.write` + written resolution notes |
| Subscriptions | `subscriptions.read` / `.write` |
| Audit logs | `audit_logs.read` |
| Analytics | `analytics.read` |

Child usage and location need `child_usage.read` / `child_location.read`, which
no default role except `super_admin` holds. Do not build UI that assumes they
are available.

### Things to get right

- **Reads are audited.** Tell staff that in the UI. Searching for a family is a
  recorded action, and that is deliberate.
- **Reasons are mandatory** for a status change and for an abuse-report
  decision. The API returns `422` without them, so make the field required in
  the form.
- **Pagination is `limit`/`offset` with a `total`** on admin endpoints, unlike
  the cursor pagination used for parent-facing histories.
- **Store the access token in memory only.** `localStorage` turns any XSS into
  a full session compromise. Rotate via `POST /admin/auth/refresh` on `401`.

## Local development against the API

```bash
make venv && make dev-migrate && make seed-rbac && make seed && make dev
```

| Account | Credential |
| --- | --- |
| Parent | `parent@example.test` / `dev-password-not-secret` |
| Co-parent | `coparent@example.test` / `dev-password-not-secret` |
| Admin | `make admin email=you@example.test role=super_admin` |

The seed creates a family, a child, a registered device with reported
capabilities, one app restriction, a screen-time policy with an overnight
schedule, and three days of reported usage. With Docker, verification and reset
emails land in mailpit at <http://localhost:8025>.

To drive the device side by hand, pair a fake device:

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"parent@example.test","password":"dev-password-not-secret"}' \
  | jq -r .data.access_token)

CHILD=$(curl -s localhost:8000/api/v1/families -H "Authorization: Bearer $TOKEN" \
  | jq -r .data[0].id \
  | xargs -I{} curl -s localhost:8000/api/v1/families/{}/children \
      -H "Authorization: Bearer $TOKEN" | jq -r .data[0].id)

curl -s -X POST localhost:8000/api/v1/children/$CHILD/pairing-invitations \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{}' | jq
```

## Reporting a contract problem

Include the `request_id` from `meta`, the full request (with secrets removed),
the response, and the OpenAPI version you generated against. If a payload shape
genuinely needs to change, that is a backend change plus a
[CHANGELOG_API.md](CHANGELOG_API.md) entry — not a client working around it.
