# Architecture

## Shape

A modular monolith. One deployable FastAPI application plus a Celery worker and
scheduler, sharing PostgreSQL and Redis. Module boundaries are enforced by
import direction rather than by network calls, so the pieces can be separated
later without rewriting the domain logic — and until there is a concrete
operational reason to split them, a monolith keeps a multi-step transaction
(policy change + command + outbox row) genuinely atomic, which is the property
this product most depends on.

```text
            ┌─────────────────────────────────────────────┐
            │                 Clients                     │
            │  Parent App · Child App · Admin Dashboard   │
            └───────────────────┬─────────────────────────┘
                                │ HTTPS / WSS
┌───────────────────────────────▼─────────────────────────────────┐
│ FastAPI application                                             │
│                                                                 │
│  middleware   RequestContext → SecurityHeaders → BodyLimit      │
│               → TrustedHost → CORS                              │
│                                                                 │
│  api/deps.py  verify token → check session row → load principal │
│               → resolve resource through membership             │
│                                                                 │
│  endpoints    thin: validate, delegate, envelope                │
│  services     all business rules and authorization decisions    │
│  repositories query helpers (keyset pagination, row counts)     │
│  db/models    50 tables, UUID keys, UTC timestamps              │
└───────┬──────────────────┬───────────────────┬──────────────────┘
        │                  │                   │
   PostgreSQL           Redis            integrations/
   source of truth      rate limits      email · fcm · payments · storage
                        pub/sub          (each has a disabled mode)
                        celery broker
        ▲                  ▲
        │                  │
┌───────┴──────────────────┴──────────┐
│ Celery worker + scheduler           │
│  outbox publication, command expiry │
│  retention sweeps, due deletions    │
└─────────────────────────────────────┘
```

## Layering rules

| Layer | May import | Must not |
| --- | --- | --- |
| `api/endpoints` | schemas, services, deps, core | models directly for business rules |
| `api/deps` | services, core, models | endpoints |
| `services` | models, repositories, integrations, core | endpoints, FastAPI types |
| `repositories` | models, core | services |
| `integrations` | core | services, models |
| `core` | nothing from the layers above | — |

Endpoints contain no authorization logic of their own. They declare a
dependency that resolves scope, then call a service. That is what makes the
authorization story auditable: there is one place to read.

## Trust boundaries

```text
         UNTRUSTED                     │        TRUSTED
                                       │
  request body, query, headers         │  verified JWT claims
  device-reported telemetry            │  database rows
  push provider responses              │  server clock
  payment webhook bodies ──signature──▶│  verified webhook payload
  pairing claim token ──hash lookup───▶│  invitation row
```

Four rules follow from that diagram and are enforced in code:

1. **Scope is derived, never accepted.** No handler reads `family_id`, `role`,
   `user_id` or `device_id` from a body or header. `api/deps.py` resolves the
   principal from a verified token and then resolves the resource *through* that
   principal's membership. Request schemas use `extra="forbid"`, so a client
   sending `owner_user_id` gets a `422` rather than having it ignored.

2. **Telemetry is reported, not proven.** Usage and capability data is
   plausibility-checked (a day cannot exceed 86 400 seconds; a date cannot be
   in the device's own future; a backfill cannot reach past 30 days) and then
   stored labelled as device-reported. `DailySummaryOut.device_reported` is
   always `true` so a client team cannot forget.

3. **Only verified webhooks change entitlement.** There is no code path where a
   client asserting a purchase alters a subscription.

4. **A 404 is sometimes the honest answer.** Accessing another family's
   resource returns `404`, not `403`: confirming that an id exists would let a
   client enumerate other tenants.

## Request flow: a parent blocks an app

```text
POST /api/v1/children/{id}/app-restrictions
  │
  ├─ RequestContextMiddleware  assigns X-Request-ID, binds it to logs
  ├─ BodySizeLimitMiddleware   rejects an oversized body before buffering
  ├─ require_child_access(POLICIES_MANAGE)
  │     └─ resolve child → its family → caller's membership → permission
  │
  └─ policy_service.create_app_restriction      ── one transaction ──┐
        ├─ reject a protected package (dialer, settings, this app)   │
        ├─ insert app_restrictions row                               │
        └─ bump_policy_version                                       │
              ├─ child_profiles.policy_version += 1                  │
              ├─ insert policy_versions audit row                    │
              ├─ insert device_policy_states (pending_sync) per device
              ├─ insert device_commands (sync_policies) per device   │
              └─ insert outbox_events                                │
                                                        commit ──────┘
  ↓
201 { sync_status: "pending_sync", policy_version: 4, commands_queued: [...] }
```

Nothing in that path calls FCM. The response does not claim the app is blocked.

Later, asynchronously:

```text
Celery (every 10s) → outbox claim (conditional UPDATE, one winner)
                   → FCM wake-up: {"reason": "commands_pending"}   ← no content
                   → record a delivery attempt
Device wakes       → GET /device/commands          ← this marks "delivered"
                   → GET /device/policies/current  ← precedence already resolved
                   → POST /device/commands/{id}/result
                        { result: "succeeded" | "unsupported" | ... }
Server             → device_policy_states.sync_status = synced | unsupported | ...
Parent App         → sees the real per-device state
```

## Why the outbox

A push notification cannot be a queue. An Android device may be offline,
force-stopped, battery-restricted, or subject to background limits, and FCM is
explicitly best-effort. Three consequences shaped the design:

- The command is written to PostgreSQL **before** any delivery attempt, so a
  dropped push costs nothing.
- `delivered` is set when the device *fetches* the command, not when the
  provider accepts the message. A provider receipt is not evidence the device
  received anything.
- The outbox row and the state change it describes commit together, so the
  system cannot end up with a policy change that nobody was told about, or a
  notification about a change that was rolled back.

## Concurrency

| Hazard | Mechanism |
| --- | --- |
| Two devices claiming one pairing invitation | Conditional `UPDATE ... WHERE status='pending' AND expires_at > now`; the loser matches zero rows |
| Two workers publishing one outbox row | Conditional `UPDATE ... WHERE status='pending'`, plus a lease so a crashed worker's row returns to `pending` |
| Two guardians editing one policy | Optimistic concurrency via `if_revision`, answered with `VERSION_CONFLICT` |
| A retried client request | `(device_id, idempotency_key)` unique constraint, and a stored-response idempotency table |
| Duplicate device telemetry | Unique `(device_id, deduplication_key)` and `(device_id, local_date)` |
| Duplicate alerts for a standing condition | Unique `(family_id, deduplication_key)`, bucketed per day |

## Persistence decisions

- **UUID primary keys everywhere.** No endpoint exposes a sequential id, so
  resources are not enumerable.
- **`UtcDateTime`**, a `TypeDecorator` over `timestamptz`, normalises both
  directions. PostgreSQL returns aware datetimes and SQLite does not; without
  this, `row.expires_at <= utcnow()` would behave differently under test than
  in production, which is exactly how a real bug hides.
- **Enums as VARCHAR + CHECK** (`native_enum=False`). Adding a value is an
  ordinary constraint migration rather than an `ALTER TYPE` that cannot run in
  some transaction contexts.
- **`JSONB` on PostgreSQL via a variant**, so the same metadata emits correct
  DDL on the test backend too. JSON is used only for genuinely variable data
  (command payloads, safe audit metadata, category totals); anything queried is
  a typed column.
- **Soft deletes are explicit.** There is no global query filter; every query
  states `deleted_at IS NULL` at the call site, so the intent is visible.

## Transactions

`get_db` yields a request-scoped session, commits when the handler returns, and
rolls back on any exception. A request is therefore atomic by default.

Two places deliberately commit early, before raising:

- **Refresh-token reuse detection** — revoking the token family must survive the
  `401` that follows.
- **Pairing attempt counters** — a counter that resets whenever the attempt
  fails would protect nothing.

Both are commented in place, because "commit then raise" otherwise looks like a
mistake.

## Observability

Structured JSON logs with a redaction processor that strips credential-shaped
keys and inline JWTs before an event leaves the process, so an accidental
`log.info("x", token=...)` cannot leak. Request logs carry the correlation id,
route template, status and duration. Health probes are separated: `/health/live`
touches nothing, `/health/ready` checks the database (fatal) and Redis
(reported, not fatal, since rate limiting can fail open and the outbox drains
later). `/health/integrations` reports which optional integrations are actually
configured, so a client never has to guess whether a feature will work.

## Known architectural limits

- **Policy evaluation is server-side only for precedence.** Actual enforcement
  timing lives on the device; the server cannot verify a bedtime was honoured.
- **WebSocket events are hints.** A client that misses a frame recovers through
  REST. Durable state is never WebSocket-only.
- **Admin MFA is delegated.** The session records whether MFA was satisfied;
  the factor itself is verified by the identity provider or reverse proxy in
  production. No server-side TOTP verifier is implemented, and none is faked.
- **Object storage is not implemented.** Avatars, support attachments and
  export artifacts have a defined interface and a `disabled` provider that
  raises `503`.
