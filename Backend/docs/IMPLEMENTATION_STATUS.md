# Implementation status

An honest account of what is built, what is deliberately disabled, and what is
not built. Written so another developer — or a reviewer — does not have to
discover a gap by hitting it.

Status: **✔ implemented and tested** · **◐ implemented but gated off** ·
**◻ interface only** · **✖ not built**

## Verified results

Python 3.14.4. The suite runs on two backends.

```text
ruff check .            All checks passed
ruff format --check .   144 files already formatted
mypy                    Success: no issues found in 114 source files

# SQLite (default, hermetic — Redis tests skip)
pytest                  292 passed, 14 skipped

# PostgreSQL 18.6 + Redis 6.2.14 (nothing skipped)
pytest                  306 passed
```

Test breakdown: 55 unit · 161 integration · 72 security · 18 contract.

### Verified against real PostgreSQL

Migration applied to PostgreSQL 18.6, then the **entire suite run against the
migrated schema** (not `create_all`), via `TEST_DATABASE_URL`:

```text
alembic upgrade head    ok
alembic check           No new upgrade operations detected
alembic current         d59a190f423e (head) — single head, no branches

51 tables · 213 indexes · 405 CHECK constraints · 101 FKs · 41 unique constraints
22 jsonb columns, 0 json          ← the PostgreSQL variant resolved correctly
151 timestamptz, 0 naive          ← no timezone-less column anywhere
160 uuid columns                  ← no integer id is exposed
audit_logs: 0 foreign keys        ← deletion cannot cascade the audit trail away
uq_app_restrictions_profile_wide_package ... WHERE (device_id IS NULL)
                                  ← the partial unique index exists as designed
```

End-to-end HTTP flow executed against PostgreSQL, then verified by querying the
database directly: argon2id password hashes (never plaintext), 64-char SHA-256
hashes for every session and pairing secret, the full command lifecycle
including an `unsupported` row at `target=5, applied=4`, the policy version
history, and `jsonb` columns that are genuinely queryable (`category_totals->>'social'`).

### Verified against real Redis

Rate limiting and pub/sub fan-out exercised against Redis 6.2.14, and the
complete realtime chain end to end: HTTP policy change → outbox row → worker →
Redis pub/sub → WebSocket client, with 24 real events delivered to a live
`websockets` client. Subscribing to another family's channel was refused.

### What is still *not* verified

This matters as much as the list above.

- **No Docker available**, so the image and compose stack are unbuilt. The
  Dockerfile and `docker-compose.yml` are written but have never been run.
- **PostgreSQL 18.6, not 16.** The compose file pins `postgres:16-alpine`.
  Nothing used is version-specific, but 16 has not been exercised.
- **Redis 6.2, not 7.** That turned out to be valuable (see the bug below), but
  Redis 7 has not been exercised.
- **Single-instance only.** Redis pub/sub fan-out works, but two API instances
  serving one family's sockets has not been tested.
- **FCM was never contacted.** Verified: the disabled provider reports
  `not_configured` and never fakes success; the adapter fails safely on a
  missing credentials file; the payload deny-list is enforced; a command stays
  durable with no push provider, recording an attempt with outcome
  `provider_not_configured`. **Not verified:** real delivery, and the mapping
  of live FCM errors (`UnregisteredError`, `SenderIdMismatchError`, quota) to
  token deactivation.
- **No load testing.** The index set was chosen from query shapes, not measured.
- **No external security or privacy review.**

### Defects found by this verification

Both were invisible to the original test suite, and both are recorded here
because the way they hid is the useful part.

1. **Swagger UI served a blank page.** `SecurityHeadersMiddleware` applied
   `Content-Security-Policy: default-src 'none'` to every response, including
   the `/docs` HTML, so the browser blocked Swagger's own stylesheet, script
   bundle and inline bootstrap. Curl reported `200` throughout; only a browser
   enforces CSP. Fixed by giving the documentation paths their own allow-list
   policy, derived from `app.docs_url`/`app.redoc_url`. Three regression tests
   added.

2. **Rate limiting silently did nothing on Redis 6.x.** The limiter used
   `INCRBY` + `EXPIRE key seconds NX` in a pipeline. The `NX` flag requires
   Redis 7.0; on 6.x the call raised `ResponseError`, and because the limiter
   fails open by default **every limit disappeared with no error surfaced**.
   Every existing test had run on the in-process fallback, so none caught it.
   Replaced with an `EVAL` script (atomic, one round trip, works on Redis 2.6+,
   and self-heals a key that lost its TTL). `tests/integration/test_rate_limit_redis.py`
   now covers it and produces 9 failures against the old code.

A third, smaller defect was found by the new WebSocket tests:
`logger.error("...", event=event)` collided with structlog's own positional
`event` parameter, raising `TypeError` inside the realtime payload-rejection
path — turning a handled rejection into a crash. Fixed, and an AST-walking test
now asserts no logger call in `app/` passes a reserved structlog keyword.

## By feature area

### Foundation ✔

FastAPI app factory, fail-fast settings validation, async SQLAlchemy sessions
with request-scoped transactions, structured JSON logging with credential
redaction, correlation ids, global exception handling with a uniform error
envelope, body-size limits, security headers, CORS and trusted-host allow-lists,
Redis-backed rate limiting with an in-process fallback, health and readiness
probes, an integration-status endpoint.

### Database ✔

50 tables, UUID keys, timezone-aware timestamps, portable column types, foreign
keys with deliberate cascade behaviour, 121 indexes, CHECK constraints, a
partial unique index for profile-wide restrictions, deterministic constraint
names. One initial Alembic migration, verified for upgrade, downgrade,
re-upgrade and model parity.

### Authentication and RBAC ✔

Registration, email verification, login, refresh with rotation and reuse
detection, logout and logout-all, password reset and change, session listing and
revocation. Device principal via pairing, with rotation and revocation. Admin
principal with row-based RBAC. Reusable authorization dependencies. Rate
limiting without lockout. Anti-enumeration on every account-facing endpoint.

**Gap:** admin MFA is delegated (see below).

### Families, guardians, children ✔

Family creation with owner permissions, guardian invitations with
non-delegatable permissions stripped and address binding, member listing and
removal, child profile CRUD with age bands, deactivation that unlinks devices
and revokes pending invitations, quotas.

### Pairing ✔

Invitation generation with hashed 256-bit tokens and optional short codes,
atomic single-use claim, race handling, attempt limiting that survives the
rejection, disclosure consent recording, device session issuance, re-pairing
into the same device row, revocation and recovery. Every failure mode in the
master prompt has a test.

### Policies ✔

App restrictions (profile- and device-scoped), screen-time policies, recurring
schedules with DST-correct local-time semantics, overlap rejection, protected
packages, optimistic concurrency, monotonic policy versioning with an audit
trail, server-side precedence resolution, per-device sync state, capability
warnings.

### Commands and synchronisation ✔

Strict allow-list with per-type payload schemas and a discriminated union, a
validated state machine, durable creation before any delivery attempt, a
transactional outbox with claim-by-lease and bounded backoff and dead-lettering,
content-free FCM wake-ups, device fetch marking `delivered`, acknowledgement and
result handling with late/duplicate/out-of-order reconciliation, pre-flight
capability checks, TTL expiry, wake-up re-queueing.

### Usage, alerts, events ✔

Daily summary ingestion as an upsert with plausibility validation and per-day
rejection reasons, batch backfill, per-app breakdown with a bounded tail,
aggregate reports that report missing days, deduplicated device events with a
payload deny-list, deduplicated alerts, auto-resolution when a condition clears,
notification preferences with quiet hours and non-suppressible security
notifications.

### Realtime ✔ (single-node verified)

WebSocket ticket exchange with a dedicated audience and kind, membership
re-checked against the database at subscribe time, content-free event payloads,
Redis pub/sub fan-out, ping/pong, reconnection documented.

**Gap:** multi-instance fan-out through Redis is written but untested.

### Admin ✔

Separate authentication boundary, row-based granular permissions, overview and
analytics, user/family/device search with narrow projections, status changes
with mandatory reasons, support tickets, abuse reports with mandatory
resolution notes, device revocation, audit log reading. Sensitive reads are
audited, not only writes.

### Privacy ✔

Versioned consent records, consent withdrawal that deletes the data it
authorised, inline data export, account deletion with immediate device
unlinking and a cancellable grace period, retention sweeps per data category,
anonymisation on completion, explicit retention exceptions.

### Background jobs ✔

Celery app with a beat schedule, plus a single-job CLI runner. Outbox
publication, command expiry, pairing invitation expiry, stale-device marking,
session and token cleanup, retention application, due deletions, wake-up
re-queueing, revoked-device token sweeping. All idempotent, bounded and tested
through direct calls rather than through a broker.

## Gated off by default ◐

| Feature | Flag | Why |
| --- | --- | --- |
| Location | `FEATURE_LOCATION_ENABLED=false` | Needs disclosure text, a consent flow in both apps, a privacy/legal review and Play background-location approval. The server path is complete and tested. |
| Website restrictions | `FEATURE_WEBSITE_RESTRICTIONS_ENABLED=false` | No compliant general cross-browser mechanism on Android. Model and read endpoint exist; there is no write endpoint, deliberately, so intent cannot be stored for something nothing can enforce. |

Enabling either requires the checklist in
[FEATURE_CAPABILITY_MATRIX.md](FEATURE_CAPABILITY_MATRIX.md).

## Interface only ◻

| Surface | State | Behaviour |
| --- | --- | --- |
| Payment provider | `PaymentProvider` interface, a `disabled` provider, and a working HMAC webhook verifier (`generic_hmac`) with signature, timestamp-tolerance, replay and idempotency handling — all tested | `POST /billing/.../checkout` returns `503 INTEGRATION_NOT_CONFIGURED`. No provider selected, and none hardcoded. |
| Object storage | `ObjectStorage` interface with content-type and size allow-lists, and a `disabled` provider | Every method raises `503`. Avatars, support attachments and export artifacts are therefore unavailable; export is returned inline instead. |
| SMTP email | Implemented, but only exercised against the console sink and a fake in tests | Works; unverified against a real provider. |

The inbound half of billing — the half that moves money-backed entitlement — is
real. The outbound half needs a provider SDK and a product decision.

## Not built ✖

| Item | Note |
| --- | --- |
| Admin TOTP verification | Delegated to the identity provider or reverse proxy. The session records whether MFA was satisfied; in production an account marked `mfa_required` whose session does not record it is refused. **No fake verifier was written.** See [DEPLOYMENT.md](DEPLOYMENT.md). |
| Phone verification | The master prompt lists it as a later integration, not an assumption. No model, no endpoint. |
| Uninstall protection / remote lock | Needs a device-owner deployment. The product reports an uninstall *attempt* as an event and alerts instead. |
| Server-side usage aggregation jobs | Devices submit per-day aggregates and the API aggregates ranges on read. A pre-aggregation job would only be needed at a data volume this deployment has not reached. |
| Ownership transfer | A family owner cannot currently hand ownership to another guardian. Removal of the owner is refused, so this is a real functional gap. |
| Prometheus endpoint | `METRICS_ENABLED` exists and the signals to export are documented, but no exporter is wired. |
| Sentry | `SENTRY_DSN` is accepted; no SDK is initialised. |
| CI pipeline | `make check` is the single command CI should run; no workflow file is included. |

## Deliberately out of scope — permanently

Not a backlog. These are the product's boundary, and the API rejects attempts
to supply them:

message and call content · SMS · contacts · call logs · keystrokes · clipboard ·
microphone · camera · screen capture · browsing history · full installed-app
inventory · hardware identifiers (IMEI, serial, MAC, advertising id) · a child's
full date of birth · covert installation · permission bypass · stealth
persistence · any arbitrary-execution device command

`tests/unit/test_command_state_machine.py` asserts no execution-style command
type exists; `tests/security/test_input_and_disclosure.py` asserts the API
rejects both the command types and the telemetry fields.

## Honest risk list

Ranked by what would hurt most if it went wrong.

1. **App blocking may be `unsupported` on many real devices.** This is the
   product's core promise and the most platform-constrained feature. The server
   handles it correctly — it reports `unsupported` rather than pretending — but
   the product-level answer is an Android and Play-policy question the Child App
   team must settle. See
   [FEATURE_CAPABILITY_MATRIX.md](FEATURE_CAPABILITY_MATRIX.md).
2. **No PostgreSQL run yet.** The DDL compiles for PostgreSQL and the models are
   exercised on SQLite, but a first real run is required. Most likely surprises:
   collation behaviour on `ilike` searches, and index build time on large tables.
3. **Admin API must not be exposed without the MFA layer.** The code refuses a
   non-MFA session in production, but the factor itself is external.
4. **Push delivery is unverified against live FCM.** Error-code mapping
   (`UnregisteredError`, `SenderIdMismatchError`, quota errors) is written from
   the SDK contract, not observed.
5. **Rate limiting under a Redis outage fails open by default.** Deliberate, and
   configurable, but it should be a conscious decision per deployment.
6. **No load testing.** Device polling and usage ingestion are the paths that
   scale with installed devices.
7. **Ownership transfer is missing**, which will become a support burden.

## Next steps, in order

1. Run against PostgreSQL 16: migrate, run the suite against it, fix anything
   dialect-specific.
2. Build the Docker image and bring the compose stack up; verify the worker and
   scheduler actually drain the outbox.
3. Verify rate limiting and WebSocket fan-out against a real Redis, with two API
   instances.
4. Configure a real FCM project in a sandbox and verify wake-up delivery and
   token-invalidation handling end to end.
5. Wire CI to `make check`, plus `pip-audit` and image scanning.
6. Add the metrics exporter and the alerting thresholds from
   [DEPLOYMENT.md](DEPLOYMENT.md).
7. Have the Child App team validate the capability matrix against target devices
   and Play policy.
8. Commission the external security review and the privacy/legal review.
9. Load-test device polling and usage ingestion; revisit indexes with
   `EXPLAIN ANALYZE`.
10. Decide on a payment provider, then implement checkout against the existing
    interface.

**The application starting is not production readiness.** Production readiness
needs the security review, the privacy and legal review, Android capability
validation, load testing, monitoring, a verified backup *and restore*, and a
successful staging deployment with all three clients.
