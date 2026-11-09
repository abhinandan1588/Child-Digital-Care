# Child Digital Care — Backend

Backend API for an Android-first parental-control and family digital-wellbeing
platform. This service is the single source of truth for three separately
developed clients: a **Parent App** (Flutter), a **Child App** (Kotlin/Android),
and an **Admin Dashboard** (Next.js). The clients never talk to each other or to
the database directly.

**Stack:** Python 3.12+, FastAPI, PostgreSQL 16, SQLAlchemy 2.x (async),
Alembic, Pydantic v2, Redis, Celery, Firebase Cloud Messaging (optional),
WebSockets, Docker.

---

## What this service does and does not claim

The server stores policy **intent**, distributes typed commands, and records
what devices report back. It cannot enforce anything on an Android device.

That distinction is visible in the API, not just the documentation:

- A policy change returns `sync_status: "pending_sync"`. It never claims an app
  is blocked.
- A rule is reported as applied only because a device acknowledged applying it.
- `unsupported` and `permission_denied` are first-class command results and are
  stored verbatim. Nothing translates them into success.
- Device capabilities and Android permission states are stored as
  *device-reported facts*, and the policy bundle returns
  `capability_warnings` naming devices that cannot enforce what is configured.

---

## Quick start (Docker)

```bash
cp .env.example .env            # review before first run
docker compose up --build       # api, worker, scheduler, postgres, redis, mailpit

docker compose exec api alembic upgrade head
docker compose exec api python -m app.scripts.seed_admin_rbac
docker compose exec api python -m app.scripts.seed_dev          # fake dev data
docker compose exec api python -m app.scripts.create_admin \
    --email ops@example.com --role super_admin --generate-password
```

| Service | URL |
| --- | --- |
| API | <http://localhost:8000> |
| Interactive docs | <http://localhost:8000/docs> |
| OpenAPI schema | <http://localhost:8000/openapi.json> |
| Mail sink (verification/reset emails) | <http://localhost:8025> |

```bash
docker compose exec api pytest              # tests
docker compose exec api ruff check .        # lint
docker compose exec api ruff format --check .
docker compose exec api mypy                # types
docker compose down                         # stop
```

## Quick start (no Docker)

The test suite and a local dev server run on SQLite, so no external services are
needed to get going. **PostgreSQL remains the only supported production
database**; SQLite support exists so tests are fast and hermetic.

```bash
make venv              # virtualenv + dependencies
make dev-migrate       # migrate ./local.sqlite3
make seed-rbac         # admin permission/role catalogue
make seed              # fake development data
make dev               # http://localhost:8000
```

Seeded development credentials (never valid anywhere real):

| Account | Password |
| --- | --- |
| `parent@example.test` | `dev-password-not-secret` |
| `coparent@example.test` | `dev-password-not-secret` |

Run `make help` for the full task list.

---

## Project layout

```text
app/
├── main.py                 FastAPI app factory, middleware order, OpenAPI
├── api/
│   ├── deps.py             authn/authz dependencies (the only place scope is derived)
│   ├── health.py           liveness, readiness, integration status
│   └── v1/
│       ├── router.py       route assembly
│       └── endpoints/      one module per surface
├── core/                   config, errors, logging, security, permissions, rate limits
├── db/
│   ├── base.py             declarative base, naming convention, mixins
│   ├── types.py            portable column types (UUID, UTC timestamp, JSONB variant)
│   ├── enums.py            domain vocabulary shared by models and schemas
│   ├── session.py          async engine and request-scoped transactional session
│   └── models/             50 tables
├── schemas/                request/response models (the API contract)
├── repositories/           query helpers (keyset pagination, row counts)
├── services/               all business logic and every authorization decision
├── integrations/           email, firebase, payments, storage (each with a disabled mode)
├── workers/                celery app, async jobs, single-job CLI runner
├── websocket/              connection registry and Redis fan-out
├── scripts/                create_admin, seed_admin_rbac, seed_dev
└── utils/                  timezone-aware time helpers
migrations/                 Alembic environment and versions
tests/{unit,integration,security,contract}
docs/                       architecture, contract, privacy, deployment, integration
```

---

## Architecture in one picture

```text
Parent App (Flutter) ─────┐
                          │  HTTPS + WebSocket
Child App (Android) ──────┼──── FastAPI ──── PostgreSQL  (source of truth)
                          │        │
Admin Dashboard (Next.js) ┘        ├── Redis            (rate limits, pub/sub, broker)
                                   ├── Celery worker    (outbox, retention, expiry)
                                   ├── FCM              (wake-up signals only)
                                   ├── Email provider   (verification, reset)
                                   ├── Payments         (webhook-verified; none selected)
                                   └── Object storage   (optional; disabled)
```

The reliability model is a **transactional outbox**, not a push queue:

1. A parent's change and the resulting command commit in one transaction.
2. The same transaction writes an outbox row.
3. A worker turns that row into a content-free FCM wake-up.
4. The device wakes, polls `GET /device/commands`, acts, and reports back.

A lost push loses nothing: the command is still in PostgreSQL waiting to be
polled. See [docs/COMMAND_DELIVERY.md](docs/COMMAND_DELIVERY.md).

---

## Three principals, three audiences

| Principal | Token audience | Obtained from |
| --- | --- | --- |
| Parent / guardian | `cdc:parent` | `POST /api/v1/auth/login` |
| Child device | `cdc:device` | `POST /api/v1/device/pairing/claim` |
| Admin | `cdc:admin` | `POST /api/v1/admin/auth/login` |

A credential for one principal is rejected on another's routes, and the
authorization tests assert that in both directions.

Access tokens are short-lived JWTs. Refresh tokens are opaque 256-bit values,
stored only as SHA-256 hashes, rotated on every use, with reuse of a consumed
token revoking the whole token family. See
[docs/AUTH_AND_RBAC.md](docs/AUTH_AND_RBAC.md).

---

## API conventions

Every success response:

```json
{
  "success": true,
  "message": "Policy created successfully",
  "data": { "id": "uuid", "status": "pending" },
  "meta": { "request_id": "request-id" }
}
```

Every error:

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

- `error.code` is a stable machine-readable value from a documented enum.
  Branch on the code, never on the message.
- Timestamps are ISO 8601 UTC. Externally exposed ids are UUIDs.
- Large collections use opaque cursor pagination (`page_info.next_cursor`).
- `Idempotency-Key` is honoured where a retry could duplicate work. The same
  key with a *different* body is rejected with `IDEMPOTENCY_KEY_REUSED`.
- `X-Request-ID` is accepted and echoed for correlation.

Full endpoint reference: [docs/API_CONTRACT.md](docs/API_CONTRACT.md).

---

## Configuration

All configuration comes from the environment. `.env.example` documents every
variable. Settings are validated at startup and a deployment **fails to boot**
when it is unsafe rather than running in a degraded state:

- `SECRET_KEY` still holding the example placeholder (staging/production)
- `DEBUG=true`, wildcard `CORS_ORIGINS`, or wildcard `TRUSTED_HOSTS` in production
- `EMAIL_PROVIDER=console` in production
- SQLite outside development/test
- a payment provider selected without `PAYMENT_WEBHOOK_SECRET`
- `PUSH_PROVIDER=fcm` without a credentials path

Optional integrations default to **disabled** and report themselves honestly at
`GET /health/integrations`. A disabled integration returns an explicit
`INTEGRATION_NOT_CONFIGURED` or `FEATURE_DISABLED` error; nothing fakes success.

Feature gates, all off by default except where noted:

| Flag | Default | Notes |
| --- | --- | --- |
| `FEATURE_LOCATION_ENABLED` | `false` | Also needs a consent record and a device-reported permission |
| `FEATURE_WEBSITE_RESTRICTIONS_ENABLED` | `false` | No compliant cross-browser Android implementation yet |
| `FEATURE_GUARDIAN_INVITATIONS_ENABLED` | `true` | |
| `FEATURE_WEBSOCKETS_ENABLED` | `true` | REST remains the source of truth |

---

## Database and migrations

Alembic is the schema strategy. `Base.metadata.create_all` is used **only** by
the test fixtures, and `tests/integration/test_migrations.py` asserts the
migration and the models agree (tables, columns, uniqueness, rollback).

```bash
make migrate                      # alembic upgrade head
make migration m="add x"          # autogenerate
make migration-check              # fail if models and migrations disagree
make sql                          # print the DDL without applying it
```

50 tables. Data model: [docs/ERD.md](docs/ERD.md) and
[docs/DATABASE_DICTIONARY.md](docs/DATABASE_DICTIONARY.md).

---

## Testing

```bash
make test             # whole suite
make test-security    # authorization boundaries only
make check            # lint + format + types + migration drift + tests
```

| Suite | Covers |
| --- | --- |
| `tests/unit` | password hashing, token audiences, command state machine, policy precedence, schedule/DST logic, permission evaluation |
| `tests/integration` | auth flows, pairing (including races and brute force), policies and versioning, outbox and commands, usage, alerts, admin workflows, privacy workflows, billing webhooks, background jobs, migration parity |
| `tests/security` | cross-family isolation, cross-principal rejection, device scope, admin privilege boundaries, command allow-list, telemetry scope, response and log disclosure |
| `tests/contract` | OpenAPI generation, envelope shape, documented examples |

The suite uses an isolated database per test and fake integrations: no email
leaves the process, no push is sent, no payment provider is contacted.

By default it runs on in-memory SQLite with the in-process rate-limit fallback,
which reports **292 passed, 14 skipped** — the skips are the PostgreSQL- and
Redis-specific tests. Point it at real services to run all of them:

```bash
TEST_DATABASE_URL="postgresql+asyncpg://user@/db?host=/run/pg" \
TEST_REDIS_URL="redis://127.0.0.1:6379/0" \
make test             # 306 passed
```

`TEST_DATABASE_URL` switches `conftest.py` to `TRUNCATE` between tests instead
of recreating the schema. `TEST_REDIS_URL` enables the rate-limiter and pub/sub
tests, which are skipped without it — a Redis-version defect once hid there
because every test ran on the fallback, so CI should set it against the oldest
Redis the deployment supports.

[docs/LOCAL_VERIFICATION.md](docs/LOCAL_VERIFICATION.md) has copy-pasteable
steps for standing up PostgreSQL and Redis in userspace, with no Docker or
`sudo`.

---

## Privacy and child safety

This is a product about children's data, so the constraints are structural:

- An age **band**, not a date of birth.
- No message content, call content, keystrokes, microphone, camera, screen
  capture, or browsing history — anywhere. Device events carrying such fields
  are rejected with `409`.
- Location is off by default and gated on four independent conditions. Every
  read is audited. Coordinates are stored rounded to about 110 m.
- Push payloads are content-free: a reason code, never child telemetry.
- `audit_logs` is append-only and has no foreign keys, so deleting a family
  cannot erase its own audit trail.
- Deletion unlinks every device immediately and erases data after a
  cancellable grace period, with retained categories stated explicitly.
- No admin role carries `child_location.read` or `child_usage.read` by default.

See [docs/PRIVACY_AND_RETENTION.md](docs/PRIVACY_AND_RETENTION.md) and
[docs/FEATURE_CAPABILITY_MATRIX.md](docs/FEATURE_CAPABILITY_MATRIX.md).

---

## Documentation

| Document | Contents |
| --- | --- |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, trust boundaries, request flows |
| [ERD.md](docs/ERD.md) | Entity-relationship diagram |
| [DATABASE_DICTIONARY.md](docs/DATABASE_DICTIONARY.md) | Every table, purpose, classification, retention |
| [API_CONTRACT.md](docs/API_CONTRACT.md) | Endpoints, auth, errors, pagination, examples |
| [AUTH_AND_RBAC.md](docs/AUTH_AND_RBAC.md) | Principals, token lifecycle, permission matrices |
| [PAIRING_FLOW.md](docs/PAIRING_FLOW.md) | QR/code pairing, claim, recovery, revocation |
| [COMMAND_DELIVERY.md](docs/COMMAND_DELIVERY.md) | Outbox, wake-ups, lifecycle, retries, sync semantics |
| [PRIVACY_AND_RETENTION.md](docs/PRIVACY_AND_RETENTION.md) | Data inventory, access, retention, deletion |
| [FEATURE_CAPABILITY_MATRIX.md](docs/FEATURE_CAPABILITY_MATRIX.md) | Android capability reality per feature |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Staging/production config, TLS, secrets, backups, runbooks |
| [INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) | How each client team integrates |
| [CHANGELOG_API.md](docs/CHANGELOG_API.md) | API contract changes |
| [IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) | What is implemented, stubbed, or not built |
| [LOCAL_VERIFICATION.md](docs/LOCAL_VERIFICATION.md) | Running PostgreSQL, Redis and the full suite without Docker |

---

## Production readiness

The application starting is not production readiness. Before a production
launch this service still needs: an external security review, a privacy and
legal review for the target jurisdictions, Android capability and Google Play
policy validation by the Child App team, load testing, monitoring and alerting,
verified backup **and restore**, and a successful staging deployment.

[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) lists the known
gaps honestly.
