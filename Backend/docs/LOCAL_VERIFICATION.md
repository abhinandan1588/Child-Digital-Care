# Local verification environment

This document records how the verification run described in
[`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md) was executed, so it can be
reproduced without Docker, `sudo`, or a system package manager.

Everything below runs entirely in userspace under `/tmp`. Nothing is installed
system-wide, and nothing persists across a reboot.

## What gets started

| Service | Version | How it is provided | Address |
| --- | --- | --- | --- |
| PostgreSQL | 18.6 | `embedded-postgres` pip package | Unix socket at `/tmp/cdc_pgdata` (no TCP listener) |
| Redis | 6.2.14 | `redislite` pip package (bundled binary) | `127.0.0.1:6399` |
| API | — | `uvicorn` | `127.0.0.1:8000` |

> The deployment target is PostgreSQL 16 and Redis 7. These userspace builds are
> what was available in the verification environment. The schema uses no
> version-specific features, but this is a known difference — see "What remains
> unverified" in `IMPLEMENTATION_STATUS.md`.

## Shared environment variables

```bash
cd "/home/abhi/Apps/Child Digital Care/Backend"
. .venv/bin/activate

export PGBIN="$PWD/.venv/lib/python3.14/site-packages/embedded_postgres/pginstall/bin"
export PGURL="postgresql+asyncpg://postgres@/child_digital_care?host=/tmp/cdc_pgdata"
export TEST_REDIS="redis://127.0.0.1:6399/0"
```

The workspace path contains spaces. Always quote it. The `embedded_postgres`
package's own `.psql()` helper breaks on the spaces, so the steps below invoke
the PostgreSQL binaries directly instead of going through the library.

## 1. Start PostgreSQL

First time only — initialise the cluster and create the database:

```bash
mkdir -p /tmp/cdc_pgdata
"$PGBIN/initdb" -D /tmp/cdc_pgdata -U postgres --auth=trust
"$PGBIN/postgres" -D /tmp/cdc_pgdata -h "" -k /tmp/cdc_pgdata &
sleep 2
"$PGBIN/createdb" -h /tmp/cdc_pgdata -U postgres child_digital_care
```

On later runs, only the server needs starting:

```bash
"$PGBIN/postgres" -D /tmp/cdc_pgdata -h "" -k /tmp/cdc_pgdata &
```

`-h ""` disables the TCP listener, so the cluster is reachable only over the
local socket. Check it is up:

```bash
"$PGBIN/psql" -h /tmp/cdc_pgdata -U postgres -d child_digital_care -c "select version();"
```

## 2. Start Redis

```bash
REDIS_BIN=$(python -c "import redislite, os; print(os.path.join(os.path.dirname(redislite.__file__),'bin','redis-server'))")
mkdir -p /tmp/cdc_redis
"$REDIS_BIN" --port 6399 --bind 127.0.0.1 --dir /tmp/cdc_redis --save '' --appendonly no &
```

Persistence is off deliberately: this instance holds only rate-limit counters
and pub/sub traffic, both of which are disposable.

## 3. Migrate and seed

```bash
DATABASE_URL="$PGURL" alembic upgrade head
DATABASE_URL="$PGURL" alembic current   # expect: d59a190f423e (head)
DATABASE_URL="$PGURL" alembic check     # expect: no new upgrade operations

DATABASE_URL="$PGURL" APP_ENV=development python -m app.scripts.seed_dev
DATABASE_URL="$PGURL" APP_ENV=development python -m app.scripts.seed_admin_rbac
```

### Seeded credentials

These are development fixtures. They are intentionally fake and must never
exist in a deployed environment.

| Account | Password | Notes |
| --- | --- | --- |
| `parent@example.test` | `dev-password-not-secret` | Family owner |
| `coparent@example.test` | `dev-password-not-secret` | Delegated member |
| `admin@example.test` | `admin-local-password-123456` | `super_admin`; accepts any `mfa_code` locally |

## 4. Run the API

```bash
DATABASE_URL="$PGURL" \
REDIS_URL="$TEST_REDIS" \
APP_ENV=development DEBUG=true LOG_FORMAT=console \
SECRET_KEY="local-dev-secret-at-least-32-characters-long" \
RATE_LIMIT_ENABLED=true \
uvicorn app.main:app --port 8000
```

Then:

- Swagger UI — <http://localhost:8000/docs>
- Readiness (reports database and Redis status) — <http://localhost:8000/health/ready>

Note the absence of `--reload`. The reloader spawns a child process that can
survive a `Ctrl-C` and keep port 8000 bound; three such orphans had to be killed
during verification. If port 8000 is already taken, find the owner with
`ss -ltnp | grep 8000`.

## 5. Run the test suite against PostgreSQL and Redis

Two environment variables switch the suite off its defaults:

- `TEST_DATABASE_URL` is read by `tests/conftest.py`. When set, tables are
  `TRUNCATE`d between tests rather than dropped and recreated, which keeps a
  50-table schema fast enough to use per test.
- `TEST_REDIS_URL` is read by `tests/integration/test_rate_limit_redis.py`,
  which skips entirely when it is unset. That module covers both the rate
  limiter and the Redis pub/sub fan-out path.

```bash
APP_ENV=test \
SECRET_KEY="test-secret-key-at-least-32-characters-long" \
RATE_LIMIT_ENABLED=false \
DATABASE_URL="$PGURL" \
TEST_DATABASE_URL="$PGURL" \
TEST_REDIS_URL="$TEST_REDIS" \
python -m pytest tests
```

Expected: **306 passed**.

With neither variable set, the suite falls back to SQLite via `aiosqlite` and
reports **292 passed, 14 skipped** — the skips are the PostgreSQL- and
Redis-specific tests. `make check` runs lint, format check, mypy, the migration
drift check, and the SQLite suite.

## Shutting everything down

```bash
pkill -f "uvicorn app.main:app"
pkill -f "redis-server .*6399"
"$PGBIN/pg_ctl" -D /tmp/cdc_pgdata stop -m fast
```

To discard the data as well:

```bash
rm -rf /tmp/cdc_pgdata /tmp/cdc_redis
```

That removes the cluster entirely, so the next run needs the `initdb` step from
section 1 again.

## Manual testing notes

- Passwords must be at least 12 characters **and** must not contain the local
  part of the account's email address. `parent@example.test` cannot use a
  password containing `parent`.
- Swagger UI pre-fills string fields with the literal `"string"`. Submitting a
  request body unchanged returns `422` from validation, not a server error.
- Most endpoints need a bearer token: log in via `POST /api/v1/auth/login`, then
  paste the `access_token` into Swagger's **Authorize** dialog. 104 of the 119
  operations are marked with `BearerAuth` in the OpenAPI schema.
