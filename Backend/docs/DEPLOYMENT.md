# Deployment

## Environments

| | development | test | staging | production |
| --- | --- | --- | --- | --- |
| Database | SQLite or Postgres | SQLite (in-memory) | PostgreSQL | PostgreSQL |
| Redis | optional | not used | required | required |
| JWT algorithm | HS256 | HS256 | RS256 | RS256 (enforced) |
| Email | console / mailpit | fake | real provider | real provider (console rejected) |
| Interactive docs | on | on | on | off |
| `DEBUG` | true | false | false | false (enforced) |
| CORS | localhost | localhost | allow-list | allow-list, no wildcard (enforced) |

## Fail-fast configuration

Settings are validated at import. A deployment **refuses to start** rather than
running in a quietly unsafe state. Staging and production both reject:

- `SECRET_KEY` still holding the `.env.example` placeholder, or under 32 chars
- `*` in `CORS_ORIGINS`, or an empty allow-list
- a missing `REDIS_URL`
- a SQLite `DATABASE_URL`

Production additionally rejects `DEBUG=true`, `EMAIL_PROVIDER=console`,
`TRUSTED_HOSTS=*`, and `JWT_ALGORITHM` other than RS256. Any environment
rejects a payment provider without `PAYMENT_WEBHOOK_SECRET`, `PUSH_PROVIDER=fcm`
without a credentials path, and `EMAIL_PROVIDER=smtp` without `SMTP_HOST`.

Verify before rollout:

```bash
APP_ENV=production <your env> python -c "from app.core.config import get_settings; get_settings(); print('config ok')"
```

## Secrets

| Secret | Source | Rotation |
| --- | --- | --- |
| `SECRET_KEY` | secret manager | quarterly; invalidates all access tokens |
| JWT keypair | mounted PEM files | quarterly or on suspicion |
| `DATABASE_URL` | secret manager | on credential rotation |
| Firebase service account | mounted file (`FIREBASE_CREDENTIALS_PATH`) | per Google guidance |
| `PAYMENT_WEBHOOK_SECRET` | secret manager | per provider guidance |
| SMTP credentials | secret manager | per provider guidance |

Never in the image, never in the repository, never in a build argument. The
`.gitignore` and `.dockerignore` both exclude `.env`, `*.pem`, `*.key` and
`*service-account*.json`, and the Dockerfile copies no configuration.

### Key rotation runbook

```text
1. Generate the new keypair:
     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out jwt-new.pem
     openssl rsa -in jwt-new.pem -pubout -out jwt-new.pub
2. Publish the new PUBLIC key to all instances first and restart them, so every
   instance can verify tokens signed with either key.
3. Switch JWT_PRIVATE_KEY_PATH to the new private key and restart.
4. Wait for ACCESS_TOKEN_EXPIRE_MINUTES (15) so old access tokens expire.
5. Remove the old keys.
```

Refresh tokens are unaffected by signing-key rotation: they are opaque and
validated against the database, so users are not signed out.

Rotating `SECRET_KEY` under HS256 invalidates every access token immediately —
which is exactly what you want during an incident, and exactly what you do not
want during routine maintenance. Prefer RS256 in production for that reason.

## Database

### Role grants

Give the application the narrowest role that works, and in particular make the
append-only audit log append-only *in the database*, not only by convention:

```sql
CREATE ROLE cdc_app LOGIN PASSWORD '<from secret manager>';
GRANT CONNECT ON DATABASE child_digital_care TO cdc_app;
GRANT USAGE ON SCHEMA public TO cdc_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cdc_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cdc_app;

-- Audit log: insert and read only. No UPDATE, no DELETE, ever.
REVOKE UPDATE, DELETE ON audit_logs FROM cdc_app;

-- Migrations run as a separate, higher-privileged role.
CREATE ROLE cdc_migrator LOGIN PASSWORD '<from secret manager>';
GRANT ALL ON SCHEMA public TO cdc_migrator;
```

Retention of audit rows is then handled by a scheduled job running as
`cdc_migrator` (or a dedicated role), not by the application.

### Connection pooling

`DATABASE_POOL_SIZE` (10) + `DATABASE_MAX_OVERFLOW` (5) per instance. Total
connections must stay below the Postgres `max_connections` budget:

```text
instances × (pool_size + max_overflow) + workers × (pool_size + max_overflow) < max_connections
```

Put PgBouncer in **transaction** pooling mode in front of Postgres if the
instance count grows. The application uses no session-level state (no temp
tables, no `SET LOCAL`), so transaction pooling is safe.

### Migrations

```bash
alembic upgrade head          # as cdc_migrator
alembic upgrade head --sql    # review the DDL first for a risky change
alembic downgrade -1          # roll back one revision
```

Rollout order: run migrations **before** deploying code that needs them, and
make them backwards compatible with the currently running version so a rollback
does not require a down-migration under pressure.

- Adding a column: nullable, or with a default. Never `NOT NULL` without a
  default on a populated table.
- Dropping a column: deploy code that stops using it, then drop it in a later
  release.
- Adding an index on a large table: `CREATE INDEX CONCURRENTLY` in a migration
  marked non-transactional.

CI runs `make migration-check`, which fails if the models and the migrations
have drifted.

### Backups

| | |
| --- | --- |
| Full backup | nightly `pg_dump` or a managed snapshot |
| PITR | WAL archiving with a 7-day minimum window |
| Retention | 30 daily, 12 monthly |
| Encryption | at rest, with a separate key from the database |
| Access | restricted; backups contain children's data |

**A backup that has never been restored is not a backup.** Schedule a quarterly
restore drill:

```text
1. Restore the latest backup into an isolated environment.
2. alembic current   → confirm the expected revision.
3. Row-count the main tables against expectations.
4. Boot the API against it and check /health/ready.
5. Record the wall-clock restore time. That number is your real RTO.
6. Destroy the environment.
```

## Running

### Container

The image runs as non-root (`uid 10001`), has no compiler and no pip cache, and
contains no configuration. Recommended runtime hardening:
read-only root filesystem, `--cap-drop ALL`, no privilege escalation.

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --workers 4 --proxy-headers --forwarded-allow-ips '<proxy CIDR>'
```

`--forwarded-allow-ips` must name the proxy, not `*`. Client IPs feed rate
limiting and audit records; trusting `X-Forwarded-For` from anywhere lets a
caller spoof both.

### Worker and scheduler

```bash
celery -A app.workers.tasks worker --loglevel=info --concurrency=4
celery -A app.workers.tasks beat  --loglevel=info      # exactly one instance
```

Running two beat schedulers double-fires every job. The jobs are idempotent, so
it is survivable, but it is still wrong.

### TLS and the reverse proxy

TLS terminates at the proxy. The application assumes HTTPS and sets HSTS when
`APP_ENV=production`. The proxy must:

- overwrite `X-Forwarded-For` and `X-Forwarded-Proto` (never append to a
  client-supplied value)
- enforce a request body limit at or below `MAX_REQUEST_BODY_BYTES`
- support WebSocket upgrades on `/api/v1/realtime/ws`
- front the admin API with the MFA-enforcing identity provider

### Admin MFA

This service does **not** implement a TOTP verifier. `admin_users.mfa_required`
records the requirement, the session records whether MFA was satisfied, and in
production an admin whose session does not record MFA is refused with
`MFA_REQUIRED`. Enforcement must happen in front of the API:

1. Put the admin surface behind an identity-aware proxy or SSO with MFA.
2. Restrict `/api/v1/admin/*` to that path at the network layer.
3. Keep `mfa_required = true` on every admin account.

Do not expose the admin API publicly without that layer.

## Scaling

| Component | Scaling | Notes |
| --- | --- | --- |
| API | horizontal, stateless | Redis carries rate limits and WebSocket fan-out |
| Worker | horizontal | Outbox claiming is race-safe by conditional UPDATE |
| Scheduler | **one instance** | |
| Postgres | vertical, then read replicas | Reports are the read-heavy path |
| Redis | single primary + replica | Losing Redis degrades rate limiting and realtime, not correctness |

Hot paths and their indexes: device command polling
(`ix_device_commands_device_id_status`), usage reports
(`ix_usage_daily_summaries_child_profile_id_local_date`), alert pagination
(`ix_alerts_family_id_status_occurred_at`), outbox draining
(`ix_outbox_events_status_available_at`). Re-check plans with `EXPLAIN ANALYZE`
once real data volumes exist; the index set was chosen from the query shapes,
not measured against production traffic.

## Monitoring

Minimum alerting:

| Signal | Threshold | Why it matters |
| --- | --- | --- |
| 5xx rate | > 1% over 5 min | |
| p99 latency | > 1 s | |
| `/health/ready` failing | any instance | database unreachable |
| Outbox backlog | > 1 000 or rising 10 min | devices are not being told to sync |
| Outbox dead-letters | > 0 | publication is broken |
| Expired commands | spike | devices are not reaching the API |
| `REFRESH_TOKEN_REUSED` | any spike | possible credential theft |
| Auth failure rate | spike | credential stuffing |
| Push failure rate | > 10% | FCM or token hygiene problem |
| Pool saturation | > 80% | |
| Celery queue depth | rising | |

`GET /admin/analytics/summary` exposes the command and push failure rates, which
are the two numbers that predict whether parents are being told the truth about
their devices.

Logs are structured JSON on stdout with a redaction processor. Ship them to a
store with restricted access: even redacted, they contain family identifiers.
Set `SENTRY_DSN` to enable error reporting, and confirm its own scrubbing is on.

## Dependency and image scanning

```bash
pip install pip-audit && pip-audit -r requirements.lock   # dependency CVEs
trivy image child-digital-care-backend:latest             # image CVEs
pip list --outdated
```

Run both in CI and fail the build on a high-severity finding with a fix
available. `requirements.lock` pins the full transitive set.

## Pre-launch checklist

Nothing below is optional, and the application starting is not evidence of any
of it.

- [ ] Configuration validated with `APP_ENV=production`
- [ ] RS256 keypair generated, mounted, and rotation rehearsed
- [ ] `SECRET_KEY` and all secrets from a secret manager
- [ ] `cdc_app` role granted; `UPDATE`/`DELETE` revoked on `audit_logs`
- [ ] Backups running **and a restore drill completed**
- [ ] TLS, HSTS, `--forwarded-allow-ips` set to the proxy
- [ ] Admin API behind MFA-enforcing SSO and network-restricted
- [ ] Rate limiting verified against a live Redis
- [ ] Monitoring and alerting wired to a rota
- [ ] Dependency and image scans clean
- [ ] `make check` green in CI
- [ ] External security review completed
- [ ] Privacy/legal review completed for each target jurisdiction
- [ ] Android capability and Play policy validation signed off by the Child App team
- [ ] Load test on the device-polling and usage-ingestion paths
- [ ] Incident response rota and runbooks in place
- [ ] Staging deployment exercised end to end with all three clients
