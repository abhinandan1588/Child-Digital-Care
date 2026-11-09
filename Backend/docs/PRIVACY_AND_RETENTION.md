# Privacy, data inventory and retention

This product handles data about children. The constraints below are
architectural, not a checklist appended at the end — several of them are
enforced by database constraints and tests rather than by convention.

> **Scope note.** This document describes what the software does. It is not
> legal advice and does not substitute for a DPIA, a privacy policy, or a
> jurisdiction-specific legal review. Those are prerequisites to launch.

## What is deliberately not collected

The following are absent from the schema, absent from the API, and rejected if
submitted:

- Message, SMS, chat or call **content**
- Keystrokes, clipboard contents, passwords
- Microphone audio, camera images, screen captures or recordings
- Browsing history or visited URLs
- Contact lists, call logs
- A full installed-app inventory
- Hardware identifiers: IMEI, serial number, MAC address, advertising id
- A child's full date of birth
- A child's email address or phone number

`POST /device/events` rejects a payload containing `latitude`, `longitude`,
`message_body`, `keystrokes`, `screenshot`, `browsing_history` and similar keys
with `409`. There is no endpoint that accepts them, and
`tests/security/test_input_and_disclosure.py` asserts the rejection.

There is also no mechanism for covert operation: no hidden installation, no
permission bypass, no accessibility-service abuse, no stealth persistence, and
no command that circumvents Android security. See
[FEATURE_CAPABILITY_MATRIX.md](FEATURE_CAPABILITY_MATRIX.md).

## Data inventory

Classification: **P** personal, **S** sensitive, **C** credential,
**T** telemetry, **O** operational.

### Identity

| Field | Class | Purpose | Access | Retention |
| --- | --- | --- | --- | --- |
| `users.email`, `normalized_email` | P | Login, notifications, recovery | self; admin with `users.read` | Life of account, then anonymised |
| `users.display_name` | P | Addressing the user | self; admin with `users.read` | As above |
| `users.password_hash` | C | Authentication | never returned | Life of account |
| `users.timezone`, `locale` | P | Schedule and display correctness | self; admin with `users.pii.read` | Life of account |
| `users.last_login_at`, `failed_login_count` | O | Abuse detection | self; admin | Life of account |
| `user_sessions.refresh_token_hash` | C | Session validation | never returned | Until expiry + 7-day grace |
| `user_sessions.ip_prefix` | P | Session review, abuse | self (as session metadata) | With the session |
| `email_verification_tokens`, `password_reset_tokens` | C | One-time flows | never returned | Until expiry + grace |

IP addresses are **never stored in full**: IPv4 is truncated to a /24 and IPv6
to a /48 before storage, in sessions and in the audit log.

### Children and devices

| Field | Class | Purpose | Access | Retention |
| --- | --- | --- | --- | --- |
| `child_profiles.display_name` | P | Parent-facing label | family; admin with `families.read` | Life of profile |
| `child_profiles.age_band` | P | Age-appropriate defaults | family | Life of profile |
| `child_profiles.birth_year` | P | **Nullable and unused by default** | family | Only if a documented legal need exists |
| `child_profiles.timezone` | O | Schedule correctness | family | Life of profile |
| `devices.device_label`, `device_model`, `manufacturer` | P | Identify which device | family; admin with `devices.read` | Life of device |
| `devices.os_version`, `app_version` | O | Capability reasoning, support | family; admin | Life of device |
| `devices.install_id` | O | Idempotent re-pairing (random, not hardware) | internal | Life of device |
| `devices.last_seen_at` | T | Presence inference | family; admin | Life of device |
| `device_capabilities`, `device_permission_reports` | T | Explain what can be enforced | family; admin with `devices.read` | Latest state only |
| `device_sessions.refresh_token_hash` | C | Device authentication | never returned | Until expiry + grace |
| `pairing_invitations.token_hash`, `short_code_hash` | C | Pairing | never returned | 15 min, then swept |

Only the *latest* capability and permission state is kept per device;
transitions become `device_events`, so this table stays small.

### Policies

| Field | Class | Purpose | Access | Retention |
| --- | --- | --- | --- | --- |
| `app_restrictions.package_identifier` | P | The rule itself | family | Life of policy |
| `screen_time_policies` / `_schedules` | P | The rule itself | family | Life of policy |
| `policy_versions` | O | Change history, accountability | family; admin with `audit_logs.read` | Life of child profile |
| `device_policy_states` | T | What each device actually applied | family | Life of device |

### Telemetry

| Field | Class | Purpose | Access | Retention |
| --- | --- | --- | --- | --- |
| `usage_daily_summaries` | T | Screen-time reports | family with `usage.read`; admin with `child_usage.read` | `RETENTION_USAGE_SUMMARIES_DAYS` (400) |
| `app_usage_summaries` | T | Per-app breakdown, top 100/day | as above | With its parent summary |
| `device_events` | T | Alerting, diagnosis | family | `RETENTION_DEVICE_EVENTS_DAYS` (90) |
| `alerts` | T | Parent notifications | family with `alerts.read` | Life of family |
| `location_samples` | **S** | Optional location feature | family with `location.read` only | `RETENTION_LOCATION_SAMPLES_DAYS` (30) |

Usage is **aggregate only**: per-day totals, per-category totals, and
per-package foreground seconds. There is no per-launch timeline and no content.
The tail beyond the top 100 packages per day is collapsed into a single
`other.aggregated` row, which bounds the table and is all a report needs.

### Notifications, billing, support, audit

| Field | Class | Purpose | Access | Retention |
| --- | --- | --- | --- | --- |
| `push_tokens.token_value` | C | Delivery routing | never returned (last 6 chars only) | Until deregistered or rejected |
| `notification_deliveries` | O | Delivery observability | admin | 90 days (operational) |
| `subscriptions`, `plans` | P/O | Entitlement | family with `billing.manage`; admin with `subscriptions.read` | Legal/tax period |
| `payment_webhook_events.payload` | O | Idempotency, dispute evidence | admin with `subscriptions.read` | Legal/tax period |
| `support_tickets` / `_messages` | P | Support | ticket owner; admin with `support_tickets.read` | 2 years after closure |
| `abuse_reports` | **S** | Trust and safety | admin with `abuse_reports.read` | Retained for pattern detection |
| `audit_logs` | O | Accountability | admin with `audit_logs.read` | `RETENTION_AUDIT_LOG_DAYS` (730) |
| `consent_records` | P | Proof of disclosure | self; admin | Life of account + legal period |
| `privacy_requests` | P | Proof an obligation was met | self; admin | Retained after completion |

## The location module

Off by default. A sample is accepted only when **all four** hold:

1. `FEATURE_LOCATION_ENABLED=true` for the deployment.
2. A `location_collection` consent record exists, is `granted`, not revoked.
3. The device reported a location capability as `supported`.
4. The device reported the Android permission as `granted`.

If any fails, the API returns `accepted: false` with a `rejection_code` and
stores nothing. It never fabricates or interpolates a position.

| Control | Implementation |
| --- | --- |
| Precision | Rounded to 3 decimal places (~110 m) **before storage** |
| Retention | Hard `retention_expires_at` per row; swept daily |
| Parent access | Non-delegatable `location.read`; never in the default guardian grant |
| Admin access | `child_location.read` — held by no default role but `super_admin` |
| Audit | Every read logged, including reads that return nothing; coordinates never in the audit metadata |
| Consent withdrawal | Deletes every sample for the family immediately |
| Collection pattern | Command-driven or an explicitly consented interval. No continuous or covert collection path exists |
| Logs | `latitude`/`longitude` are in the logging deny-list and redacted before an event leaves the process |

Precision is reduced because a parent needs "which part of town", and a
doorstep-accurate history would increase harm from a breach without improving
the product.

## Consent and disclosure

Each record pins the exact policy version shown, who recorded it, how, and on
which surface. Withdrawal is a state change on the record, never a deletion, so
the history of what was disclosed when stays intact.

| Type | Recorded when | By |
| --- | --- | --- |
| `parent_terms` | Registration | Parent App |
| `parent_privacy_policy` | Registration | Parent App |
| `child_device_disclosure` | Pairing claim | Child App, with `disclosure_version` |
| `location_collection` | Explicit opt-in | Parent App |
| `usage_collection` | Where a deployment requires separate consent | Parent App |

The pairing claim **requires** `disclosure_acknowledged: true`. A device cannot
be enrolled without someone acknowledging an on-device disclosure, and the
acknowledged version is stored.

## Retention and deletion

| Category | Default | Setting |
| --- | --- | --- |
| Device events | 90 days | `RETENTION_DEVICE_EVENTS_DAYS` |
| Usage summaries | 400 days | `RETENTION_USAGE_SUMMARIES_DAYS` |
| Location samples | 30 days | `RETENTION_LOCATION_SAMPLES_DAYS` |
| Command history | 180 days | `RETENTION_COMMAND_HISTORY_DAYS` |
| Audit logs | 730 days | `RETENTION_AUDIT_LOG_DAYS` |
| Idempotency records | 24 hours | `RETENTION_IDEMPOTENCY_HOURS` |
| Expired sessions/tokens | expiry + 7 days | `cleanup_sessions` grace |

`cdc.maintenance.apply_retention` runs daily and deletes past-deadline rows.
Retention is enforced by a deadline column on the row, set at write time, so a
later change to the configured window does not retroactively resurrect or
destroy data unexpectedly.

### Deletion workflow

```text
POST /privacy/account/delete   (password + "DELETE MY ACCOUNT")
  ├─ account_status → pending_deletion
  ├─ every device unlinked NOW          ← monitoring stops immediately
  ├─ every session revoked
  └─ privacy_requests row created, due_at set

  ... 14-day grace period (DELETION_GRACE_PERIOD_DAYS) ...
  └─ cancellable via POST /privacy/account/delete/cancel

After the grace period, cdc.privacy.execute_due_deletions:
  ├─ usage summaries        DELETE
  ├─ location samples       DELETE
  ├─ device events          DELETE
  ├─ families               DELETE (cascades devices, policies, commands, alerts)
  ├─ child profiles         anonymised then marked deleted
  ├─ user row               anonymised: deleted+<uuid>@invalid, "[deleted]"
  └─ audit log entry written
```

Two choices worth stating plainly:

- **Devices are unlinked at the start, not the end.** The point of deletion is
  that monitoring stops. Waiting two weeks would be the wrong behaviour,
  especially if the request came from someone escaping unwanted surveillance.
- **The user row is anonymised rather than dropped.** Foreign keys elsewhere use
  `ON DELETE SET NULL`, and a tombstone prevents id reuse.

### What is retained, and why

Returned to the user on the request as `retention_exceptions`:

| Retained | Reason |
| --- | --- |
| `audit_logs` | Security and abuse investigation. Contains no personal payloads and is not linked to deleted data by foreign key. |
| Billing records | Tax and accounting obligations. |
| `abuse_reports` | So a repeat pattern remains identifiable after an account is removed. |
| The `privacy_requests` row | Proof the obligation was met. |

## Export

`GET /privacy/export` returns the account, families, child profiles, devices and
consent records inline, plus a note pointing at the usage and location endpoints
for per-child telemetry. Credentials, token hashes and password hashes are
excluded, which `tests/integration/test_privacy_and_billing.py` asserts.

Object storage is not configured in this release, so there is no signed download
URL. The interface exists; see
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Logging and audit hygiene

The structured logger runs a redaction processor before any event leaves the
process. Deny-listed keys are replaced with `[redacted]`, and inline JWTs and
`Bearer` values are scrubbed from free text — so an accidental
`log.info("x", token=...)` cannot leak.

Never logged: passwords, access or refresh tokens, pairing secrets, reset or
verification tokens, full push tokens, coordinates, full request bodies.

`audit_logs` is append-only. The application never issues an UPDATE or DELETE
against it, the table has **no foreign keys at all** (so deleting a family
cannot cascade its audit trail away), and metadata is passed through a
deny-list before it is written. The deployment should additionally grant the
application role only `INSERT, SELECT` on the table; see
[DEPLOYMENT.md](DEPLOYMENT.md).

## Abuse: non-consensual monitoring

The central abuse risk for a parental-control product is an adult using it to
monitor another adult, or a child, without consent. Mitigations:

- `non_consensual_monitoring` is a first-class `abuse_reports` category with its
  own review path.
- Pairing requires an on-device disclosure acknowledgement, recorded with its
  version.
- The Child App is expected to be visibly installed and identifiable; the
  backend provides no covert mode.
- Trust-and-safety staff can unlink a device (`devices.revoke`) and must record
  written `resolution_notes` — the API rejects a decision without them.
- Every privileged read and write is audited with the actor's identity.

## Incident response outline

1. **Detect** — alerting on authentication failure spikes, `REFRESH_TOKEN_REUSED`
   events, outbox dead-letters, and rate-limit saturation.
2. **Contain** — rotate `SECRET_KEY` or the JWT keypair (invalidates all access
   tokens), revoke sessions for affected accounts, suspend accounts if needed.
3. **Assess** — query `audit_logs` by actor, family or action to establish what
   was accessed and when.
4. **Notify** — follow the jurisdiction's breach-notification requirements;
   families whose child data was involved are the priority.
5. **Recover** — restore from a verified backup if integrity is in question,
   force password resets, re-pair devices.
6. **Review** — write up the timeline and add a regression test for the cause.

Key rotation, backup/restore and the runbooks are in
[DEPLOYMENT.md](DEPLOYMENT.md).
