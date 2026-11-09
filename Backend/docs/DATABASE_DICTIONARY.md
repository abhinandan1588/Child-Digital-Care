# Database dictionary

PostgreSQL. 50 tables. Every externally addressable row has a UUID primary key;
no endpoint exposes a sequential id. Every timestamp is `timestamptz`,
normalised to aware UTC in both directions by the `UtcDateTime` type decorator.

Classification: **P** personal · **S** sensitive · **C** credential ·
**T** telemetry · **O** operational.

Column-level purpose for the interesting fields is in the model docstrings;
this file is the table-level map with retention and access.

## Identity and access

### `users` — parent/guardian accounts · P, C
Soft-deleted. `normalized_email` (lower-cased) carries the unique constraint, so
`Alice@x` and `alice@x` cannot both register, while `email` keeps the typed
form. `failed_login_count` drives slowdown only — there is no lockout, because
locking an account on failures would let an attacker deny a victim access to
their own family's controls. **Retention:** life of account, then anonymised to
`deleted+<uuid>@invalid`.

### `user_sessions` — parent refresh sessions · C
Only `refresh_token_hash` (SHA-256) is stored. `token_family_id` groups every
rotation of one login; `rotation_counter` aids diagnosis. `ip_prefix` is
truncated (/24 or /48), never a full address. **Retention:** expiry + 7 days.

### `email_verification_tokens`, `password_reset_tokens` — one-time secrets · C
Hash only. Creating a new one invalidates outstanding tokens for that user.
**Retention:** expiry + 7 days.

### `admin_users` — internal staff · P, C
Separate table, separate sessions, separate token audience. `mfa_required`
defaults true; the factor itself is verified by the identity provider in
production. **Retention:** life of employment.

### `admin_sessions` · C
As `user_sessions`, plus `mfa_satisfied`. **Retention:** expiry + 7 days.

### `admin_roles`, `admin_permissions`, `admin_role_permissions`, `admin_user_roles` · O
RBAC as rows so a deployment can adjust grants without a code change.
`admin_permissions.is_sensitive` flags the permissions
(`child_location.read`, `users.pii.read`, …) that no default role but
`super_admin` holds. **Retention:** permanent.

## Family and children

### `families` — the tenant boundary · P
`family_id` is carried redundantly on child-scoped tables so an authorization
predicate is one column comparison rather than a join chain. **Retention:**
life of account.

### `family_members` — guardian membership · P
`is_owner` means implicit full permissions; `permissions` is an explicit JSON
array for everyone else. Unique on `(family_id, user_id)`. Removal is a status
change, so the history of who had access survives. **Retention:** life of family.

### `child_profiles` — children · P
Stores `age_band`, **not** a date of birth. `birth_year` exists but is nullable
and unused by default; populate it only with a documented legal need.
`policy_version` is the monotonic counter incremented inside every policy
mutation. **Retention:** life of family; anonymised on deletion.

### `guardian_invitations` · P, C
Token hash only, bound to `normalized_invited_email` so a leaked link cannot be
redeemed by whoever finds it. Non-delegatable permissions are stripped before
the row is written. **Retention:** 72 hours, then expired.

## Devices and pairing

### `devices` — paired child devices · P, T
Many devices per child are supported. `install_id` is a **random per-install
value from the Child App**, not a hardware identifier; it exists so a factory
reset re-pairs into the same row. `applied_policy_version` and
`policy_sync_status` are device-reported and only ever advanced by a device
acknowledgement. Deliberately absent: IMEI, serial, MAC, advertising id.
**Retention:** life of child profile.

### `device_sessions` · C
Long-lived (180 days) because a child device cannot be asked for a password —
which is exactly why rotation, reuse detection and parent-side revocation
matter. **Retention:** expiry + 7 days.

### `pairing_invitations` · C
Hash of a 256-bit token, plus an optional hash of a short code and a non-secret
`short_code_prefix` so a parent can tell two invitations apart.
`attempt_count` is the brute-force counter, committed even when the attempt is
rejected. **Retention:** 15 minutes, then swept.

### `device_capabilities` — what the device says it can do · T
One row per `(device, capability)`, latest state. The server never assumes a
capability; an unreported one is surfaced as "not yet known", not as working.
**Retention:** latest state only.

### `device_permission_reports` — Android permission states · T
One row per `(device, permission)`, latest state. Transitions become
`device_events` so this table stays small. A `granted → denied` transition
raises a high-severity parent alert. **Retention:** latest state only.

## Policies

### `app_catalog` — optional curated package metadata · O
Purely advisory. The server does not assume it knows every installed package,
so a restriction may reference a package with no catalog entry.
`is_restriction_blocked` marks packages that must not be restricted.

### `app_restrictions` — per-app rules · P
`device_id` NULL means profile-wide. A partial unique index enforces one
profile-wide row per package (a plain unique constraint cannot, because NULLs
compare as distinct). `revision` drives optimistic concurrency. CHECK
constraints enforce that `time_limit` carries a limit and that the limit is
within a day. **Retention:** life of child profile.

### `screen_time_policies` — daily budgets · P
`timezone` is an IANA identifier and is what makes the attached schedules
meaningful. `priority` resolves overlap between policies. **Retention:** life of
child profile.

### `screen_time_schedules` — recurring local windows · P
`end_local_time <= start_local_time` is valid and means the window crosses
midnight. Wall-clock intent plus a zone, so a 21:00 bedtime stays 21:00 across
a DST change. **Retention:** with the policy.

### `website_restrictions` — domain rules · P
Gated off. Stores a registrable domain only — no full URLs, no query strings, so
the server never holds a browsing history. **Retention:** life of child profile.

### `policy_versions` — change history · O
One row per policy change, with the actor and change type. Unique on
`(child_profile_id, version)`. **Retention:** life of child profile.

### `device_policy_states` — per-device truth · T
What a specific device reported about a specific policy version, including
`item_results` for partial application. The table that lets the Parent App
distinguish "saved" from "applied". **Retention:** life of device.

## Commands and events

### `device_commands` — the durable queue · O
`command_type` is a strict allow-list; the payload is validated against a
per-type schema before the row is written and re-validated before it is handed
to a device. Unique on `(device_id, idempotency_key)`, so a retried request
cannot queue a second command. `expires_at` guarantees nothing pends forever.
**Retention:** `RETENTION_COMMAND_HISTORY_DAYS` (180) after completion.

### `device_command_attempts` — delivery log · O
One row per attempt, with channel and outcome, so retries are observable.
Unique on `(command_id, attempt_number)`. **Retention:** with the command.

### `outbox_events` — transactional outbox · O
Written in the same transaction as the change it describes. `status`,
`attempts`, `available_at`, `locked_at`/`locked_by` implement
claim-with-lease, bounded exponential backoff and dead-lettering. Payloads
carry ids and status only; a forbidden key raises at write time, because the
payload reaches a push provider and a WebSocket fan-out. **Retention:** 30 days
after processing (operational).

### `device_events` — device-reported events · T
Unique on `(device_id, deduplication_key)`, so the Child App can resend a batch
after a network failure. Payloads are deny-listed: a submission containing
`latitude`, `message_body`, `keystrokes`, `screenshot` or similar is rejected
with `409`. **Retention:** `RETENTION_DEVICE_EVENTS_DAYS` (90).

### `device_sync_cursors` · O
Resume points so a device can continue an interrupted upload.

## Usage and alerts

### `usage_daily_summaries` — one row per (device, local date) · T
`local_date` is the date **on the device**, stored with the timezone it was
computed in, because a "Tuesday" total only means something relative to the
child's own clock. Re-submitting a day replaces it (upsert), which makes the
Child App's retry logic trivial. CHECK constraints reject an implausible total
(> 86 400 s) or unlock count. **Retention:**
`RETENTION_USAGE_SUMMARIES_DAYS` (400).

### `app_usage_summaries` — per-package foreground time · T
Top 100 packages per day; the tail collapses into one `other.aggregated` row,
which bounds the table and is all a report needs. **Retention:** with the
parent summary.

### `alerts` — parent-facing alerts · T
Unique on `(family_id, deduplication_key)`, so a standing condition (an offline
device, a revoked permission) produces one alert rather than one per poll.
`alert_metadata` holds safe context only. **Retention:** life of family.

## Location (gated)

### `location_samples` · **S**
Only ever populated when the feature flag, a granted consent record, a reported
capability and a reported permission all hold. Coordinates are rounded to 3
decimal places (~110 m) **before** storage. `consent_record_id` links the sample
to the consent that authorised it; `requested_by_command_id` records
command-driven collection. `retention_expires_at` is a hard per-row deadline.
Access needs the non-delegatable `location.read` family permission, or the
`child_location.read` admin permission that no default role but `super_admin`
holds. Every read is audited. **Retention:**
`RETENTION_LOCATION_SAMPLES_DAYS` (30).

## Notifications

### `push_tokens` · C
A CHECK constraint enforces exactly one owner (user **or** device).
`token_value` is needed to call FCM and is excluded from every API response and
log line; `token_hash` is what is indexed. Only the last six characters are ever
returned. A token arriving for a different owner moves ownership, which prevents
delivery to the wrong person after a reinstall. **Retention:** until
deregistered or rejected by the provider.

### `notification_preferences` · P
Per user, per type, with optional quiet hours. Security notifications cannot be
disabled, and the service enforces that regardless of what is stored.

### `notification_deliveries` · O
Type and provider status only. Push payloads are content-free by design, and
nothing child-identifying is recorded. **Retention:** 90 days.

### `websocket_connections` · O
Operational visibility only. A connection is not an identity: authorization is
re-evaluated per subscription against the database. Safe to truncate.

## Billing

### `plans` · O
Money in minor units plus an ISO 4217 code — never a float.

### `subscriptions` · P, O
One per family. Provider references are opaque; no card or PAN data is ever
stored. Only a signature-verified webhook moves the status.

### `subscription_events` · O
Append-only state-change history, linked to the webhook that caused it.

### `payment_webhook_events` · O
Every delivery, recorded **before** processing, so a provider retry is
recognised as a duplicate even if the first attempt crashed mid-processing.
Unique on `(provider, provider_event_id)`. `payload_digest` is the SHA-256 of
the raw body, so a replay with a mutated payload is detectable.
**Retention:** legal/tax period.

## Support and trust & safety

### `support_tickets`, `support_ticket_messages` · P
Attachments are object-storage keys only; content never lands in the database
and is served through short-lived signed URLs after an authorization check.
`is_internal_note` marks staff-only messages. **Retention:** 2 years after
closure.

### `abuse_reports` · **S**
`non_consensual_monitoring` is a first-class category with its own review path —
it is the central abuse risk for a parental-control product.
`resolution_notes` is mandatory on a decision; the API rejects a status change
without it. **Retention:** retained for pattern detection.

## Audit and privacy

### `audit_logs` — append-only · O
**No foreign keys at all**, deliberately: deleting a family must not be able to
cascade away the record of what was done to it. The application never issues an
UPDATE or DELETE here, and the deployment grants the app role `INSERT, SELECT`
only. `event_metadata` passes through a deny-list before it is written, so no
token, password or coordinate can be stored. `ip_prefix` is truncated.
`tests/integration/test_migrations.py` asserts the absence of foreign keys.
**Retention:** `RETENTION_AUDIT_LOG_DAYS` (730).

### `consent_records` · P
Pins the exact `policy_version` presented, who recorded it, how, and on which
surface. Revocation is a state change, never a deletion, so the history of what
was disclosed when stays intact. **Retention:** life of account + legal period.

### `privacy_requests` · P
Export and deletion requests with a `due_at` regulatory deadline.
`requester_email` is duplicated so a request survives deletion of the account it
refers to. `retention_exceptions` records what was kept and why — the same
structure returned to the user. **Retention:** retained after completion as
proof the obligation was met.

### `idempotency_records` · O
Stored response per `(principal_type, principal_id, endpoint, key)`.
`request_digest` is what distinguishes a safe replay from a client bug: the same
key with a different body is rejected with `IDEMPOTENCY_KEY_REUSED` rather than
silently returning the wrong result. **Retention:**
`RETENTION_IDEMPOTENCY_HOURS` (24).

## Conventions

| Concern | Convention |
| --- | --- |
| Primary keys | `uuid`, application-generated |
| Timestamps | `timestamptz`, aware UTC both directions |
| Enums | VARCHAR + CHECK (`native_enum=False`), so adding a value is an ordinary migration |
| Variable data | `jsonb` on PostgreSQL via a variant; typed columns for anything queried |
| Constraint names | deterministic via a naming convention, so a downgrade can drop them |
| Soft delete | explicit `deleted_at IS NULL` at every call site; no global filter |
| Cascades | `CASCADE` within a tenant, `SET NULL` for actor references, `RESTRICT` on family ownership, **none** into `audit_logs` |

### Index strategy

Every foreign key, status/date pair used by a hot query, and every natural
uniqueness rule. 121 indexes. The hot paths: device command polling
(`device_id, status`), usage reports (`child_profile_id, local_date`), alert
pagination (`family_id, status, occurred_at`), outbox draining
(`status, available_at`), retention sweeps (`retention_expires_at`).

These were chosen from the query shapes in the service layer, not measured
against production traffic. Re-check with `EXPLAIN ANALYZE` once real volumes
exist.
