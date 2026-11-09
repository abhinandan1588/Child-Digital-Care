# Child Digital Care — Backend Master Prompt

> **Purpose:** Give this entire prompt to your AI coding agent to build the backend for Child Digital Care.
>
> **Backend stack:** Python, FastAPI, PostgreSQL, SQLAlchemy 2.x, Alembic, Pydantic v2, Redis, Celery, Firebase Cloud Messaging (FCM), WebSockets, Docker.
>
> **Architecture rule:** The backend is the single source of truth for the Parent App, Child App, and Admin Dashboard. The three clients must never connect directly to one another or directly to the database.

---

# 1. Role and mission

Act as a **senior backend architect, Python/FastAPI engineer, PostgreSQL database designer, application-security engineer, and test engineer**.

Build a secure, modular, maintainable, production-oriented backend for **Child Digital Care**, an Android-first parental-control and family digital-wellbeing platform.

The product consists of three separately developed clients:

1. **Parent App** — parents/guardians manage their family, paired child devices, schedules, app restrictions, location features where consented and permitted, screen-time rules, alerts, and reports.
2. **Child App** — an Android application installed on a child's device. It securely pairs with a parent account, reports permitted device information, receives policy updates, and acknowledges commands. Device-side enforcement is implemented by the Child App using Android APIs that are available and permitted on that device.
3. **Admin Dashboard** — authorized internal staff manage support cases, user/account status, subscriptions, policy configuration, abuse reports, and aggregated operational analytics.

Your responsibility is to build the **backend only**. Do not build Flutter screens, Android UI, or the Next.js dashboard. Instead, provide stable, documented APIs and integration contracts for those clients.

The backend must not pretend that a server can independently enforce Android restrictions. The server stores policy intent, distributes commands, receives device acknowledgements, and records reported state. Actual enforcement must happen on the child's device through lawful, disclosed, platform-permitted Android mechanisms.

## Primary success criteria

- All three clients can independently integrate against a versioned, documented API.
- Authentication and authorization are enforced on the server for every protected operation.
- A parent can create a family, invite/pair a child device, create policies, and see device-reported status.
- A child device can securely claim a pairing invitation, register itself, fetch pending commands/policies, report permitted telemetry, and acknowledge command execution.
- Commands are durable and idempotent; push notifications are only wake-up/synchronization signals, not the source of truth.
- Admin operations are separated from parent and child permissions and are fully audited.
- Sensitive data is minimized, access-controlled, retained only as required, and deletable through documented workflows.
- Automated tests cover authorization boundaries, critical business logic, and API contracts.
- The project can be run locally with Docker Compose and configured for staging/production without hardcoded secrets.

---

# 2. Non-negotiable engineering rules

Follow these rules throughout the project.

1. **Backend is the source of truth.** Do not put business rules, database credentials, or privileged logic in client applications.
2. **No direct client-to-client communication.** Parent and child clients communicate through authenticated backend APIs and server-mediated push notifications/WebSockets.
3. **No client-side trust.** Never trust a `role`, `family_id`, `user_id`, `device_id`, subscription status, or permission level merely because the client sent it. Derive identity and scope from verified credentials and database records.
4. **Strict tenant isolation.** A parent may access only their own family and authorized linked devices. A child device may access only its own device-scoped resources. An admin may access only what their admin role permits.
5. **Least privilege.** Give each token and service only the permissions it needs.
6. **No secrets in source control.** Use environment variables and `.env.example` placeholders. Never commit real API keys, Firebase service-account JSON, passwords, signing keys, or production URLs containing credentials.
7. **No fake production features.** Do not return hardcoded success for features that are not implemented. If an external integration is not configured, fail clearly in development or expose an explicit disabled/unavailable state.
8. **Use migrations.** Never rely on `Base.metadata.create_all()` as the production schema-management strategy. Use Alembic migrations.
9. **Use transactions.** Multi-step operations that must remain consistent must be atomic.
10. **Idempotency.** Pairing claims, webhook processing, command acknowledgements, and retryable client requests must safely handle duplicates.
11. **Document limitations.** Never promise that every Android device supports every parental-control capability. Model capability and permission status as device-reported facts.
12. **Privacy by design.** Collect the minimum data required. Do not build covert surveillance, hidden monitoring, permission bypasses, stealth persistence, or unauthorized data collection.
13. **No arbitrary code execution.** Never implement a backend endpoint that accepts executable commands or scripts to run on a child's device.
14. **No unrestricted remote shell.** Device commands must be a strict allow-listed set of typed operations with validated payloads, expiry, and audit history.
15. **Test before declaring complete.** Run formatting, linting, type checks, migrations, and tests. Report exact results and unresolved issues.

If an existing repository or PRD is present, inspect it first. Preserve established naming, requirements, and decisions unless they conflict with security, platform rules, or technical correctness. Do not silently discard existing work.

---

# 3. Product domain and roles

Implement explicit, separate principals.

## 3.1 Parent / guardian user

A normal authenticated account that can:

- Create and manage a family.
- Invite another guardian if the product scope allows it.
- Create and manage child profiles.
- Create pairing invitations for child devices.
- View only devices linked to their family and authorized relationship.
- Create, update, pause, and delete screen-time schedules and app/site restriction policies.
- Request supported device actions through typed commands.
- View device-reported usage summaries, health/status, and alerts that the product is permitted to collect.
- Manage notification preferences, subscription, and account deletion.

Do not let a parent access another family's records by guessing IDs.

## 3.2 Child device principal

The Child App must not authenticate as a parent. It receives a device-scoped credential after a secure pairing flow.

A child device can:

- Claim a valid, unexpired, single-use pairing invitation.
- Register its installation/device metadata, subject to data minimization.
- Fetch its own configuration and pending commands.
- Acknowledge commands and report execution outcomes.
- Submit permitted usage summaries and device status.
- Submit consent/disclosure/permission-state information needed to explain feature availability.
- Refresh or rotate its device credential using a secure mechanism.
- Revoke its own session where appropriate.

A child device must not:

- Read parent account credentials or tokens.
- Read another device's records.
- Access admin endpoints.
- Change family ownership or guardian permissions.
- Self-grant Android permissions or claim an enforcement capability it does not possess.

## 3.3 Admin principal

Create a separate admin authentication and authorization boundary.

Suggested roles:

- `super_admin`
- `support_admin`
- `trust_safety_admin`
- `billing_admin`
- `read_only_analyst`

Use explicit permission checks, not scattered role-name string comparisons.

Examples:

- Support staff may view limited account/device metadata and manage support tickets, but should not automatically view precise location history.
- Billing staff may manage subscription records but should not access child telemetry.
- Trust-and-safety staff may review abuse reports and perform documented safety actions.
- Only a narrowly scoped privileged role may suspend accounts or modify sensitive platform configuration.

Require stronger authentication for admin access in production where feasible, and record all privileged actions in an immutable-style audit log (append-only at application level; restrict database update/delete permissions operationally).

## 3.4 Family and child profile

Model a family as a tenant boundary. A family can have one or more guardians and one or more child profiles. Devices belong to a child profile and a family.

Do not assume one child equals one device. Support multiple devices per child unless the existing product specification explicitly says otherwise.

Use explicit relationship tables for family membership and guardian permissions.

---

# 4. Recommended technology and project structure

Use current stable, mutually compatible versions and pin dependencies. Do not blindly use pre-release packages.

- Python 3.12 or a currently supported stable Python version.
- FastAPI.
- Uvicorn.
- Pydantic v2 and pydantic-settings.
- SQLAlchemy 2.x async ORM.
- PostgreSQL.
- Alembic.
- `asyncpg` for async PostgreSQL connectivity.
- Redis for caching, rate-limit coordination, and background-task broker where appropriate.
- Celery (or a clearly justified alternative) for asynchronous jobs.
- Firebase Admin SDK for FCM.
- PyJWT or a well-maintained JWT library, with explicit algorithm allow-list and key management.
- `pwdlib`/Argon2id or another current, well-maintained password-hashing implementation.
- `httpx` for outbound HTTP.
- `pytest`, `pytest-asyncio`, and HTTPX test client.
- Ruff for linting/formatting.
- mypy or pyright for static type checking.
- Docker and Docker Compose.

Prefer a modular monolith for the first release. Do not introduce microservices unless there is a concrete operational need. Keep module boundaries clean so services can be separated later.

Create a structure similar to:

```text
backend/
├── app/
│   ├── main.py
│   ├── api/
│   │   ├── deps.py
│   │   └── v1/
│   │       ├── router.py
│   │       └── endpoints/
│   ├── core/
│   │   ├── config.py
│   │   ├── security.py
│   │   ├── permissions.py
│   │   ├── errors.py
│   │   ├── logging.py
│   │   └── rate_limit.py
│   ├── db/
│   │   ├── base.py
│   │   ├── session.py
│   │   └── models/
│   ├── schemas/
│   ├── repositories/
│   ├── services/
│   ├── integrations/
│   │   ├── firebase/
│   │   ├── email/
│   │   ├── payments/
│   │   └── storage/
│   ├── workers/
│   ├── websocket/
│   └── utils/
├── migrations/
│   ├── env.py
│   └── versions/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── contract/
├── scripts/
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── alembic.ini
├── .env.example
├── .gitignore
└── README.md
```

You may refine this structure, but preserve clear separation between API routing, schemas, domain services, persistence, integrations, and background jobs.

---

# 5. Architecture and request flow

Use this logical architecture:

```text
Parent App (Flutter) ─────┐
                          │ HTTPS / WebSocket
Child App (Android) ──────┼──── FastAPI Backend ─── PostgreSQL
                          │          │
Admin Dashboard (Web) ────┘          ├── Redis
                                     ├── Background Workers
                                     ├── Firebase Cloud Messaging
                                     ├── Email Provider
                                     ├── Payment Provider (optional module)
                                     └── Object Storage (optional module)
```

## 5.1 API versioning

- Prefix all public APIs with `/api/v1`.
- Use `/health/live` and `/health/ready` for operational health checks.
- Publish OpenAPI documentation in development and protect or disable interactive docs in production according to deployment policy.
- Treat breaking API changes as a new version or an explicitly versioned migration.
- Never change response shapes silently.

## 5.2 Standard response shape

Use a consistent response envelope for successful responses:

```json
{
  "success": true,
  "message": "Policy created successfully",
  "data": {
    "id": "uuid",
    "status": "pending"
  },
  "meta": {
    "request_id": "request-id"
  }
}
```

For errors:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request contains invalid fields.",
    "details": [
      {
        "field": "name",
        "issue": "Field is required."
      }
    ]
  },
  "meta": {
    "request_id": "request-id"
  }
}
```

Use appropriate HTTP status codes. Do not expose stack traces, SQL errors, secret values, or internal infrastructure details in production responses.

For paginated endpoints, use a consistent cursor or page-based convention. Prefer cursor pagination for large event histories. Document ordering and stable cursor semantics.

## 5.3 Common API conventions

- JSON request/response bodies unless a documented upload requires multipart.
- ISO 8601 timestamps in UTC, with timezone-aware database timestamps.
- UUIDs for externally exposed resource IDs.
- Explicit enum values in snake_case.
- `Idempotency-Key` support for operations where client retries could create duplicates.
- `X-Request-ID` correlation support.
- Optimistic concurrency (`version` or `updated_at` precondition) for sensitive mutable policies where useful.
- Consistent filtering, sorting, and pagination.
- Never expose internal database integer IDs.

---

# 6. Authentication and security architecture

Implement authentication as a first-class module.

## 6.1 Parent account authentication

Implement:

- Email registration.
- Email verification using short-lived, single-use verification tokens.
- Login.
- Logout/session revocation.
- Access-token refresh with rotation.
- Password reset request and completion.
- Change password.
- View active sessions and revoke sessions where appropriate.
- Optional phone verification as a later integration, not a hardcoded assumption.

Security requirements:

- Hash passwords with Argon2id or a well-maintained secure password-hashing algorithm.
- Never store plaintext passwords or reversible password encryption.
- Access tokens should be short-lived.
- Refresh tokens should be stored hashed server-side, rotated on use, and revoked on reuse detection.
- Include token issuer, audience, expiry, subject, token ID, and principal type.
- Use a fixed algorithm allow-list; never trust the JWT header to choose arbitrary algorithms.
- Keep signing keys in environment/secret management, not source control.
- Do not log tokens, passwords, verification links, or reset tokens.
- Rate-limit login, registration, verification, and password reset endpoints.
- Return generic login/reset responses where necessary to reduce account enumeration.
- Enforce email verification before sensitive family/device operations if that is the product's chosen policy.

## 6.2 Device authentication

After pairing, issue a device-scoped credential with:

- Device ID as subject.
- Principal type `child_device`.
- Narrow audience and scopes.
- Short-lived access token.
- Rotating refresh credential or equivalent secure device-session renewal.
- Server-side revocation and session tracking.

Do not use a parent's access token inside the Child App. Do not place long-lived secrets in ordinary app preferences. Document secure storage expectations for the Android team (Android Keystore-backed storage).

A device credential must be revocable by the parent or server. Handle lost, replaced, reset, or compromised devices.

## 6.3 Admin authentication

Use a distinct admin principal and admin login/session path. Support MFA integration or enforce MFA at the identity-provider/reverse-proxy layer for production. Add IP/device/session risk controls only if they can be implemented reliably and without creating false security guarantees.

## 6.4 Authorization

Implement reusable dependencies/policies such as:

- `require_parent_user`
- `require_child_device`
- `require_admin_permission("users.read")`
- `require_family_membership(family_id, permission)`
- `require_device_access(device_id, action)`

All resource access must be checked server-side. Avoid insecure direct object references (IDOR). Test cross-family and cross-device access explicitly.

## 6.5 Security controls

Implement:

- HTTPS-only production deployment assumptions.
- CORS allow-list from configuration; never wildcard credentials.
- Request body size limits.
- Input validation and output filtering.
- SQLAlchemy parameterized queries; no string-built SQL from user input.
- Rate limiting for sensitive routes.
- Secure headers at the deployment layer or application middleware where appropriate.
- CSRF protection if cookie-based browser authentication is used. If the admin uses bearer tokens, document storage and XSS tradeoffs.
- Audit logging for authentication and sensitive actions.
- Dependency and container vulnerability scanning instructions.
- Secret rotation and key rotation runbook.
- Account lockout/throttling that avoids easy denial-of-service against victims.
- No sensitive data in analytics events or routine logs.

---

# 7. Database design

Use PostgreSQL and SQLAlchemy 2.x declarative models. Use UUID primary keys for externally addressable records. Use foreign keys, indexes, unique constraints, check constraints, and appropriate delete behavior.

Create an ER diagram in the documentation and a data dictionary.

## 7.1 Required domain tables

Design and implement at least the following entities. You may split or add tables when justified.

### Identity and access

- `users`
  - id, email, normalized_email, password_hash, display_name, account_status, email_verified_at, created_at, updated_at, deleted_at.
- `user_sessions`
  - id, user_id, refresh_token_hash, token_family_id, device_label, expires_at, revoked_at, created_at, last_used_at.
- `email_verification_tokens`
  - id, user_id, token_hash, expires_at, used_at, created_at.
- `password_reset_tokens`
  - id, user_id, token_hash, expires_at, used_at, created_at.
- `admin_users` or a carefully separated admin identity table.
- `admin_roles`, `admin_permissions`, `admin_user_roles`, `admin_role_permissions`.

### Family and child profiles

- `families`
  - id, name, owner_user_id, status, created_at, updated_at.
- `family_members`
  - id, family_id, user_id, relationship, membership_status, permissions, invited_by, joined_at, created_at.
- `child_profiles`
  - id, family_id, display_name, birth_year or age-band only if truly required, avatar reference, profile_status, created_at, updated_at.
- `guardian_invitations`
  - id, family_id, invited_email, token_hash, permissions, expires_at, accepted_at, revoked_at, created_by.

Do not collect a child's full date of birth unless there is a clear, documented product/legal need. Prefer age band or minimum necessary attribute.

### Devices and pairing

- `devices`
  - id, family_id, child_profile_id, platform, app_version, OS_version, device_label, device_status, last_seen_at, registered_at, revoked_at, created_at, updated_at.
- `device_sessions`
  - id, device_id, refresh_token_hash, token_family_id, expires_at, revoked_at, last_used_at, created_at.
- `pairing_invitations`
  - id, family_id, child_profile_id, created_by, token_hash, short_code_hash if using a code, status, expires_at, claimed_at, claimed_device_id, attempt_count, created_at.
- `device_capabilities`
  - id, device_id, capability_key, supported, permission_state, reported_at, metadata_json.
- `device_permission_reports`
  - id, device_id, permission_key, state, reported_at, app_version, explanatory_metadata_json.

Pairing tokens must be high entropy, hashed at rest, short-lived, single-use, rate-limited, and invalidated after successful claim or revocation. If using a human-readable code, make it short-lived, sufficiently unguessable for the allowed attempt rate, and never treat it as a permanent credential.

### Policies and schedules

- `app_catalog` (optional curated metadata; do not assume every installed package is known).
- `app_restrictions`
  - id, family_id, child_profile_id, device_id nullable for profile-wide policy, package_identifier, display_label, action, enabled, created_by, created_at, updated_at.
- `screen_time_policies`
  - id, family_id, child_profile_id, name, daily_limit_seconds, enabled, timezone, created_by, created_at, updated_at.
- `screen_time_schedules`
  - id, policy_id, weekday, start_local_time, end_local_time, action, enabled.
- `website_restrictions` only if the child app has a compliant, technically supported implementation.
- `policy_versions` or a policy version field to track changes and synchronization.
- `policy_assignments` if policies can be assigned to multiple devices/profiles.

Validate time ranges, timezone identifiers, overlapping schedule behavior, and policy precedence. Document what happens when two policies conflict. Store local schedule intent with an IANA timezone; compute execution windows carefully and handle daylight-saving changes.

### Commands and device synchronization

- `device_commands`
  - id, family_id, device_id, command_type, payload_json, status, idempotency_key, created_by, created_at, expires_at, delivered_at, acknowledged_at, completed_at, failure_code, failure_message.
- `device_command_attempts`
  - id, command_id, attempt_number, attempted_at, delivery_channel, outcome.
- `device_sync_cursors` or equivalent if required.
- `device_events`
  - id, family_id, device_id, event_type, payload_json, occurred_at, received_at, deduplication_key.

Commands must use a strict allow-list of types and Pydantic schemas. Do not accept arbitrary shell commands, scripts, package installation commands, or unrestricted URLs. Define command lifecycle states, for example:

`queued -> delivered -> acknowledged -> succeeded | failed | expired | cancelled`

Make state transitions explicit and validated. A command must not remain indefinitely pending. Expiry and retry policy must be configurable.

### Usage, alerts, and location (data-minimizing)

- `usage_daily_summaries`
  - id, family_id, child_profile_id, device_id, local_date, timezone, total_screen_time_seconds, category_totals_json, source_version, received_at.
- `app_usage_summaries`
  - id, daily_summary_id, package_identifier, display_label, foreground_seconds.
- `alerts`
  - id, family_id, child_profile_id, device_id nullable, alert_type, severity, title, message, status, occurred_at, acknowledged_at, metadata_json.
- `location_samples` only if the feature is enabled, transparently disclosed, legally permitted, and technically supported.
  - id, family_id, child_profile_id, device_id, latitude, longitude, accuracy_meters, recorded_at, received_at, retention_expires_at.
  - Restrict access tightly; do not expose to support/admin roles by default.
  - Define precision, sampling, retention, consent, and deletion rules.
  - Do not build covert or continuous location collection. The Child App must request and report only permissions and data allowed by Android and applicable law.

Avoid collecting message contents, call contents, keystrokes, microphone recordings, camera streams, or private communications. Do not implement hidden capture features.

### Notifications and communication

- `push_tokens`
  - id, principal_type, user_id nullable, device_id nullable, token_encrypted_or_protected, platform, active, updated_at.
- `notification_preferences`
  - id, user_id, notification_type, enabled, quiet_hours_json.
- `notification_deliveries`
  - id, user_id nullable, device_id nullable, notification_type, provider_message_id, status, attempted_at, delivered_at, error_code.
- `websocket_connections` only if durable connection tracking is actually needed; avoid treating a connection as a durable identity/session.

### Subscription and billing

Keep billing modular and provider-neutral.

- `plans`
- `subscriptions`
- `subscription_events`
- `payment_webhook_events`

Do not trust client-reported payment success. Verify provider webhooks, signatures, timestamps, and idempotency. If no payment provider is selected yet, implement the domain interfaces and clearly mark the integration as not configured; do not fabricate successful purchases.

### Admin, support, audit, and privacy

- `support_tickets`
- `support_ticket_messages` with strict attachment/content controls.
- `abuse_reports`
- `audit_logs`
  - actor type/id, action, target type/id, family scope where applicable, request_id, timestamp, reason, safe metadata.
- `consent_records`
  - subject/profile/device, consent/disclosure type, policy version, recorded state, timestamp, method, revocation timestamp.
- `data_deletion_requests`
- `data_export_requests`

Audit records should not contain raw passwords, tokens, exact location coordinates, or unnecessary child telemetry.

## 7.2 Database implementation rules

- Add indexes for foreign keys, lookup columns, status/date queries, and unique constraints.
- Add unique constraints for normalized email and other natural uniqueness requirements.
- Use database constraints as a second line of defense, not just Pydantic validation.
- Use `JSONB` only for genuinely variable metadata/payloads; use typed columns for query-critical data.
- Define cascade/restrict behavior intentionally. Avoid accidental deletion of audit records.
- Add `created_at` and `updated_at` where appropriate.
- Use timezone-aware timestamps.
- Create Alembic migrations and test both fresh database migration and upgrade from the previous migration.
- Add seed data only for development/test environments, never silently in production.

---

# 8. API modules and endpoint requirements

Implement routes under `/api/v1`. Exact route names may be refined, but maintain the capabilities and document the final contract.

## 8.1 Authentication

Parent routes:

- `POST /auth/register`
- `POST /auth/verify-email`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/logout-all`
- `POST /auth/password/forgot`
- `POST /auth/password/reset`
- `POST /auth/password/change`
- `GET /auth/me`
- `GET /auth/sessions`
- `DELETE /auth/sessions/{session_id}`

Admin routes must use a distinct admin authentication boundary, even if they share lower-level token utilities.

Device auth routes:

- `POST /device-auth/refresh`
- `POST /device-auth/logout`
- `GET /device-auth/me`

## 8.2 Family and guardians

- `POST /families`
- `GET /families`
- `GET /families/{family_id}`
- `PATCH /families/{family_id}`
- `POST /families/{family_id}/guardian-invitations`
- `POST /guardian-invitations/accept`
- `DELETE /families/{family_id}/members/{member_id}`

Enforce family membership and permission checks on every route.

## 8.3 Child profiles

- `POST /families/{family_id}/children`
- `GET /families/{family_id}/children`
- `GET /children/{child_profile_id}`
- `PATCH /children/{child_profile_id}`
- `DELETE /children/{child_profile_id}`

Deletion should follow a documented soft-delete/deactivation and data-retention workflow rather than accidentally leaving active devices attached.

## 8.4 Pairing and device registration

- `POST /children/{child_profile_id}/pairing-invitations`
- `GET /pairing-invitations/{invitation_id}`
- `DELETE /pairing-invitations/{invitation_id}`
- `POST /device/pairing/claim`
- `POST /device/register`
- `GET /devices`
- `GET /devices/{device_id}`
- `PATCH /devices/{device_id}/label`
- `POST /devices/{device_id}/revoke`
- `POST /device/heartbeat`
- `POST /device/capabilities`
- `POST /device/permissions/report`

The pairing claim must atomically validate the invitation, mark it claimed, associate the device, and issue a device credential. Prevent race conditions where two devices claim the same invitation.

## 8.5 Policies and schedules

- `GET /children/{child_profile_id}/policies`
- `POST /children/{child_profile_id}/app-restrictions`
- `PATCH /app-restrictions/{restriction_id}`
- `DELETE /app-restrictions/{restriction_id}`
- `POST /children/{child_profile_id}/screen-time-policies`
- `PATCH /screen-time-policies/{policy_id}`
- `DELETE /screen-time-policies/{policy_id}`
- `POST /screen-time-policies/{policy_id}/schedules`
- `PATCH /screen-time-schedules/{schedule_id}`
- `DELETE /screen-time-schedules/{schedule_id}`
- `GET /device/policies/current`

Every policy change should increment a policy version or create a version record and enqueue a synchronization command/event in the same database transaction (use an outbox pattern; see section 10).

Return a clear status such as `pending_sync`, `synced`, `partially_applied`, `failed`, or `unsupported`, based on actual device acknowledgements—not an assumption that the device has applied the policy.

## 8.6 Device command and acknowledgement APIs

- `GET /device/commands?status=pending`
- `POST /device/commands/{command_id}/acknowledge`
- `POST /device/commands/{command_id}/result`
- `GET /devices/{device_id}/commands` (parent/admin authorized view)
- `POST /devices/{device_id}/commands` (parent creates an allow-listed request)

For every command:

- Validate the command type and payload schema.
- Check that the parent has permission to issue it.
- Confirm that the device is active and belongs to the same family/child profile.
- Check device capability and permission status where relevant.
- Set a TTL/expiry.
- Store it durably before sending a push notification.
- Use idempotency keys.
- Record each delivery attempt.
- Require device acknowledgement and a final result where the operation supports it.
- Handle duplicate, late, unknown, expired, and out-of-order acknowledgements.
- Never report success until a valid device result says it succeeded.

Example command types (only implement those supported by the Android client and approved for the product):

- `sync_policies`
- `refresh_device_status`
- `request_usage_sync`
- `request_location_update` (only when explicitly enabled, disclosed, permitted, and consented)
- `apply_supported_policy`

Do not create generic `execute`, `shell`, `run_script`, `capture_screen`, `record_audio`, or `record_video` command types.

## 8.7 Usage summaries and reports

- `POST /device/usage/daily-summary`
- `POST /device/usage/app-summaries`
- `GET /children/{child_profile_id}/usage`
- `GET /children/{child_profile_id}/usage/daily`
- `GET /children/{child_profile_id}/usage/apps`

Validate plausible ranges, duplicate submissions, timezone/date consistency, and payload size. Treat client telemetry as device-reported data, not cryptographically proven truth. Clearly label it as reported/synced data in the product.

## 8.8 Alerts and notifications

- `GET /alerts`
- `GET /alerts/{alert_id}`
- `PATCH /alerts/{alert_id}` (acknowledge/resolve only as authorized)
- `POST /device/events`
- `GET /notification-preferences`
- `PATCH /notification-preferences`
- `POST /device/push-token`
- `DELETE /device/push-token`

Use event-driven notifications. Avoid sending sensitive details in push payloads; use a generic notification and require the authenticated client to fetch details.

## 8.9 Location APIs (optional, gated)

If location is included in the agreed product scope:

- `POST /device/location`
- `GET /children/{child_profile_id}/location/latest`
- `GET /children/{child_profile_id}/location/history`

Before enabling this module, implement and document:
- Clear parent and child-facing disclosures.
- Permission-state reporting.
- Consent/authorization records as required.
- Explicit feature enable/disable state.
- Data minimization and configurable retention.
- Strict family authorization.
- No location access for ordinary support/admin roles.
- Access audit events.
- Deletion and export behavior.

If the Android app cannot obtain the required permission or the platform policy does not permit the use case, the API must reflect `unsupported` or `permission_denied`; do not fabricate location data.

## 8.10 Subscription APIs (modular)

- `GET /billing/plans`
- `GET /billing/subscription`
- `POST /billing/checkout` (only once a provider is selected)
- `POST /billing/webhooks/{provider}`

Verify webhook signatures and idempotency. Keep provider-specific code in `integrations/payments`.

## 8.11 Admin APIs

Use `/api/v1/admin/...` and enforce granular permissions.

Suggested routes:

- `GET /admin/overview`
- `GET /admin/users`
- `GET /admin/users/{user_id}`
- `PATCH /admin/users/{user_id}/status`
- `GET /admin/families`
- `GET /admin/devices`
- `GET /admin/support-tickets`
- `PATCH /admin/support-tickets/{ticket_id}`
- `GET /admin/abuse-reports`
- `PATCH /admin/abuse-reports/{report_id}`
- `GET /admin/subscriptions`
- `GET /admin/audit-logs`
- `GET /admin/analytics/summary`

Admin endpoints must return only the data required for the assigned permission. Do not expose child location or detailed usage to all admins by default. Record every sensitive admin read and every state-changing admin action in the audit log.

---

# 9. Pairing workflow

Implement and document this complete flow.

1. Parent authenticates.
2. Parent selects or creates a child profile.
3. Parent requests a pairing invitation.
4. Backend creates a cryptographically random, single-use, short-lived token. Store only its hash.
5. Parent App displays a QR code or short pairing code containing the invitation token/claim reference. Do not encode parent JWTs or private account details in the QR code.
6. Child App scans/enters the invitation.
7. Child App displays clear pairing/disclosure information and obtains the necessary user action before completing setup.
8. Child App sends the invitation claim plus minimal device metadata to the backend.
9. Backend validates expiry, status, attempt limit, and family/child association.
10. In one transaction, backend claims the invitation, creates the device and device session, records relevant disclosure/permission state, and marks the invitation used.
11. Backend returns a device-scoped access token and refresh credential.
12. Child App stores credentials using Android Keystore-backed secure storage.
13. Child App fetches current policies and supported capabilities.
14. Parent App sees the device as `paired` but should separately show whether it is online and whether policies have synchronized.

Add tests for:
- Expired invitation.
- Already claimed invitation.
- Revoked invitation.
- Invalid token.
- Brute-force attempt throttling.
- Two devices attempting to claim simultaneously.
- Parent attempting to claim another family's invitation.
- Device attempting to access another device's data.

---

# 10. Reliable command delivery and synchronization

This is a critical part of the product.

## 10.1 Do not rely on FCM as the command database

The correct flow is:

1. Parent creates a policy or supported action.
2. Backend validates authorization and stores the change in PostgreSQL.
3. Backend creates a durable command/event in the same transaction.
4. An outbox worker reads unsent outbox records.
5. Worker sends a generic FCM wake-up notification to the target device.
6. Child App wakes when the OS permits and calls the backend.
7. Child App fetches its pending commands/current policy version.
8. Child App applies only supported operations locally.
9. Child App acknowledges receipt and reports the result.
10. Backend updates command and policy synchronization state.
11. Parent App fetches updated status or receives a WebSocket event.

FCM is best-effort. A device may be offline, force-stopped, battery restricted, or subject to OS background limits. The backend must preserve pending work and allow the device to synchronize later.

## 10.2 Transactional outbox

Implement an outbox table so a policy/command transaction and the event-to-be-published record commit together. A worker publishes outbox messages and marks them processed. Make publication idempotent.

## 10.3 Command lifecycle

Define valid state transitions in one domain service. Store timestamps for creation, delivery attempt, acknowledgement, completion, expiry, and cancellation.

Suggested states:

- `queued`
- `delivery_attempted`
- `delivered` (only if provider confirms a delivery receipt; do not confuse this with device execution)
- `acknowledged`
- `succeeded`
- `failed`
- `expired`
- `cancelled`
- `unsupported`

Define retry/backoff behavior. Do not retry forever. Do not let a late acknowledgement overwrite a newer terminal state without an explicit reconciliation rule.

## 10.4 Policy versioning

Every policy set should have a monotonically increasing version per child profile or device scope. Child App requests the current policy snapshot and reports the applied version. Parent UI can then distinguish:

- Saved on server.
- Waiting for device sync.
- Received by device.
- Applied by device.
- Partially applied.
- Unsupported due to capability/permission.
- Failed with a safe, user-understandable reason.

---

# 11. WebSockets and real-time updates

Implement authenticated WebSocket support only where it improves the product. REST remains the durable source of truth.

Suggested channels/events:

- `device.status_changed`
- `device.last_seen`
- `policy.sync_status_changed`
- `command.status_changed`
- `usage.summary_received`
- `alert.created`
- `subscription.status_changed`

Requirements:

- Authenticate the connection during handshake using a short-lived token or another secure documented method.
- Validate the principal and resource scope before subscribing.
- Never allow a client to subscribe to arbitrary family/device IDs.
- Use heartbeat/ping and disconnect handling.
- Do not treat WebSocket messages as durable; clients must be able to recover state through REST.
- Avoid placing sensitive telemetry in broadcast messages.
- Support multiple backend instances using Redis Pub/Sub or another shared event mechanism if required.
- Document reconnect/backoff behavior for clients.

---

# 12. Background jobs and integrations

Create service interfaces and worker tasks for:

- Sending verification and password-reset emails.
- Sending FCM notifications.
- Processing outbox events.
- Expiring pairing invitations.
- Expiring device commands.
- Cleaning up expired sessions and tokens.
- Applying retention/deletion schedules.
- Processing verified billing webhooks.
- Aggregating daily usage summaries if aggregation is server-side.

Workers must be idempotent, observable, retryable with bounded backoff, and safe under duplicate execution.

## Firebase Cloud Messaging

- Initialize Firebase Admin SDK only when configured.
- Load service credentials from a secret file path or secret manager, not a committed JSON file.
- Store push tokens with ownership and active status.
- Handle token invalidation responses.
- Do not send sensitive child information in notification payloads.
- FCM failure must not delete or lose durable commands.

## Email

Create a provider interface. Configure a development mail sink or console backend. Production provider is selected by environment configuration. Never log live verification/reset tokens.

## Payments

Do not select or hardcode a payment provider unless the product owner has chosen one. Create a provider-neutral interface and document the integration point. Webhooks must be signature-verified and idempotent.

## Object storage

If avatars or support attachments are required, use private object storage with short-lived signed URLs, file-size/type validation, malware-scanning integration where available, and authorization checks. Do not expose public buckets by default.

---

# 13. Privacy, child safety, and platform compliance

This is a family-safety product involving children's data. Treat privacy and transparency as core product requirements, not a final checklist.

Implement:

- Clear versioned consent/disclosure records where required.
- Data minimization for child profile and device information.
- Explicit retention policies per data category.
- Parent account export and deletion request workflows.
- Family/device unlinking and device revocation.
- Deletion or anonymization workflows that preserve only records that must legally be retained.
- Access audit logs for sensitive records.
- Strict admin access boundaries.
- A documented incident response process.
- A privacy policy/data inventory document listing each field, purpose, access role, retention period, and deletion behavior.

Do not implement:
- Hidden installation or covert monitoring.
- Permission bypasses or accessibility abuse.
- Capturing private messages, passwords, keystrokes, microphone, camera, or screen content without a clearly lawful, permitted, disclosed, and specifically approved product requirement.
- Device commands that circumvent Android security.
- Silent location collection.
- Persistence mechanisms designed to evade user awareness or platform controls.

The backend must not assume that a feature is permitted just because an API endpoint can be created. Android and Google Play rules may restrict certain capabilities and use cases. The Android team must validate each capability against current platform APIs and Play policies. Model unsupported capabilities explicitly.

Create a `FEATURE_CAPABILITY_MATRIX.md` showing each feature, required Android capability/permission, whether the server supports it, the device-reported state, policy considerations, and known limitations.

---

# 14. Configuration and environment management

Create `.env.example` with safe placeholders and explanations. At minimum include:

```dotenv
APP_NAME=Child Digital Care API
APP_ENV=development
DEBUG=true
API_V1_PREFIX=/api/v1
SECRET_KEY=replace-this-for-local-development
JWT_PRIVATE_KEY_PATH=
JWT_PUBLIC_KEY_PATH=
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/child_digital_care
REDIS_URL=redis://redis:6379/0

CORS_ORIGINS=http://localhost:3000,http://localhost:8080
FRONTEND_BASE_URL=http://localhost:3000

EMAIL_PROVIDER=console
EMAIL_FROM=noreply@example.test
SMTP_HOST=
SMTP_PORT=
SMTP_USERNAME=
SMTP_PASSWORD=

FIREBASE_CREDENTIALS_PATH=
FIREBASE_PROJECT_ID=

PAYMENT_PROVIDER=disabled
PAYMENT_WEBHOOK_SECRET=

OBJECT_STORAGE_PROVIDER=disabled
OBJECT_STORAGE_BUCKET=
OBJECT_STORAGE_ENDPOINT=
OBJECT_STORAGE_ACCESS_KEY=
OBJECT_STORAGE_SECRET_KEY=

LOG_LEVEL=INFO
```

Use pydantic-settings. Validate required production settings at startup. Fail fast when production is configured with insecure defaults, missing keys, debug enabled, wildcard CORS, or missing required secrets.

Never use the example secret in a real deployment.

---

# 15. Logging, observability, and operational readiness

Implement structured logs with:

- Timestamp.
- Severity.
- Service/environment.
- Request ID.
- Route and method.
- Response status and duration.
- Safe actor/resource identifiers where appropriate.

Do not log:
- Passwords.
- Access/refresh tokens.
- Pairing secrets.
- Reset/verification tokens.
- Full push tokens.
- Exact location data.
- Sensitive child telemetry.
- Full request bodies by default.

Add:
- Liveness endpoint.
- Readiness endpoint that checks critical dependencies safely.
- Database connection pool configuration.
- Worker health/monitoring guidance.
- Metrics integration points for request count, latency, error rates, queue depth, command expiry, FCM failure, and database pool saturation.
- Sentry or equivalent integration as optional configuration, with sensitive-data scrubbing.
- Runbooks for migrations, backups, restore testing, key rotation, and incident response.

Do not expose internal health details publicly beyond what is operationally necessary.

---

# 16. Testing strategy and acceptance criteria

Testing is mandatory. Use isolated test databases and fake/mock integrations.

## 16.1 Unit tests

Test:
- Password hashing and verification.
- Token creation, expiry, rotation, revocation, and reuse detection.
- Permission evaluation.
- Pairing token generation/validation.
- Policy validation and precedence.
- Schedule/timezone logic.
- Command state transitions.
- Idempotency handling.
- Data-retention calculations.
- Webhook signature verification.

## 16.2 Integration tests

Test:
- Registration, email verification, login, refresh, logout.
- Family creation and membership.
- Child profile CRUD.
- Pairing flow.
- Device registration and heartbeat.
- Capability and permission reports.
- Policy CRUD and policy version increments.
- Outbox creation and processing.
- FCM adapter behavior with a fake provider.
- Command fetch/acknowledge/result flow.
- Usage submission and parent report retrieval.
- Alerts.
- Admin operations and audit logs.
- Account/device deletion workflows.

## 16.3 Security tests

At minimum test:

- Parent A cannot read Parent B's family, child, device, usage, alerts, or policies.
- A child device cannot access another device's commands or telemetry.
- A child device cannot call parent or admin endpoints.
- A parent cannot call admin endpoints.
- A low-privilege admin cannot access restricted records or operations.
- Expired/revoked tokens are rejected.
- Refresh-token reuse is detected and handled.
- Pairing invitation cannot be claimed twice.
- Pairing brute-force attempts are throttled.
- Invalid command payloads are rejected.
- Untrusted client-supplied ownership IDs are ignored or rejected.
- WebSocket subscriptions enforce the same access rules as REST.
- Sensitive data is not returned in error messages or logs.

## 16.4 API contract tests

- Verify OpenAPI generation.
- Validate example request/response payloads.
- Add contract tests for the Parent App, Child App, and Admin Dashboard API groups.
- Document generated client/model options for Flutter, Kotlin, and TypeScript.
- Do not let frontend teams independently invent API payloads.

## 16.5 Definition of done

A backend feature is complete only when:

1. Database model and migration exist.
2. Request/response schemas exist.
3. Service/business logic exists.
4. Authorization checks exist.
5. Error handling exists.
6. Unit and integration tests exist.
7. OpenAPI docs are accurate.
8. README/API documentation is updated.
9. Logs do not expose sensitive information.
10. The feature has been tested in Docker-based local development.

---

# 17. Docker and local development

Create a working `docker-compose.yml` for:

- `api`
- `db` (PostgreSQL)
- `redis`
- `worker`
- optional `scheduler`
- optional development email sink

Use health checks and persistent PostgreSQL volume. Do not expose database/Redis ports publicly in production examples. Use a non-root user in the API/worker containers where practical.

Provide commands in README for:

```bash
# Build and start services
docker compose up --build

# Run database migrations
docker compose exec api alembic upgrade head

# Create a local development admin
docker compose exec api python -m app.scripts.create_admin

# Run tests
docker compose exec api pytest

# Format/lint
docker compose exec api ruff check .
docker compose exec api ruff format --check .

# Stop services
docker compose down
```

Adjust commands to the actual project structure and ensure every documented command works.

Provide a local development seed script that creates clearly fake test users/families/devices. Never seed production automatically.

---

# 18. Documentation deliverables

Create and maintain these documents:

1. `README.md`
   - Project overview, prerequisites, setup, environment variables, run commands, migrations, tests, deployment notes.
2. `docs/ARCHITECTURE.md`
   - System architecture, module boundaries, request flows, trust boundaries.
3. `docs/ERD.md`
   - Entity relationship diagram and explanation.
4. `docs/DATABASE_DICTIONARY.md`
   - Table/column purpose, data classification, retention notes.
5. `docs/API_CONTRACT.md`
   - Endpoint list, auth requirements, payload examples, errors, pagination, versioning.
6. `docs/AUTH_AND_RBAC.md`
   - Principal types, token lifecycle, permissions matrix.
7. `docs/PAIRING_FLOW.md`
   - QR/code pairing, expiry, claim, device registration, recovery/revocation.
8. `docs/COMMAND_DELIVERY.md`
   - Outbox, FCM wake-up, command lifecycle, retry, idempotency, sync semantics.
9. `docs/PRIVACY_AND_RETENTION.md`
   - Data inventory, purpose, access, retention, deletion/export.
10. `docs/FEATURE_CAPABILITY_MATRIX.md`
    - Device capability and permission support/limitations.
11. `docs/DEPLOYMENT.md`
    - Staging/production configuration, TLS, secrets, database backups, migrations, rollback.
12. `docs/INTEGRATION_GUIDE.md`
    - How each of the three client teams integrates with the backend.
13. `docs/CHANGELOG_API.md`
    - API contract changes and compatibility notes.

Use Mermaid diagrams where useful. Keep diagrams consistent with the implementation.

---

# 19. Phased implementation plan

Do not attempt to generate the entire backend in one unreviewed code dump. Work phase by phase. At the end of each phase, run tests and report files changed, decisions made, commands run, and known gaps.

## Phase 0 — Repository inspection and architecture

1. Inspect the repository and existing PRD.
2. Identify existing files, conventions, and any implemented code.
3. Produce a short implementation plan and architecture diagram.
4. Identify ambiguities and make conservative, documented assumptions.
5. Confirm the API contract and data model before implementing endpoints.
6. Do not delete or overwrite unrelated files.

**Deliverable:** architecture and implementation plan, initial API contract outline, project structure.

## Phase 1 — Project foundation

1. Create FastAPI application and settings.
2. Add SQLAlchemy async session management.
3. Add PostgreSQL Docker service.
4. Add Redis service.
5. Add structured logging, request IDs, global exception handling.
6. Add health endpoints.
7. Add Ruff, type checking, pytest setup.
8. Add `.env.example` and README.

**Acceptance:** app starts locally; DB connection works; health/readiness behave correctly; tests pass.

## Phase 2 — Database and migrations

1. Implement base models and naming conventions.
2. Add identity, family, child, device, pairing, policy, command, audit, and privacy models.
3. Add indexes, constraints, and foreign keys.
4. Create initial Alembic migration.
5. Test fresh migration and rollback/upgrade path.
6. Add ERD and data dictionary.

**Acceptance:** clean database can be created from migrations; model constraints are tested.

## Phase 3 — Authentication and RBAC

1. Implement parent registration and verification.
2. Implement login/logout/refresh rotation.
3. Implement password reset/change.
4. Implement device principal authentication.
5. Implement admin principal authentication and permissions.
6. Add reusable authorization dependencies.
7. Add rate limiting and security tests.

**Acceptance:** role boundaries and token lifecycle tests pass.

## Phase 4 — Family, guardian, and child profiles

1. Implement family creation and membership.
2. Implement guardian invitation flow if included.
3. Implement child profile CRUD.
4. Add family-scoped repository/service helpers.
5. Add IDOR/cross-tenant tests.

**Acceptance:** users can only access authorized family data.

## Phase 5 — Device pairing and registration

1. Implement pairing invitation generation and secure storage.
2. Implement QR/short-code claim API.
3. Implement atomic claim transaction and race-condition handling.
4. Create device session and scoped credentials.
5. Implement device registration, heartbeat, capability and permission reports.
6. Implement revocation and recovery flow.

**Acceptance:** pairing works end-to-end in tests, including duplicate/race/expiry cases.

## Phase 6 — Policies and schedules

1. Implement app restriction policy APIs.
2. Implement screen-time policies and schedules.
3. Implement validation, timezones, and conflict resolution.
4. Add policy versioning.
5. Add transactional outbox event creation.
6. Add parent views of policy sync status.

**Acceptance:** policy changes are persisted, versioned, and queued for sync atomically.

## Phase 7 — Commands and reliable synchronization

1. Implement strict command schemas and allow-list.
2. Implement command lifecycle/state machine.
3. Implement device pending-command fetch.
4. Implement acknowledgements and results.
5. Implement outbox worker and bounded retries.
6. Implement FCM adapter and fake provider tests.
7. Implement expiry/cleanup jobs.

**Acceptance:** commands remain durable without FCM; duplicate requests/acks are safe; parent sees truthful device-reported status.

## Phase 8 — Usage, alerts, and reporting

1. Implement daily usage summary ingestion.
2. Implement app summary ingestion with payload limits.
3. Implement parent usage/report APIs.
4. Implement alert creation and acknowledgement.
5. Add aggregation and deduplication.
6. Add data retention.

**Acceptance:** usage is family-scoped, validated, paginated, and clearly treated as device-reported data.

## Phase 9 — WebSockets and notifications

1. Implement secure WebSocket authentication.
2. Implement resource-scoped subscriptions.
3. Publish minimal events through Redis.
4. Implement push-token management and notification preferences.
5. Add reconnect and REST recovery documentation.

**Acceptance:** clients receive only authorized events; REST remains source of truth.

## Phase 10 — Admin dashboard APIs

1. Implement admin overview and filtered list endpoints.
2. Implement support, trust/safety, billing, and read-only permissions.
3. Add admin action audit logging.
4. Add pagination and safe field projection.
5. Add tests for privilege boundaries.

**Acceptance:** each admin role sees and changes only authorized resources.

## Phase 11 — Privacy, billing, and optional modules

1. Implement consent/disclosure records.
2. Implement export/deletion request workflows.
3. Implement retention jobs.
4. Add location module only if approved and supported, with strict access controls.
5. Add provider-neutral billing domain and verified webhooks if provider selected.
6. Add private object storage integration if required.

**Acceptance:** privacy workflows are tested; optional modules remain disabled until configured and approved.

## Phase 12 — Hardening and release preparation

1. Run all tests, lint, formatting, type checks, and migration checks.
2. Add security review checklist and dependency scan instructions.
3. Validate production configuration fails safely.
4. Add backup/restore and migration runbooks.
5. Add performance tests for key list/ingestion routes.
6. Review indexes and query plans.
7. Verify no secrets or sensitive data are committed/logged.
8. Produce final API contract and integration guide.

**Acceptance:** staging deployment can be configured from documented steps; known limitations are listed honestly.

---

# 20. Integration contract for the three client teams

The backend team owns the API contract. All client teams must consume it.

## Parent App (Flutter) needs

- Parent auth and session APIs.
- Family/guardian/child APIs.
- Pairing invitation APIs.
- Device status and capability views.
- Policy CRUD and schedules.
- Usage/alerts APIs.
- Subscription APIs if enabled.
- WebSocket event contract.
- Stable error codes and pagination.

## Child App (Kotlin) needs

- Pairing claim.
- Device-scoped auth and refresh.
- Device registration and heartbeat.
- Capability/permission reports.
- Current policy snapshot.
- Pending command fetch.
- Command acknowledgement/result.
- Usage summary submission.
- Push token registration.
- Device unlink/revocation behavior.

## Admin Dashboard (Next.js) needs

- Admin login/session and MFA integration.
- Role/permission-aware endpoints.
- User/family/device search.
- Support and abuse-report workflows.
- Subscription views.
- Aggregated analytics.
- Audit logs.

Publish a sample API collection or generated OpenAPI client artifacts for each team. Include fake development accounts and example payloads, but never real user data.

---

# 21. Required API examples

Include concrete, validated examples in OpenAPI docs and `docs/API_CONTRACT.md`.

## Create a pairing invitation

`POST /api/v1/children/{child_profile_id}/pairing-invitations`

Example response:

```json
{
  "success": true,
  "message": "Pairing invitation created.",
  "data": {
    "invitation_id": "9a8b7c6d-1234-4567-8901-123456789012",
    "claim_token": "example-only-high-entropy-token",
    "expires_at": "2026-11-07T12:30:00Z",
    "status": "pending"
  },
  "meta": {
    "request_id": "example-request-id"
  }
}
```

Important: the raw claim token should be returned only once to the authorized parent client, never stored in plaintext, and never written to logs. Use illustrative fake values in documentation.

## Claim a pairing invitation

`POST /api/v1/device/pairing/claim`

Example request:

```json
{
  "claim_token": "example-only-high-entropy-token",
  "device": {
    "platform": "android",
    "app_version": "1.0.0",
    "os_version": "Android 16",
    "device_label": "Child's phone"
  },
  "disclosure_version": "2026-01"
}
```

Example response:

```json
{
  "success": true,
  "message": "Device paired successfully.",
  "data": {
    "device_id": "c2d2b1a0-1234-4567-8901-123456789012",
    "device_access_token": "example-short-lived-device-token",
    "device_refresh_token": "example-one-time-refresh-secret",
    "token_type": "Bearer",
    "expires_in": 900,
    "status": "paired"
  },
  "meta": {
    "request_id": "example-request-id"
  }
}
```

The actual refresh-token design may use an opaque token with server-side hash storage rather than a JWT. Document the chosen design. Do not include real secrets in tests or docs.

## Create an app restriction

`POST /api/v1/children/{child_profile_id}/app-restrictions`

Example request:

```json
{
  "package_identifier": "com.example.video",
  "display_label": "Example Video",
  "action": "block",
  "enabled": true
}
```

Example response:

```json
{
  "success": true,
  "message": "Restriction saved and queued for synchronization.",
  "data": {
    "restriction_id": "e1e2e3e4-1234-4567-8901-123456789012",
    "policy_version": 4,
    "sync_status": "pending_sync"
  },
  "meta": {
    "request_id": "example-request-id"
  }
}
```

Do not claim the app is blocked until the device reports a successful application result.

## Device command result

`POST /api/v1/device/commands/{command_id}/result`

Example request:

```json
{
  "result": "unsupported",
  "applied_policy_version": 3,
  "error_code": "REQUIRED_PERMISSION_NOT_GRANTED",
  "message": "The required permission is not enabled on this device."
}
```

Return and persist an explicit state. Never transform `unsupported` or `permission_denied` into success.

---

# 22. Coding-agent working protocol

Follow this workflow while implementing.

1. **Inspect first.** List repository files and read the existing PRD and any existing API/database docs before editing.
2. **Plan before coding.** Present a concise phase plan and identify assumptions.
3. **Work in small vertical slices.** Implement a feature end-to-end rather than creating dozens of empty files.
4. **Keep changes scoped.** Do not modify Parent App, Child App, or Admin Dashboard source directories unless explicitly asked.
5. **Use the API contract as authority.** If a contract change is necessary, update docs and tests in the same change and explain its impact on all clients.
6. **No placeholder success.** Return explicit `501 NOT_IMPLEMENTED` or a documented disabled state where appropriate; do not pretend the feature works.
7. **Run tests after each phase.** Fix regressions before continuing.
8. **Report accurately.** Distinguish implemented, partially implemented, stubbed, and not implemented.
9. **Ask only blocking questions.** If an unresolved choice does not block safe progress, choose a conservative default and document it.
10. **Do not silently change the stack.** If you believe a stack change is essential, explain the tradeoff and request approval before switching.

At the end of every phase, provide:

- Summary of what was implemented.
- Files created/modified.
- Database migrations added.
- API endpoints added/changed.
- Tests executed and exact pass/fail counts.
- Commands to run locally.
- Security/privacy considerations addressed.
- Known limitations and next phase.

---

# 23. Final instruction to the AI coding agent

Begin with **Phase 0 only**. Inspect the existing project and PRD, then propose the architecture, database entities, API contract outline, and implementation sequence. Do not immediately generate the entire backend.

After the plan is reviewed, implement the phases in order. Prioritize authentication, tenant isolation, pairing, policy versioning, durable command delivery, and reliable API contracts before optional features.

The final backend must be understandable and maintainable by another developer, independently testable, safe by default, and ready to integrate with three separately developed clients.

**Do not claim production readiness merely because the application starts.** Production readiness requires security review, privacy/legal review, platform capability validation, load testing, monitoring, backup/restore verification, and a successful staging deployment.
