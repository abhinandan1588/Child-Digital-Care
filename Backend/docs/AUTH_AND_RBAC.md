# Authentication and authorization

## Three principals

| Principal | `typ` claim | Audience | Issued by |
| --- | --- | --- | --- |
| Parent / guardian | `parent_user` | `cdc:parent` | `POST /auth/login` |
| Child device | `child_device` | `cdc:device` | `POST /device/pairing/claim` |
| Admin | `admin_user` | `cdc:admin` | `POST /admin/auth/login` |
| WebSocket ticket | `parent_user` + `knd=ws_ticket` | `cdc:ws` | `POST /realtime/ticket` |

Each has its own identity table, its own session table and its own audience. A
token minted for one is rejected on another's routes, and the decoder checks
`typ`, `aud` **and** `knd` — so a WebSocket ticket (which travels in a URL and
therefore lands in proxy logs) cannot be used against the REST API.

## Token design

| | Access token | Refresh token |
| --- | --- | --- |
| Format | JWT | opaque, 256-bit `secrets.token_urlsafe(32)` |
| Stored | not stored | SHA-256 hash only |
| Parent TTL | 15 min | 30 days |
| Device TTL | 15 min | 180 days |
| Admin TTL | 15 min | 1 day |
| Rotation | — | every use |
| Revocable | yes, via the session row | yes |

**Why the asymmetry.** An access token is a bearer credential that must be
cheap to verify, so it is a signed JWT with a short life. A refresh token is
long-lived and therefore must be revocable and detectable if stolen, so it is
opaque with server-side state.

**Why only a SHA-256 hash.** The input already has 256 bits of entropy, so
there is no dictionary for an attacker to search and a slow KDF buys nothing. A
fast digest keeps refresh and pairing lookups indexable. Passwords, which *are*
low entropy, use Argon2id instead.

**Why access tokens are still checked against the database.** "Short-lived" is
not "revoked". Every authenticated request confirms the backing session row is
live, so logout, device revocation and admin suspension take effect
immediately rather than after the token's TTL.

### Claims

```json
{
  "iss": "child-digital-care",
  "aud": "cdc:device",
  "sub": "<device uuid>",
  "typ": "child_device",
  "knd": "access",
  "jti": "<uuid>",
  "sid": "<device_session uuid>",
  "scp": ["device:self", "device:commands", "device:policies", "device:telemetry"],
  "fam": "<family uuid>",
  "iat": 1762500000,
  "nbf": 1762500000,
  "exp": 1762500900
}
```

`fam` is re-checked against the device's current family on every request, so a
credential cannot outlive a re-pairing. Device scopes are narrow so that a
future endpoint which forgets its own check still fails closed.

### Algorithm handling

The verifier is given a fixed algorithm from configuration and never reads the
algorithm from the token header. `iss`, `aud`, `exp`, `iat`, `sub` and `jti` are
all required. An `alg: none` token is rejected, which
`tests/unit/test_security.py` asserts directly.

HS256 is the local default. Staging and production use RS256 with a PEM keypair
from `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH`, so verification keys can be
distributed without sharing the signing secret. Startup validation refuses to
boot a production configuration that is still on HS256.

## Refresh rotation and reuse detection

```text
login ──▶ R1 (family F, counter 0)
          │
          └─ use R1 ──▶ R1 revoked "rotated", R2 issued (family F, counter 1)
                        │
                        ├─ use R2 ──▶ R3 ...                  normal
                        │
                        └─ use R1 again ──▶ REUSE DETECTED
                                            every session in family F revoked
                                            committed, then 401 REFRESH_TOKEN_REUSED
```

`token_family_id` groups every rotation of one original login. Replaying a
consumed token kills the whole family, which turns a stolen refresh token into a
loud, contained event: the attacker and the legitimate user both lose the
session, and the audit log records it. The revocation is committed *before* the
`401` is raised, because the request-scoped session rolls back on exceptions and
a security response that vanishes with the failed request is no response at all.

## Password handling

- Argon2id via `pwdlib`, OWASP second-recommended parameters (19 MiB, t=2, p=1).
- Minimum 12 characters, maximum 128, screened against an obvious-password list,
  and rejected if it contains the email local part.
- Login uses `verify_and_update`, so raising the Argon2 cost later re-hashes
  accounts transparently as people sign in.
- A login against a missing account still performs an Argon2 verification
  against a dummy hash, so response time does not reveal whether the account
  exists. `tests/unit/test_security.py` asserts the timing floor.

## Anti-enumeration

| Endpoint | Behaviour |
| --- | --- |
| `POST /auth/register` | Identical `201` and message whether or not the address exists; the real owner is told by email |
| `POST /auth/login` | Generic `INVALID_CREDENTIALS` for both wrong password and unknown account |
| `POST /auth/password/forgot` | Always `200` with "if an account exists..." |
| `POST /device/pairing/claim` | `404` with one message for unknown, expired, revoked and already-claimed |
| Cross-tenant reads | `404`, not `403` |

## Throttling without lockout

Sensitive endpoints are limited per IP **and** per hashed identifier. There is
deliberately **no account lockout**: locking an account on repeated failures
would let an attacker deny a victim access to their own family's controls by
hammering their email address. Failures are counted and slowed, never fatal.

| Rule | Limit |
| --- | --- |
| `auth.login.ip` | 30 / 15 min |
| `auth.login.account` | 10 / 15 min (hashed email) |
| `auth.register` | 5 / hour |
| `auth.password.forgot` | 5 / hour |
| `admin.login.ip` | 10 / 15 min |
| `admin.login.account` | 5 / 15 min |
| `pairing.claim.ip` | 20 / 10 min |
| `pairing.claim.token` | 5 / 10 min (hashed secret) |
| `device.heartbeat` | 120 / hour |
| `device.usage_submit` | 240 / hour |

Counters live in Redis so they are shared across API instances, with an
in-process fallback for single-node development. With Redis unreachable the
limiter fails open by default (`RATE_LIMIT_FAIL_OPEN=true`) and can be switched
to fail closed.

## Authorization dependencies

Every protected route composes its guard from `app/api/deps.py`:

| Dependency | Resolves |
| --- | --- |
| `get_current_parent` | token → live session → user → usable account |
| `get_verified_parent` | the above, plus a verified email address |
| `get_current_device` | token → device → **not revoked** → live session → family match |
| `get_active_device` | the above, plus completed registration |
| `get_current_admin` | token → live session → active admin → roles/permissions from rows |
| `require_admin_permission(p)` | one `AdminPermission` |
| `require_family_membership(p)` | `{family_id}` → caller's membership → one `FamilyPermission` |
| `require_child_access(p)` | `{child_profile_id}` → its family → membership → permission |
| `require_device_access(p)` | `{device_id}` → its family → membership → permission |
| `require_feature(flag)` | `403 FEATURE_DISABLED` when a gate is off |

For devices, the revocation check runs **before** the session check, so an
unlinked device receives the specific `DEVICE_REVOKED` code it can act on rather
than a generic token error.

## Family permissions

Tenant-scoped. Stored as a JSON array on `family_members`. The owner holds
everything implicitly, so an empty array on the owner row is still fully
privileged.

| Permission | Owner | Guardian (default) | Viewer |
| --- | :-: | :-: | :-: |
| `family.read` | ✔ | ✔ | ✔ |
| `family.update` | ✔ | | |
| `family.members.manage` | ✔ | | |
| `children.read` | ✔ | ✔ | ✔ |
| `children.manage` | ✔ | ✔ | |
| `devices.read` | ✔ | ✔ | ✔ |
| `devices.manage` | ✔ | ✔ | |
| `pairing.manage` | ✔ | ✔ | |
| `policies.read` | ✔ | ✔ | ✔ |
| `policies.manage` | ✔ | ✔ | |
| `commands.issue` | ✔ | ✔ | |
| `usage.read` | ✔ | ✔ | ✔ |
| `alerts.read` | ✔ | ✔ | ✔ |
| `alerts.manage` | ✔ | ✔ | |
| `location.read` | ✔ | | |
| `billing.manage` | ✔ | | |
| `privacy.manage` | ✔ | | |

`location.read`, `family.update`, `family.members.manage`, `billing.manage` and
`privacy.manage` are **non-delegatable**: an invitation requesting them has them
stripped before the invitation row is written. Reading a child's location is
therefore always a deliberate, owner-level grant, never something that arrives
bundled with "help me manage the kids".

## Admin permissions

Expressed as rows (`admin_roles` → `admin_role_permissions` → `admin_permissions`)
so a deployment can adjust them without a code change. Checks go through
`admin_can()`; no module compares role-name strings.

| Permission | super | support | trust&safety | billing | analyst |
| --- | :-: | :-: | :-: | :-: | :-: |
| `overview.read` | ✔ | ✔ | ✔ | ✔ | ✔ |
| `analytics.read` | ✔ | | | | ✔ |
| `users.read` | ✔ | ✔ | ✔ | ✔ | |
| `users.status.write` | ✔ | | ✔ | | |
| `users.pii.read` | ✔ | | | | |
| `families.read` | ✔ | ✔ | ✔ | | |
| `devices.read` | ✔ | ✔ | ✔ | | |
| `devices.revoke` | ✔ | | ✔ | | |
| `child_usage.read` | ✔ | | | | |
| `child_location.read` | ✔ | | | | |
| `support_tickets.read` | ✔ | ✔ | ✔ | | |
| `support_tickets.write` | ✔ | ✔ | | | |
| `abuse_reports.read` | ✔ | | ✔ | | |
| `abuse_reports.write` | ✔ | | ✔ | | |
| `subscriptions.read` | ✔ | ✔ | | ✔ | |
| `subscriptions.write` | ✔ | | | ✔ | |
| `audit_logs.read` | ✔ | | ✔ | | |
| `platform_config.write` | ✔ | | | | |
| `admin_users.manage` | ✔ | | | | |
| `privacy_requests.read` | ✔ | | | | |
| `privacy_requests.write` | ✔ | | | | |

Three deliberate separations:

- **Child telemetry is not support data.** `child_usage.read` and
  `child_location.read` are separate from `devices.read`, and no default role
  other than `super_admin` holds them.
- **Billing staff see billing.** No device or child data at all.
- **Suspension is not a support capability.** It needs
  `users.status.write` and a mandatory written reason.

Every sensitive admin *read* is audited, not only writes: "who looked at this
family's records" is the question a support-tooling incident actually turns on.

## Admin MFA

`admin_users.mfa_required` defaults to `true` and the session records whether
MFA was satisfied. The factor itself is verified by the identity provider or
reverse proxy in front of this API in production; there is no server-side TOTP
verifier here, and none is faked. In production, an admin account marked
`mfa_required` whose session does not record MFA is refused with `MFA_REQUIRED`.
Outside production a code must be supplied so the branch is exercised by tests.
See [DEPLOYMENT.md](DEPLOYMENT.md).

## Session lifecycle events

| Event | Effect |
| --- | --- |
| Logout | that session revoked |
| Logout-all | every session revoked |
| Password change | other sessions revoked (current one optionally kept) |
| Password reset | **all** sessions revoked — it is the compromise recovery path |
| Refresh reuse | entire token family revoked |
| Device revoked by parent | device sessions revoked, pending commands cancelled, push tokens deactivated |
| Account suspended by admin | all sessions revoked |
| Deletion requested | all sessions revoked, all devices unlinked |

## Secure storage expectations for clients

| Client | Requirement |
| --- | --- |
| Child App (Kotlin) | Store the device refresh token in **Android Keystore-backed** storage (`EncryptedSharedPreferences` or an equivalent hardware-backed keystore). Never plain `SharedPreferences`, never a file, never logs. |
| Parent App (Flutter) | Keychain / Keystore via `flutter_secure_storage`. |
| Admin Dashboard | Bearer tokens in memory only. Persisting them in `localStorage` makes any XSS a full session compromise; if cookie-based sessions are adopted later, CSRF protection becomes mandatory and this document must be updated. |
