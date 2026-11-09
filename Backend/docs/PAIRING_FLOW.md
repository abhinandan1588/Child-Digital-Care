# Pairing flow

Pairing converts a short-lived secret into a long-lived device credential. It is
the most security-sensitive flow in the product, and the only unauthenticated
write in the device API.

## The flow

```text
 Parent App                    Backend                      Child App
     │                            │                             │
     │ 1. authenticated           │                             │
     │ 2. select/create child     │                             │
     │─── POST /children/{id}/pairing-invitations ─────────────▶ │
     │                            │ 3. generate 256-bit token   │
     │                            │    + optional 8-char code   │
     │                            │    store SHA-256 hashes only│
     │◀── 201 { claim_token, short_code, expires_at } ────────── │
     │     (returned exactly once)│                             │
     │                            │                             │
     │ 4. render QR / show code   │                             │
     │ ────────── QR or spoken code ──────────────────────────▶  │
     │                            │                   5. scan/type
     │                            │                   6. show disclosure,
     │                            │                      get acknowledgement
     │                            │◀── POST /device/pairing/claim
     │                            │     { claim_token, device, disclosure_* }
     │                            │                             │
     │                            │ 7. validate: expiry, status,│
     │                            │    attempt count, child active
     │                            │ 8. ONE TRANSACTION:         │
     │                            │      claim invitation       │
     │                            │      create/revive device   │
     │                            │      create device session  │
     │                            │      record consent         │
     │                            │      queue sync_policies    │
     │                            │      write outbox + audit   │
     │                            │── 201 { device_id, tokens } ▶│
     │                            │                   9. store in Keystore
     │                            │◀── POST /device/register ────│
     │                            │     (+ capabilities, permissions)
     │                            │◀── GET /device/policies/current
     │◀── GET /devices/{id} ──────│                             │
     │    status: active          │                             │
     │    policy_sync_status: pending_sync   ← separate facts   │
```

Step 4 carries **only the claim token**. Never a parent JWT, never an email,
never a family id. The QR payload is a secret with a 15-minute life, nothing
more.

Step 9's distinction matters: the Parent App shows "paired" and "waiting for the
device to sync" as two different things, because they are two different facts.

## Security properties

| Property | Mechanism |
| --- | --- |
| High entropy | `secrets.token_urlsafe(32)` — 256 bits |
| Not recoverable | only SHA-256 hashes stored; the raw token is returned once and never logged |
| Short-lived | `PAIRING_INVITATION_EXPIRE_MINUTES`, default 15, max 60 |
| Single use | conditional `UPDATE ... WHERE status='pending' AND expires_at > now` |
| Race-safe | the losing claim matches zero rows and gets `409`/`404` |
| Attempt-limited | `attempt_count` incremented and **committed** on every attempt; past `PAIRING_MAX_CLAIM_ATTEMPTS` (5) the invitation is burned |
| Rate-limited | per client IP *and* per hashed presented secret |
| Revocable | `DELETE /pairing-invitations/{id}` |
| Quota-bounded | 3 pending invitations and 5 devices per child |
| Disclosure-gated | `disclosure_acknowledged` must be `true`; the version is stored as a consent record |
| Audited | success and every distinct failure reason |

### Why the short code is safe

Eight characters from a 32-symbol alphabet (`I`, `O`, `0`, `1` excluded) is
40 bits. That is only acceptable because the code is short-lived, single-use,
attempt-limited to 5, and rate-limited per IP and per secret. It is never a
long-term credential. A deployment that wants to raise the bar should disable
short codes (`include_short_code: false`) and use QR only.

### Why the attempt counter commits before the rejection

The request-scoped session rolls back when a handler raises. A counter that
resets whenever the attempt fails would protect nothing, so the counter and the
audit entry are committed first and then the rejection is raised. That is the
one place in the codebase where "commit, then raise" is correct, and it is
commented as such.

## Failure modes, all tested

| Case | Response |
| --- | --- |
| Unknown token | `404` "not valid, has expired, or has already been used" |
| Expired invitation | `404`, same message |
| Revoked invitation | `404`, same message |
| Already claimed | `409 INVITATION_ALREADY_CLAIMED` (or `404` if the row was burned) |
| Attempt limit exceeded | `409 INVITATION_ATTEMPT_LIMIT`, invitation revoked |
| Two simultaneous claims | exactly one `201`; the other `409`/`404` |
| Disclosure not acknowledged | `422` |
| Child profile inactive | `404`, attempt still counted |
| Parent claiming another family's invitation | `404` from the parent routes |
| Device reading another device's data | `404` (device id comes from the token) |

Unknown, expired, revoked and already-claimed deliberately share one message:
an attacker guessing codes learns nothing about which guess was "closer". The
specific reason is in the server-side audit log.

## Re-pairing after a reset

A device that is wiped and re-pairs sends the same `install_id`. The server
revives the existing device row rather than creating a second one:

- previous device sessions revoked (`re_paired`)
- pending commands cancelled
- `applied_policy_version` cleared, `policy_sync_status` reset to `pending_sync`
- usage history stays attached to the same device

So a parent does not accumulate three entries called "Child's phone", and the
old credential stops working immediately. `install_id` is a random per-install
value generated by the Child App — **not** a hardware identifier, IMEI, serial
or advertising id.

## Revocation and recovery

| Situation | Action | Result |
| --- | --- | --- |
| Device lost or stolen | `POST /devices/{id}/revoke` | sessions revoked, pending commands cancelled, push tokens deactivated, alert raised |
| Device replaced | revoke, then pair the new device | old credential dead immediately |
| Child profile removed | `DELETE /children/{id}` | every device unlinked, pending invitations revoked |
| Account deletion requested | automatic | every device unlinked at once, before the grace period |
| Credential suspected compromised | revoke, then re-pair | reuse detection also fires if the old token is replayed |

Revocation takes effect on the device's next API call, whether or not the device
is currently reachable. That is the only mechanism that works for an offline
device — there is no "remote wipe" that can be relied on.

A device **cannot unlink itself**. `POST /devices/{id}/revoke` is a parent
route; a device token on it returns `401`. A child cannot end supervision from
the device.

## Child App checklist

1. `POST /device/pairing/claim` with the scanned token, minimal device metadata,
   and the acknowledged disclosure version.
2. Store `device_refresh_token` in Android Keystore-backed storage. Never plain
   `SharedPreferences`, never a file, never a log.
3. `POST /device/register` with capabilities and permission states. Idempotent —
   safe on every app start.
4. `GET /device/policies/current`; apply what the device supports.
5. `POST /device/commands/{id}/result` with the honest outcome. Report
   `unsupported` or `permission_denied` when that is the truth; the server
   stores it verbatim and the parent is told.
6. `POST /device/push-token` so wake-ups can be delivered.
7. On `401`: rotate via `POST /device-auth/refresh`. On `403 DEVICE_REVOKED`:
   stop, clear local credentials, and show the user that supervision ended.

Metadata the server accepts, deliberately minimal: platform, app version, OS
version, label, model, manufacturer, timezone, `install_id`. Not accepted and
not wanted: hardware serial, IMEI, MAC address, advertising id, phone number,
or an installed-app inventory.
