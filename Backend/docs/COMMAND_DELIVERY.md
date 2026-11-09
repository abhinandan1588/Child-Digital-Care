# Command delivery and synchronisation

## FCM is not the queue

A push notification cannot be a command queue. An Android device may be offline,
force-stopped, battery-restricted, or subject to Doze and background limits, and
FCM is explicitly best-effort delivery.

So the durable record is PostgreSQL, and a push is only a wake-up signal:

```text
1. Parent changes a policy (or requests an action)
2. Backend validates authorization, writes the change        ┐
3. ...and the command, and an outbox row                     │ one transaction
                                                             ┘
4. Outbox worker claims pending rows
5. Worker sends a content-free FCM wake-up
6. Device wakes when the OS permits and calls the API
7. Device fetches pending commands and the current policy
8. Device applies what it supports
9. Device reports the outcome
10. Backend records the real per-device sync state
11. Parent App polls, or receives a WebSocket hint
```

Losing step 5 costs nothing. The command is still in the database waiting to be
polled, and the device polls on its own schedule anyway.

## Transactional outbox

```text
┌─ request transaction ──────────────────────────────┐
│  app_restrictions       INSERT                     │
│  child_profiles         policy_version += 1        │
│  policy_versions        INSERT (audit trail)       │
│  device_policy_states   INSERT pending_sync × N    │
│  device_commands        INSERT sync_policies × N   │
│  outbox_events          INSERT pending × N         │
└──────────────────── COMMIT ────────────────────────┘
                          │
            Celery, every 10 seconds
                          ▼
        claim_batch()  conditional UPDATE per row:
          WHERE available_at <= now
            AND (status='pending'
                 OR (status='processing' AND locked_at < now - 300s))
          SET status='processing', locked_at=now, attempts += 1
                          │
        exactly one worker owns each row
                          ▼
        publish  → FCM wake-up and/or Redis realtime hint
                          │
          ┌───────────────┴───────────────┐
       success                         failure
    mark_sent()                   mark_failed()
                                  backoff = min(2^attempts × 15s, 1h)
                                  attempts >= OUTBOX_MAX_ATTEMPTS → dead_letter
```

The lease is what makes a worker crash survivable: a row stuck in `processing`
becomes claimable again after 300 seconds rather than being lost.

Publication is idempotent. Re-publishing a wake-up is harmless — the device
re-polls and finds the same commands.

### Outbox payload rules

A payload carries ids and status only, and `_safe_payload()` raises if a
forbidden key is present. The payload reaches a push provider and a WebSocket
fan-out, so coordinates, email addresses, display names, tokens and message
bodies are rejected at write time rather than filtered at send time.

| Topic | Published as |
| --- | --- |
| `device.command_queued` | FCM wake-up + `device.commands_pending` hint |
| `policy.sync_requested` | `policy.sync_status_changed` hint |
| `command.status_changed` | `command.status_changed` hint |
| `policy.sync_status_changed` | `policy.sync_status_changed` hint |
| `device.status_changed` / `device.revoked` | `device.status_changed` hint |
| `usage.summary_received` | `usage.summary_received` hint |
| `alert.created` | `alert.created` hint, plus a generic push for medium/high severity |
| `subscription.status_changed` | `subscription.status_changed` hint |

## Command allow-list

```python
class CommandType(StrEnum):
    sync_policies            # converge on the current policy snapshot
    refresh_device_status    # re-report capabilities and permissions
    request_usage_sync       # re-send 1-14 days of daily summaries
    request_location_update  # gated: feature + consent + permission
    apply_supported_policy   # server-generated
    revoke_device            # server-generated
```

Parents may request only the first four. `apply_supported_policy` and
`revoke_device` are server-generated and refused on the API.

**There is no generic command and there will not be one.** No `execute`,
`shell`, `run_script`, `install_package`, `capture_screen`, `record_audio`,
`record_video` or `read_messages`. `tests/unit/test_command_state_machine.py`
asserts that those names are absent from the enum, and
`tests/security/test_input_and_disclosure.py` asserts the API rejects them.

Each type has its own Pydantic payload model with `extra="forbid"`, combined
into a discriminated union on `command_type`. A payload with an unexpected field
fails validation before any code runs, and a stored payload is re-validated
against its model before it is handed to a device.

### Pre-flight capability check

A command the device has told us it cannot run is refused immediately rather
than queued to expire silently:

| Command | Requires | Refusal |
| --- | --- | --- |
| `request_usage_sync` | `app_usage_stats` supported and permitted | `409 CAPABILITY_UNSUPPORTED` / `PERMISSION_STATE_BLOCKS_ACTION` |
| `request_location_update` | feature enabled, consent granted, location capability and permission | `403 FEATURE_DISABLED`, `403 PERMISSION_STATE_BLOCKS_ACTION`, `409 CAPABILITY_UNSUPPORTED` |

Queueing a command that will certainly fail would show a parent a pending
action that quietly expires. Failing now, with a specific code, lets the Parent
App explain what is missing on the device.

## Lifecycle

```text
                ┌──────────────── cancelled ◀── parent revokes device
                │                               child profile removed
   queued ──▶ delivery_attempted ──▶ delivered ──▶ acknowledged
      │              │                   │              │
      │              │                   ├──────────────┼──▶ succeeded
      │              │                   ├──────────────┼──▶ failed
      │              │                   └──────────────┼──▶ unsupported
      └──────────────┴───────────────────────────────────┴──▶ expired (TTL)
```

| State | Set by |
| --- | --- |
| `queued` | creation, in the parent's transaction |
| `delivery_attempted` | the first push attempt |
| `delivered` | **the device fetching the command** |
| `acknowledged` | `POST /device/commands/{id}/acknowledge` |
| `succeeded` / `failed` / `unsupported` | `POST /device/commands/{id}/result` |
| `expired` | the scheduler, past `expires_at` |
| `cancelled` | device revocation, re-pairing, child deactivation |

**`delivered` means the device fetched it.** A provider receipt means FCM
accepted the message, not that the device received or ran anything. Conflating
the two is how a product ends up telling a parent a rule is active when it is
not, so the two are kept apart.

Transitions are validated in one place (`ALLOWED_TRANSITIONS`). Terminal states
accept nothing, and `queued → succeeded` is impossible: success requires
evidence the device actually received the command.

### Result mapping

| Device reports | Command status | Policy sync status |
| --- | --- | --- |
| `succeeded` | `succeeded` | `synced` |
| `partially_applied` | `succeeded` | `partially_applied` |
| `unsupported` | `unsupported` | `unsupported` |
| `permission_denied` | `failed` | `failed` |
| `failed` | `failed` | `failed` |

`unsupported` and `permission_denied` are stored exactly as reported. Nothing
maps them to success — a parent being told a restriction is active when it is
not is the worst failure this product can have.

## Idempotency and out-of-order reports

| Situation | Behaviour |
| --- | --- |
| Duplicate create with the same `Idempotency-Key` | returns the original command |
| Same key, different body | `409 IDEMPOTENCY_KEY_REUSED` |
| Duplicate acknowledgement | `200` with `duplicate: true` |
| Acknowledgement after a terminal state | `200 duplicate: true`; terminal state untouched |
| Contradictory late result | `200 duplicate: true`; first terminal outcome stands, discrepancy logged |
| Acknowledgement of an expired command | `409 COMMAND_EXPIRED` |
| Result for another device's command | `404` |

The reconciliation rule is "first terminal outcome wins". A device that
reported success and then, after a retry, reports failure does not flip the
record; the conflict is logged for investigation instead.

## Retry and expiry

| Setting | Default | Meaning |
| --- | --- | --- |
| `COMMAND_DEFAULT_TTL_SECONDS` | 86 400 | A command never pends forever |
| `COMMAND_MAX_DELIVERY_ATTEMPTS` | 5 | Cap on wake-up attempts per command |
| `OUTBOX_MAX_ATTEMPTS` | 8 | Then dead-letter |
| `OUTBOX_BATCH_SIZE` | 100 | Rows per worker pass |

Scheduled jobs:

| Job | Schedule | Effect |
| --- | --- | --- |
| `cdc.outbox.process` | every 10 s | publish pending rows |
| `cdc.maintenance.expire_commands` | every 60 s | past-TTL commands → `expired` |
| `cdc.maintenance.resend_pending_wakeups` | on demand | re-queue a wake-up for a command unfetched after an hour |
| `cdc.maintenance.mark_stale_devices` | every 30 min | silent > 24 h → `inactive` + one alert per day |

`resend_pending_wakeups` exists because a device may miss every push. It
re-queues an outbox row without touching the command's own retry accounting.

## Policy versioning and what the parent sees

`child_profiles.policy_version` increments on every policy mutation, in the same
transaction. `device_policy_states` records what each device reported for each
version.

| Parent App shows | Server state |
| --- | --- |
| Saved | the mutation's `200`/`201` |
| Waiting for device | `pending_sync` |
| Received by device | command `delivered` / `acknowledged` |
| Applied | `synced` after a `succeeded` result |
| Partially applied | `partially_applied`, with `item_results` |
| Not supported on this device | `unsupported` |
| Failed | `failed`, with a safe `failure_message` |

Two numbers are kept apart deliberately: the version a command tried to deliver,
and the version the device says it has applied. A failed move to v4 shows as
"v4 unsupported" while the device remains honestly reported on v3.

## Push payload contract

```json
{ "data": { "reason": "commands_pending", "action": "poll_commands", "pending": "3" } }
```

Data-only, collapsible (`collapse_key: "wakeup:<device_id>"`), high priority,
1-hour TTL, and no notification UI. A forbidden-key deny-list is enforced by
the provider adapter *and* by the fake provider used in tests, so a test that
tries to smuggle telemetry into a notification fails.

Parent notifications are generic by design — "New activity to review" — and the
app fetches the detail with its own credential. A push traverses a third party
and can surface on a lock screen, which is the wrong place for a child's data.
