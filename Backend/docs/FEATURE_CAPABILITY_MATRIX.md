# Feature capability matrix

> **This document is a starting point, not a verdict.** The Android team must
> validate every row against the current Android platform and the current
> Google Play Families and Device and Network Abuse policies for the devices
> and markets being targeted. Platform behaviour and Play policy both change,
> and both differ by OEM. Nothing here should be read as "approved".

The server never assumes a capability. It models capability and permission as
**device-reported facts**, and surfaces `unsupported` honestly rather than
implying a rule is active.

Legend — Server: ✔ implemented · ◐ modelled, gated off · ✖ not built.

## Features

| Feature | Server | Android requirement | Device-reported as | Known limitations |
| --- | :-: | --- | --- | --- |
| **App usage reporting** | ✔ | `PACKAGE_USAGE_STATS` (special access, user grants it in Settings) | `app_usage_stats`, `usage_stats` | Aggregates only. Attribution varies by OEM. Revoking the access silently stops collection, which is why a permission change raises a parent alert. |
| **App blocking** | ✔ | No general API. Requires an accessibility service, a device-owner/profile-owner deployment, or OEM-specific support. | `app_blocking` | **Most constrained feature.** Accessibility-service use for blocking is heavily restricted by Play policy and must be declared and justified. A consumer, non-managed install may be unable to do this at all. Expect `unsupported` on many devices. |
| **Screen-time limits** | ✔ | Depends on the same enforcement path as blocking | `screen_time_enforcement` | Server stores the budget and schedule; the device enforces. A device that cannot enforce reports `unsupported`. |
| **Schedules / bedtime** | ✔ | Local scheduling plus the enforcement path | `screen_time_enforcement` | Server resolves DST and precedence. Doze may delay a transition by minutes. |
| **Device status / heartbeat** | ✔ | Network access, background execution | `background_execution`, `foreground_service` | Battery optimisation, force-stop and OEM task killers all suppress heartbeats. "Offline" is an inference from `last_seen_at`, labelled as such. |
| **Command delivery** | ✔ | FCM plus `POST_NOTIFICATIONS` (Android 13+) for visible notifications | `notification_post`, `post_notifications` | FCM is best-effort. Commands are durable server-side and polled, so a lost push costs nothing. |
| **Location (coarse/fine)** | ◐ | `ACCESS_COARSE_LOCATION` / `ACCESS_FINE_LOCATION`, plus `ACCESS_BACKGROUND_LOCATION` for background | `location_coarse`, `location_fine`, `location_background` | Off by default. Background location requires a Play review with a justified use case. Coordinates stored at ~110 m. Four gates must all pass. |
| **Website filtering** | ◐ | No compliant general mechanism. Would need a `VpnService` or a DNS approach. | `web_content_filtering` | **Disabled by default and should stay disabled** until the Child App has a reviewed, supported implementation. A VPN-based filter has significant Play-policy, battery and reliability consequences, and cannot cover every browser. |
| **Uninstall protection** | ✖ | Device admin / device owner | `device_admin_lock` | Not implemented. Consumer device-admin APIs are deprecated for this purpose. The product instead *reports* an uninstall attempt as an event and alerts the parent. |
| **Remote lock** | ✖ | Device owner | `device_admin_lock` | Not implemented. Needs a managed-device deployment. |
| **Call/SMS monitoring** | ✖ | — | — | **Will not be implemented.** Out of product scope and restricted by Play policy. |
| **Message content** | ✖ | — | — | **Will not be implemented.** |
| **Keystroke logging** | ✖ | — | — | **Will not be implemented.** |
| **Screen/audio/video capture** | ✖ | — | — | **Will not be implemented.** |
| **Browsing history** | ✖ | — | — | **Will not be implemented.** |
| **Covert operation** | ✖ | — | — | **Will not be implemented.** No hidden install, no permission bypass, no stealth persistence. |

The last six rows are not a backlog. They are the boundary of the product.

## Permission vocabulary

The server accepts these keys from `POST /device/permissions/report`:

| Key | Android permission or access | Blocks |
| --- | --- | --- |
| `usage_stats` | `PACKAGE_USAGE_STATS` special access | usage reporting |
| `accessibility_service` | Accessibility service enabled | app blocking (where that is the chosen path) |
| `device_admin` | Device admin active | lock features (not implemented) |
| `post_notifications` | `POST_NOTIFICATIONS` (13+) | visible notifications |
| `location_coarse` / `location_fine` | `ACCESS_*_LOCATION` | location |
| `location_background` | `ACCESS_BACKGROUND_LOCATION` | background location |
| `ignore_battery_optimisations` | `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | timely sync |
| `query_all_packages` | `QUERY_ALL_PACKAGES` | app discovery |
| `vpn_service` | `VpnService` consent | web filtering (disabled) |

States: `granted`, `denied`, `permanently_denied`, `restricted`,
`not_requested`, `not_applicable`, `unknown`.

`QUERY_ALL_PACKAGES` deserves specific attention: Play restricts it to a narrow
set of use cases and may reject an app that requests it without qualifying. The
Child App should prefer the minimum discovery that works.

## How the server behaves when a capability is missing

1. **A command that cannot succeed is refused up front**, with a specific code
   (`CAPABILITY_UNSUPPORTED`, `PERMISSION_STATE_BLOCKS_ACTION`), rather than
   queued to expire silently.
2. **The policy bundle carries `capability_warnings`** naming how many devices
   report the relevant capability as unsupported, and how many have not
   reported yet — "not yet known" and "cannot" are different answers.
3. **A permission moving from `granted` to denied raises a high-severity
   alert.** That is the common way enforcement silently stops working, so the
   parent is told rather than left with a dashboard that still looks green.
4. **Losing a critical capability raises an alert too** and notifies guardians.
5. **A device result of `unsupported` is stored verbatim** and shown as
   `sync_status: "unsupported"`.

## Parent-facing honesty

| Server state | What the Parent App should say |
| --- | --- |
| `pending_sync` | "Saved. Waiting for the device." |
| `delivered` / `acknowledged` | "Sent to the device." |
| `synced` | "Active on this device." |
| `partially_applied` | "Partly active — tap for detail." |
| `unsupported` | "This device cannot apply this rule." |
| `failed` | Show the safe `failure_message`. |
| No capability report yet | "Not yet confirmed on this device." |

The one phrasing to avoid everywhere: implying a restriction is in force when
the only evidence is that the server saved it.

## Before enabling a gated feature

For `FEATURE_LOCATION_ENABLED` or `FEATURE_WEBSITE_RESTRICTIONS_ENABLED`:

1. Confirm the Child App has a working, reviewed implementation on the target
   Android versions.
2. Confirm the Play Console declarations (sensitive permissions, data safety
   form, background location justification) are complete and accepted.
3. Complete a privacy and legal review for the target jurisdictions.
4. Add the disclosure text and a versioned consent flow to both apps.
5. Set the retention window deliberately.
6. Confirm no admin role has been granted the corresponding sensitive
   permission by accident.
7. Only then flip the flag.
