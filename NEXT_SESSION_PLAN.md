# Priority Roadmap: Device Understanding and Policy

This document records the agreed next-session scope. Do not start items 5–7
(passive-only discovery, additional notification channels, or a web UI) before
these priorities are complete.

## 0. Make `scan-health` Check Selection Predictable

Status: completed on 2026-07-24.

Goal: make the command behavior follow a simple rule: no check selector means
run the complete health suite; one or more selectors mean run only the selected
checks.

Expected behavior:

| Command | Checks to run |
| --- | --- |
| `./scan-health` | Complete suite: network, gateway, DNS, HTTPS, Wi-Fi, public IP, Tailscale, and speedtest |
| `./scan-health --speedtest` | Speedtest only |
| `./scan-health --public-ip` | Public IP and approximate geolocation only |
| `./scan-health --tailscale-diagnostics` | Active Tailscale exit-node diagnostics only |
| `./scan-health --public-ip --speedtest` | Only public-IP lookup and speedtest |
| `./scan-health --no-speedtest` | Complete suite except speedtest |

Treat check selectors separately from output and tuning options. Options such
as `--output`, `--json-out`, `--md-out`, `--timeout`, `--verbose`, and
`--network-profile` must not narrow the check set. For example,
`./scan-health --output focus` still runs the complete suite.

Implementation notes:

- Centralize selection in one function instead of scattering flag checks
  through orchestration.
- Make selected-only runs skip unrelated setup such as LAN target resolution,
  DNS probes, Wi-Fi collection, and gateway probing.
- Allow multiple selectors and preserve a stable report order.
- Keep JSON and Markdown exports valid for both complete and selected-only
  runs; record the selected mode/check names in `scan_context`.
- Decide how `--wifi-stability-seconds` participates in selection: it should
  likely select Wi-Fi stability when used alone and tune that check when Wi-Fi
  is already part of the complete suite.
- A complete run performs a data-consuming speedtest (currently approximately
  10 MB download plus 2 MB upload), so document this prominently and retain
  `--no-speedtest` for lightweight full runs.
- Update CLI help and README examples so “selector” versus “modifier” is
  explicit.

Required tests:

- no selectors execute the complete check set;
- each selector executes only its own check;
- multiple selectors execute exactly their union;
- modifiers do not change selection;
- `--no-speedtest` excludes only speedtest;
- unrelated collectors are not called in selected-only modes;
- summaries, progress step counts, JSON, Markdown, and exit codes remain
  correct for every mode.

Success criterion: a user can predict exactly which checks will run by looking
only at the presence or absence of check-selector flags.

## 1. Unified Device Profile

Status: completed on 2026-07-24.

Goal: combine the currently separate observations into one host profile.

- Add a `device_profiles` SQLite model/table.
- Associate LAN devices by MAC; allow an IP-based temporary profile for
  `--target` scans until a MAC is known.
- Preserve user name, MAC vendor, hostname, IP history, open ports, HTTP/HTTPS
  details, SSH fingerprint, and TLS metadata.
- Add a conservative `device_hint`, such as `Synology-like`, `router-like`,
  `printer-like`, `Linux-like`, or `unknown`.
- Store evidence and confidence for a hint; never present it as a definitive
  device identification.

Success criterion: JSON and SQLite expose a coherent device profile instead of
only separate scan snapshots.

## 2. Event History

Status: completed on 2026-07-24.

Goal: turn scan diffs into a meaningful event history.

- Add a `device_events` table.
- Record `device_first_seen`, `device_missing`, `device_returned`, `ip_changed`,
  `port_opened`, `port_closed`, `http_changed`, `ssh_key_changed`, and
  `tls_changed` events.
- Attach every event to its timestamp, network scope, source scan run, and
  relevant before/after values.
- Alert about a missing device only after a configurable number of consecutive
  missed ARP scans (initial default: 3).
- Distinguish a genuinely opened port from a port observed for the first time
  because the scan coverage changed.

Success criterion: the tool can answer what changed, when it changed, and
whether the result is an observation or a confirmed change.

## 3. Known Devices and Policy Engine

Status: completed on 2026-07-24.

Goal: make results meaningful for this specific network.

- Add a human-editable `config.yaml` or `config.json`.
- Allow known devices to be named and pinned by MAC address.
- Allow expected ports and services to be declared per device.
- Add policies for unknown devices, new ports, SSH host-key changes, unexpected
  HTTP identity changes, and TLS expiry.
- Add `--check-config` to validate the configuration before use.
- Never store passwords, private keys, or other credentials.
- Feed policy outcomes into console alerts and existing webhooks.

Success criterion: findings are described in context, for example “new SSH on
an unknown device,” not merely “22/tcp open.”

## 4. Target Device Profile View

Status: completed on 2026-07-24.

Goal: provide a short operator-facing card for a single host.

Proposed command:

```bash
./scan-ports -t 192.168.2.66 --profile
```

The view should include:

- identity: user-assigned name, MAC, hostname, first seen, IP history;
- service observations: SSH fingerprint, HTTP status/redirect/title, TLS data;
- conservative device hint with its evidence;
- policy status and active alerts.

Keep complete raw observations in JSON; keep this console view compact.

## Implementation Order

1. Design and test the SQLite migrations for profiles and events.
2. Populate/update profiles after ARP and port scans.
3. Generate event history and add missing-device suppression.
4. Add known-device configuration and policy evaluation.
5. Connect policy results to alerts and webhooks.
6. Implement `--profile` for a target IP.
7. Add migration, unit, and end-to-end scenario tests.
8. Update README with configuration and output examples.
