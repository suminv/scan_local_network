# Priority Roadmap: Device Understanding and Policy

This document records the agreed next-session scope. Do not start items 5–7
(passive-only discovery, additional notification channels, or a web UI) before
these priorities are complete.

## 1. Unified Device Profile

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
