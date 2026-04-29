# Network Scan Project Plan

## Goal

Develop the project from a pair of local CLI scripts into a stable network inventory and monitoring tool that runs both:

- locally on macOS;
- on Synology NAS;
- from the same codebase without host-specific forks.

## Working Principles

- Keep the codebase cross-platform between macOS and Synology/Linux.
- Do not hardcode Synology-specific interfaces, paths, or Python locations.
- Put environment-specific behavior behind CLI flags or config.
- Prefer incremental refactoring over a large rewrite.
- Keep the project usable after every milestone.
- Keep automated tests up to date and run them after each meaningful code change.

## Current State

- `arp_scanner.py` works locally and on Synology.
- `port_scan.py` works locally and on Synology.
- ARP discovery, vendor lookup, JSON export, and SQLite storage already work.
- Port scanning already supports per-run history, diff reporting, and multiple console output modes.
- Default port scanning now targets a dev/self-hosted-friendly set: `22, 80, 443, 3000, 5000, 8000, 8080, 8443`.
- Synology runs successfully on `Python 3.9` in a project-local `venv`.
- `requirements.txt` has already been simplified.

## Main Product Direction

This repository now has two active product tracks:

- `network_scan`: inventory and change monitoring for your own local network
- `network-health-check`: trust and exposure assessment for guest, hotel, cafe, and other untrusted networks

These tracks should share reusable plumbing where it helps, but they should not be forced into one user workflow.

## Scope Boundaries

### In Scope For This Repository

- local-network inventory and change detection
- port visibility on your own hosts and subnets
- export/reporting/alerts around those changes
- safe trust checks for untrusted networks
- Wi-Fi environment, DNS, captive portal, HTTPS/TLS, and path sanity checks

### Explicitly Out Of Scope For This Repository

- broad active scanning of third-party or open public networks
- “what is reachable on everyone else’s network” style probing
- aggressive discovery logic aimed at unknown external devices

If active probing of open/public networks becomes a real goal, that should be a separate project with its own threat model, UX, legal boundary, and safety rules.

## Active Roadmap

### Track A: `network_scan`

Priority:

- High

Current role:

- monitor your own LAN
- maintain device and port history
- surface actionable changes

Remaining work:

- decide whether snapshot tables are enough or whether to move to richer observation/event modeling
- continue selective cleanup of `port_scan.py` and shared persistence/reporting boundaries
- extend alert delivery beyond the first webhook path when needed, for example Telegram or email
- improve long-term inventory semantics if device history needs to become more than “latest state + snapshots”

Backlog:

- Synology scheduler / cron-ready execution
- heavier automation wrappers
- UI

### Track B: `network-health-check`

Priority:

- High

Current role:

- assess whether a network looks trustworthy enough to use
- inspect current path, Wi-Fi conditions, DNS behavior, captive portal behavior, and HTTPS/TLS behavior

Remaining work:

- expand macOS-first Wi-Fi environment detail where the platform allows it
- improve guest/open-network exposure assessment beyond the current gateway-local and passive local-peer visibility checks without crossing into broad active scanning
- add a concise overall trust/path explanation on top of the current gateway, peer-visibility, DNS, captive, and HTTPS reasoning layers
- keep refining dual-connectivity, mesh instability, and route/path diagnostics
- continue cleanup inside `network_health.py` so collection, analysis, and rendering boundaries stay explicit

Backlog:

- fuller macOS-native Wi-Fi discovery if `CoreWLAN` remains restricted
- any future discovery-oriented mode that goes beyond safe trust checks

## Release Direction

### Near Term

Focus:

- cleanup and internal structure
- extend alert delivery beyond the initial webhook path
- history model decision
- `network-health-check` capability expansion within safe bounds

### Later

Focus:

- notification integrations
- richer inventory semantics
- possible extraction of `network-health-check` into a more standalone tool if it keeps growing

## Immediate Next Tasks

1. Decide whether `network_scan` should stay on snapshot tables or move toward observation/event modeling.
2. Continue selective cleanup in `network_health.py`, especially around macOS Wi-Fi collectors and trust-check composition.
3. Add a short overall trust summary that explains the combined outcome of local-segment, DNS, captive-portal, and HTTPS reasoning.
4. Decide whether the next alert channel should be Telegram or email on top of the current webhook path.
5. Keep Synology scheduler work in backlog unless automation pressure becomes real.

## Progress Snapshot

Completed:

- `--iface` added to both scanners.
- `--cidr` added to both scanners.
- Shared scan target resolution reused across both scanners.
- SQLite schema extended with `last_seen`.
- `scan_runs` is the shared run-history mechanism for the project.
- ARP scan snapshots are persisted per run.
- Port scan snapshots are now persisted per run.
- Port scan diffing is available for new ports, closed ports, and service changes.
- Port scan JSON export includes both the full snapshot and the diff summary.
- Minimal ARP diff summary added for new devices, returned devices, missing devices, and IP changes.
- ARP scanner supports explicit DB and JSON output paths.
- Port scanner now also supports an explicit shared DB path.
- ARP JSON export now includes both the full snapshot and the diff summary.
- Shared reporting helpers are now used by both scanners for JSON report generation.
- Shared reporting helpers are now also used for diff-style console summaries.
- Shared model helpers are now used for scan context, device snapshots, and port snapshots.
- Port parsing now validates bounds, malformed ranges, and empty entries explicitly.
- Port scan console output now supports `grouped`, `table`, and `focus` modes.
- Port scan output now normalizes service labels into clearer statuses such as `HTTP`, `HTTPS`, `SSH`, `WEB`, and `TLS`.
- Unknown or weak banner results are now rendered with clearer details such as `open port, no banner` and `banner grab failed`.
- Default port scanning now includes common dev/self-hosted ports such as `3000`, `5000`, `8000`, and `8443`.
- Optional reverse-DNS hostname enrichment is available in both ARP and port scan flows.
- ARP diff now reports hostname changes when hostname enrichment is enabled.
- TLS metadata is now captured for `443/tcp`, persisted in scan history, and reported in port diffs.
- Snapshot CSV export is now available for both ARP and port scan runs.
- Snapshot Markdown export is now available for ARP, port scan, and network health reports.
- Alert-only console mode is now available for both scanners.
- Scheduled-friendly exit codes are now available in alert-only mode.
- Webhook alert delivery is now available for ARP, port scan, and network health checks when actionable findings exist.
- Port scan alerting now treats hostname changes and TLS changes as first-class findings where applicable.
- Port scan reporting and export logic have been split out into a dedicated `port_reporting.py` module.
- Initial `network-health-check` support now exists for gateway, DNS, captive portal, and HTTPS/TLS sanity checks on untrusted networks.
- The next `network-health-check` expansion should prioritize macOS Wi-Fi visibility first, with broader cross-platform discovery kept as a separate track.
- Mesh-oriented Wi-Fi stability diagnostics are now an explicit follow-up track for `network-health-check`.
- `network-health-check` now raises an explicit `active_path` alert for dual-connected macOS scenarios where Ethernet is active while Wi-Fi is also connected.
- `network-health-check` now includes a gateway-local exposure check to show whether the current gateway exposes DNS and web/admin surfaces directly to the client.
- `network-health-check` now includes a passive `local_peer_visibility` check based on the current ARP cache to show whether peer devices are already visible on the local segment without broad active probing.
- `network-health-check` now includes a derived `client_isolation_hint` that summarizes whether the current segment appears to expose peer devices to the client based on passive visibility signals.
- `network-health-check` now includes aggregated `dns_trust_reasoning`, `captive_trust_reasoning`, and `https_trust_reasoning` checks on top of the existing probe results.
- `network-health-check` collection, reporting, and Wi-Fi environment logic have started being split into cleaner orchestration helpers.
- README updated with scan history behavior, Synology examples, and suggested data layout.
- Baseline `unittest` suite added for CLI/network resolution helpers and SQLite persistence behavior.

## Risks and Constraints

- ARP and raw socket behavior require elevated privileges.
- Synology networking may differ from macOS and should remain configurable.
- Vendor database updates are not fully reliable in every environment.
- Port scanning can produce inconsistent results for sleeping or intermittently reachable devices.
- Large structural changes should not break the current simple CLI workflow.

## Rules for Future Changes

- Do not break local execution while optimizing for Synology.
- Keep new features optional when they increase scan time noticeably.
- Prefer data model improvements before adding notifications or UI.
- Avoid hardcoding deployment assumptions into core logic.

## Current Execution Standard

Recommended launch pattern:

```bash
sudo ./venv/bin/python arp_scanner.py
```

```bash
sudo ./venv/bin/python port_scan.py
```

On Synology, explicit interface selection is the preferred stable mode:

```bash
sudo ./venv/bin/python arp_scanner.py --iface ovs_eth0 --cidr 192.168.2.0/24
```

```bash
sudo ./venv/bin/python port_scan.py --iface ovs_eth0 --cidr 192.168.2.0/24
```
