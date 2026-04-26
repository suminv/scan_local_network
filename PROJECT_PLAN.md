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

The next stage is not deployment work. The next stage is to turn the scanner into a repeatable monitoring tool with:

- scan history;
- change detection;
- better runtime configurability;
- cleaner service detection;
- a more maintainable internal structure.

## Roadmap

### Phase 1: Stabilize Runtime and CLI

Priority: High

Scope:

- Add `--iface` override.
- Add `--cidr` override.
- Add optional output path flags for DB and JSON.
- Validate port ranges and invalid CLI input.
- Standardize recommended launch commands in README.

Done when:

- The same code runs locally and on NAS without edits.
- Synology can explicitly use `--iface ovs_eth0`.
- Local runs can still rely on automatic interface detection.

### Phase 2: Improve Persistence Model

Priority: High

Scope:

- Extend storage beyond `first_seen`.
- Add `last_seen`.
- Track scan runs explicitly.
- Prepare schema for device observations and later port history.

Target schema direction:

- `devices`
- `scan_runs`
- `device_observations`
- later `port_observations`

Done when:

- Each scan has a recorded run entry.
- Devices persist across runs with both first and last seen timestamps.
- The project can compare current and previous observations.

### Phase 3: Diff Between Scans

Priority: High

Scope:

- Detect new devices.
- Detect missing devices.
- Detect IP changes.
- Prepare comparison of open ports across runs.
- Print a concise change summary after each scan.

Done when:

- A repeated scan clearly reports what changed since the previous run.
- “New device” is no longer the only tracked change type.
- Known devices that disappear and later respond again are reported as returned devices, not as brand-new devices.

### Phase 4: Host Identity Improvements

Priority: Medium

Scope:

- Add reverse DNS hostname lookup.
- Store hostname per observation, not as permanent device truth.
- Keep hostname resolution optional if it slows scans too much.

Done when:

- Results can show hostname when available.
- Missing reverse DNS does not break scans.

### Phase 5: Clean Port Scanning Logic

Priority: Medium

Scope:

- Remove duplicated or dead code from `port_scan.py`.
- Reduce warnings and rough edges in SYN scanning flow.
- Improve service detection structure.
- Keep console rendering modular and extensible.

Done when:

- `port_scan.py` has cleaner control flow.
- Service detection is separated enough to evolve without turning into a single giant function.
- Output formats can evolve without making the main scan path harder to maintain.

### Phase 6: TLS and Service Probes

Priority: Medium

Scope:

- Add HTTPS/TLS certificate inspection.
- Split probes by protocol where useful.
- Improve HTTP, HTTPS, SSH, and generic TCP identification.

Done when:

- `443/tcp` reports more than a best-effort plaintext banner.
- Open ports have more reliable service labels.

### Phase 7: Reporting and Automation

Priority: Medium

Scope:

- Add machine-readable scan diff output.
- Add CSV or Markdown export.
- Prepare scheduled execution on Synology.
- Later add alerts for new devices or changed ports.

Done when:

- A scheduled run can produce history plus a usable summary of changes.

## Release Plan

### v0.2

Focus:

- CLI overrides
- storage improvements
- scan history
- basic diff

Candidate tasks:

- add `--iface`
- add `--cidr`
- add `last_seen`
- add `scan_runs`
- print scan diff summary

### v0.3

Focus:

- hostname resolution
- report export
- code cleanup around scanning flow

### v0.4

Focus:

- improved service detection
- TLS inspection
- better reporting of open port changes

### v0.5

Focus:

- scheduled execution
- notifications
- richer inventory features

## Immediate Next Tasks

1. Decide whether the next report target should be Markdown export or diff-first CSV/JSON output.
2. Continue reducing responsibility inside `port_scan.py` now that probing moved into a dedicated module.
3. Consider whether hostname and TLS changes should become first-class alert conditions for scheduled runs.
4. Decide whether long-term history should move beyond snapshot tables into richer observation/event modeling.
5. Evaluate a future `network-health-check` mode for untrusted networks such as hotel Wi-Fi, focused on safe checks like client isolation, captive portal behavior, DNS consistency, and TLS anomalies rather than broad discovery.

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
