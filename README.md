# 🔍 Network Scanning Suite

A Python-based suite of network scanning tools, including an ARP scanner for device discovery and a multi-threaded port scanner.

Current milestone: `v1.0.0`

- `network_scan` is a working LAN inventory and change-monitoring tool.
- `network-health-check` is a working safe trust-assessment tool for guest and untrusted networks.
- The current `v1` scope is CLI-first, report-oriented, and intentionally avoids broad active probing of third-party networks.

## ✨ Features

- **Automatic Network Detection**: Automatically finds the default network interface and IP range.
- **Manual Interface and CIDR Overrides**: Allows forcing a specific interface or subnet when auto-detection is not ideal.
- **Device Discovery**: Scans the local network using ARP requests to find active devices.
- **Vendor Information**: Fetches MAC address vendor details for identified devices.
- **Scan History**: Records each ARP scan run in SQLite, including interface, CIDR, status, and device counters.
- **New Device Tracking**: Uses a local SQLite database to track new devices over time.
- **Change Detection**: Compares ARP scan snapshots and reports new devices, returned devices, missing devices, and IP changes since the previous successful scan.
- **Multi-threaded Port Scanning**: Quickly scans devices for open TCP ports.
- **Service & Version Detection**: Identifies services (e.g., HTTP, SSH) running on open ports and attempts to grab their banners.
- **Customizable Port Selection**: Allows specifying ports or port ranges to scan via command-line arguments.
- **Rich Console Output**: Displays results in a clean, color-coded, tabular format.
- **Data Export**: Saves full scan results to a JSON file.
- **Webhook Alerts**: Can POST actionable ARP, port, and health alerts to a webhook endpoint.

## 🛠 Requirements

- Python 3.7+
- Administrative/root privileges to send ARP packets and open raw sockets.

## 📦 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/suminv/scan_local_network.git
    cd scan_local_network
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Optional macOS Wi-Fi backend for nearby SSID/BSSID discovery:**
    ```bash
    pip install -r requirements-macos.txt
    ```
    This enables the `PyObjC/CoreWLAN` backend used by `network-health-check` on modern macOS.

4.  **Run the test suite:**
    ```bash
    python -m unittest discover -s tests -v
    ```

## 🚀 Usage

Helper scripts are provided for convenience. They ensure that the tools are run with the correct Python interpreter from the virtual environment and with the necessary `sudo` privileges.

### Recommended Direct Invocation

The most reliable way to run the tools is to call the virtualenv Python explicitly:

```bash
sudo ./venv/bin/python arp_scanner.py
```

```bash
sudo ./venv/bin/python port_scan.py
```

```bash
./venv/bin/python network_health_check.py
```

### Consistent Progress Indicators

`scan-arp`, `scan-ports`, and `scan-health` use the same compact progress format:

```text
Port scan [████████░░░░░░░░░░] 44% · 4400/9999 ports · 192.168.2.45
```

The indicator is written to `stderr`, so redirected reports and machine-readable `stdout` remain clean. In an interactive terminal it updates in place. In redirected logs, high-frequency counter updates are suppressed while meaningful stage changes and the final completion line are retained. Port scans count ports for a single target and completed devices for a subnet scan; ARP and network-health checks show their current processing stage.

### Consistent Report Style

Interactive reports from all three tools use the same compact section heading:

```text
--- Scan Results ---
```

Decorative closing borders are omitted so adjacent result, change, and alert sections remain easy to scan. Status markers have one meaning throughout the CLI:

- `[OK]` — expected or healthy
- `[~]` — reviewable notice or uncertain condition
- `[!]` — actionable alert or detected change

### Unified Scan Summary

The normal output starts with the same compact summary structure in every tool. Fields that do not apply to the current command are omitted:

```text
--- Scan Summary ---
Target  : 192.168.2.0/24
Duration: 6.9s
Devices : 27 scanned · 20 with open ports
Findings: 31 open ports
Changes : 3 new · 5 closed
Status  : [~] review detected changes
```

`scan-health` uses the same block for interface, network profile, check counts, and the final trust status. A target-only port scan does not show historical changes unless `--show-changes` was requested.

The output modes follow the same scope rules:

| Command or mode | What is shown |
| --- | --- |
| default / `--output grouped` | Complete grouped inventory and complete change details |
| `scan-ports --output table` | Complete current inventory in an adaptive flat table and complete change details |
| `scan-ports --output focus` | Prioritized current hosts and compact change counters; use `grouped` for individual change rows |
| `--alerts-only` | Scan context plus actionable findings only; exit code `2` means action is required |
| `scan-ports -t IP` | Only observations for the requested target; historical changes stay hidden |
| `scan-ports -t IP --show-changes` | Target observations plus explicitly requested history comparison |

An empty scan still prints `Scan Summary`, including in `--alerts-only` mode. This makes redirected and scheduled output self-describing instead of producing a context-free “no alerts” line.

After the summary, reports place actionable context before detailed inventory: changes first, then policy findings, then device or open-port details. ARP output no longer repeats new devices in both a dedicated section and the change report, and counts already present in the summary are not printed again.

Standard runs keep report-save messages hidden. With `--verbose`, generated paths are collected once at the end:

```text
--- Output Files ---
Database: arp_scan_v1.db
JSON    : port_scan_result.json
Markdown: reports/ports.md
```

ARP inventory and `scan-ports --output table` adapt to the current terminal width. Long hostname, vendor, and service-detail values are shortened with `…`. Wide port tables retain all identity columns; narrower layouts prioritize IP, MAC, port, service, and the available detail space instead of wrapping every row across multiple lines.

Color is semantic and optional. Ordinary IP, MAC, vendor, table, and open-port text remains neutral; green, yellow, and red are reserved for `[OK]`, `[~]`, `[!]`, and actual error messages. ANSI color is disabled automatically when output is redirected. Set the standard `NO_COLOR` environment variable to disable it explicitly:

```bash
NO_COLOR=1 ./scan-health --network-profile public
```

### 1. ARP Scanner (`scan-arp`)

This tool discovers all devices on your local network, identifies their MAC address and vendor, stores scan history in SQLite, and reports device-level changes between runs.

Optional reverse-DNS hostname enrichment is available with `--resolve-hostnames`.

**To run a scan:**

```bash
./scan-arp
```

**To force a specific interface or subnet:**

```bash
./scan-arp --iface ovs_eth0
```

```bash
./scan-arp --iface ovs_eth0 --cidr 192.168.2.0/24
```

**To store the database and JSON report in explicit paths:**

```bash
./scan-arp --db-file data/arp_scan.db --json-out data/reports/arp_scan_result.json
```

**To also export the ARP snapshot as CSV:**

```bash
./scan-arp --csv-out data/reports/arp_scan_result.csv
```

**To also export the ARP snapshot and diff as Markdown:**

```bash
./scan-arp --md-out data/reports/arp_scan_result.md
```

**To enrich ARP results with reverse-DNS hostnames:**

```bash
./scan-arp --resolve-hostnames
```

**To print only actionable ARP alerts for cron or systemd runs:**

```bash
./scan-arp --alerts-only
```

With `--alerts-only`, the process exits with:

- `0` when no actionable alerts are detected
- `2` when new, missing, returned, IP-change, or hostname-change alerts are detected

**To send actionable ARP alerts to a webhook:**

```bash
./scan-arp --alerts-only --webhook-url https://example.test/webhook
```

Webhook delivery is attempted only when actionable ARP changes exist. Use `--webhook-timeout` to override the default 10-second timeout.

**Recommended Synology NAS run:**

```bash
sudo ./venv/bin/python arp_scanner.py --iface ovs_eth0 --cidr 192.168.2.0/24 --db-file data/arp_scan.db --json-out data/reports/arp_scan_result.json
```

**What gets stored after each ARP run:**

- device inventory in `devices`
- scan metadata in `scan_runs`
- device snapshots per run in `scan_run_devices`
- full JSON export at the configured `--json-out` path with `devices` and `arp_diff_summary`
- optional CSV export at the configured `--csv-out` path
- optional Markdown export at the configured `--md-out` path

**What the ARP diff summary currently reports:**

- new devices never seen before in the local inventory
- returned devices that were known earlier but absent from the previous successful ARP snapshot
- missing devices since the previous successful ARP scan
- IP address changes by MAC address
- hostname changes when reverse-DNS enrichment is enabled

### Viewing Run History

`scan_runs` is not a separate script. It is a SQLite table that is filled automatically when you run `arp_scanner.py` or `port_scan.py`.

**View all recorded scan runs from the default database:**

```bash
sqlite3 arp_scan_v1.db "SELECT id, scan_type, started_at, finished_at, interface, cidr, status, device_count, new_device_count FROM scan_runs ORDER BY id DESC;"
```

**View only ARP scan runs:**

```bash
sqlite3 arp_scan_v1.db "SELECT id, started_at, finished_at, interface, cidr, status, device_count, new_device_count FROM scan_runs WHERE scan_type = 'arp' ORDER BY id DESC;"
```

**View only port scan runs:**

```bash
sqlite3 arp_scan_v1.db "SELECT id, started_at, finished_at, interface, cidr, status, device_count FROM scan_runs WHERE scan_type = 'port' ORDER BY id DESC;"
```

**If you use a custom database path, query that file instead:**

```bash
sqlite3 data/arp_scan.db "SELECT id, scan_type, started_at, finished_at, interface, cidr, status, device_count, new_device_count FROM scan_runs ORDER BY id DESC;"
```

### 2. Port Scanner (`scan-ports`)

This tool discovers devices and then scans them for open TCP ports and running services.

**To run a scan with default ports (22, 80, 443, 3000, 5000, 8000, 8080, 8443):**

```bash
./scan-ports
```

**To force a specific interface or subnet during discovery:**

```bash
./scan-ports --iface ovs_eth0
```

```bash
./scan-ports --iface ovs_eth0 --cidr 192.168.2.0/24
```

**Recommended Synology NAS run:**

```bash
sudo ./venv/bin/python port_scan.py --iface ovs_eth0 --cidr 192.168.2.0/24 --db-file data/arp_scan.db --json-out data/reports/port_scan_result.json
```

**To save a machine-readable port scan report:**

```bash
./scan-ports --json-out data/reports/port_scan_result.json
```

**To store port-scan history in an explicit SQLite database path:**

```bash
./scan-ports --db-file data/arp_scan.db --json-out data/reports/port_scan_result.json
```

**To also export the port snapshot as CSV:**

```bash
./scan-ports --csv-out data/reports/port_scan_result.csv
```

**To also export the port snapshot and diff as Markdown:**

```bash
./scan-ports --md-out data/reports/port_scan_result.md
```

**To scan a specific IP address, use the `-t` or `--target` flag:**

```bash
./scan-ports -t 192.168.1.101
```

This will skip the network discovery phase and scan only the specified host. You can combine this with the `-p` flag to scan for specific ports on that host:

```bash
./scan-ports -t 192.168.1.101 -p 80,443,22
```

Target scans show only the current service observations by default. To compare a
target with a previous scan of the same IP and the same port set, add
`--show-changes`:

```bash
./scan-ports -t 192.168.1.101 -p 22,80 --show-changes
```

For an open HTTP/HTTPS port, the scanner performs one bounded, unauthenticated
request and reports the status, redirect, server header, content type, and page
title when available. For SSH it records the pre-authentication banner and a
host-key SHA-256 fingerprint. It never attempts passwords or logins.

To inspect one device using the stored profile (MAC/vendor, hostname, IP
history, observed services, and confidence evidence):

```bash
./scan-ports -t 192.168.1.101 --profile
```

The profile view is observation-only: it does not authenticate to SSH or HTTP.

For a first policy baseline, create a JSON file from a full LAN scan:

```bash
./scan-ports --write-baseline data/network_policy.json
```

Review the generated file, then use it on later scans:

```bash
./scan-ports --config data/network_policy.json --alerts-only
```

The policy file may contain known device names, expected ports, expected SSH
host-key fingerprints, and selected HTTP identity fields. Credentials and
passwords are rejected by validation and are never stored or tested.

**To specify custom ports or ranges, use the `-p` or `--ports` flag:**

-   Scan specific ports:
    ```bash
    ./scan-ports -p 80,443,8000,8080
    ```
-   Scan a range of ports:
    ```bash
    ./scan-ports -p 1-1024
    ```

**To switch the console report layout, use `--output`:**

-   Grouped by device:
    ```bash
    ./scan-ports --output grouped
    ```
-   Flat table:
    ```bash
    ./scan-ports --output table
    ```
-   Focused operator view:
    ```bash
    ./scan-ports --output focus
    ```

    This view keeps only change counters. Run the grouped mode when the IP,
    port, and old/new values for every historical change are needed.

**To show setup, database, vendor, and progress diagnostics:**

```bash
./scan-ports --verbose
```

**To enrich port scan results with reverse-DNS hostnames:**

```bash
./scan-ports --resolve-hostnames
```

**To print only actionable port alerts for scheduled runs:**

```bash
./scan-ports --alerts-only
```

With `--alerts-only`, the process exits with:

- `0` when no actionable alerts are detected
- `2` when TLS alerts, new open ports, service/SSH/HTTP changes, policy findings, or TLS metadata changes are detected

For a target scan, historical changes affect this report and its exit code only
when `--show-changes` is also present. Findings from the current target, such as
an expired TLS certificate or a policy violation, remain actionable normally.

**To send actionable port alerts to a webhook:**

```bash
./scan-ports --alerts-only --webhook-url https://example.test/webhook
```

Webhook delivery is attempted only when actionable port findings exist. Use `--webhook-timeout` to override the default 10-second timeout.

**Example Output with Service Detection:**

```
Scanning 192.168.1.0/24 · ports: 22, 80, 443, 3000, 5000, 8000, 8080, 8443
Port scan [██████████████████] 100% · 15/15 devices · completed in 6.2s

--- Scan Summary ---
Target  : 192.168.1.0/24
Duration: 6.2s
Devices : 15 scanned · 7 with open ports
Findings: 11 open ports
Changes : none
Status  : [OK] no actionable findings

--- Port Changes Since Last Scan ---
No port-level changes detected since last scan.

--- Open Ports ---

192.168.1.1  Ubiquiti Networks Inc.  a1:b2:c3:d4:e5:f6
  80/tcp    HTTP    nginx
  443/tcp   HTTPS   HTTP response detected

192.168.1.50  Raspberry Pi Foundation  d1:e2:f3:a4:b5:c6
  22/tcp    SSH     SSH-2.0-OpenSSH_8.2p1
```

**What gets stored after each port run:**

- scan metadata in `scan_runs`
- open-port snapshots in `scan_run_ports`
- full JSON export at the configured `--json-out` path with `devices` and `port_diff_summary`
- optional CSV export at the configured `--csv-out` path
- optional Markdown export at the configured `--md-out` path

**What the port diff summary currently reports:**

- new open ports since the previous successful port scan
- closed ports since the previous successful port scan
- service label changes on the same `(MAC, port)`
- SSH banner or host-key fingerprint changes
- HTTP status/server/title/content-type identity changes

### 3. Network Health Check (`scan-health`)

This tool performs safe network trust checks intended for guest Wi-Fi and other untrusted networks without doing broad host discovery.

It currently checks:

- default gateway identity
- default gateway MAC/vendor fingerprint when available from the local ARP cache
- whether the default gateway exposes common local services such as DNS or web/admin endpoints to the current client
- basic reachability to the default gateway using a short local ping probe
- whether the passive ARP cache already shows other local peers besides the gateway on the current interface
- a client-isolation hint that summarizes whether the current segment appears to expose peer devices to the client
- whether an active Wi-Fi interface is present while the default route is using a different interface
- macOS Wi-Fi interface inventory and best-effort nearby Wi-Fi visibility
- DNS server inventory for the current environment
- DNS resolution sanity for public domains plus an aggregated DNS trust interpretation
- captive portal behavior through common connectivity-check endpoints plus an aggregated captive/interception interpretation
- HTTPS/TLS sanity through certificate-validated probes plus an aggregated HTTPS trust interpretation
- an overall trust explanation that summarizes the current local-segment posture and internet trust path in one short human-readable block

**To run a health check:**

```bash
./scan-health
```

**To tell the tool what kind of network you expect:**

```bash
./scan-health --network-profile home
```

```bash
./scan-health --network-profile guest
```

```bash
./scan-health --network-profile travel
```

```bash
./scan-health --network-profile public
```

Use this when you want the report wording to reflect different expectations. For example, peer visibility and gateway-local web surfaces are often normal on a home LAN, but deserve more attention on guest or travel networks.
`home`, `guest`, `travel`, and `public` are interpreted separately:

- `home`: peer visibility and router administration surfaces can be expected; client isolation is normally not required.
- `guest`: client isolation is expected on a managed guest segment, so visible peers or gateway administration deserve review.
- `travel`: isolation is desirable but must not be assumed on hotel or temporary networks; visible peers are treated as untrusted.
- `public`: isolation is expected on a well-configured shared network, but the local segment remains untrusted even when no peers are currently visible.

The detailed checks expose the normalized profile posture, whether isolation is expected or merely desired, and a profile-specific recommended action. A passive empty ARP cache is never presented as proof that isolation exists.

On macOS, the report includes a Wi-Fi environment section with interface details such as supported PHY modes, channels, and country code. Current-network details are collected from `wdutil` when possible, with a `system_profiler` fallback. The report shows channel/band width, RSSI, noise, security, PHY mode, and an SNR-based quality assessment when macOS exposes those fields.

For nearby Wi-Fi inventory on modern macOS, the tool first tries an optional `PyObjC/CoreWLAN` backend. If macOS returns hidden/incomplete objects without SSID, BSSID, or security data, the report states that nearby analysis is unavailable instead of presenting those objects as usable networks.

**To inspect the current Wi-Fi connection and nearby-analysis status:**

```bash
./scan-health --debug-wifi
```

The compact debug view prioritizes the current connection and suppresses raw backend counters. When complete nearby records are available, the report can compare them with the current channel and identify potential overlap using the reported 2.4/5/6 GHz band and 20/40/80/160/320 MHz channel width.

The Wi-Fi section now also raises risk signals for:

- open or unencrypted visible networks
- weak legacy security such as WEP
- duplicate SSIDs advertised by multiple BSSIDs with mixed security profiles
- very weak nearby signal levels that can correlate with unstable or suspicious guest-network behavior

On macOS, the report also identifies cases where an active Wi-Fi interface is present but the system default route uses another interface such as Ethernet. Direct current-interface evidence is treated more strongly than the lower-confidence `system_profiler` fallback, so ordinary Ethernet + Wi-Fi dual connectivity is not automatically promoted to a hard alert.

The gateway exposure check only inspects the current default gateway and only for a short fixed set of ports such as `53`, `80`, `443`, `8080`, and `8443`. It does not do broad host discovery or sweep the local subnet.
Gateway web/admin surfaces are treated as expected for an explicit `home` profile, reviewable on `guest`, and sensitive on `travel` or `public`. The service marker follows the same context (`expected`, `review`, `sensitive`, or `alert`) instead of labeling every private router page as an alert.

The standard health check now also pings the default gateway briefly. This catches local Wi-Fi or router-link failures where the client is still associated to Wi-Fi but cannot reliably reach the gateway. Intermittent mesh/roaming issues can still be missed by a one-shot run, so use the stability window when the problem comes and goes.

DNS diagnostics compare resolver interface metadata with the current default-route interface. A reachable resolver on another interface is reported as a notice rather than a hard alert because VPN and split-DNS configurations can legitimately produce this layout. Direct public upstream DNS and failed name resolution retain stronger alert semantics.

The overall trust explanation includes both alerts and notices from DNS, captive portal, HTTPS, active-path, and gateway-reachability checks. A notice-only route mismatch or split-DNS condition therefore no longer produces a contradictory “path looks healthy” summary.

#### Connecting to a non-home Wi-Fi network

Use the `public` profile for an unknown network in a cafe, airport, train, or other public place. Use `travel` for hotel or temporary accommodation Wi-Fi, and `guest` for a guest network operated by an organization or a person you know.

Run the full check immediately after connecting:

```bash
./scan-health --network-profile public --output full --debug-wifi
```

If the network opens a sign-in or terms page, complete that process without entering unrelated credentials, then run the same command again. The first result may legitimately report captive-portal behavior; the second result should show a normal Internet and HTTPS path.

Review these parts of the report:

- **Overall trust explanation**: start here for the combined local-network and Internet-path assessment. Treat `suspicious` or `untrusted` as a reason to inspect the detailed findings before using the connection.
- **Wi-Fi environment**: confirm the expected SSID, security mode, signal quality, BSSID, and channel when macOS exposes them. An open network, WEP, or the same SSID advertised with inconsistent security deserves attention. An SSID alone does not prove that an access point is genuine.
- **Gateway and Active path**: confirm that the default route uses the interface you expect. Unexpected Ethernet, VPN, or tunnel routing can change which network is actually carrying traffic.
- **Local peer visibility and Client isolation hint**: visible unrelated peers are more important on `public` and `travel` profiles than at home. Visibility does not by itself prove an attack, but it means the network is not fully isolating clients.
- **DNS servers and DNS trust reasoning**: check the listed nameservers, resolver profile, and resolution issues. Gateway DNS is common on public Wi-Fi. Direct public DNS may be intentional. `dns_route_mismatch` can be normal with a VPN or split DNS, but the other interface should be one you recognize. Failed lookups or public domains resolving only to private addresses require investigation.
- **Captive portal reasoning**: a portal is expected before sign-in. Repeated interception after sign-in is not expected.
- **HTTPS trust reasoning**: certificate-validated HTTPS probes should succeed after portal sign-in. DNS that looks normal does not compensate for TLS or certificate failures.

A reassuring post-login result normally has successful HTTPS probes, normal public-domain resolution, no unexplained route/interface change, and no hard alerts. Notices can still be expected—for example, a VPN resolver on a tunnel interface or visible peers on a poorly isolated hotspot—but they should have an explanation that matches your setup.

If the report shows unexplained HTTPS failures, public domains resolving to private addresses, an unknown DNS/tunnel interface, or persistent captive interception, avoid sensitive activity on that network. Disconnect or use a trusted cellular connection. If you intentionally use a VPN, connect it and run the check again to confirm that the route and DNS findings changed as expected.

For intermittent signal, roaming, or packet-loss problems, add a short stability observation:

```bash
sudo ./scan-health --network-profile public --output full --wifi-stability-seconds 20
```

This health check is diagnostic evidence, not proof that a public network is safe. It does not inspect all traffic or authenticate the operator of the access point.

**To print only actionable health alerts:**

```bash
./scan-health --alerts-only
```

This mode is intended for scheduled runs. It prints compact check/notices/alerts counters, the trust assessment when findings exist, and only the top alert or notice reasons.
Notice-only output is sorted by operational priority so local exposure and path findings appear before lower-priority context, and long notice lists are truncated with a remaining count.

**To use the short operator view:**

```bash
./scan-health --output focus
```

This mode keeps the trust assessment and important context while suppressing routine OK details.
When many notices are present, focus mode shows the highest-priority notices first and points to `--output full` for complete detail.

**To run short Wi-Fi stability diagnostics for mesh or roaming problems:**

```bash
sudo ./scan-health --wifi-stability-seconds 20
```

This adds a short observation window with repeated gateway latency checks and current Wi-Fi sampling, looking for:

- BSSID changes
- weak signal
- packet loss to the gateway
- elevated gateway latency

With `--alerts-only`, the process exits with:

- `0` when no actionable health alerts are detected
- `2` when suspicious gateway path, DNS, captive portal, Wi-Fi, or TLS findings are detected

**To send actionable network health alerts to a webhook:**

```bash
./scan-health --alerts-only --webhook-url https://example.test/webhook
```

Webhook delivery is attempted only when actionable health findings exist. Use `--webhook-timeout` to override the default 10-second timeout.

The standard report now also includes a top-level trust assessment:

- `trusted`
- `suspicious`
- `untrusted`

**To customize DNS probe domains:**

```bash
./scan-health --dns-domain example.com --dns-domain openai.com
```

**To save the report to a specific JSON path:**

```bash
./scan-health --json-out data/reports/network_health_check_result.json
```

**To also export the health report as Markdown:**

```bash
./scan-health --md-out data/reports/network_health_check_result.md
```

**What gets stored after each health run:**

- full JSON export at the configured `--json-out` path with `scan_context`, `health_checks`, `health_summary`, and `trust_assessment`
- optional Markdown export at the configured `--md-out` path

## ⚙️ Configuration

-   **`DB_FILE`**: `"arp_scan_v1.db"` - The filename for the SQLite database.
-   **`JSON_OUTPUT_FILE`**: `"arp_scan_result.json"` - The default JSON report output path.
-   **`VENDOR_DB_CACHE_DAYS`**: `7` - The number of days before the MAC vendor database is automatically updated.
-   **`arp_scanner.py --csv-out`**: Optional CSV snapshot export path.
-   **`arp_scanner.py --md-out`**: Optional Markdown snapshot and diff export path.
-   **`arp_scanner.py --alerts-only`**: Alert-only console output with exit code `2` when actionable device-level changes are detected.
-   **`arp_scanner.py --webhook-url`**: Optional webhook URL for actionable ARP alerts.
-   **`arp_scanner.py --webhook-timeout`**: Webhook timeout in seconds. Defaults to `10`.
-   **`network_health_check.py --json-out`**: Defaults to `"network_health_check_result.json"` in the working directory.
-   **`network_health_check.py --md-out`**: Optional Markdown health report export path.
-   **`network_health_check.py --network-profile`**: Interprets the network as `auto`, `home`, `guest`, `travel`, or `public`. Defaults to `auto`.
-   **`network_health_check.py --alerts-only`**: Compact alert-only console output with exit code `2` when actionable health findings are detected.
-   **`network_health_check.py --output focus`**: Short operator view with trust assessment, compact counters, and key checks only.
-   **`network_health_check.py --webhook-url`**: Optional webhook URL for actionable network health alerts.
-   **`network_health_check.py --webhook-timeout`**: Webhook timeout in seconds. Defaults to `10`.
-   **`port_scan.py --json-out`**: Defaults to `"port_scan_result.json"` in the working directory.
-   **`port_scan.py --db-file`**: Optional SQLite database path for shared scan history.
-   **`port_scan.py --csv-out`**: Optional CSV snapshot export path.
-   **`port_scan.py --md-out`**: Optional Markdown snapshot and diff export path.
-   **`port_scan.py --alerts-only`**: Alert-only console output with exit code `2` when actionable port-level changes are detected.
-   **`port_scan.py --webhook-url`**: Optional webhook URL for actionable port alerts.
-   **`port_scan.py --webhook-timeout`**: Webhook timeout in seconds. Defaults to `10`.
-   **`port_scan.py --output`**: Console output mode. One of `"grouped"`, `"table"`, or `"focus"`.

## 📂 Suggested Data Layout

For a cleaner long-running setup, especially on Synology, keep runtime data outside the code root:

```text
scan_local_network/
  venv/
  arp_scanner.py
  port_scan.py
  data/
    arp_scan.db
    reports/
      arp_scan_result.json
      port_scan_result.json
```

## ⚠️ Notes

-   **Root Privileges**: These tools will not work without `sudo`.
-   **Network Interface**: If you encounter issues, ensure the script is detecting the correct network interface. The automatic detection relies on the default gateway setting.
-   **Synology**: Explicit interface selection such as `--iface ovs_eth0` is the most reliable mode on Synology NAS.

## 📄 License

MIT License
