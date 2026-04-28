# 🔍 Network Scanning Suite

A Python-based suite of network scanning tools, including an ARP scanner for device discovery and a multi-threaded port scanner.

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
sudo ./venv/bin/python port_scan.py --iface ovs_eth0 --cidr 192.168.2.0/24
```

**To save a machine-readable port scan report:**

```bash
./scan-ports --json-out data/reports/port_scan_result.json
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
- `2` when TLS alerts, new open ports, service changes, or TLS metadata changes are detected

**To send actionable port alerts to a webhook:**

```bash
./scan-ports --alerts-only --webhook-url https://example.test/webhook
```

Webhook delivery is attempted only when actionable port findings exist. Use `--webhook-timeout` to override the default 10-second timeout.

**Example Output with Service Detection:**

```
--- Port Scanner ---
Using interface: en0
Scanning IP range: 192.168.1.100/24

Discovering devices on the network...
Found 15 devices. Now scanning ports and services...

Scanning Devices: 100%|██████████| 15/15 [00:15<00:00,  1.00it/s]

--- Scan Results ---
15 devices scanned | 7 with open ports | 11 open ports total

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

### 3. Network Health Check (`scan-health`)

This tool performs safe network trust checks intended for guest Wi-Fi and other untrusted networks without doing broad host discovery.

It currently checks:

- default gateway identity
- default gateway MAC/vendor fingerprint when available from the local ARP cache
- whether the default gateway exposes common local services such as DNS or web/admin endpoints to the current client
- whether an active Wi-Fi interface is present while the default route is using a different interface
- macOS Wi-Fi interface inventory and best-effort nearby Wi-Fi visibility
- DNS server inventory for the current environment
- DNS resolution sanity for public domains
- captive portal behavior through common connectivity-check endpoints
- HTTPS/TLS sanity through certificate-validated probes

**To run a health check:**

```bash
./scan-health
```

On macOS, the report now includes a Wi-Fi environment section with interface details such as supported PHY modes, channels, and country code. Current-network details and nearby SSID/BSSID visibility are collected on a best-effort basis because Apple exposes them differently across macOS versions, and some details may require `sudo`.

For nearby Wi-Fi inventory on modern macOS, the tool now first tries an optional `PyObjC/CoreWLAN` backend. If that bridge is not installed or macOS denies access, it falls back to older system mechanisms when available.

The Wi-Fi section now also raises risk signals for:

- open or unencrypted visible networks
- weak legacy security such as WEP
- duplicate SSIDs advertised by multiple BSSIDs with mixed security profiles
- very weak nearby signal levels that can correlate with unstable or suspicious guest-network behavior

On macOS, the report now also raises an alert when an active Wi-Fi interface is present but the system default route is currently using another interface such as Ethernet. This is meant to catch dual-connected situations where a health check might otherwise look healthy because traffic is leaving through the wired path instead of the Wi-Fi path you intended to assess.

The gateway exposure check only inspects the current default gateway and only for a short fixed set of ports such as `53`, `80`, `443`, `8080`, and `8443`. It does not do broad host discovery or sweep the local subnet.

**To print only actionable health alerts:**

```bash
./scan-health --alerts-only
```

**To use the short operator view:**

```bash
./scan-health --output focus
```

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

- full JSON export at the configured `--json-out` path with `scan_context`, `health_checks`, and `health_summary`
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
-   **`network_health_check.py --alerts-only`**: Alert-only console output with exit code `2` when actionable health findings are detected.
-   **`network_health_check.py --webhook-url`**: Optional webhook URL for actionable network health alerts.
-   **`network_health_check.py --webhook-timeout`**: Webhook timeout in seconds. Defaults to `10`.
-   **`port_scan.py --json-out`**: Defaults to `"port_scan_result.json"` in the working directory.
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
