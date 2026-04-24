# 🔍 Network Scanning Suite

A Python-based suite of network scanning tools, including an ARP scanner for device discovery and a multi-threaded port scanner.

## ✨ Features

- **Automatic Network Detection**: Automatically finds the default network interface and IP range.
- **Manual Interface and CIDR Overrides**: Allows forcing a specific interface or subnet when auto-detection is not ideal.
- **Device Discovery**: Scans the local network using ARP requests to find active devices.
- **Vendor Information**: Fetches MAC address vendor details for identified devices.
- **Scan History**: Records each ARP scan run in SQLite, including interface, CIDR, status, and device counters.
- **New Device Tracking**: Uses a local SQLite database to track new devices over time.
- **Change Detection**: Compares ARP scan snapshots and reports new devices, missing devices, and IP changes since the previous successful scan.
- **Multi-threaded Port Scanning**: Quickly scans devices for open TCP ports.
- **Service & Version Detection**: Identifies services (e.g., HTTP, SSH) running on open ports and attempts to grab their banners.
- **Customizable Port Selection**: Allows specifying ports or port ranges to scan via command-line arguments.
- **Rich Console Output**: Displays results in a clean, color-coded, tabular format.
- **Data Export**: Saves full scan results to a JSON file.

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

### 1. ARP Scanner (`scan-arp`)

This tool discovers all devices on your local network, identifies their MAC address and vendor, stores scan history in SQLite, and reports device-level changes between runs.

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

**Recommended Synology NAS run:**

```bash
sudo ./venv/bin/python arp_scanner.py --iface ovs_eth0 --cidr 192.168.2.0/24 --db-file data/arp_scan.db --json-out data/reports/arp_scan_result.json
```

**What gets stored after each ARP run:**

- device inventory in `devices`
- scan metadata in `scan_runs`
- device snapshots per run in `scan_run_devices`
- full JSON export at the configured `--json-out` path with `devices` and `arp_diff_summary`

**What the ARP diff summary currently reports:**

- new devices since the previous successful ARP scan
- missing devices since the previous successful ARP scan
- IP address changes by MAC address

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

**To run a scan with default ports (22, 23, 80, 443, 8080):**

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
    ./scan-ports -p 80,443,8080
    ```
-   Scan a range of ports:
    ```bash
    ./scan-ports -p 1-1024
    ```

**Example Output with Service Detection:**

```
--- Port Scanner ---
Using interface: en0
Scanning IP range: 192.168.1.100/24

Discovering devices on the network...
Found 15 devices. Now scanning ports and services...

Scanning Devices: 100%|██████████| 15/15 [00:15<00:00,  1.00it/s]

--- Scan Results ---
  Device: 192.168.1.1 (Ubiquiti Networks Inc.) (a1:b2:c3:d4:e5:f6)
    Open Ports:
      80/tcp         HTTP (Server: nginx)
      443/tcp        HTTP

  Device: 192.168.1.50 (Raspberry Pi Foundation) (d1:e2:f3:a4:b5:c6)
    Open Ports:
      22/tcp         SSH (SSH-2.0-OpenSSH_8.2p1)
```

**What gets stored after each port run:**

- scan metadata in `scan_runs`
- open-port snapshots in `scan_run_ports`
- full JSON export at the configured `--json-out` path with `devices` and `port_diff_summary`

**What the port diff summary currently reports:**

- new open ports since the previous successful port scan
- closed ports since the previous successful port scan
- service label changes on the same `(MAC, port)`

## ⚙️ Configuration

-   **`DB_FILE`**: `"arp_scan_v1.db"` - The filename for the SQLite database.
-   **`JSON_OUTPUT_FILE`**: `"arp_scan_result.json"` - The default JSON report output path.
-   **`VENDOR_DB_CACHE_DAYS`**: `7` - The number of days before the MAC vendor database is automatically updated.
-   **`port_scan.py --json-out`**: Defaults to `"port_scan_result.json"` in the working directory.

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
