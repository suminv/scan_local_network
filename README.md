# 🔍 Network Scanning Suite

A Python-based suite of network scanning tools, including an ARP scanner for device discovery and a multi-threaded port scanner.

## ✨ Features

- **Automatic Network Detection**: Automatically finds the default network interface and IP range.
- **Device Discovery**: Scans the local network using ARP requests to find active devices.
- **Vendor Information**: Fetches MAC address vendor details for identified devices.
- **New Device Tracking**: Uses a local SQLite database to track new devices over time.
- **Multi-threaded Port Scanning**: Quickly scans devices for open TCP ports.
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
    cd network_scan
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

## 🚀 Usage

All scripts must be run with `sudo` because they require elevated privileges for network operations.

### 1. ARP Scanner (`arp_scanner.py`)

This tool discovers all devices on your local network, identifies their MAC address and vendor, and tracks new devices.

**To run a scan:**

```bash
sudo python3 arp_scanner.py
```

**Example Output:**

```
ARP Network Scanner starting...

=== Vendor Database ===
Vendor database is up-to-date (last updated 0 days ago).
======================

=== Network Setup ===
Interface: en0
IP Range: 192.168.1.100/24
====================

=== Database Operations ===
Initializing database...
Loading known devices...
Found 15 devices in database.
=========================

=== Scanning Network ===
Starting ARP scan...
ARP scan completed. Found 15 devices.
======================

=== Scan Results ===
IP               MAC                Vendor
---------------  -----------------  ------------------------
192.168.1.1      a1:b2:c3:d4:e5:f6  Ubiquiti Networks Inc.
192.168.1.10     b1:c2:d3:e4:f5:a6  Apple, Inc.
...

Total devices found: 15
Results saved to arp_scan_result.json

=== New Devices ===
No new devices detected since last scan.
===================

ARP Network Scanner completed.
```

### 2. Port Scanner (`port_scan.py`)

This tool first discovers all devices on the network (using an ARP scan) and then scans them for open TCP ports.

**To run a scan with default ports (22, 23, 80, 443, 8080):**

```bash
sudo python3 port_scan.py
```

**To specify custom ports or ranges, use the `-p` or `--ports` flag:**

-   Scan specific ports:
    ```bash
    sudo python3 port_scan.py -p 80,443,8080
    ```
-   Scan a range of ports:
    ```bash
    sudo python3 port_scan.py -p 1-1024
    ```
-   Scan a combination:
    ```bash
    sudo python3 port_scan.py -p 22,80,1000-2000
    ```

**Example Output:**

```
--- Port Scanner ---
Using interface: en0
Scanning IP range: 192.168.1.100/24

Discovering devices on the network...
Found 15 devices. Now scanning for open ports...

Overall Progress: 100%|██████████| 15/15 [00:10<00:00,  1.48it/s]

--- Scan Results ---
  Device: 192.168.1.1 (Ubiquiti Networks Inc.) (a1:b2:c3:d4:e5:f6)
    Open Ports: 80, 443
  Device: 192.168.1.50 (Raspberry Pi Foundation) (d1:e2:f3:a4:b5:c6)
    Open Ports: 22
```

## ⚙️ Configuration

-   **`DB_FILE`**: `"arp_scan_v1.db"` - The filename for the SQLite database.
-   **`VENDOR_DB_CACHE_DAYS`**: `7` - The number of days before the MAC vendor database is automatically updated.

## ⚠️ Notes

-   **Root Privileges**: These tools will not work without `sudo`.
-   **Network Interface**: If you encounter issues, ensure the script is detecting the correct network interface. The automatic detection relies on the default gateway setting.

## 📄 License

MIT License
