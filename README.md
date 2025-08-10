# 🔍 Network Scanning Suite

A Python-based suite of network scanning tools, including an ARP scanner for device discovery and a multi-threaded port scanner.

## ✨ Features

- **Automatic Network Detection**: Automatically finds the default network interface and IP range.
- **Device Discovery**: Scans the local network using ARP requests to find active devices.
- **Vendor Information**: Fetches MAC address vendor details for identified devices.
- **New Device Tracking**: Uses a local SQLite database to track new devices over time.
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

## 🚀 Usage

Helper scripts are provided for convenience. They ensure that the tools are run with the correct Python interpreter from the virtual environment and with the necessary `sudo` privileges.

### 1. ARP Scanner (`scan-arp`)

This tool discovers all devices on your local network, identifies their MAC address and vendor, and tracks new devices.

**To run a scan:**

```bash
./scan-arp
```

### 2. Port Scanner (`scan-ports`)

This tool discovers devices and then scans them for open TCP ports and running services.

**To run a scan with default ports (22, 23, 80, 443, 8080):**

```bash
./scan-ports
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

## ⚙️ Configuration

-   **`DB_FILE`**: `"arp_scan_v1.db"` - The filename for the SQLite database.
-   **`VENDOR_DB_CACHE_DAYS`**: `7` - The number of days before the MAC vendor database is automatically updated.

## ⚠️ Notes

-   **Root Privileges**: These tools will not work without `sudo`.
-   **Network Interface**: If you encounter issues, ensure the script is detecting the correct network interface. The automatic detection relies on the default gateway setting.

## 📄 License

MIT License
