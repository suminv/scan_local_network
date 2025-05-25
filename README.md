# 🔍 ARP Network Scanner

A Python-based ARP scanner that automatically detects your network interface and IP range, scans for active devices, fetches their MAC vendors, tracks new devices over time using a local SQLite database, and saves the results to a JSON file.

## ✨ Features

- Automatic detection of default network interface and subnet
- Local network scanning using ARP requests
- Display of IP address, MAC address, and vendor name for each device
- Showing total number of discovered devices
- Detection and highlighting of **new devices** not seen in previous scans
- Automatic updating of MAC vendor database (with configurable caching interval)
- Saving results to:
  - `arp_scan_result.json` (latest scan result)
  - `arp_scan_v1.db` (persistent SQLite database)
- Clean tabular output using `tabulate`

## 🛠 Requirements

- Python 3.6+
- Admin/root privileges to send ARP packets

## 📦 Installation

```bash
pip install scapy netifaces mac-vendor-lookup tabulate
```

## 🚀 Usage

Run the script with elevated privileges:

```bash
sudo python3 arp_scanner.py
```

## 📋 Example Output

```
ARP Network Scanner starting...

=== Vendor Database ===
Updating vendor database... This may take a few moments...
Vendor database updated successfully!
======================

=== Network Setup ===
Interface: eth0
IP Range: 192.168.1.12/24
====================

=== Database Operations ===
Initializing database...
Loading known devices...
Found 1 devices in database.
=========================

=== Scanning Network ===
Starting ARP scan...
ARP scan completed. Found 3 devices.
======================

=== Processing Results ===
Looking up vendor information...

=== Scan Results ===
IP               MAC                Vendor
------------- ------------------ -------------------------
192.168.1.1   a4:5e:60:xx:xx:xx  Ubiquiti Networks Inc.
192.168.1.20  b8:27:eb:xx:xx:xx  Raspberry Pi Foundation
192.168.1.35  dc:a6:32:xx:xx:xx  Raspberry Pi Trading Ltd

Total devices found: 3
Results saved to arp_scan_result.json

=== New Devices ===
🔔 1 new device(s) detected since last scan:
IP               MAC                Vendor
------------- ------------------ -----------------------
192.168.1.35  dc:a6:32:xx:xx:xx  Raspberry Pi Trading Ltd
====================

ARP Network Scanner completed.
```

## ⚙️ Configuration

- `DB_FILE = "arp_scan_v1.db"` - SQLite database filename
- `VENDOR_DB_CACHE_DAYS = 7` - MAC vendor database cache lifetime in days

## ⚠️ Notes

- Run the script with administrator/root privileges or you will not be able to send ARP packets
- If you receive "No devices found", check your network interface name and connectivity
- The MAC vendor database is automatically updated every 7 days (configurable)

## 📄 License

MIT License
