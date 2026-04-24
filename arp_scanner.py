import argparse
import ipaddress
import os
import sqlite3
import sys
from datetime import datetime

import netifaces
from mac_vendor_lookup import MacLookup
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from tabulate import tabulate

from models import build_device_snapshot, build_port_snapshot
from reporting import build_report_payload, print_change_report, save_json_report

DB_FILE = "arp_scan_v1.db"
JSON_OUTPUT_FILE = "arp_scan_result.json"
SCAN_TYPE_ARP = "arp"
SCAN_TYPE_PORT = "port"
VENDOR_DB_CACHE_DAYS = 7

class LocalMacVendorLookup:
    """Offline fallback that resolves MAC prefixes using Scapy's bundled manuf data."""

    _prefix_map = {}
    _prefix_lengths = []
    _loaded = False

    def __init__(self):
        if not self.__class__._loaded:
            self.__class__._load_data()

    @classmethod
    def _load_data(cls):
        try:
            from scapy.libs import manuf
        except ImportError as exc:
            raise RuntimeError("Failed to import scapy.manuf data for offline vendor lookup") from exc
        prefix_map = {}
        prefix_lengths = set()
        for raw_line in manuf.DATA.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            columns = [col.strip() for col in raw_line.split("\t") if col.strip()]
            if not columns:
                continue
            prefix_token = columns[0]
            vendor = columns[-1]
            prefix_part, bit_length = cls._extract_prefix(prefix_token)
            if not prefix_part or not vendor:
                continue
            prefix_map[(bit_length, prefix_part)] = vendor
            prefix_lengths.add(bit_length)
        cls._prefix_map = prefix_map
        cls._prefix_lengths = sorted(prefix_lengths, reverse=True)
        cls._loaded = True

    @staticmethod
    def _sanitise(mac):
        clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        if not clean:
            raise ValueError("Empty MAC address provided")
        return clean

    @classmethod
    def _extract_prefix(cls, token):
        if "/" in token:
            prefix, bit_str = token.split("/", 1)
            try:
                bit_length = int(bit_str)
            except ValueError:
                return None, None
        else:
            prefix = token
            bit_length = len(cls._sanitise(prefix)) * 4
        hex_prefix = cls._sanitise(prefix)
        hex_length = bit_length // 4
        if not hex_prefix or hex_length == 0:
            return None, None
        return hex_prefix[:hex_length], hex_length

    def lookup(self, mac):
        clean = self._sanitise(mac)
        for length in self._prefix_lengths:
            if len(clean) < length:
                continue
            candidate = clean[:length]
            vendor = self._prefix_map.get((length, candidate))
            if vendor:
                return vendor
        raise KeyError(mac)

def update_vendor_database():
    """Updates the MAC address vendor database if necessary and returns a MacLookup instance."""
    print("\n=== Vendor Database ===")
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        update_marker_file = os.path.join(current_dir, "mac_vendor_update")
        need_update = True
        if os.path.exists(update_marker_file):
            last_update_time = os.path.getmtime(update_marker_file)
            current_time = datetime.now().timestamp()
            days_since_update = (current_time - last_update_time) / (60 * 60 * 24)
            if days_since_update < VENDOR_DB_CACHE_DAYS:
                print(f"Vendor database is up-to-date (last updated {int(days_since_update)} days ago).")
                need_update = False
        mac_lookup = MacLookup()
        cache_path = getattr(mac_lookup, "cache_path", "")
        cache_exists = os.path.exists(cache_path)
        cache_non_empty = False
        if cache_exists:
            try:
                cache_non_empty = os.path.getsize(cache_path) > 0
            except OSError as size_error:
                print(f"Warning: Unable to read vendor cache file: {size_error}", file=sys.stderr)
        if not cache_exists:
            print("Vendor cache file is missing; forcing update.")
        elif not cache_non_empty:
            print("Vendor cache file is empty; forcing update.")
        if not cache_non_empty:
            need_update = True
        if need_update:
            print("Updating vendor database... This may take a few moments...")
            mac_lookup.update_vendors()
            with open(update_marker_file, "w", encoding="utf-8") as f:
                f.write(datetime.now().isoformat())
            print("Vendor database updated successfully!")
        prefixes_loaded = False
        try:
            mac_lookup.load_vendors()
            prefixes_loaded = bool(getattr(mac_lookup.async_lookup, "prefixes", {}))
        except Exception as load_error:
            print(f"Warning: Failed to load vendor database: {load_error}", file=sys.stderr)
        if not prefixes_loaded:
            if not need_update:
                print("Vendor database appears empty; attempting a refresh...")
                try:
                    mac_lookup.update_vendors()
                    mac_lookup.load_vendors()
                    prefixes_loaded = bool(getattr(mac_lookup.async_lookup, "prefixes", {}))
                    with open(update_marker_file, "w", encoding="utf-8") as f:
                        f.write(datetime.now().isoformat())
                    print("Vendor database refreshed successfully!")
                except Exception as refresh_error:
                    print(f"Warning: Failed to refresh vendor database: {refresh_error}", file=sys.stderr)
                    prefixes_loaded = False
        if not prefixes_loaded:
            print("Warning: Vendor database is empty; falling back to offline vendor list.", file=sys.stderr)
            try:
                mac_lookup = LocalMacVendorLookup()
                print("Offline vendor database loaded successfully.")
            except Exception as fallback_error:
                print(f"Warning: Failed to load offline vendor database: {fallback_error}", file=sys.stderr)
        print("======================\n")
        return mac_lookup
    except Exception as e:
        print(f"Warning: Failed to update vendor database: {e}", file=sys.stderr)
        print("======================\n")
        try:
            return LocalMacVendorLookup()
        except Exception:
            return MacLookup()

def get_vendor(mac_address, mac_lookup):
    """Gets vendor information for a given MAC address.\n\n    Args:\n        mac_address (str): The MAC address to look up.\n        mac_lookup (MacLookup): An instance of the MacLookup class.\n\n    Returns:\n        str: The vendor name, or 'Unknown' if not found.\n    """
    try:
        return mac_lookup.lookup(mac_address)
    except KeyError:
        return "Unknown"
    except Exception as e:
        print(f"Warning: An unexpected error occurred during vendor lookup for {mac_address}: {e}", file=sys.stderr)
        return "Error"

def validate_ip_range(ip_range):
    """Validate and normalize an IPv4 CIDR string."""
    try:
        network = ipaddress.IPv4Network(ip_range, strict=False)
    except ValueError as exc:
        raise RuntimeError(f"Invalid IPv4 CIDR range '{ip_range}': {exc}") from exc
    return f"{network.network_address}/{network.prefixlen}"

def get_ip_range_for_interface(interface):
    """Return the IPv4 CIDR range for a specific interface."""
    try:
        iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip = iface_info["addr"]
        netmask = iface_info["netmask"]
        netmask_bits = sum(bin(int(x)).count("1") for x in netmask.split("."))
        ip_range = f"{ip}/{netmask_bits}"
        return validate_ip_range(ip_range)
    except Exception as e:
        raise RuntimeError(f"Failed to detect IP range for interface '{interface}': {e}") from e

def get_default_interface_and_ip_range():
    """Automatically detect the default network interface and IPv4 range."""
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways["default"][netifaces.AF_INET]
        interface = default_gateway[1]
        return interface, get_ip_range_for_interface(interface)
    except Exception as e:
        raise RuntimeError(f"Failed to detect interface or IP range: {e}") from e

def resolve_scan_target(interface_override=None, ip_range_override=None):
    """Resolve which interface and IPv4 CIDR range should be scanned."""
    print("=== Network Setup ===")
    try:
        available_interfaces = set(netifaces.interfaces())
        if interface_override and interface_override not in available_interfaces:
            raise RuntimeError(
                f"Interface '{interface_override}' was not found. Available interfaces: {', '.join(sorted(available_interfaces))}"
            )

        if interface_override:
            interface = interface_override
            ip_range = (
                validate_ip_range(ip_range_override)
                if ip_range_override
                else get_ip_range_for_interface(interface)
            )
        else:
            interface, detected_ip_range = get_default_interface_and_ip_range()
            ip_range = (
                validate_ip_range(ip_range_override)
                if ip_range_override
                else detected_ip_range
            )

        print(f"Interface: {interface}")
        print(f"IP Range: {ip_range}")
        print("====================\n")
        return interface, ip_range
    except Exception:
        print("====================\n")
        raise

def arp_scan(ip_range, interface):
    """Performs an ARP scan on the given IP range.\n\n    Args:\n        ip_range (str): The IP range to scan (e.g., '192.168.1.1/24').\n        interface (str): The network interface to use for the scan.\n\n    Returns:\n        list: A list of dictionaries, where each dictionary represents a device.\n    """
    print("=== Scanning Network ===")
    print("Starting ARP scan...")
    try:
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = srp(packet, iface=interface, timeout=2, verbose=False)
        devices = [{"ip": received.psrc, "mac": received.hwsrc} for _, received in answered]
        print(f"ARP scan completed. Found {len(devices)} devices.")
        print("======================\n")
        return devices
    except Exception as e:
        print(f"Error during ARP scan: {e}", file=sys.stderr)
        print("======================\n")
        return []

def column_exists(conn, table_name, column_name):
    """Check whether a column exists in a SQLite table."""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row[1] == column_name for row in cursor.fetchall())

def ensure_parent_dir(file_path):
    """Create the parent directory for a file path when needed."""
    directory = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(directory, exist_ok=True)

def init_db():
    """Initialize the SQLite database and run lightweight schema migrations."""
    print("=== Database Operations ===")
    print("Initializing database...")
    ensure_parent_dir(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        ip TEXT,
        vendor TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    '''
    )
    if not column_exists(conn, "devices", "last_seen"):
        cursor.execute("ALTER TABLE devices ADD COLUMN last_seen TEXT")
        cursor.execute("UPDATE devices SET last_seen = first_seen WHERE last_seen IS NULL")
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        interface TEXT,
        cidr TEXT,
        status TEXT NOT NULL,
        device_count INTEGER DEFAULT 0,
        new_device_count INTEGER DEFAULT 0
    )
    '''
    )
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS scan_run_devices (
        scan_run_id INTEGER NOT NULL,
        mac TEXT NOT NULL,
        ip TEXT NOT NULL,
        vendor TEXT,
        PRIMARY KEY (scan_run_id, mac),
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
    )
    '''
    )
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS scan_run_ports (
        scan_run_id INTEGER NOT NULL,
        mac TEXT NOT NULL,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        service TEXT,
        PRIMARY KEY (scan_run_id, mac, port),
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
    )
    '''
    )
    conn.commit()
    return conn

def create_scan_run(conn, interface, ip_range, scan_type=SCAN_TYPE_ARP):
    """Create a scan run record and return its identifier."""
    started_at = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scan_runs (scan_type, started_at, interface, cidr, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (scan_type, started_at, interface, ip_range, "running"),
    )
    conn.commit()
    return cursor.lastrowid

def finalize_scan_run(conn, scan_run_id, status, device_count=0, new_device_count=0):
    """Mark a scan run as completed and store high-level counters."""
    finished_at = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE scan_runs
        SET finished_at = ?, status = ?, device_count = ?, new_device_count = ?
        WHERE id = ?
        """,
        (finished_at, status, device_count, new_device_count, scan_run_id),
    )
    conn.commit()

def save_scan_run_devices(conn, scan_run_id, devices):
    """Persist the device snapshot observed during a scan run."""
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT OR REPLACE INTO scan_run_devices (scan_run_id, mac, ip, vendor)
        VALUES (?, ?, ?, ?)
        """,
        [
            (
                scan_run_id,
                device["mac"],
                device["ip"],
                device.get("vendor", "Unknown"),
            )
            for device in devices
        ],
    )
    conn.commit()

def save_scan_run_ports(conn, scan_run_id, devices):
    """Persist open-port observations for a port scan run."""
    rows = []
    for device in devices:
        for port_info in device.get("open_ports", []):
            rows.append(
                (
                    scan_run_id,
                    device["mac"],
                    device["ip"],
                    port_info["port"],
                    port_info.get("service", "Unknown"),
                )
            )
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT OR REPLACE INTO scan_run_ports (scan_run_id, mac, ip, port, service)
        VALUES (?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()

def load_previous_scan_ports(conn, current_scan_run_id):
    """Load the most recent successful port-scan snapshot before the current run."""
    cursor = conn.cursor()
    row = cursor.execute(
        """
        SELECT id
        FROM scan_runs
        WHERE scan_type = ? AND status = 'success' AND id < ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (SCAN_TYPE_PORT, current_scan_run_id),
    ).fetchone()
    if row is None:
        return []
    previous_scan_run_id = row[0]
    rows = cursor.execute(
        """
        SELECT mac, ip, port, service
        FROM scan_run_ports
        WHERE scan_run_id = ?
        ORDER BY ip, mac, port
        """,
        (previous_scan_run_id,),
    ).fetchall()
    return [
        build_port_snapshot(mac=mac, ip=ip, port=port, service=service)
        for mac, ip, port, service in rows
    ]

def load_previous_scan_devices(conn, current_scan_run_id):
    """Load the most recent successful ARP scan snapshot before the current run."""
    cursor = conn.cursor()
    row = cursor.execute(
        """
        SELECT id
        FROM scan_runs
        WHERE scan_type = ? AND status = 'success' AND id < ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (SCAN_TYPE_ARP, current_scan_run_id),
    ).fetchone()
    if row is None:
        return []
    previous_scan_run_id = row[0]
    rows = cursor.execute(
        """
        SELECT mac, ip, vendor
        FROM scan_run_devices
        WHERE scan_run_id = ?
        ORDER BY ip, mac
        """,
        (previous_scan_run_id,),
    ).fetchall()
    return [build_device_snapshot(ip=ip, mac=mac, vendor=vendor) for mac, ip, vendor in rows]

def build_scan_diff(previous_devices, current_devices):
    """Compare two scan snapshots and return changes by device MAC."""
    previous_by_mac = {device["mac"]: device for device in previous_devices}
    current_by_mac = {device["mac"]: device for device in current_devices}

    new_devices = [
        current_by_mac[mac]
        for mac in sorted(current_by_mac.keys() - previous_by_mac.keys())
    ]
    missing_devices = [
        previous_by_mac[mac]
        for mac in sorted(previous_by_mac.keys() - current_by_mac.keys())
    ]
    ip_changes = []
    for mac in sorted(previous_by_mac.keys() & current_by_mac.keys()):
        previous_device = previous_by_mac[mac]
        current_device = current_by_mac[mac]
        if previous_device["ip"] != current_device["ip"]:
            ip_changes.append(
                {
                    "mac": mac,
                    "vendor": current_device.get("vendor", previous_device.get("vendor", "Unknown")),
                    "old_ip": previous_device["ip"],
                    "new_ip": current_device["ip"],
                }
            )

    return {
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "ip_changes": ip_changes,
    }

def build_port_scan_diff(previous_ports, current_ports):
    """Compare two port scan snapshots and return port-level changes."""
    previous_by_key = {(row["mac"], row["port"]): row for row in previous_ports}
    current_by_key = {(row["mac"], row["port"]): row for row in current_ports}

    new_ports = [
        current_by_key[key]
        for key in sorted(current_by_key.keys() - previous_by_key.keys())
    ]
    closed_ports = [
        previous_by_key[key]
        for key in sorted(previous_by_key.keys() - current_by_key.keys())
    ]
    service_changes = []
    for key in sorted(previous_by_key.keys() & current_by_key.keys()):
        previous_port = previous_by_key[key]
        current_port = current_by_key[key]
        if previous_port.get("service") != current_port.get("service"):
            service_changes.append(
                {
                    "mac": current_port["mac"],
                    "ip": current_port["ip"],
                    "port": current_port["port"],
                    "old_service": previous_port.get("service", "Unknown"),
                    "new_service": current_port.get("service", "Unknown"),
                }
            )

    return {
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "service_changes": service_changes,
    }

def load_known_devices(conn):
    """Loads known MAC addresses from the database.\n\n    Args:\n        conn (sqlite3.Connection): The database connection object.\n\n    Returns:\n        set: A set of known MAC addresses.\n    """
    print("Loading known devices...")
    cursor = conn.cursor()
    cursor.execute("SELECT mac FROM devices")
    known_macs = set(row[0] for row in cursor.fetchall())
    print(f"Found {len(known_macs)} devices in database.")
    print("=========================\n")
    return known_macs

def save_new_devices(conn, new_devices):
    """Saves newly discovered devices to the database.\n\n    Args:\n        conn (sqlite3.Connection): The database connection object.\n        new_devices (list): A list of new device dictionaries to save.\n    """
    if not new_devices:
        return
    cursor = conn.cursor()
    for dev in new_devices:
        cursor.execute(
            """
            INSERT INTO devices (mac, ip, vendor, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                dev["mac"],
                dev["ip"],
                dev["vendor"],
                dev["first_seen"],
                dev["last_seen"],
            ),
        )
    conn.commit()

def update_existing_device(conn, mac, ip, vendor, seen_at):
    """Update the current state for an already known device."""
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE devices SET ip = ?, vendor = ?, last_seen = ? WHERE mac = ?",
        (ip, vendor, seen_at, mac),
    )
    conn.commit()

def process_scan_results(devices, mac_lookup, known_macs, conn):
    """Processes scan results, identifies new devices, and updates existing ones.\n\n    Args:\n        devices (list): A list of discovered device dictionaries.\n        mac_lookup (MacLookup): An instance of the MacLookup class.\n        known_macs (set): A set of known MAC addresses from the database.\n        conn (sqlite3.Connection): The database connection object.\n\n    Returns:\n        tuple: A tuple containing table_data, json_output, and a list of new_devices.\n    """
    print("=== Processing Results ===")
    print("Looking up vendor information...")
    table_data = []
    json_output = []
    new_devices = []
    scan_time = datetime.now().isoformat()
    for device in devices:
        mac = device["mac"]
        ip = device["ip"]
        vendor = get_vendor(mac, mac_lookup)
        device_info = build_device_snapshot(ip=ip, mac=mac, vendor=vendor)
        table_data.append([ip, mac, vendor])
        json_output.append(device_info)
        if mac not in known_macs:
            device_info["first_seen"] = scan_time
            device_info["last_seen"] = scan_time
            new_devices.append(device_info)
        else:
            update_existing_device(conn, mac, ip, vendor, scan_time)
    print("Processing complete.")
    print("========================\n")
    return table_data, json_output, new_devices

def save_and_report_results(conn, json_output, new_devices, diff_summary):
    """Save the ARP snapshot, diff summary, and any newly discovered devices."""
    payload = build_report_payload("devices", json_output, "arp_diff_summary", diff_summary)
    save_json_report(JSON_OUTPUT_FILE, payload, label="Results")
    if new_devices:
        save_new_devices(conn, new_devices)
        print(f"Saved {len(new_devices)} new device(s) to the database.")

def print_diff_summary(diff_summary):
    """Print changes between the current and previous ARP scan."""
    if diff_summary is None:
        print_change_report(
            title="=== Changes Since Last Scan ===",
            border="==============================",
            unavailable_message="No previous scan snapshot available.",
        )
        return

    new_devices = diff_summary["new_devices"]
    missing_devices = diff_summary["missing_devices"]
    ip_changes = diff_summary["ip_changes"]
    if not any([new_devices, missing_devices, ip_changes]):
        print_change_report(
            title="=== Changes Since Last Scan ===",
            border="==============================",
            empty_message="No device-level changes detected since last scan.",
        )
        return

    print_change_report(
        title="=== Changes Since Last Scan ===",
        border="==============================",
        summary_line=(
            f"New: {len(new_devices)} | Missing: {len(missing_devices)} | IP changes: {len(ip_changes)}"
        ),
        sections=[
            {
                "title": "New devices",
                "rows": new_devices,
                "formatter": lambda rows: [
                    tabulate(
                        [[device["ip"], device["mac"], device.get("vendor", "Unknown")] for device in rows],
                        headers=["IP", "MAC", "Vendor"],
                    )
                ],
            },
            {
                "title": "Missing devices",
                "rows": missing_devices,
                "formatter": lambda rows: [
                    tabulate(
                        [[device["ip"], device["mac"], device.get("vendor", "Unknown")] for device in rows],
                        headers=["Last IP", "MAC", "Vendor"],
                    )
                ],
            },
            {
                "title": "IP changes",
                "rows": ip_changes,
                "formatter": lambda rows: [
                    tabulate(
                        [
                            [device["old_ip"], device["new_ip"], device["mac"], device.get("vendor", "Unknown")]
                            for device in rows
                        ],
                        headers=["Previous IP", "Current IP", "MAC", "Vendor"],
                    )
                ],
            },
        ],
    )

def print_summary(table_data, new_devices, diff_summary=None):
    """Prints the final summary to the console.\n\n    Args:\n        table_data (list): A list of lists containing device information for the table.\n        new_devices (list): A list of new device dictionaries.\n    """
    if not table_data:
        print("\n=== Scan Results ===")
        print("No devices found.")
        print("====================")
        print_diff_summary(diff_summary)
        return
    print("=== Scan Results ===")
    print(tabulate(table_data, headers=["IP", "MAC", "Vendor"]))
    print(f"\nTotal devices found: {len(table_data)}")
    print("====================\n")
    print("=== New Devices ===")
    if new_devices:
        print(f"\U0001f514 {len(new_devices)} new device(s) detected since last scan:")
        new_devices_table = [[d["ip"], d["mac"], d["vendor"]] for d in new_devices]
        print(tabulate(new_devices_table, headers=["IP", "MAC", "Vendor"]))
    else:
        print("No new devices detected since last scan.")
    print("===================")
    print_diff_summary(diff_summary)

def parse_args():
    """Parse CLI arguments for the ARP scanner."""
    parser = argparse.ArgumentParser(description="ARP Network Scanner")
    parser.add_argument(
        "--iface",
        type=str,
        help="Network interface to use instead of automatic detection.",
    )
    parser.add_argument(
        "--cidr",
        type=str,
        help="IPv4 CIDR range to scan (for example, '192.168.2.0/24').",
    )
    parser.add_argument(
        "--db-file",
        type=str,
        help="SQLite database path. Defaults to arp_scan_v1.db in the working directory.",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        help="JSON report output path. Defaults to arp_scan_result.json in the working directory.",
    )
    return parser.parse_args()

def main():
    """Main function to run the ARP scanner."""
    global DB_FILE, JSON_OUTPUT_FILE
    args = parse_args()
    if os.geteuid() != 0:
        print("Error: This script requires root/administrator privileges to send ARP packets.", file=sys.stderr)
        print("Please run with 'sudo'.", file=sys.stderr)
        sys.exit(1)
    if args.db_file:
        DB_FILE = args.db_file
    if args.json_out:
        JSON_OUTPUT_FILE = args.json_out
    print("ARP Network Scanner starting...")
    mac_lookup = update_vendor_database()
    try:
        interface, ip_range = resolve_scan_target(args.iface, args.cidr)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    db_conn = init_db()
    scan_run_id = create_scan_run(db_conn, interface, ip_range)
    try:
        known_macs = load_known_devices(db_conn)
        previous_devices = load_previous_scan_devices(db_conn, scan_run_id)
        scanned_devices = arp_scan(ip_range, interface)
        if scanned_devices:
            table_data, json_output, new_devices = process_scan_results(
                scanned_devices, mac_lookup, known_macs, db_conn
            )
            save_scan_run_devices(db_conn, scan_run_id, json_output)
            diff_summary = build_scan_diff(previous_devices, json_output)
            save_and_report_results(db_conn, json_output, new_devices, diff_summary)
            print_summary(table_data, new_devices, diff_summary)
            finalize_scan_run(
                db_conn,
                scan_run_id,
                status="success",
                device_count=len(table_data),
                new_device_count=len(new_devices),
            )
        else:
            diff_summary = build_scan_diff(previous_devices, [])
            print_summary([], [], diff_summary)
            finalize_scan_run(db_conn, scan_run_id, status="success")
    except Exception:
        finalize_scan_run(db_conn, scan_run_id, status="failed")
        raise
    finally:
        db_conn.close()
    print(f"\nScan run recorded with id: {scan_run_id}")
    print("ARP Network Scanner completed.")

if __name__ == "__main__":
    main()
