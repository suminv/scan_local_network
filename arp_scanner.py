import argparse
from contextlib import nullcontext, redirect_stdout
from io import StringIO
import ipaddress
import json
import os
import sqlite3
import sys
from datetime import datetime

import netifaces
from mac_vendor_lookup import MacLookup
from scapy.layers.l2 import ARP, Ether, getmacbyip
from scapy.sendrecv import srp
from tabulate import tabulate

from alert_delivery import build_alert_payload, send_webhook_payload
from hostname_lookup import enrich_devices_with_hostnames
from models import build_device_snapshot, build_port_snapshot
from reporting import (
    build_report_payload,
    print_change_report,
    render_markdown_table,
    save_csv_report,
    save_json_report,
    save_markdown_report,
)

DB_FILE = "arp_scan_v1.db"
JSON_OUTPUT_FILE = "arp_scan_result.json"
CSV_OUTPUT_FILE = None
MARKDOWN_OUTPUT_FILE = None
SCAN_TYPE_ARP = "arp"
SCAN_TYPE_PORT = "port"
MISSING_DEVICE_CONFIRMATION_SCANS = 3
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


def lookup_mac_for_ip(ip):
    """Resolve a local IPv4 neighbour MAC with one ARP lookup when possible."""
    try:
        return getmacbyip(ip)
    except Exception:
        return None

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
    if not column_exists(conn, "scan_runs", "target"):
        cursor.execute("ALTER TABLE scan_runs ADD COLUMN target TEXT")
    if not column_exists(conn, "scan_runs", "ports_json"):
        cursor.execute("ALTER TABLE scan_runs ADD COLUMN ports_json TEXT")
    if not column_exists(conn, "scan_runs", "hostname_resolution"):
        cursor.execute(
            "ALTER TABLE scan_runs ADD COLUMN hostname_resolution INTEGER NOT NULL DEFAULT 0"
        )
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS scan_run_devices (
        scan_run_id INTEGER NOT NULL,
        mac TEXT NOT NULL,
        ip TEXT NOT NULL,
        vendor TEXT,
        hostname TEXT,
        PRIMARY KEY (scan_run_id, mac),
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
    )
    '''
    )
    if not column_exists(conn, "scan_run_devices", "hostname"):
        cursor.execute("ALTER TABLE scan_run_devices ADD COLUMN hostname TEXT")
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS scan_run_ports (
        scan_run_id INTEGER NOT NULL,
        mac TEXT NOT NULL,
        ip TEXT NOT NULL,
        hostname TEXT,
        port INTEGER NOT NULL,
        service TEXT,
        tls_json TEXT,
        http_json TEXT,
        ssh_json TEXT,
        PRIMARY KEY (scan_run_id, mac, port),
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
    )
    '''
    )
    if not column_exists(conn, "scan_run_ports", "hostname"):
        cursor.execute("ALTER TABLE scan_run_ports ADD COLUMN hostname TEXT")
    if not column_exists(conn, "scan_run_ports", "tls_json"):
        cursor.execute("ALTER TABLE scan_run_ports ADD COLUMN tls_json TEXT")
    if not column_exists(conn, "scan_run_ports", "http_json"):
        cursor.execute("ALTER TABLE scan_run_ports ADD COLUMN http_json TEXT")
    if not column_exists(conn, "scan_run_ports", "ssh_json"):
        cursor.execute("ALTER TABLE scan_run_ports ADD COLUMN ssh_json TEXT")
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS device_profiles (
        identity_key TEXT PRIMARY KEY,
        identity_type TEXT NOT NULL,
        mac TEXT,
        current_ip TEXT NOT NULL,
        vendor TEXT,
        hostname TEXT,
        user_name TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        device_hint TEXT NOT NULL DEFAULT 'unknown',
        hint_confidence TEXT NOT NULL DEFAULT 'low',
        hint_evidence_json TEXT,
        latest_services_json TEXT,
        last_scan_run_id INTEGER,
        FOREIGN KEY (last_scan_run_id) REFERENCES scan_runs(id)
    )
    '''
    )
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS device_profile_ips (
        identity_key TEXT NOT NULL,
        ip TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (identity_key, ip),
        FOREIGN KEY (identity_key) REFERENCES device_profiles(identity_key)
    )
    '''
    )
    cursor.execute(
        '''
    CREATE TABLE IF NOT EXISTS device_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_run_id INTEGER NOT NULL,
        identity_key TEXT,
        event_type TEXT NOT NULL,
        ip TEXT,
        port INTEGER,
        old_value_json TEXT,
        new_value_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
    )
    '''
    )
    conn.commit()
    return conn

def create_scan_run(
    conn,
    interface,
    ip_range,
    scan_type=SCAN_TYPE_ARP,
    *,
    target=None,
    ports=None,
    resolve_hostnames=False,
):
    """Create a scan run record and return its identifier."""
    started_at = datetime.now().isoformat()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scan_runs (
            scan_type, started_at, interface, cidr, target, ports_json,
            hostname_resolution, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_type,
            started_at,
            interface,
            ip_range,
            target,
            json.dumps(sorted(ports)) if ports is not None else None,
            int(resolve_hostnames),
            "running",
        ),
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


def build_profile_identity(device):
    """Return a stable LAN identity, falling back to IP for target-only scans."""
    mac = (device.get("mac") or "").lower()
    if mac and mac != "00:00:00:00:00:00":
        return f"mac:{mac}", "mac"
    return f"ip:{device['ip']}", "ip"


def infer_device_hint(device):
    """Return a conservative device classification and the observed evidence."""
    ports = {item.get("port") for item in device.get("open_ports", [])}
    services = " ".join(
        item.get("service", "") for item in device.get("open_ports", [])
    ).lower()
    vendor_name = (device.get("vendor") or "").strip()
    vendor = vendor_name.lower()
    if "enphase" in vendor:
        return "Enphase Energy device", "medium", ["MAC vendor: Enphase Energy"]
    if "synology" in vendor:
        return "Synology-like", "medium", ["MAC vendor: Synology"]
    if "hewlett" in vendor or "hp" in vendor:
        return "printer-like", "low", ["MAC vendor: HP/Hewlett-Packard"]
    if ports.intersection({5000, 5001}) or "synology" in services:
        return "Synology-like", "medium", ["DSM-style management port or banner"]
    if ports.intersection({515, 631, 9100}):
        return "printer-like", "medium", ["common printing service port"]
    if ports.intersection({53, 67, 68}):
        return "router-like", "low", ["network infrastructure service port"]
    if 22 in ports or "openssh" in services:
        return "Linux-like", "low", ["SSH service observed"]
    if vendor_name and vendor not in {"unknown", "n/a", "error"}:
        return f"{vendor_name} device", "medium", [f"MAC vendor: {vendor_name}"]
    return "unknown", "low", []


def upsert_device_profiles(conn, devices, scan_run_id=None):
    """Merge ARP or port observations into persistent device profiles."""
    now = datetime.now().isoformat()
    cursor = conn.cursor()
    profiles = []
    for device in devices:
        identity_key, identity_type = build_profile_identity(device)
        services = device.get("open_ports")
        hint, confidence, evidence = infer_device_hint(device)
        cursor.execute(
            """
            INSERT INTO device_profiles (
                identity_key, identity_type, mac, current_ip, vendor, hostname,
                first_seen, last_seen, device_hint, hint_confidence,
                hint_evidence_json, latest_services_json, last_scan_run_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(identity_key) DO UPDATE SET
                current_ip = excluded.current_ip,
                mac = COALESCE(excluded.mac, device_profiles.mac),
                vendor = COALESCE(excluded.vendor, device_profiles.vendor),
                hostname = COALESCE(excluded.hostname, device_profiles.hostname),
                last_seen = excluded.last_seen,
                device_hint = CASE WHEN excluded.latest_services_json IS NOT NULL
                    THEN excluded.device_hint ELSE device_profiles.device_hint END,
                hint_confidence = CASE WHEN excluded.latest_services_json IS NOT NULL
                    THEN excluded.hint_confidence ELSE device_profiles.hint_confidence END,
                hint_evidence_json = CASE WHEN excluded.latest_services_json IS NOT NULL
                    THEN excluded.hint_evidence_json ELSE device_profiles.hint_evidence_json END,
                latest_services_json = COALESCE(
                    excluded.latest_services_json, device_profiles.latest_services_json
                ),
                last_scan_run_id = COALESCE(excluded.last_scan_run_id, device_profiles.last_scan_run_id)
            """,
            (
                identity_key,
                identity_type,
                device.get("mac") if identity_type == "mac" else None,
                device["ip"],
                device.get("vendor"),
                device.get("hostname"),
                now,
                now,
                hint,
                confidence,
                json.dumps(evidence),
                json.dumps(services, sort_keys=True) if services is not None else None,
                scan_run_id,
            ),
        )
        cursor.execute(
            """
            INSERT INTO device_profile_ips (identity_key, ip, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(identity_key, ip) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (identity_key, device["ip"], now, now),
        )
        profiles.append(
            {
                "identity_key": identity_key,
                "identity_type": identity_type,
                "ip": device["ip"],
                "device_hint": hint,
                "hint_confidence": confidence,
                "hint_evidence": evidence,
            }
        )
    conn.commit()
    return profiles


def get_device_profile_by_ip(conn, ip):
    """Load the best known profile for an IP, including its observed IP history."""
    row = conn.execute(
        """
        SELECT p.identity_key, p.identity_type, p.mac, p.current_ip, p.vendor,
               p.hostname, p.user_name, p.first_seen, p.last_seen,
               p.device_hint, p.hint_confidence, p.hint_evidence_json,
               p.latest_services_json
        FROM device_profiles AS p
        LEFT JOIN device_profile_ips AS history ON history.identity_key = p.identity_key
        WHERE p.current_ip = ? OR history.ip = ?
        ORDER BY CASE p.identity_type WHEN 'mac' THEN 0 ELSE 1 END, p.last_seen DESC
        LIMIT 1
        """,
        (ip, ip),
    ).fetchone()
    if row is None:
        return None
    (
        identity_key,
        identity_type,
        mac,
        current_ip,
        vendor,
        hostname,
        user_name,
        first_seen,
        last_seen,
        device_hint,
        hint_confidence,
        evidence_json,
        services_json,
    ) = row
    ip_history = [
        value[0]
        for value in conn.execute(
            "SELECT ip FROM device_profile_ips WHERE identity_key = ? ORDER BY last_seen DESC",
            (identity_key,),
        ).fetchall()
    ]
    return {
        "identity_key": identity_key,
        "identity_type": identity_type,
        "mac": mac,
        "ip": current_ip,
        "vendor": vendor,
        "hostname": hostname,
        "user_name": user_name,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "device_hint": device_hint,
        "hint_confidence": hint_confidence,
        "hint_evidence": json.loads(evidence_json) if evidence_json else [],
        "ip_history": ip_history,
        "services": json.loads(services_json) if services_json else [],
    }


def save_device_events(conn, scan_run_id, diff_summary, scan_type):
    """Persist normalized, scope-compatible change events from a scan diff."""
    event_rows = []
    now = datetime.now().isoformat()
    if scan_type == SCAN_TYPE_ARP:
        event_map = {
            "new_devices": "device_first_seen",
            "returned_devices": "device_returned",
            "missing_devices": "device_missing",
        }
        for key, event_type in event_map.items():
            for device in diff_summary.get(key, []):
                identity_key, _ = build_profile_identity(device)
                event_rows.append((identity_key, event_type, device.get("ip"), None, None, device))
        for change in diff_summary.get("ip_changes", []):
            event_rows.append((f"mac:{change['mac'].lower()}", "ip_changed", change.get("new_ip"), None, {"ip": change.get("old_ip")}, {"ip": change.get("new_ip")}))
    else:
        event_map = {"new_ports": "port_opened", "closed_ports": "port_closed"}
        for key, event_type in event_map.items():
            for observation in diff_summary.get(key, []):
                identity_key, _ = build_profile_identity(observation)
                event_rows.append((identity_key, event_type, observation.get("ip"), observation.get("port"), None, observation))
        for change in diff_summary.get("service_changes", []):
            identity_key, _ = build_profile_identity(change)
            event_rows.append((identity_key, "service_changed", change.get("ip"), change.get("port"), {"service": change.get("old_service")}, {"service": change.get("new_service")}))
        for change in diff_summary.get("tls_changes", []):
            identity_key, _ = build_profile_identity(change)
            event_rows.append((identity_key, "tls_changed", change.get("ip"), change.get("port"), change.get("old_tls"), change.get("new_tls")))
        for change in diff_summary.get("ssh_changes", []):
            identity_key, _ = build_profile_identity(change)
            event_rows.append((identity_key, "ssh_key_changed", change.get("ip"), change.get("port"), change.get("old_ssh"), change.get("new_ssh")))
        for change in diff_summary.get("http_changes", []):
            identity_key, _ = build_profile_identity(change)
            event_rows.append((identity_key, "http_changed", change.get("ip"), change.get("port"), change.get("old_http"), change.get("new_http")))
    conn.executemany(
        """
        INSERT INTO device_events (
            scan_run_id, identity_key, event_type, ip, port, old_value_json,
            new_value_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                scan_run_id,
                identity_key,
                event_type,
                ip,
                port,
                json.dumps(old_value, sort_keys=True) if old_value is not None else None,
                json.dumps(new_value, sort_keys=True) if new_value is not None else None,
                now,
            )
            for identity_key, event_type, ip, port, old_value, new_value in event_rows
        ],
    )
    conn.commit()
    return len(event_rows)


def confirm_missing_devices(conn, current_scan_run_id, diff_summary):
    """Keep missing devices only after consecutive absent scans in the same scope."""
    missing_devices = diff_summary.get("missing_devices", [])
    if not missing_devices:
        return diff_summary
    cursor = conn.cursor()
    current_scope = cursor.execute(
        "SELECT interface, cidr FROM scan_runs WHERE id = ?",
        (current_scan_run_id,),
    ).fetchone()
    if current_scope is None:
        return diff_summary
    interface, cidr = current_scope
    prior_runs = cursor.execute(
        """
        SELECT id FROM scan_runs
        WHERE scan_type = ? AND status = 'success' AND id < ?
          AND interface IS ? AND cidr IS ?
        ORDER BY id DESC
        """,
        (SCAN_TYPE_ARP, current_scan_run_id, interface, cidr),
    ).fetchall()
    confirmed = []
    for device in missing_devices:
        consecutive_absences = 1  # The current scan is the first absence.
        for (run_id,) in prior_runs:
            seen = cursor.execute(
                "SELECT 1 FROM scan_run_devices WHERE scan_run_id = ? AND mac = ?",
                (run_id, device["mac"]),
            ).fetchone()
            if seen:
                break
            consecutive_absences += 1
        if consecutive_absences >= MISSING_DEVICE_CONFIRMATION_SCANS:
            confirmed.append(device)
    filtered = dict(diff_summary)
    filtered["missing_devices"] = confirmed
    return filtered

def save_scan_run_devices(conn, scan_run_id, devices):
    """Persist the device snapshot observed during a scan run."""
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT OR REPLACE INTO scan_run_devices (scan_run_id, mac, ip, vendor, hostname)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                scan_run_id,
                device["mac"],
                device["ip"],
                device.get("vendor", "Unknown"),
                device.get("hostname"),
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
                    device.get("hostname"),
                    port_info["port"],
                    port_info.get("service", "Unknown"),
                    (
                        json.dumps(port_info.get("tls"), sort_keys=True)
                        if port_info.get("tls") is not None
                        else None
                    ),
                    (
                        json.dumps(port_info.get("http"), sort_keys=True)
                        if port_info.get("http") is not None
                        else None
                    ),
                    (
                        json.dumps(port_info.get("ssh"), sort_keys=True)
                        if port_info.get("ssh") is not None
                        else None
                    ),
                )
            )
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT OR REPLACE INTO scan_run_ports (
            scan_run_id, mac, ip, hostname, port, service, tls_json, http_json, ssh_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()

def load_previous_scan_ports(conn, current_scan_run_id):
    """Load the previous port snapshot only when its scan scope is identical."""
    cursor = conn.cursor()
    row = cursor.execute(
        """
        SELECT previous.id
        FROM scan_runs AS current
        JOIN scan_runs AS previous
          ON previous.scan_type = current.scan_type
         AND previous.interface IS current.interface
         AND previous.cidr IS current.cidr
         AND previous.target IS current.target
         AND previous.ports_json IS current.ports_json
        WHERE current.id = ?
          AND previous.status = 'success'
          AND previous.id < current.id
        ORDER BY previous.id DESC
        LIMIT 1
        """,
        (current_scan_run_id,),
    ).fetchone()
    if row is None:
        return []
    previous_scan_run_id = row[0]
    rows = cursor.execute(
        """
        SELECT mac, ip, hostname, port, service, tls_json, http_json, ssh_json
        FROM scan_run_ports
        WHERE scan_run_id = ?
        ORDER BY ip, mac, port
        """,
        (previous_scan_run_id,),
    ).fetchall()
    return [
        build_port_snapshot(
            mac=mac,
            ip=ip,
            hostname=hostname,
            port=port,
            service=service,
            tls=json.loads(tls_json) if tls_json else None,
            http=json.loads(http_json) if http_json else None,
            ssh=json.loads(ssh_json) if ssh_json else None,
        )
        for mac, ip, hostname, port, service, tls_json, http_json, ssh_json in rows
    ]

def load_previous_scan_devices(conn, current_scan_run_id):
    """Load the previous ARP snapshot only from the same interface and CIDR."""
    cursor = conn.cursor()
    row = cursor.execute(
        """
        SELECT previous.id, previous.hostname_resolution
        FROM scan_runs AS current
        JOIN scan_runs AS previous
          ON previous.scan_type = current.scan_type
         AND previous.interface IS current.interface
         AND previous.cidr IS current.cidr
        WHERE current.id = ?
          AND previous.status = 'success'
          AND previous.id < current.id
        ORDER BY previous.id DESC
        LIMIT 1
        """,
        (current_scan_run_id,),
    ).fetchone()
    if row is None:
        return []
    previous_scan_run_id, _previous_hostname_resolution = row
    rows = cursor.execute(
        """
        SELECT mac, ip, vendor, hostname
        FROM scan_run_devices
        WHERE scan_run_id = ?
        ORDER BY ip, mac
        """,
        (previous_scan_run_id,),
    ).fetchall()
    return [
        build_device_snapshot(ip=ip, mac=mac, vendor=vendor, hostname=hostname)
        for mac, ip, vendor, hostname in rows
    ]


def previous_scan_collected_hostnames(conn, current_scan_run_id):
    """Return whether the compatible previous ARP scan collected hostnames."""
    cursor = conn.cursor()
    row = cursor.execute(
        """
        SELECT previous.hostname_resolution
        FROM scan_runs AS current
        JOIN scan_runs AS previous
          ON previous.scan_type = current.scan_type
         AND previous.interface IS current.interface
         AND previous.cidr IS current.cidr
        WHERE current.id = ?
          AND previous.status = 'success'
          AND previous.id < current.id
        ORDER BY previous.id DESC
        LIMIT 1
        """,
        (current_scan_run_id,),
    ).fetchone()
    return bool(row[0]) if row else False

def build_scan_diff(
    previous_devices,
    current_devices,
    known_macs=None,
    *,
    compare_hostnames=True,
):
    """Compare two scan snapshots and return changes by device MAC."""
    known_macs = known_macs or set()
    previous_by_mac = {device["mac"]: device for device in previous_devices}
    current_by_mac = {device["mac"]: device for device in current_devices}

    new_devices = []
    returned_devices = []
    for mac in sorted(current_by_mac.keys() - previous_by_mac.keys()):
        device = current_by_mac[mac]
        if mac in known_macs:
            returned_devices.append(device)
        else:
            new_devices.append(device)
    missing_devices = [
        previous_by_mac[mac]
        for mac in sorted(previous_by_mac.keys() - current_by_mac.keys())
    ]
    ip_changes = []
    hostname_changes = []
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
        if compare_hostnames and previous_device.get("hostname") != current_device.get("hostname"):
            hostname_changes.append(
                {
                    "mac": mac,
                    "ip": current_device["ip"],
                    "vendor": current_device.get("vendor", previous_device.get("vendor", "Unknown")),
                    "old_hostname": previous_device.get("hostname"),
                    "new_hostname": current_device.get("hostname"),
                }
            )

    return {
        "new_devices": new_devices,
        "returned_devices": returned_devices,
        "missing_devices": missing_devices,
        "ip_changes": ip_changes,
        "hostname_changes": hostname_changes,
    }

def build_port_scan_diff(previous_ports, current_ports, observed_macs=None):
    """Compare two port scan snapshots and return port-level changes."""
    previous_by_key = {(row["mac"], row["port"]): row for row in previous_ports}
    current_by_key = {(row["mac"], row["port"]): row for row in current_ports}
    observed_macs = set(observed_macs) if observed_macs is not None else None

    new_ports = [
        current_by_key[key]
        for key in sorted(current_by_key.keys() - previous_by_key.keys())
    ]
    closed_ports = [
        previous_by_key[key]
        for key in sorted(previous_by_key.keys() - current_by_key.keys())
        if observed_macs is None or key[0] in observed_macs
    ]
    service_changes = []
    tls_changes = []
    ssh_changes = []
    http_changes = []
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
        if previous_port.get("tls") != current_port.get("tls"):
            tls_changes.append(
                {
                    "mac": current_port["mac"],
                    "ip": current_port["ip"],
                    "port": current_port["port"],
                    "old_tls": previous_port.get("tls"),
                    "new_tls": current_port.get("tls"),
                }
            )
        if previous_port.get("ssh") != current_port.get("ssh"):
            ssh_changes.append(
                {
                    "mac": current_port["mac"],
                    "ip": current_port["ip"],
                    "port": current_port["port"],
                    "old_ssh": previous_port.get("ssh"),
                    "new_ssh": current_port.get("ssh"),
                }
            )
        if previous_port.get("http") != current_port.get("http"):
            http_changes.append(
                {
                    "mac": current_port["mac"],
                    "ip": current_port["ip"],
                    "port": current_port["port"],
                    "old_http": previous_port.get("http"),
                    "new_http": current_port.get("http"),
                }
            )

    return {
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "service_changes": service_changes,
        "tls_changes": tls_changes,
        "ssh_changes": ssh_changes,
        "http_changes": http_changes,
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

def process_scan_results(devices, mac_lookup, known_macs, conn, resolve_hostnames=False):
    """Processes scan results, identifies new devices, and updates existing ones.\n\n    Args:\n        devices (list): A list of discovered device dictionaries.\n        mac_lookup (MacLookup): An instance of the MacLookup class.\n        known_macs (set): A set of known MAC addresses from the database.\n        conn (sqlite3.Connection): The database connection object.\n\n    Returns:\n        tuple: A tuple containing table_data, json_output, and a list of new_devices.\n    """
    print("=== Processing Results ===")
    print("Looking up vendor information...")
    if resolve_hostnames:
        print("Resolving hostnames...")
        enrich_devices_with_hostnames(devices)
    table_data = []
    json_output = []
    new_devices = []
    scan_time = datetime.now().isoformat()
    for device in devices:
        mac = device["mac"]
        ip = device["ip"]
        vendor = get_vendor(mac, mac_lookup)
        hostname = device.get("hostname")
        device_info = build_device_snapshot(ip=ip, mac=mac, vendor=vendor, hostname=hostname)
        table_data.append([ip, hostname or "-", mac, vendor])
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

def build_arp_csv_rows(devices):
    """Build CSV rows for ARP snapshot export."""
    return [
        [
            device["ip"],
            device.get("hostname", ""),
            device["mac"],
            device.get("vendor", "Unknown"),
            device.get("first_seen", ""),
            device.get("last_seen", ""),
        ]
        for device in devices
    ]


def build_arp_markdown_report(devices, diff_summary):
    """Build a Markdown report for ARP scan output."""
    lines = [
        "# ARP Scan Report",
        "",
        f"Devices found: **{len(devices)}**",
        "",
    ]

    if devices:
        lines.extend(
            [
                "## Devices",
                "",
                render_markdown_table(
                    ["IP", "Hostname", "MAC", "Vendor"],
                    [
                        [
                            device["ip"],
                            device.get("hostname", "-") or "-",
                            device["mac"],
                            device.get("vendor", "Unknown"),
                        ]
                        for device in devices
                    ],
                ),
                "",
            ]
        )

    lines.extend(["## Changes Since Last Scan", ""])
    if diff_summary is None:
        lines.extend(["No previous scan snapshot available.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            f"- New devices: `{len(diff_summary['new_devices'])}`",
            f"- Returned devices: `{len(diff_summary['returned_devices'])}`",
            f"- Missing devices: `{len(diff_summary['missing_devices'])}`",
            f"- IP changes: `{len(diff_summary['ip_changes'])}`",
            f"- Hostname changes: `{len(diff_summary.get('hostname_changes', []))}`",
            "",
        ]
    )

    section_specs = [
        (
            "New devices",
            diff_summary["new_devices"],
            ["IP", "Hostname", "MAC", "Vendor"],
            lambda device: [
                device["ip"],
                device.get("hostname", "-") or "-",
                device["mac"],
                device.get("vendor", "Unknown"),
            ],
        ),
        (
            "Returned devices",
            diff_summary["returned_devices"],
            ["IP", "Hostname", "MAC", "Vendor"],
            lambda device: [
                device["ip"],
                device.get("hostname", "-") or "-",
                device["mac"],
                device.get("vendor", "Unknown"),
            ],
        ),
        (
            "Missing devices",
            diff_summary["missing_devices"],
            ["Last IP", "Hostname", "MAC", "Vendor"],
            lambda device: [
                device["ip"],
                device.get("hostname", "-") or "-",
                device["mac"],
                device.get("vendor", "Unknown"),
            ],
        ),
        (
            "IP changes",
            diff_summary["ip_changes"],
            ["Previous IP", "Current IP", "MAC", "Vendor"],
            lambda device: [
                device["old_ip"],
                device["new_ip"],
                device["mac"],
                device.get("vendor", "Unknown"),
            ],
        ),
        (
            "Hostname changes",
            diff_summary.get("hostname_changes", []),
            ["IP", "MAC", "Old Hostname", "New Hostname"],
            lambda device: [
                device["ip"],
                device["mac"],
                device.get("old_hostname") or "-",
                device.get("new_hostname") or "-",
            ],
        ),
    ]
    for title, rows, headers, row_builder in section_specs:
        if not rows:
            continue
        lines.extend(
            [
                f"### {title}",
                "",
                render_markdown_table(headers, [row_builder(row) for row in rows]),
                "",
            ]
        )

    return "\n".join(lines)


def save_and_report_results(
    conn,
    json_output,
    new_devices,
    diff_summary,
    profiles=None,
    csv_output_file=None,
    markdown_output_file=None,
):
    """Save the ARP snapshot, diff summary, and any newly discovered devices."""
    payload = build_report_payload("devices", json_output, "arp_diff_summary", diff_summary)
    if profiles is not None:
        payload["device_profiles"] = profiles
    save_json_report(JSON_OUTPUT_FILE, payload, label="Results")
    if csv_output_file:
        save_csv_report(
            csv_output_file,
            ["ip", "hostname", "mac", "vendor", "first_seen", "last_seen"],
            build_arp_csv_rows(json_output),
            label="ARP CSV report",
        )
    if markdown_output_file:
        save_markdown_report(
            markdown_output_file,
            build_arp_markdown_report(json_output, diff_summary),
            label="ARP Markdown report",
        )
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
    returned_devices = diff_summary["returned_devices"]
    missing_devices = diff_summary["missing_devices"]
    ip_changes = diff_summary["ip_changes"]
    hostname_changes = diff_summary.get("hostname_changes", [])
    if not any([new_devices, returned_devices, missing_devices, ip_changes, hostname_changes]):
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
            " | ".join(
                [
                    f"New: {len(new_devices)}",
                    f"Returned: {len(returned_devices)}",
                    f"Missing: {len(missing_devices)}",
                    f"IP changes: {len(ip_changes)}",
                    f"Hostname changes: {len(hostname_changes)}",
                ]
            )
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
                "title": "Returned devices",
                "rows": returned_devices,
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
            {
                "title": "Hostname changes",
                "rows": hostname_changes,
                "formatter": lambda rows: [
                    tabulate(
                        [
                            [
                                device["ip"],
                                device.get("old_hostname") or "-",
                                device.get("new_hostname") or "-",
                                device["mac"],
                                device.get("vendor", "Unknown"),
                            ]
                            for device in rows
                        ],
                        headers=["IP", "Previous Hostname", "Current Hostname", "MAC", "Vendor"],
                    )
                ],
            },
        ],
    )

def print_alert_summary(diff_summary):
    """Print only actionable ARP/device-level alerts."""
    if diff_summary is None:
        print_change_report(
            title="=== Alerts ===",
            border="=============",
            unavailable_message="No previous scan snapshot available.",
        )
        return

    new_devices = diff_summary["new_devices"]
    returned_devices = diff_summary["returned_devices"]
    missing_devices = diff_summary["missing_devices"]
    ip_changes = diff_summary["ip_changes"]
    hostname_changes = diff_summary.get("hostname_changes", [])
    if not any([new_devices, returned_devices, missing_devices, ip_changes, hostname_changes]):
        print_change_report(
            title="=== Alerts ===",
            border="=============",
            empty_message="No actionable alerts detected.",
        )
        return

    print_change_report(
        title="=== Alerts ===",
        border="=============",
        summary_line=(
            " | ".join(
                [
                    f"New: {len(new_devices)}",
                    f"Returned: {len(returned_devices)}",
                    f"Missing: {len(missing_devices)}",
                    f"IP changes: {len(ip_changes)}",
                    f"Hostname changes: {len(hostname_changes)}",
                ]
            )
        ),
        sections=[
            {
                "title": "New devices",
                "rows": new_devices,
                "formatter": lambda rows: [
                    tabulate(
                        [[device["ip"], device.get("hostname", "-"), device["mac"], device.get("vendor", "Unknown")] for device in rows],
                        headers=["IP", "Hostname", "MAC", "Vendor"],
                    )
                ],
            },
            {
                "title": "Returned devices",
                "rows": returned_devices,
                "formatter": lambda rows: [
                    tabulate(
                        [[device["ip"], device.get("hostname", "-"), device["mac"], device.get("vendor", "Unknown")] for device in rows],
                        headers=["IP", "Hostname", "MAC", "Vendor"],
                    )
                ],
            },
            {
                "title": "Missing devices",
                "rows": missing_devices,
                "formatter": lambda rows: [
                    tabulate(
                        [[device["ip"], device.get("hostname", "-"), device["mac"], device.get("vendor", "Unknown")] for device in rows],
                        headers=["Last IP", "Last Hostname", "MAC", "Vendor"],
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
            {
                "title": "Hostname changes",
                "rows": hostname_changes,
                "formatter": lambda rows: [
                    tabulate(
                        [
                            [
                                device["ip"],
                                device.get("old_hostname") or "-",
                                device.get("new_hostname") or "-",
                                device["mac"],
                                device.get("vendor", "Unknown"),
                            ]
                            for device in rows
                        ],
                        headers=["IP", "Previous Hostname", "Current Hostname", "MAC", "Vendor"],
                    )
                ],
            },
        ],
    )


def has_alerts(diff_summary):
    """Return True when the diff contains actionable ARP/device alerts."""
    if diff_summary is None:
        return False
    return any(
        [
            diff_summary.get("new_devices", []),
            diff_summary.get("returned_devices", []),
            diff_summary.get("missing_devices", []),
            diff_summary.get("ip_changes", []),
            diff_summary.get("hostname_changes", []),
        ]
    )


def build_arp_alert_summary(diff_summary):
    """Build a compact ARP alert count summary for webhook delivery."""
    if diff_summary is None:
        return {
            "has_alerts": False,
            "new_devices": 0,
            "returned_devices": 0,
            "missing_devices": 0,
            "ip_changes": 0,
            "hostname_changes": 0,
        }
    return {
        "has_alerts": has_alerts(diff_summary),
        "new_devices": len(diff_summary.get("new_devices", [])),
        "returned_devices": len(diff_summary.get("returned_devices", [])),
        "missing_devices": len(diff_summary.get("missing_devices", [])),
        "ip_changes": len(diff_summary.get("ip_changes", [])),
        "hostname_changes": len(diff_summary.get("hostname_changes", [])),
    }


def maybe_send_arp_webhook(webhook_url, timeout, interface, cidr, diff_summary):
    """Send ARP alert summary to a webhook when actionable findings exist."""
    if not webhook_url or not has_alerts(diff_summary):
        return False
    payload = build_alert_payload(
        source="arp_scanner",
        scan_context={"interface": interface, "cidr": cidr},
        alert_summary=build_arp_alert_summary(diff_summary),
        alerts=diff_summary,
    )
    return send_webhook_payload(webhook_url, payload, timeout=timeout, label="ARP webhook alert")

def print_summary(table_data, new_devices, diff_summary=None):
    """Prints the final summary to the console.\n\n    Args:\n        table_data (list): A list of lists containing device information for the table.\n        new_devices (list): A list of new device dictionaries.\n    """
    if not table_data:
        print("\n=== Scan Results ===")
        print("No devices found.")
        print("====================")
        print_diff_summary(diff_summary)
        return
    print("=== Scan Results ===")
    print(tabulate(table_data, headers=["IP", "Hostname", "MAC", "Vendor"]))
    print(f"\nTotal devices found: {len(table_data)}")
    print("====================\n")
    print("=== New Devices ===")
    if new_devices:
        print(f"\U0001f514 {len(new_devices)} new device(s) detected since last scan:")
        new_devices_table = [[d["ip"], d.get("hostname", "-"), d["mac"], d["vendor"]] for d in new_devices]
        print(tabulate(new_devices_table, headers=["IP", "Hostname", "MAC", "Vendor"]))
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
    parser.add_argument(
        "--csv-out",
        type=str,
        help="CSV report output path. Disabled unless explicitly set.",
    )
    parser.add_argument(
        "--md-out",
        type=str,
        help="Markdown report output path. Disabled unless explicitly set.",
    )
    parser.add_argument(
        "--resolve-hostnames",
        action="store_true",
        help="Resolve reverse-DNS hostnames for discovered devices.",
    )
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Print only actionable alerts instead of the full ARP snapshot table.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show setup, database, vendor lookup, and storage details.",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        help="Optional webhook URL that receives ARP alerts when actionable changes are detected.",
    )
    parser.add_argument(
        "--webhook-timeout",
        type=float,
        default=10,
        help="Webhook timeout in seconds. Defaults to 10.",
    )
    return parser.parse_args()

def main():
    """Main function to run the ARP scanner."""
    global DB_FILE, JSON_OUTPUT_FILE, CSV_OUTPUT_FILE, MARKDOWN_OUTPUT_FILE
    exit_code = 0
    args = parse_args()
    if os.geteuid() != 0:
        print("Error: This script requires root/administrator privileges to send ARP packets.", file=sys.stderr)
        print("Please run with 'sudo'.", file=sys.stderr)
        sys.exit(1)
    if args.db_file:
        DB_FILE = args.db_file
    if args.json_out:
        JSON_OUTPUT_FILE = args.json_out
    if args.csv_out:
        CSV_OUTPUT_FILE = args.csv_out
    if args.md_out:
        MARKDOWN_OUTPUT_FILE = args.md_out
    if args.verbose:
        print("ARP Network Scanner starting...")
    quiet_output = nullcontext() if args.verbose else redirect_stdout(StringIO())
    with quiet_output:
        mac_lookup = update_vendor_database()
    try:
        with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
            interface, ip_range = resolve_scan_target(args.iface, args.cidr)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
        db_conn = init_db()
    scan_run_id = create_scan_run(
        db_conn,
        interface,
        ip_range,
        resolve_hostnames=args.resolve_hostnames,
    )
    try:
        with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
            known_macs = load_known_devices(db_conn)
        previous_devices = load_previous_scan_devices(db_conn, scan_run_id)
        previous_collected_hostnames = previous_scan_collected_hostnames(
            db_conn, scan_run_id
        )
        print(f"Scanning {ip_range}")
        with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
            scanned_devices = arp_scan(ip_range, interface)
        if scanned_devices:
            with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
                table_data, json_output, new_devices = process_scan_results(
                    scanned_devices, mac_lookup, known_macs, db_conn, resolve_hostnames=args.resolve_hostnames
                )
            save_scan_run_devices(db_conn, scan_run_id, json_output)
            profiles = upsert_device_profiles(db_conn, json_output, scan_run_id)
            diff_summary = build_scan_diff(
                previous_devices,
                json_output,
                known_macs,
                compare_hostnames=(
                    args.resolve_hostnames and previous_collected_hostnames
                ),
            )
            diff_summary = confirm_missing_devices(db_conn, scan_run_id, diff_summary)
            save_device_events(db_conn, scan_run_id, diff_summary, SCAN_TYPE_ARP)
            with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
                save_and_report_results(
                    db_conn,
                    json_output,
                new_devices,
                diff_summary,
                profiles=profiles,
                    csv_output_file=CSV_OUTPUT_FILE,
                    markdown_output_file=MARKDOWN_OUTPUT_FILE,
                )
            if args.alerts_only:
                print_alert_summary(diff_summary)
                if has_alerts(diff_summary):
                    exit_code = 2
            else:
                print_summary(table_data, new_devices, diff_summary)
            maybe_send_arp_webhook(
                args.webhook_url,
                args.webhook_timeout,
                interface,
                ip_range,
                diff_summary,
            )
            finalize_scan_run(
                db_conn,
                scan_run_id,
                status="success",
                device_count=len(table_data),
                new_device_count=len(new_devices),
            )
            if args.verbose:
                print(f"\nScan run recorded with id: {scan_run_id}")
        else:
            diff_summary = build_scan_diff(
                previous_devices,
                [],
                known_macs,
                compare_hostnames=(
                    args.resolve_hostnames and previous_collected_hostnames
                ),
            )
            diff_summary = confirm_missing_devices(db_conn, scan_run_id, diff_summary)
            save_device_events(db_conn, scan_run_id, diff_summary, SCAN_TYPE_ARP)
            if args.alerts_only:
                print_alert_summary(diff_summary)
                if has_alerts(diff_summary):
                    exit_code = 2
            else:
                print_summary([], [], diff_summary)
            maybe_send_arp_webhook(
                args.webhook_url,
                args.webhook_timeout,
                interface,
                ip_range,
                diff_summary,
            )
            finalize_scan_run(db_conn, scan_run_id, status="success")
            if args.verbose:
                print(f"\nScan run recorded with id: {scan_run_id}")
    except Exception:
        finalize_scan_run(db_conn, scan_run_id, status="failed")
        raise
    finally:
        db_conn.close()
    if args.verbose:
        print("ARP Network Scanner completed.")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
