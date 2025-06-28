import netifaces
import sqlite3
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from tabulate import tabulate
import json
from datetime import datetime
import os
import sys

DB_FILE = "arp_scan_v1.db"
VENDOR_DB_CACHE_DAYS = 7

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
        if need_update:
            print("Updating vendor database... This may take a few moments...")
            mac_lookup.update_vendors()
            with open(update_marker_file, "w") as f:
                f.write(datetime.now().isoformat())
            print("Vendor database updated successfully!")
        print("======================\n")
        return mac_lookup
    except Exception as e:
        print(f"Warning: Failed to update vendor database: {e}", file=sys.stderr)
        print("======================\n")
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

def get_default_interface_and_ip_range():
    """Automatically detects the default network interface and IP range.\n\n    Returns:\n        tuple: A tuple containing the interface name and the IP range in CIDR notation.\n    """
    print("=== Network Setup ===")
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways["default"][netifaces.AF_INET]
        interface = default_gateway[1]
        iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip = iface_info["addr"]
        netmask = iface_info["netmask"]
        netmask_bits = sum([bin(int(x)).count("1") for x in netmask.split(".")])
        ip_range = f"{ip}/{netmask_bits}"
        print(f"Interface: {interface}")
        print(f"IP Range: {ip_range}")
        print("====================\n")
        return interface, ip_range
    except Exception as e:
        raise RuntimeError(f"Failed to detect interface or IP range: {e}")

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

def init_db():
    """Initializes the SQLite database and creates the 'devices' table if it doesn't exist.\n\n    Returns:\n        sqlite3.Connection: A connection object to the database.\n    """
    print("=== Database Operations ===")
    print("Initializing database...")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        ip TEXT,
        vendor TEXT,
        first_seen TEXT
    )
    ''')
    conn.commit()
    return conn

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
            "INSERT INTO devices (mac, ip, vendor, first_seen) VALUES (?, ?, ?, ?)",
            (dev["mac"], dev["ip"], dev["vendor"], dev["first_seen"]),
        )
    conn.commit()

def update_existing_device_ip(conn, mac, ip):
    """Updates the IP address for an existing device.\n\n    Args:\n        conn (sqlite3.Connection): The database connection object.\n        mac (str): The MAC address of the device to update.\n        ip (str): The new IP address of the device.\n    """
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET ip = ? WHERE mac = ?", (ip, mac))
    conn.commit()

def process_scan_results(devices, mac_lookup, known_macs, conn):
    """Processes scan results, identifies new devices, and updates existing ones.\n\n    Args:\n        devices (list): A list of discovered device dictionaries.\n        mac_lookup (MacLookup): An instance of the MacLookup class.\n        known_macs (set): A set of known MAC addresses from the database.\n        conn (sqlite3.Connection): The database connection object.\n\n    Returns:\n        tuple: A tuple containing table_data, json_output, and a list of new_devices.\n    """
    print("=== Processing Results ===")
    print("Looking up vendor information...")
    table_data = []
    json_output = []
    new_devices = []
    for device in devices:
        mac = device["mac"]
        ip = device["ip"]
        vendor = get_vendor(mac, mac_lookup)
        device_info = {"ip": ip, "mac": mac, "vendor": vendor}
        table_data.append([ip, mac, vendor])
        json_output.append(device_info)
        if mac not in known_macs:
            device_info["first_seen"] = datetime.now().isoformat()
            new_devices.append(device_info)
        else:
            update_existing_device_ip(conn, mac, ip)
    print("Processing complete.")
    print("========================\n")
    return table_data, json_output, new_devices

def save_and_report_results(conn, json_output, new_devices):
    """Saves results to a JSON file and the database.\n\n    Args:\n        conn (sqlite3.Connection): The database connection object.\n        json_output (list): A list of all discovered device dictionaries.\n        new_devices (list): A list of new device dictionaries.\n    """
    with open("arp_scan_result.json", "w") as f:
        json.dump(json_output, f, indent=4)
    print("Results saved to arp_scan_result.json")
    if new_devices:
        save_new_devices(conn, new_devices)
        print(f"Saved {len(new_devices)} new device(s) to the database.")

def print_summary(table_data, new_devices):
    """Prints the final summary to the console.\n\n    Args:\n        table_data (list): A list of lists containing device information for the table.\n        new_devices (list): A list of new device dictionaries.\n    """
    if not table_data:
        print("\n=== Scan Results ===")
        print("No devices found.")
        print("====================")
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

def main():
    """Main function to run the ARP scanner."""
    print("ARP Network Scanner starting...")
    mac_lookup = update_vendor_database()
    try:
        interface, ip_range = get_default_interface_and_ip_range()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    db_conn = init_db()
    known_macs = load_known_devices(db_conn)
    scanned_devices = arp_scan(ip_range, interface)
    if scanned_devices:
        table_data, json_output, new_devices = process_scan_results(
            scanned_devices, mac_lookup, known_macs, db_conn
        )
        save_and_report_results(db_conn, json_output, new_devices)
        print_summary(table_data, new_devices)
    else:
        print_summary([], [])
    db_conn.close()
    print("\nARP Network Scanner completed.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This script requires root/administrator privileges to send ARP packets.", file=sys.stderr)
        print("Please run with 'sudo'.", file=sys.stderr)
        sys.exit(1)
    main()