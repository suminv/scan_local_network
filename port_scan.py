import argparse
import json
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style, init
from models import build_device_snapshot, build_port_snapshot, build_scan_context
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP
from scapy.error import Scapy_Exception
from scapy.sendrecv import sr1, srp
from tqdm import tqdm

from arp_scanner import (
    create_scan_run,
    finalize_scan_run,
    build_port_scan_diff,
    get_vendor,
    init_db,
    load_previous_scan_ports,
    resolve_scan_target,
    save_scan_run_ports,
    SCAN_TYPE_PORT,
    update_vendor_database,
)
from reporting import build_report_payload, print_change_report, save_csv_report, save_json_report
from hostname_lookup import enrich_devices_with_hostnames
from service_detection import (
    build_certificate_validity_status,
    build_service_result,
    extract_certificate_common_name,
    extract_certificate_organization,
    get_current_utc,
    get_plaintext_service_banner,
    get_service_banner,
    get_service_details,
    get_tls_service_details,
    parse_certificate_time,
)

DEFAULT_PORTS = [22, 80, 443, 3000, 5000, 8000, 8080, 8443]
MAX_WORKERS = 20
MIN_PORT = 1
MAX_PORT = 65535
JSON_OUTPUT_FILE = "port_scan_result.json"
CSV_OUTPUT_FILE = None
DEFAULT_OUTPUT_FORMAT = "grouped"
OUTPUT_FORMATS = ["grouped", "table", "focus"]


def arp_scan(ip_range, interface):
    """Performs an ARP scan to discover devices on the network."""
    try:
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = srp(packet, timeout=2, verbose=False, iface=interface)
        return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in answered]
    except Exception as e:
        print(f"{Fore.RED}Error during ARP scan: {e}{Style.RESET_ALL}", file=sys.stderr)
        return []

def scan_single_port(ip, port):
    """Scans a single port on a given IP using a SYN scan.

    Args:
        ip (str): The IP address to scan.
        port (int): The port to scan.

    Returns:
        int: The port number if it's open, otherwise None.
    """
    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            # Send RST to close the connection gracefully
            rst_packet = IP(dst=ip) / TCP(
                dport=port,
                sport=response[TCP].dport,
                seq=response[TCP].ack,
                ack=response[TCP].seq + 1,
                flags="R",
            )
            sr1(rst_packet, timeout=1, verbose=False)
            return port
    except (Scapy_Exception, socket.timeout, OSError):
        # Handle known network-related and Scapy errors explicitly
        return None
    return None


def scan_ports_for_device(device, ports):
    """Scans ports, and for open ones, tries to identify the service."""
    ip = device["ip"]
    open_ports_info = []

    # Step 1: Find open ports quickly using SYN scan
    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS, thread_name_prefix="SYN_Scan"
    ) as executor:
        future_to_port = {
            executor.submit(scan_single_port, ip, port): port for port in ports
        }
        open_ports = []
        for future in as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    # Step 2: For open ports, try to get service banners
    if open_ports:
        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS, thread_name_prefix="Banner_Grab"
        ) as executor:
            future_to_service = {
                executor.submit(get_service_details, ip, port): port
                for port in open_ports
            }
            for future in as_completed(future_to_service):
                port = future_to_service[future]
                try:
                    service_info = future.result()
                except Exception:
                    service_info = build_service_result("Error")
                open_ports_info.append({"port": port, **service_info})

    device["open_ports"] = sorted(open_ports_info, key=lambda x: x["port"])
    return device

def validate_port_number(port):
    """Validate that a TCP port is within the valid numeric range."""
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(
            f"Port {port} is out of range. Valid TCP ports are {MIN_PORT}-{MAX_PORT}."
        )
    return port

def parse_ports(port_string):
    """Parses a comma-separated string of ports and ranges (e.g., '22,80,100-200').

    Args:
        port_string (str): The string of ports to parse.

    Returns:
        list: A sorted list of integers representing the ports.
    """
    ports = set()
    if not port_string:
        return DEFAULT_PORTS
    parts = [part.strip() for part in port_string.split(",")]
    if any(not part for part in parts):
        raise ValueError("Invalid port format. Empty port entries are not allowed.")

    try:
        for part in parts:
            if "-" in part:
                bounds = [bound.strip() for bound in part.split("-")]
                if len(bounds) != 2 or not bounds[0] or not bounds[1]:
                    raise ValueError(
                        f"Invalid port range '{part}'. Use ranges like '100-200'."
                    )
                start = validate_port_number(int(bounds[0]))
                end = validate_port_number(int(bounds[1]))
                if start > end:
                    raise ValueError(
                        f"Invalid port range '{part}'. Range start must be less than or equal to range end."
                    )
                ports.update(range(start, end + 1))
            else:
                ports.add(validate_port_number(int(part)))
    except ValueError as exc:
        raise ValueError(
            f"Invalid port format. {exc}"
        ) from exc
    return sorted(list(ports))

def flatten_port_results(devices):
    """Flatten per-device port results into a comparable snapshot."""
    rows = []
    for device in devices:
        for port_info in device.get("open_ports", []):
            rows.append(
                build_port_snapshot(
                    mac=device["mac"],
                    ip=device["ip"],
                    hostname=device.get("hostname"),
                    port=port_info["port"],
                    service=port_info.get("service", "Unknown"),
                    tls=port_info.get("tls"),
                )
            )
    return rows


def format_tls_metadata(tls_info):
    """Render structured TLS metadata into a concise human-readable string."""
    if not tls_info:
        return "none"
    parts = []
    if tls_info.get("protocol"):
        parts.append(tls_info["protocol"])
    if tls_info.get("common_name"):
        parts.append(f"CN={tls_info['common_name']}")
    if tls_info.get("issuer"):
        parts.append(f"issuer={tls_info['issuer']}")
    if tls_info.get("not_before"):
        parts.append(f"from={tls_info['not_before']}")
    if tls_info.get("not_after"):
        parts.append(f"until={tls_info['not_after']}")
    if tls_info.get("certificate_status"):
        parts.append(f"status={tls_info['certificate_status']}")
    if tls_info.get("cipher"):
        parts.append(tls_info["cipher"])
    if tls_info.get("handshake_error"):
        parts.append(f"error={tls_info['handshake_error']}")
    return ", ".join(parts) if parts else "present"


def get_tls_alert_marker(tls_info):
    """Return a compact visual marker for actionable TLS certificate states."""
    if not tls_info:
        return ""
    status = tls_info.get("certificate_status")
    if status == "expired":
        return "TLS! expired"
    if status == "expiring_soon":
        return "TLS! expiring"
    return ""


def format_port_diff_host(row):
    """Render the host identity for a port diff row."""
    hostname = row.get("hostname")
    if hostname:
        return f"{row['ip']} [{hostname}] ({row['mac']})"
    return f"{row['ip']} ({row['mac']})"

def print_port_diff_summary(diff_summary):
    """Print changes between the current and previous port scan."""
    if diff_summary is None:
        print_change_report(
            title="=== Port Changes Since Last Scan ===",
            border="===================================",
            unavailable_message="No previous port scan snapshot available.",
        )
        return

    new_ports = diff_summary["new_ports"]
    closed_ports = diff_summary["closed_ports"]
    service_changes = diff_summary["service_changes"]
    tls_changes = diff_summary.get("tls_changes", [])
    if not any([new_ports, closed_ports, service_changes, tls_changes]):
        print_change_report(
            title="=== Port Changes Since Last Scan ===",
            border="===================================",
            empty_message="No port-level changes detected since last scan.",
        )
        return

    print_change_report(
        title="=== Port Changes Since Last Scan ===",
        border="===================================",
        summary_line=(
            f"New ports: {len(new_ports)} | Closed ports: {len(closed_ports)} | Service changes: {len(service_changes)} | TLS changes: {len(tls_changes)}"
        ),
        sections=[
            {
                "title": "New open ports",
                "rows": new_ports,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row.get('service', 'Unknown')}"
                    for row in rows
                ],
            },
            {
                "title": "Closed ports",
                "rows": closed_ports,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row.get('service', 'Unknown')}"
                    for row in rows
                ],
            },
            {
                "title": "Service changes",
                "rows": service_changes,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row['old_service']} -> {row['new_service']}"
                    for row in rows
                ],
            },
            {
                "title": "TLS metadata changes",
                "rows": tls_changes,
                "formatter": lambda rows: [
                    (
                        f"  {format_port_diff_host(row)} {row['port']}/tcp "
                        f"{format_tls_metadata(row.get('old_tls'))} -> {format_tls_metadata(row.get('new_tls'))}"
                    )
                    for row in rows
                ],
            },
        ],
    )

def build_port_csv_rows(results):
    """Build CSV rows for port scan snapshot export."""
    rows = []
    for device in results:
        for port_info in device.get("open_ports", []):
            rows.append(
                [
                    device["ip"],
                    device.get("hostname", ""),
                    device["mac"],
                    device.get("vendor", "Unknown"),
                    port_info["port"],
                    port_info.get("service", "Unknown"),
                    json.dumps(port_info.get("tls"), sort_keys=True)
                    if port_info.get("tls") is not None
                    else "",
                ]
            )
    return rows


def save_port_scan_results(results, diff_summary, json_output_file, csv_output_file=None):
    """Save the port scan snapshot and diff summary to JSON/CSV."""
    payload = build_report_payload("devices", results, "port_diff_summary", diff_summary)
    save_json_report(json_output_file, payload, label="Port scan results")
    if csv_output_file:
        save_csv_report(
            csv_output_file,
            ["ip", "hostname", "mac", "vendor", "port", "service", "tls_json"],
            build_port_csv_rows(results),
            label="Port scan CSV report",
        )

def discover_devices_to_scan(args, mac_lookup):
    """Resolve scan context and discover or select devices to scan."""
    scan_context = build_scan_context()
    if args.target:
        target_device = build_device_snapshot(
            ip=args.target,
            mac="00:00:00:00:00:00",
            vendor="N/A",
        )
        if args.resolve_hostnames:
            print("Resolving hostname...")
            enrich_devices_with_hostnames([target_device])
        print(f"Scanning target IP: {Fore.YELLOW}{args.target}{Style.RESET_ALL}")
        scan_context["cidr"] = args.target
        return (
            [target_device],
            scan_context,
        )

    interface, ip_range = resolve_scan_target(args.iface, args.cidr)
    scan_context["interface"] = interface
    scan_context["cidr"] = ip_range
    print(f"Using interface: {Fore.YELLOW}{interface}{Style.RESET_ALL}")
    print(f"Scanning IP range: {Fore.YELLOW}{ip_range}{Style.RESET_ALL}")
    print("\nDiscovering devices on the network...")
    discovered_devices = arp_scan(ip_range, interface)
    if not discovered_devices:
        return [], scan_context

    print("Looking up vendor information...")
    for device in discovered_devices:
        device["vendor"] = get_vendor(device["mac"], mac_lookup)
    if args.resolve_hostnames:
        print("Resolving hostnames...")
        enrich_devices_with_hostnames(discovered_devices)
    return discovered_devices, scan_context

def run_port_scan(devices_to_scan, ports_to_scan):
    """Run port scanning for all selected devices."""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_device = {
            executor.submit(scan_ports_for_device, device, ports_to_scan): device
            for device in devices_to_scan
        }
        for future in tqdm(
            as_completed(future_to_device),
            total=len(devices_to_scan),
            desc="Scanning Devices",
        ):
            results.append(future.result())
    return results

def count_open_ports(results):
    """Count open port observations across all scanned devices."""
    return sum(len(device.get("open_ports", [])) for device in results)


def normalize_service_entry(port, service):
    """Normalize a raw service banner into a display label and detail string."""
    raw_service = (service or "").strip()
    if not raw_service:
        if port == 443:
            return "TLS", "open port, no banner"
        if port in [80, 8080]:
            return "WEB", "open port, no banner"
        return "OPEN", "open port, no banner"

    lowered = raw_service.lower()

    if raw_service.startswith("SSH"):
        details = raw_service[raw_service.find("(") + 1 : -1] if "(" in raw_service and raw_service.endswith(")") else raw_service
        return "SSH", details

    if raw_service.startswith("FTP"):
        details = raw_service[raw_service.find("(") + 1 : -1] if "(" in raw_service and raw_service.endswith(")") else raw_service
        return "FTP", details

    if raw_service.startswith("HTTP"):
        if "(" in raw_service and raw_service.endswith(")"):
            details = raw_service[raw_service.find("(") + 1 : -1]
            if details.lower().startswith("server:"):
                details = details.split(":", 1)[1].strip()
        else:
            details = "HTTP response detected"
        return ("HTTPS" if port == 443 else "HTTP"), details

    if raw_service.startswith("TLS"):
        if "(" in raw_service and raw_service.endswith(")"):
            details = raw_service[raw_service.find("(") + 1 : -1]
            return "TLS", details
        return "TLS", "TLS service detected"

    if lowered == "unknown":
        if port == 443:
            return "TLS", "open port, no banner"
        if port in [80, 8080]:
            return "WEB", "open port, no banner"
        return "OPEN", "open port, no banner"

    if lowered == "error grabbing banner":
        if port == 443:
            return "TLS", "banner grab failed"
        if port in [80, 8080]:
            return "WEB", "banner grab failed"
        return "OPEN", "banner grab failed"

    if lowered.startswith("tls handshake failed"):
        details = raw_service[raw_service.find("(") + 1 : -1] if "(" in raw_service and raw_service.endswith(")") else raw_service
        return "TLS", details

    if port == 443:
        return "TLS", raw_service
    return "OPEN", raw_service


def format_device_heading(device):
    """Build a compact device heading for terminal output."""
    vendor = device.get("vendor", "Unknown")
    mac = device.get("mac", "Unknown")
    hostname = device.get("hostname")
    if hostname:
        return f"{device['ip']}  {hostname}  {vendor}  {mac}"
    return f"{device['ip']}  {vendor}  {mac}"


def build_port_result_lines(results):
    """Build structured display lines for grouped console output."""
    device_lines = []
    for device in sorted(results, key=lambda x: x["ip"]):
        open_ports = device.get("open_ports", [])
        if not open_ports:
            continue
        rows = []
        for port_info in open_ports:
            service_label, details = normalize_service_entry(
                port_info["port"],
                port_info.get("service", "Unknown"),
            )
            alert_marker = get_tls_alert_marker(port_info.get("tls"))
            line = f"  {port_info['port']}/tcp".ljust(12)
            line += service_label.ljust(8)
            detail_parts = []
            if alert_marker:
                detail_parts.append(alert_marker)
            if details:
                detail_parts.append(details)
            if detail_parts:
                line += " | ".join(detail_parts)
            rows.append(line)
        device_lines.append((format_device_heading(device), rows))
    return device_lines


def build_port_observations(results):
    """Flatten results into normalized rows for display-specific renderers."""
    observations = []
    for device in sorted(results, key=lambda x: x["ip"]):
        for port_info in device.get("open_ports", []):
            service_label, details = normalize_service_entry(
                port_info["port"],
                port_info.get("service", "Unknown"),
            )
            observations.append(
                {
                    "ip": device["ip"],
                    "hostname": device.get("hostname"),
                    "vendor": device.get("vendor", "Unknown"),
                    "mac": device.get("mac", "Unknown"),
                    "port": port_info["port"],
                    "service_label": service_label,
                    "details": details,
                    "tls": port_info.get("tls"),
                }
            )
    return observations


def print_port_scan_summary(results):
    """Print the shared top-line summary for all console formats."""
    print(f"\n{Fore.CYAN}--- Scan Results ---{Style.RESET_ALL}")
    open_device_count = sum(1 for device in results if device.get("open_ports"))
    open_port_count = count_open_ports(results)
    print(
        f"{len(results)} devices scanned | {open_device_count} with open ports | {open_port_count} open ports total"
    )


def print_grouped_port_scan_results(results):
    """Print grouped port scan results by device."""
    device_lines = build_port_result_lines(results)
    if not device_lines:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )
        return

    for heading, port_lines in device_lines:
        print(f"\n{Fore.GREEN}{heading}{Style.RESET_ALL}")
        for line in port_lines:
            port_part, service_part = line[:12], line[12:]
            print(f"{port_part}{Fore.YELLOW}{service_part}{Style.RESET_ALL}")


def print_table_port_scan_results(results):
    """Print normalized port scan results in a flat table."""
    observations = build_port_observations(results)
    if not observations:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )
        return

    header = f"{'IP':<15} {'Hostname':<24} {'Vendor':<28} {'MAC':<17} {'Port':<8} {'Service':<8} Details"
    print(f"\n{Fore.GREEN}{header}{Style.RESET_ALL}")
    for row in observations:
        hostname = (row.get("hostname") or "-")[:24]
        vendor = row["vendor"][:28]
        alert_marker = get_tls_alert_marker(row.get("tls"))
        details_parts = []
        if alert_marker:
            details_parts.append(alert_marker)
        if row["details"]:
            details_parts.append(row["details"])
        details = " | ".join(details_parts) if details_parts else "-"
        port_display = f"{row['port']}/tcp"
        line = (
            f"{row['ip']:<15} {hostname:<24} {vendor:<28} {row['mac']:<17} "
            f"{port_display:<8} {row['service_label']:<8} {details}"
        )
        print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")


def _format_focus_host_lines(rows):
    """Format condensed host lines for focus mode sections."""
    lines = []
    by_host = {}
    for row in rows:
        key = (row["ip"], row.get("hostname"), row["vendor"], row["mac"])
        by_host.setdefault(key, []).append(row)

    for (ip, hostname, vendor, mac), host_rows in sorted(by_host.items(), key=lambda item: item[0][0]):
        ports = ", ".join(f"{entry['port']}/{entry['service_label']}" for entry in sorted(host_rows, key=lambda entry: entry["port"]))
        details = "; ".join(
            entry["details"] for entry in sorted(host_rows, key=lambda entry: entry["port"]) if entry["details"]
        )
        suffix = f" | {details}" if details else ""
        hostname_part = f"  {hostname}" if hostname else ""
        lines.append(f"  {ip}{hostname_part}  {vendor}  {mac}  {ports}{suffix}")
    return lines


def print_focus_port_scan_results(results):
    """Print scan results grouped by operator-relevant categories."""
    observations = build_port_observations(results)
    if not observations:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )
        return

    tls_alerts = []
    interesting = []
    web_only = []
    unidentified_web = []

    by_host = {}
    for row in observations:
        key = (row["ip"], row.get("hostname"), row["vendor"], row["mac"])
        by_host.setdefault(key, []).append(row)

    for host_rows in by_host.values():
        service_labels = {row["service_label"] for row in host_rows}
        has_tls_alert = any(
            row.get("tls", {}).get("certificate_status") in ["expired", "expiring_soon"]
            for row in host_rows
            if row.get("tls")
        )
        has_interesting = any(row["port"] not in [80, 443, 8080] or row["service_label"] in ["SSH", "FTP"] for row in host_rows)
        has_unidentified_web = any(
            row["service_label"] in ["WEB", "TLS"] and row["details"] in ["open port, no banner", "banner grab failed"]
            for row in host_rows
        )

        if has_tls_alert:
            tls_alerts.extend(host_rows)
        elif has_interesting:
            interesting.extend(host_rows)
        elif has_unidentified_web:
            unidentified_web.extend(host_rows)
        elif service_labels.issubset({"HTTP", "HTTPS", "WEB", "TLS"}):
            web_only.extend(host_rows)
        else:
            interesting.extend(host_rows)

    sections = [
        ("TLS certificate alerts", tls_alerts),
        ("Interesting hosts", interesting),
        ("Web-only hosts", web_only),
        ("Unidentified web endpoints", unidentified_web),
    ]
    printed_any = False
    for title, rows in sections:
        if not rows:
            continue
        printed_any = True
        print(f"\n{Fore.GREEN}{title}:{Style.RESET_ALL}")
        for line in _format_focus_host_lines(rows):
            print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
    if not printed_any:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )


def print_port_scan_results(results, output_format=DEFAULT_OUTPUT_FORMAT):
    """Print human-readable port scan results."""
    print_port_scan_summary(results)
    if output_format == "table":
        print_table_port_scan_results(results)
        return
    if output_format == "focus":
        print_focus_port_scan_results(results)
        return
    print_grouped_port_scan_results(results)


def main():
    """Main function to run the port scanner."""
    global CSV_OUTPUT_FILE
    init(autoreset=True)
    parser = argparse.ArgumentParser(
        description="Network Port Scanner with Service Detection"
    )
    parser.add_argument(
        "-t", "--target", type=str, help="A specific IP address to scan."
    )
    parser.add_argument(
        "--iface",
        type=str,
        help="Network interface to use instead of automatic detection.",
    )
    parser.add_argument(
        "--cidr",
        type=str,
        help="IPv4 CIDR range to scan during discovery (for example, '192.168.2.0/24').",
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        help="Ports to scan (e.g., '22,80,443' or '1-1024'). Defaults to a dev/self-hosted set: 22,80,443,3000,5000,8000,8080,8443.",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        help="JSON report output path. Defaults to port_scan_result.json in the working directory.",
    )
    parser.add_argument(
        "--csv-out",
        type=str,
        help="CSV report output path. Disabled unless explicitly set.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=DEFAULT_OUTPUT_FORMAT,
        choices=OUTPUT_FORMATS,
        help="Console output format: grouped, table, or focus. Defaults to grouped.",
    )
    parser.add_argument(
        "--resolve-hostnames",
        action="store_true",
        help="Resolve reverse-DNS hostnames for scanned devices.",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        print(
            f"{Fore.RED}Error: This script requires root/administrator privileges.{Style.RESET_ALL}",
            file=sys.stderr,
        )
        print(f"{Fore.RED}Please run with 'sudo'.{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    try:
        ports_to_scan = parse_ports(args.ports)
    except ValueError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    json_output_file = args.json_out or JSON_OUTPUT_FILE
    CSV_OUTPUT_FILE = args.csv_out
    print(f"{Fore.CYAN}--- Port Scanner ---{Style.RESET_ALL}")
    mac_lookup = update_vendor_database()
    db_conn = init_db()
    try:
        try:
            devices_to_scan, scan_context = discover_devices_to_scan(args, mac_lookup)
        except RuntimeError as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)

        scan_run_id = create_scan_run(
            db_conn,
            scan_context["interface"],
            scan_context["cidr"],
            scan_type=SCAN_TYPE_PORT,
        )
        previous_ports = load_previous_scan_ports(db_conn, scan_run_id)
        if not devices_to_scan:
            print(f"{Fore.YELLOW}No devices found on the network.{Style.RESET_ALL}")
            print_port_diff_summary(build_port_scan_diff(previous_ports, []))
            finalize_scan_run(db_conn, scan_run_id, status="success", device_count=0)
            print(f"\nScan run recorded with id: {scan_run_id}")
            return

        print(f"Found {len(devices_to_scan)} devices. Now scanning ports and services...")
        results = run_port_scan(devices_to_scan, ports_to_scan)
        print_port_scan_results(results, output_format=args.output)
        save_scan_run_ports(db_conn, scan_run_id, results)
        diff_summary = build_port_scan_diff(previous_ports, flatten_port_results(results))
        print_port_diff_summary(diff_summary)
        save_port_scan_results(
            results,
            diff_summary,
            json_output_file,
            csv_output_file=CSV_OUTPUT_FILE,
        )
        finalize_scan_run(
            db_conn,
            scan_run_id,
            status="success",
            device_count=len(devices_to_scan),
        )
        print(f"\nScan run recorded with id: {scan_run_id}")
    except Exception:
        if "scan_run_id" in locals():
            finalize_scan_run(db_conn, scan_run_id, status="failed")
        raise
    finally:
        db_conn.close()


if __name__ == "__main__":
    main()
