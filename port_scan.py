import argparse
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from alert_delivery import build_alert_payload, send_webhook_payload
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
from hostname_lookup import enrich_devices_with_hostnames
from port_reporting import (
    DEFAULT_OUTPUT_FORMAT,
    build_port_csv_rows,
    build_port_observations,
    build_port_result_lines,
    count_open_ports,
    format_device_heading,
    format_port_diff_host,
    format_tls_metadata,
    has_port_alerts,
    get_tls_alert_marker,
    normalize_service_entry,
    print_focus_port_scan_results,
    print_grouped_port_scan_results,
    print_port_alert_summary,
    print_port_diff_summary,
    print_port_scan_results,
    print_port_scan_summary,
    print_table_port_scan_results,
    save_port_scan_results,
)
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
MARKDOWN_OUTPUT_FILE = None
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


def build_parser():
    """Build the CLI parser for the port scanner."""
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
        "--md-out",
        type=str,
        help="Markdown report output path. Disabled unless explicitly set.",
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
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Print only actionable alerts instead of the full port scan report.",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        help="Optional webhook URL that receives port alerts when actionable findings are detected.",
    )
    parser.add_argument(
        "--webhook-timeout",
        type=float,
        default=10,
        help="Webhook timeout in seconds. Defaults to 10.",
    )
    return parser


def parse_args():
    """Parse CLI arguments for the port scanner."""
    return build_parser().parse_args()


def resolve_report_output_paths(args):
    """Resolve JSON/CSV/Markdown output paths from CLI arguments."""
    return {
        "json": args.json_out or JSON_OUTPUT_FILE,
        "csv": args.csv_out,
        "markdown": args.md_out,
    }


def render_port_scan_outcome(args, results, diff_summary):
    """Render scan output and return the appropriate process exit code."""
    if args.alerts_only:
        print_port_alert_summary(results, diff_summary)
        return 2 if has_port_alerts(results, diff_summary) else 0

    print_port_scan_results(results, output_format=args.output)
    print_port_diff_summary(diff_summary)
    return 0


def render_empty_scan_outcome(args, diff_summary):
    """Render the empty-discovery case and return the appropriate process exit code."""
    if args.alerts_only:
        print_port_alert_summary([], diff_summary)
        return 2 if has_port_alerts([], diff_summary) else 0

    print(f"{Fore.YELLOW}No devices found on the network.{Style.RESET_ALL}")
    print_port_diff_summary(diff_summary)
    return 0


def build_port_alert_summary(results, diff_summary):
    """Build a compact port alert count summary for webhook delivery."""
    observations = build_port_observations(results)
    tls_alert_count = sum(
        1
        for row in observations
        if (row.get("tls") or {}).get("certificate_status") in ["expired", "expiring_soon"]
    )
    diff_summary = diff_summary or {}
    return {
        "has_alerts": has_port_alerts(results, diff_summary),
        "tls_alerts": tls_alert_count,
        "new_ports": len(diff_summary.get("new_ports", [])),
        "service_changes": len(diff_summary.get("service_changes", [])),
        "tls_changes": len(diff_summary.get("tls_changes", [])),
    }


def maybe_send_port_webhook(webhook_url, timeout, scan_context, results, diff_summary):
    """Send port scan alert summary to a webhook when actionable findings exist."""
    if not webhook_url or not has_port_alerts(results, diff_summary):
        return False
    payload = build_alert_payload(
        source="port_scan",
        scan_context=scan_context,
        alert_summary=build_port_alert_summary(results, diff_summary),
        alerts={"port_diff_summary": diff_summary},
    )
    return send_webhook_payload(webhook_url, payload, timeout=timeout, label="Port webhook alert")


def main():
    """Main function to run the port scanner."""
    global CSV_OUTPUT_FILE, MARKDOWN_OUTPUT_FILE
    exit_code = 0
    init(autoreset=True)
    args = parse_args()
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
    output_paths = resolve_report_output_paths(args)
    CSV_OUTPUT_FILE = output_paths["csv"]
    MARKDOWN_OUTPUT_FILE = output_paths["markdown"]
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
            diff_summary = build_port_scan_diff(previous_ports, [])
            exit_code = render_empty_scan_outcome(args, diff_summary)
            finalize_scan_run(db_conn, scan_run_id, status="success", device_count=0)
            print(f"\nScan run recorded with id: {scan_run_id}")
            sys.exit(exit_code)

        print(f"Found {len(devices_to_scan)} devices. Now scanning ports and services...")
        results = run_port_scan(devices_to_scan, ports_to_scan)
        save_scan_run_ports(db_conn, scan_run_id, results)
        diff_summary = build_port_scan_diff(previous_ports, flatten_port_results(results))
        exit_code = render_port_scan_outcome(args, results, diff_summary)
        save_port_scan_results(
            results,
            diff_summary,
            output_paths["json"],
            csv_output_file=CSV_OUTPUT_FILE,
            markdown_output_file=MARKDOWN_OUTPUT_FILE,
        )
        maybe_send_port_webhook(
            args.webhook_url,
            args.webhook_timeout,
            scan_context,
            results,
            diff_summary,
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
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
