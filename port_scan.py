import argparse
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
from reporting import build_report_payload, save_json_report
from reporting import print_change_report

DEFAULT_PORTS = [22, 23, 80, 443, 8080]
MAX_WORKERS = 20
MIN_PORT = 1
MAX_PORT = 65535
JSON_OUTPUT_FILE = "port_scan_result.json"
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


def get_service_banner(ip, port):
    """Tries to grab a service banner from an open port by connecting and receiving data."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))

            # For common web ports, send a simple HTTP request to elicit a response
            if port in [80, 8080, 443]:
                s.sendall(b"GET / HTTP/1.0\nHost: %b\n\n" % ip.encode())

            banner = s.recv(1024)
            banner_str = banner.decode("utf-8", errors="ignore").strip()

            if not banner_str:
                return "Unknown"

            # Basic service identification from banner
            if "SSH" in banner_str:
                return f"SSH ({banner_str.splitlines()[0]})"
            if "FTP" in banner_str.splitlines()[0]:
                return f"FTP ({banner_str.splitlines()[0]})"
            if "HTTP" in banner_str:
                server_line = next(
                    (
                        line
                        for line in banner_str.splitlines()
                        if line.lower().startswith("server:")
                    ),
                    None,
                )
                if server_line:
                    return f"HTTP ({server_line.strip()})"
                return "HTTP"

            # Return first line of banner if not identified
            return banner_str.splitlines()[0]

    except (socket.timeout, ConnectionRefusedError):
        # Timeout or connection refused likely means the port is not talkative or closed
        return "Unknown"
    except Exception:
        # Other errors during banner grabbing
        return "Error grabbing banner"


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
                executor.submit(get_service_banner, ip, port): port
                for port in open_ports
            }
            for future in as_completed(future_to_service):
                port = future_to_service[future]
                try:
                    service = future.result()
                except Exception:
                    service = "Error"
                open_ports_info.append({"port": port, "service": service})

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
                    port=port_info["port"],
                    service=port_info.get("service", "Unknown"),
                )
            )
    return rows

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
    if not any([new_ports, closed_ports, service_changes]):
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
            f"New ports: {len(new_ports)} | Closed ports: {len(closed_ports)} | Service changes: {len(service_changes)}"
        ),
        sections=[
            {
                "title": "New open ports",
                "rows": new_ports,
                "formatter": lambda rows: [
                    f"  {row['ip']} ({row['mac']}) {row['port']}/tcp {row.get('service', 'Unknown')}"
                    for row in rows
                ],
            },
            {
                "title": "Closed ports",
                "rows": closed_ports,
                "formatter": lambda rows: [
                    f"  {row['ip']} ({row['mac']}) {row['port']}/tcp {row.get('service', 'Unknown')}"
                    for row in rows
                ],
            },
            {
                "title": "Service changes",
                "rows": service_changes,
                "formatter": lambda rows: [
                    f"  {row['ip']} ({row['mac']}) {row['port']}/tcp {row['old_service']} -> {row['new_service']}"
                    for row in rows
                ],
            },
        ],
    )

def save_port_scan_results(results, diff_summary, json_output_file):
    """Save the port scan snapshot and diff summary to JSON."""
    payload = build_report_payload("devices", results, "port_diff_summary", diff_summary)
    save_json_report(json_output_file, payload, label="Port scan results")

def discover_devices_to_scan(args, mac_lookup):
    """Resolve scan context and discover or select devices to scan."""
    scan_context = build_scan_context()
    if args.target:
        print(f"Scanning target IP: {Fore.YELLOW}{args.target}{Style.RESET_ALL}")
        scan_context["cidr"] = args.target
        return (
            [build_device_snapshot(ip=args.target, mac="00:00:00:00:00:00", vendor="N/A")],
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

def print_port_scan_results(results):
    """Print human-readable port scan results."""
    print(f"\n{Fore.CYAN}--- Scan Results ---{Style.RESET_ALL}")
    found_any_ports = False
    for device in sorted(results, key=lambda x: x["ip"]):
        if device["open_ports"]:
            found_any_ports = True
            vendor_str = f"({device.get('vendor', 'Unknown')})"
            print(
                f"  {Fore.GREEN}Device:{Style.RESET_ALL} {device['ip']} {Fore.CYAN}{vendor_str}{Style.RESET_ALL} ({device['mac']})"
            )
            print(f"    {Fore.GREEN}Open Ports:{Style.RESET_ALL}")
            table_data = []
            for port_info in device["open_ports"]:
                port = port_info["port"]
                service = port_info["service"]
                table_data.append([f"      {port}/tcp", service])
            for row in table_data:
                print(f"{row[0]:<15} {Fore.YELLOW}{row[1]}{Style.RESET_ALL}")
    if not found_any_ports:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )


def main():
    """Main function to run the port scanner."""
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
        help="Ports to scan (e.g., '22,80,443' or '1-1024'). Defaults to scanning popular ports.",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        help="JSON report output path. Defaults to port_scan_result.json in the working directory.",
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
        print_port_scan_results(results)
        save_scan_run_ports(db_conn, scan_run_id, results)
        diff_summary = build_port_scan_diff(previous_ports, flatten_port_results(results))
        print_port_diff_summary(diff_summary)
        save_port_scan_results(results, diff_summary, json_output_file)
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
