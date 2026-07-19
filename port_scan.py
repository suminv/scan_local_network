import argparse
from contextlib import contextmanager, nullcontext, redirect_stdout
from io import StringIO
import logging
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import arp_scanner
from alert_delivery import build_alert_payload, send_webhook_payload
from cli_progress import ProgressIndicator
from colorama import Fore, Style, init
from models import build_device_snapshot, build_port_snapshot, build_scan_context
from policy_config import (
    build_baseline_config,
    evaluate_device_policies,
    load_policy_config,
    save_policy_config,
)
from reporting import print_output_files, print_section_heading, should_use_color
from scapy.layers.inet import IP, TCP
from scapy.error import Scapy_Exception
from scapy.sendrecv import sr1

from arp_scanner import (
    DEFAULT_NETWORK_PROFILE,
    NETWORK_PROFILES,
    create_scan_run,
    finalize_scan_run,
    build_port_scan_diff,
    get_vendor,
    init_db,
    load_previous_scan_ports,
    resolve_scan_target,
    save_scan_run_ports,
    save_device_events,
    SCAN_TYPE_PORT,
    update_vendor_database,
    upsert_device_profiles,
    get_device_profile_by_ip,
    lookup_mac_for_ip,
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
    print_port_focus_diff_summary,
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
SCAPY_MISSING_MAC_WARNING = "MAC address to reach destination not found. Using broadcast."


class ScapyProgressNoiseFilter(logging.Filter):
    """Hide only Scapy's missing-MAC broadcast warning during a port scan."""

    def filter(self, record):
        return SCAPY_MISSING_MAC_WARNING not in record.getMessage()


@contextmanager
def suppress_scapy_progress_noise():
    """Keep known non-actionable Scapy warnings from corrupting progress output."""
    logger = logging.getLogger("scapy.runtime")
    noise_filter = ScapyProgressNoiseFilter()
    logger.addFilter(noise_filter)
    try:
        yield
    finally:
        logger.removeFilter(noise_filter)


def arp_scan(ip_range, interface):
    """Use the shared ARP discovery implementation and failure semantics."""
    return arp_scanner.arp_scan(ip_range, interface)

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


def scan_ports_for_device(device, ports, progress_callback=None):
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
        for completed, future in enumerate(as_completed(future_to_port), start=1):
            result = future.result()
            if result is not None:
                open_ports.append(result)
            if progress_callback is not None:
                progress_callback(completed, len(future_to_port), ip)

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


def format_ports_for_display(ports):
    """Render a port list compactly, collapsing consecutive values into ranges."""
    if not ports:
        return "none"
    ranges = []
    start = previous = ports[0]
    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append((start, previous))
        start = previous = port
    ranges.append((start, previous))
    return ", ".join(
        str(start) if start == end else f"{start}-{end}"
        for start, end in ranges
    )

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
                    http=port_info.get("http"),
                    ssh=port_info.get("ssh"),
                )
            )
    return rows

def discover_devices_to_scan(args, mac_lookup):
    """Resolve scan context and discover or select devices to scan."""
    scan_context = build_scan_context()
    if args.target:
        target_mac = lookup_mac_for_ip(args.target)
        target_device = build_device_snapshot(
            ip=args.target,
            mac=target_mac or "00:00:00:00:00:00",
            vendor=(get_vendor(target_mac, mac_lookup) if target_mac and mac_lookup else "N/A"),
        )
        if args.resolve_hostnames:
            print("Resolving hostname...")
            enrich_devices_with_hostnames([target_device])
        print(f"Scanning target IP: {args.target}")
        scan_context["cidr"] = args.target
        return (
            [target_device],
            scan_context,
        )

    interface, ip_range = resolve_scan_target(args.iface, args.cidr)
    scan_context["interface"] = interface
    scan_context["cidr"] = ip_range
    print(f"Using interface: {interface}")
    print(f"Scanning IP range: {ip_range}")
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

def run_port_scan(
    devices_to_scan,
    ports_to_scan,
    progress_callback=None,
    progress_by_port=False,
):
    """Run port scanning for all selected devices."""
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_device = {
            executor.submit(
                scan_ports_for_device,
                device,
                ports_to_scan,
                progress_callback=(progress_callback if progress_by_port else None),
            ): device
            for device in devices_to_scan
        }
        for completed, future in enumerate(as_completed(future_to_device), start=1):
            results.append(future.result())
            if progress_callback is not None and not progress_by_port:
                device = future_to_device[future]
                progress_callback(completed, len(devices_to_scan), device["ip"])
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
        "--db-file",
        type=str,
        help="SQLite database path. Defaults to arp_scan_v1.db in the working directory.",
    )
    parser.add_argument(
        "--network-profile",
        choices=NETWORK_PROFILES,
        default=DEFAULT_NETWORK_PROFILE,
        help=(
            "Storage policy: 'home' records scan history and device profiles; "
            "'untrusted' keeps the scan ephemeral. Defaults to untrusted."
        ),
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
        "--show-changes",
        action="store_true",
        help="Show changes from the previous compatible scan. Target scans hide this by default.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show setup, database, vendor lookup, and progress details.",
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Optional JSON file with known devices and alert policies.",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate --config and exit without scanning.",
    )
    parser.add_argument(
        "--write-baseline",
        type=str,
        help="Write a JSON known-device baseline from this complete LAN scan.",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Show a compact device profile after scanning one --target IP.",
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
        "db": getattr(args, "db_file", None),
        "json": args.json_out or JSON_OUTPUT_FILE,
        "csv": args.csv_out,
        "markdown": args.md_out,
    }


def render_port_scan_outcome(
    args,
    results,
    diff_summary,
    policy_findings=None,
    *,
    target=None,
    duration_seconds=None,
):
    """Render scan output and return the appropriate process exit code."""
    show_changes = diff_summary is not None and (
        not getattr(args, "target", None) or getattr(args, "show_changes", False)
    )
    visible_diff = diff_summary if show_changes else None
    if args.alerts_only:
        print_port_scan_summary(
            results,
            target=target,
            duration_seconds=duration_seconds,
            diff_summary=visible_diff,
            policy_findings=policy_findings,
        )
        print_port_alert_summary(results, visible_diff)
        if policy_findings:
            print_policy_findings(policy_findings)
        return 2 if (has_port_alerts(results, visible_diff) or policy_findings) else 0

    print_port_scan_summary(
        results,
        target=target,
        duration_seconds=duration_seconds,
        diff_summary=visible_diff,
        policy_findings=policy_findings,
    )
    if show_changes:
        if args.output == "focus":
            print_port_focus_diff_summary(diff_summary)
        else:
            print_port_diff_summary(diff_summary)
    if policy_findings:
        print_policy_findings(policy_findings)
    print_port_scan_results(
        results,
        output_format=args.output,
        target=target,
        duration_seconds=duration_seconds,
        diff_summary=visible_diff,
        policy_findings=policy_findings,
        include_summary=False,
    )
    return 0


def render_empty_scan_outcome(
    args, diff_summary, policy_findings=None, *, target=None
):
    """Render the empty-discovery case and return the appropriate process exit code."""
    show_changes = diff_summary is not None and (
        not getattr(args, "target", None) or getattr(args, "show_changes", False)
    )
    visible_diff = diff_summary if show_changes else None
    if args.alerts_only:
        print_port_scan_summary(
            [],
            target=target,
            diff_summary=visible_diff,
            policy_findings=policy_findings,
        )
        print_port_alert_summary([], visible_diff)
        if policy_findings:
            print_policy_findings(policy_findings)
        return 2 if (has_port_alerts([], visible_diff) or policy_findings) else 0

    print_port_scan_summary(
        [],
        target=target,
        diff_summary=visible_diff,
        policy_findings=policy_findings,
    )
    print("\nNo devices found on the network.")
    if show_changes:
        if getattr(args, "output", DEFAULT_OUTPUT_FORMAT) == "focus":
            print_port_focus_diff_summary(diff_summary)
        else:
            print_port_diff_summary(diff_summary)
    if policy_findings:
        print_policy_findings(policy_findings)
    return 0


def print_device_profile(profile, policy_findings=None):
    """Render one compact profile card for an operator-facing target scan."""
    if profile is None:
        print("No profile data available.")
        return
    title = profile.get("user_name") or profile["ip"]
    print(f"\n{title} · {profile['device_hint']} ({profile['hint_confidence']} confidence)")
    print(f"  IP history: {', '.join(profile['ip_history']) or profile['ip']}")
    if profile.get("mac"):
        print(f"  MAC: {profile['mac']} · {profile.get('vendor') or 'Unknown vendor'}")
    if profile.get("hostname"):
        print(f"  Hostname: {profile['hostname']}")
    if profile["hint_evidence"]:
        print(f"  Evidence: {'; '.join(profile['hint_evidence'])}")
    print("  Services:")
    for service in profile["services"]:
        print(f"    {service['port']}/tcp  {service.get('service', 'Unknown')}")
    if policy_findings:
        print("  Policy:")
        for finding in policy_findings:
            print(f"    {finding['type'].replace('_', ' ')}")


def print_policy_findings(policy_findings):
    """Print policy findings before detailed port observations."""
    if not policy_findings:
        return
    print_section_heading("Policy Findings", leading_blank=True)
    for finding in policy_findings:
        if finding["type"] == "unknown_device":
            print(f"  unknown device: {finding['ip']} ({finding['mac']})")
        else:
            name = finding.get("name") or finding["mac"]
            print(f"  unexpected port: {name} {finding['ip']}:{finding['port']}")


def apply_profile_policy_name(profile, policy_config):
    """Apply a user-assigned known-device name without changing stored observations."""
    if profile is None or not profile.get("mac"):
        return profile
    known = policy_config.get("known_devices", {}).get(profile["mac"].lower())
    if not known or not known.get("name"):
        return profile
    named_profile = dict(profile)
    named_profile["user_name"] = known["name"]
    return named_profile


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
        "ssh_changes": len(diff_summary.get("ssh_changes", [])),
        "http_changes": len(diff_summary.get("http_changes", [])),
    }


def maybe_send_port_webhook(
    webhook_url, timeout, scan_context, results, diff_summary, policy_findings=None
):
    """Send port scan alert summary to a webhook when actionable findings exist."""
    policy_findings = policy_findings or []
    if not webhook_url or not (has_port_alerts(results, diff_summary) or policy_findings):
        return False
    alert_summary = build_port_alert_summary(results, diff_summary)
    alert_summary["policy_findings"] = len(policy_findings)
    payload = build_alert_payload(
        source="port_scan",
        scan_context=scan_context,
        alert_summary=alert_summary,
        alerts={
            "port_diff_summary": diff_summary,
            "policy_findings": policy_findings,
        },
    )
    return send_webhook_payload(webhook_url, payload, timeout=timeout, label="Port webhook alert")


def main():
    """Main function to run the port scanner."""
    global CSV_OUTPUT_FILE, MARKDOWN_OUTPUT_FILE
    exit_code = 0
    init(autoreset=True, strip=not should_use_color(sys.stdout))
    args = parse_args()
    try:
        policy_config = load_policy_config(getattr(args, "config", None))
    except ValueError as exc:
        print(f"{Fore.RED}Error: {exc}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    if getattr(args, "check_config", False):
        print("Policy config is valid.")
        sys.exit(0)
    selected_profile = getattr(args, "network_profile", "home")
    if selected_profile not in NETWORK_PROFILES:
        selected_profile = "home"
    persistent = selected_profile == "home"
    home_only_options = []
    if args.db_file:
        home_only_options.append("--db-file")
    if args.config:
        home_only_options.append("--config")
    if args.write_baseline:
        home_only_options.append("--write-baseline")
    if args.profile:
        home_only_options.append("--profile")
    if args.webhook_url:
        home_only_options.append("--webhook-url")
    if args.show_changes:
        home_only_options.append("--show-changes")
    if not persistent and home_only_options:
        print(
            f"{Fore.RED}Error: {', '.join(home_only_options)} require "
            f"--network-profile home because they use stored home history.{Style.RESET_ALL}",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.target and (args.iface or args.cidr):
        print(
            f"{Fore.RED}Error: --target cannot be combined with --iface or --cidr.{Style.RESET_ALL}",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.profile and not args.target:
        print(f"{Fore.RED}Error: --profile requires --target.{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    if args.write_baseline and args.target:
        print(
            f"{Fore.RED}Error: --write-baseline requires a full LAN scan, not --target.{Style.RESET_ALL}",
            file=sys.stderr,
        )
        sys.exit(1)
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
    if output_paths["db"]:
        arp_scanner.DB_FILE = output_paths["db"]
    CSV_OUTPUT_FILE = output_paths["csv"]
    MARKDOWN_OUTPUT_FILE = output_paths["markdown"]
    if args.verbose:
        print_section_heading("Port Scanner")
    quiet_output = nullcontext() if args.verbose else redirect_stdout(StringIO())
    with quiet_output:
        mac_lookup = update_vendor_database()
    db_conn = None
    if persistent:
        with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
            db_conn = init_db()
    try:
        try:
            with (nullcontext() if args.verbose else redirect_stdout(StringIO())):
                devices_to_scan, scan_context = discover_devices_to_scan(args, mac_lookup)
        except RuntimeError as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)

        scan_run_id = None
        previous_ports = []
        if persistent:
            scan_run_id = create_scan_run(
                db_conn,
                scan_context["interface"],
                scan_context["cidr"],
                scan_type=SCAN_TYPE_PORT,
                target=args.target,
                ports=ports_to_scan,
                resolve_hostnames=args.resolve_hostnames,
            )
            previous_ports = load_previous_scan_ports(db_conn, scan_run_id)
        if not devices_to_scan:
            diff_summary = (
                build_port_scan_diff(previous_ports, [], observed_macs=[])
                if persistent
                else None
            )
            exit_code = render_empty_scan_outcome(
                args,
                diff_summary,
                target=args.target or scan_context["cidr"],
            )
            if persistent:
                finalize_scan_run(db_conn, scan_run_id, status="success", device_count=0)
            if args.verbose:
                print_output_files([("Database", arp_scanner.DB_FILE if persistent else None)])
                print(f"Storage: {'home history' if persistent else 'ephemeral'}")
                if scan_run_id is not None:
                    print(f"Scan run: {scan_run_id}")
            sys.exit(exit_code)

        target_label = args.target or scan_context["cidr"]
        print(
            f"Scanning {target_label} · ports: "
            f"{format_ports_for_display(ports_to_scan)}"
        )
        started_at = time.monotonic()
        progress_by_port = bool(args.target)
        progress = ProgressIndicator(
            "Port scan",
            len(ports_to_scan) if progress_by_port else len(devices_to_scan),
            unit="ports" if progress_by_port else "devices",
        )
        progress.update(0, target_label, force=True)
        try:
            with suppress_scapy_progress_noise():
                results = run_port_scan(
                    devices_to_scan,
                    ports_to_scan,
                    progress_callback=lambda current, total, detail: progress.update(
                        current, detail
                    ) if current < total else None,
                    progress_by_port=progress_by_port,
                )
        except Exception:
            progress.fail()
            raise
        elapsed = time.monotonic() - started_at
        progress.finish(f"completed in {elapsed:.1f}s")
        profiles = []
        if persistent:
            save_scan_run_ports(db_conn, scan_run_id, results)
            profiles = upsert_device_profiles(db_conn, results, scan_run_id)
        policy_findings = (
            evaluate_device_policies(results, policy_config) if args.config else []
        )
        if args.write_baseline:
            save_policy_config(args.write_baseline, build_baseline_config(results))
            print(f"Baseline saved to {args.write_baseline}")
        diff_summary = None
        if persistent:
            diff_summary = build_port_scan_diff(
                previous_ports,
                flatten_port_results(results),
                observed_macs=[device["mac"] for device in results],
            )
            save_device_events(db_conn, scan_run_id, diff_summary, SCAN_TYPE_PORT)
        if args.profile:
            print_device_profile(
                apply_profile_policy_name(
                    get_device_profile_by_ip(db_conn, args.target), policy_config
                ),
                policy_findings,
            )
            exit_code = 0
        else:
            exit_code = render_port_scan_outcome(
                args,
                results,
                diff_summary,
                policy_findings,
                target=target_label,
                duration_seconds=elapsed,
            )
        should_save_reports = persistent or any(
            [args.json_out, args.csv_out, args.md_out]
        )
        if should_save_reports:
            with redirect_stdout(StringIO()):
                save_port_scan_results(
                    results,
                    diff_summary,
                    output_paths["json"] if persistent or args.json_out else None,
                    csv_output_file=CSV_OUTPUT_FILE,
                    markdown_output_file=MARKDOWN_OUTPUT_FILE,
                    profiles=profiles if persistent else None,
                    policy_findings=policy_findings,
                )
        if persistent:
            maybe_send_port_webhook(
                args.webhook_url,
                args.webhook_timeout,
                scan_context,
                results,
                diff_summary,
                policy_findings,
            )
            finalize_scan_run(
                db_conn,
                scan_run_id,
                status="success",
                device_count=len(devices_to_scan),
            )
    except Exception:
        if "progress" in locals() and not progress.finished:
            progress.fail()
        if persistent and "scan_run_id" in locals() and scan_run_id is not None:
            finalize_scan_run(db_conn, scan_run_id, status="failed")
        raise
    finally:
        if db_conn is not None:
            db_conn.close()
    if args.verbose:
        print_output_files(
            [
                ("Database", arp_scanner.DB_FILE if persistent else None),
                ("JSON", output_paths["json"] if persistent or args.json_out else None),
                ("CSV", CSV_OUTPUT_FILE),
                ("Markdown", MARKDOWN_OUTPUT_FILE),
                ("Baseline", args.write_baseline),
            ]
        )
        print(f"Storage: {'home history' if persistent else 'ephemeral'}")
        if scan_run_id is not None:
            print(f"Scan run: {scan_run_id}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
