import argparse
import sys

from alert_delivery import build_alert_payload, send_webhook_payload
from arp_scanner import resolve_scan_target
from colorama import Fore, Style, init
from models import build_scan_context
from network_health import (
    DEFAULT_DNS_DOMAINS,
    build_health_summary,
    run_network_health_checks,
)
from reporting import render_markdown_table, save_json_report, save_markdown_report


JSON_OUTPUT_FILE = "network_health_check_result.json"
MARKDOWN_OUTPUT_FILE = None
DEFAULT_OUTPUT_FORMAT = "full"
CHECK_GROUPS = [
    ("Network", ["gateway_identity", "gateway_fingerprint", "gateway_exposure", "local_peer_visibility", "client_isolation_hint", "active_path"]),
    ("DNS", ["dns_environment", "dns_trust_reasoning", "dns_"]),
    ("Wi-Fi", ["wifi_environment", "wifi_stability"]),
    ("Internet", ["captive_trust_reasoning", "captive_", "https_trust_reasoning", "https_"]),
]
CHECK_LABELS = {
    "gateway_identity": "Gateway",
    "gateway_fingerprint": "Gateway fingerprint",
    "gateway_exposure": "Gateway exposure",
    "local_peer_visibility": "Local peer visibility",
    "client_isolation_hint": "Client isolation hint",
    "active_path": "Active path",
    "dns_environment": "DNS servers",
    "dns_trust_reasoning": "DNS trust reasoning",
    "wifi_environment": "Wi-Fi environment",
    "wifi_stability": "Wi-Fi stability",
    "captive_gstatic_204": "Gstatic probe",
    "captive_apple_captive": "Apple probe",
    "captive_trust_reasoning": "Captive portal reasoning",
    "https_trust_reasoning": "HTTPS trust reasoning",
    "https_example_https": "Example HTTPS",
    "https_google_204_https": "Google HTTPS 204",
}
DNS_CLASSIFICATION_LABELS = {
    "gateway_dns": "gateway DNS",
    "local_private": "private/local DNS",
    "on_link": "on-link DNS",
    "directly_reachable": "on-link DNS",
    "public_upstream": "public upstream DNS",
    "invalid": "invalid DNS",
    "unknown": "unknown",
}
WIFI_STATUS_LABELS = {
    "spairport_status_connected": "connected",
    "spairport_status_inactive": "inactive",
}


def format_gateway_identity_details(details):
    lines = []
    if details.get("hostname"):
        lines.append(f"  hostname: {details['hostname']}")
    lines.append(f"  interface: {details.get('interface')}")
    lines.append(
        "  scope: public network edge" if details.get("is_public_ip") else "  scope: private/local gateway"
    )
    return lines


def format_gateway_fingerprint_details(details):
    return [
        f"  mac: {details.get('gateway_mac') or 'unavailable'}",
        f"  vendor: {details.get('vendor', 'Unknown')}",
        f"  interface: {details.get('interface')}",
    ]


def format_gateway_exposure_details(details):
    lines = [
        f"  gateway: {details.get('gateway_ip')}",
        f"  interface: {details.get('interface')}",
    ]
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    reachable = details.get("reachable_services", [])
    if not reachable:
        lines.append("  reachable local services: none detected")
        return lines
    lines.append("  reachable local services:")
    for service in reachable:
        risk_marker = " [alert]" if service.get("risk") else ""
        lines.append(f"    - {service['port']}/tcp {service['label']}{risk_marker}")
        http_probe = service.get("http_probe") or {}
        if http_probe.get("url"):
            lines.append(f"      url: {http_probe['url']}")
        if http_probe.get("status_code") is not None:
            lines.append(f"      status: {http_probe['status_code']}")
        if http_probe.get("content_type"):
            lines.append(f"      content_type: {http_probe['content_type']}")
        if http_probe.get("server"):
            lines.append(f"      server: {http_probe['server']}")
        if http_probe.get("location"):
            lines.append(f"      location: {http_probe['location']}")
        if http_probe.get("title"):
            lines.append(f"      title: {http_probe['title']}")
        if http_probe.get("page_hint"):
            lines.append(f"      page_hint: {http_probe['page_hint']}")
        if http_probe.get("error"):
            lines.append(f"      probe_error: {http_probe['error']}")
    return lines


def format_local_peer_visibility_details(details):
    lines = [
        f"  interface: {details.get('interface')}",
        f"  gateway: {details.get('gateway_ip')}",
    ]
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    peers = details.get("visible_peers", [])
    if not peers:
        lines.append("  visible peers: none")
        return lines
    lines.append("  visible peers:")
    for peer in peers[:8]:
        lines.append(f"    - {peer['ip']} ({peer['mac']})")
    extra_count = max(0, len(peers) - 8)
    if extra_count:
        lines.append(f"    - ... {extra_count} more")
    return lines


def format_client_isolation_hint_details(details):
    lines = [
        f"  interface: {details.get('interface')}",
        f"  gateway: {details.get('gateway_ip')}",
        f"  hint level: {details.get('hint_level')}",
        f"  visible peers: {details.get('visible_peer_count', 0)}",
        f"  risky gateway services: {details.get('risky_gateway_service_count', 0)}",
    ]
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    peers = details.get("visible_peers", [])
    if peers:
        lines.append("  peer samples:")
        for peer in peers[:5]:
            lines.append(f"    - {peer['ip']} ({peer['mac']})")
    return lines


def format_active_path_details(details):
    lines = [
        f"  default interface: {details.get('default_interface')}",
        f"  gateway: {details.get('gateway_ip')}",
    ]
    if details.get("wifi_active"):
        lines.append(f"  active wifi interface: {details.get('wifi_interface')}")
    else:
        lines.append("  active wifi interface: none detected")
    return lines


def format_dns_environment_details(details):
    lines = []
    nameservers = details.get("nameservers", [])
    if nameservers:
        lines.append("  resolver classes:")
        for entry in details.get("analysis", {}).get("classifications", []):
            lines.append(
                f"    - {entry['server']} [{DNS_CLASSIFICATION_LABELS.get(entry['classification'], entry['classification'])}]"
            )
    search_domains = details.get("search_domains", [])
    if search_domains:
        lines.append(f"  search: {', '.join(search_domains)}")
    if details.get("analysis", {}).get("risks"):
        lines.append("  risks:")
        for risk in details["analysis"]["risks"]:
            lines.append(f"    - {risk['server']}: {risk['reason']}")
    lines.append(f"  source: {details.get('source')}")
    return lines


def format_dns_trust_reasoning_details(details):
    lines = [f"  hint level: {details.get('hint_level')}"]
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    if details.get("nameservers"):
        lines.append(f"  nameservers: {', '.join(details['nameservers'])}")
    if details.get("resolver_profile"):
        lines.append(f"  resolver profile: {', '.join(details['resolver_profile'])}")
    lines.append(f"  resolver risks: {details.get('risk_count', 0)}")
    lines.append(f"  resolution issues: {details.get('resolution_issue_count', 0)}")
    if details.get("affected_domains"):
        lines.append(f"  affected domains: {', '.join(details['affected_domains'])}")
    return lines


def format_captive_trust_reasoning_details(details):
    lines = [f"  hint level: {details.get('hint_level')}"]
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    lines.append(f"  probes: {details.get('probe_count', 0)}")
    lines.append(f"  affected probes: {details.get('alert_probe_count', 0)}")
    if details.get("affected_probes"):
        lines.append(f"  probe names: {', '.join(details['affected_probes'])}")
    return lines


def format_https_trust_reasoning_details(details):
    lines = [f"  hint level: {details.get('hint_level')}"]
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    lines.append(f"  probes: {details.get('probe_count', 0)}")
    lines.append(f"  affected probes: {details.get('alert_probe_count', 0)}")
    if details.get("affected_probes"):
        lines.append(f"  probe names: {', '.join(details['affected_probes'])}")
    return lines


def format_wifi_environment_details(details):
    lines = []
    inventory = details.get("inventory", {})
    interfaces = inventory.get("interfaces", [])
    if interfaces:
        lines.append("  interfaces:")
        for interface in interfaces:
            name = interface.get("name")
            raw_status = interface.get("status")
            status = WIFI_STATUS_LABELS.get(raw_status, raw_status or "unknown")
            country = interface.get("country_code") or "-"
            phy = interface.get("supported_phy_modes") or "-"
            lines.append(f"    - {name}: {status}, {country}, {phy}")

    nearby = details.get("nearby", {})
    analysis = details.get("analysis", {})
    if analysis.get("limited_scan"):
        lines.append(
            f"  nearby: restricted by macOS/CoreWLAN ({analysis.get('visible_network_count', 0)} incomplete object(s))"
        )
        lines.append("  note: nearby scan returned hidden/incomplete objects only")
    elif nearby.get("available"):
        lines.append(
            f"  nearby: {len(nearby.get('networks', []))} network(s) via {nearby.get('backend')}"
        )
        for network in nearby.get("networks", [])[:5]:
            ssid = network.get("ssid") or "<hidden>"
            channel = network.get("channel") or "?"
            rssi = network.get("rssi") or "?"
            security = network.get("security") or "unknown security"
            bssid = network.get("bssid") or "-"
            lines.append(
                f"    - {ssid} | ch {channel} | rssi {rssi} | {security} | {bssid}"
            )
        extra_count = max(0, len(nearby.get("networks", [])) - 5)
        if extra_count:
            lines.append(f"    - ... {extra_count} more")
    else:
        lines.append(f"  nearby: unavailable ({nearby.get('reason')})")

    risks = analysis.get("risks", [])
    if risks:
        lines.append("  risks:")
        for risk in risks:
            target = risk.get("ssid") or risk.get("server") or "network"
            lines.append(f"    - {humanize_risk_type(risk['type'])}: {target} ({risk['reason']})")

    current = details.get("current", {})
    if current.get("available") is False and current.get("reason"):
        lines.append(f"  current: unavailable ({current['reason']})")
    return lines


def format_domain_resolution_details(details):
    ips = details.get("ips", [])
    if not ips:
        return []
    return [f"  ips: {', '.join(ips)}"]


def format_http_probe_details(details):
    lines = [f"  status_code: {details.get('status_code')}"]
    if details.get("location"):
        lines.append(f"  location: {details['location']}")
    return lines


def format_wifi_stability_details(details):
    lines = [
        f"  level: {details.get('level')}",
        f"  gateway: {details.get('gateway_ip')}",
        f"  samples: {details.get('sample_count')}",
    ]
    if details.get("avg_rssi") is not None:
        lines.append(f"  avg rssi: {details['avg_rssi']:.0f} dBm")
    if details.get("avg_latency_ms") is not None:
        lines.append(f"  avg gateway latency: {details['avg_latency_ms']:.1f} ms")
    if details.get("max_loss_percent") is not None:
        lines.append(f"  max packet loss: {details['max_loss_percent']:.0f}%")
    if details.get("bssid_changes") is not None:
        lines.append(f"  BSSID changes: {details['bssid_changes']}")
    if details.get("reasons"):
        lines.append("  reasons:")
        for reason in details["reasons"]:
            lines.append(f"    - {reason}")
    if details.get("reason"):
        lines.append(f"  reason: {details['reason']}")
    return lines


def humanize_risk_type(risk_type):
    return {
        "open_network": "open network",
        "weak_security": "weak security",
        "very_low_signal": "very low signal",
        "mixed_security_duplicate_ssid": "mixed-security duplicate SSID",
    }.get(risk_type, risk_type.replace("_", " "))


def format_check_details(check):
    name = check["name"]
    details = check.get("details", {})
    if name == "gateway_identity":
        return format_gateway_identity_details(details)
    if name == "gateway_fingerprint":
        return format_gateway_fingerprint_details(details)
    if name == "gateway_exposure":
        return format_gateway_exposure_details(details)
    if name == "local_peer_visibility":
        return format_local_peer_visibility_details(details)
    if name == "client_isolation_hint":
        return format_client_isolation_hint_details(details)
    if name == "active_path":
        return format_active_path_details(details)
    if name == "dns_environment":
        return format_dns_environment_details(details)
    if name == "dns_trust_reasoning":
        return format_dns_trust_reasoning_details(details)
    if name == "captive_trust_reasoning":
        return format_captive_trust_reasoning_details(details)
    if name == "https_trust_reasoning":
        return format_https_trust_reasoning_details(details)
    if name == "wifi_environment":
        return format_wifi_environment_details(details)
    if name == "wifi_stability":
        return format_wifi_stability_details(details)
    if name.startswith("dns_"):
        return format_domain_resolution_details(details)
    if name.startswith("captive_") or name.startswith("https_"):
        return format_http_probe_details(details)
    return []


def format_check_heading(check):
    status = check["status"].upper()
    label = format_check_label(check["name"])
    return f"{format_status_badge(status)} {label}"


def format_status_badge(status):
    if status == "OK":
        return f"{Fore.GREEN}[OK]{Style.RESET_ALL}"
    if status == "NOTICE":
        return f"{Fore.YELLOW}[~]{Style.RESET_ALL}"
    if status == "ALERT":
        return f"{Fore.RED}[!]{Style.RESET_ALL}"
    return f"{Fore.YELLOW}[?]{Style.RESET_ALL}"


def matches_group(check_name, patterns):
    for pattern in patterns:
        if pattern.endswith("_"):
            if check_name.startswith(pattern):
                return True
            continue
        if check_name == pattern:
            return True
    return False


def group_checks(checks):
    grouped = []
    for title, patterns in CHECK_GROUPS:
        rows = [check for check in checks if matches_group(check["name"], patterns)]
        if rows:
            grouped.append((title, rows))
    return grouped


def format_check_label(check_name):
    if check_name in CHECK_LABELS:
        return CHECK_LABELS[check_name]
    if check_name.startswith("dns_") and check_name != "dns_environment":
        return check_name[4:]
    if check_name.startswith("captive_"):
        return "Captive portal"
    if check_name.startswith("https_"):
        return "HTTPS"
    return check_name.replace("_", " ")


def format_top_alert_summary(summary):
    alerts = summary.get("alerts", [])
    notices = summary.get("notices", [])
    if not alerts:
        if notices:
            labels = [format_check_label(check["name"]) for check in notices[:4]]
            suffix = " ..." if len(notices) > 4 else ""
            return f"Risk summary: no hard alerts; {len(notices)} notice(s) in {', '.join(labels)}{suffix}"
        return "Risk summary: no active alerts"
    labels = []
    for check in alerts[:4]:
        name = check["name"]
        if name == "wifi_environment":
            labels.append("Wi-Fi")
        elif name == "dns_environment":
            labels.append("DNS")
        elif name.startswith("captive_"):
            labels.append("Captive portal")
        elif name.startswith("https_"):
            labels.append("HTTPS")
        else:
            labels.append(format_check_label(name))
    suffix = " ..." if len(alerts) > 4 else ""
    return f"Risk summary: {len(alerts)} alert(s) in {', '.join(labels)}{suffix}"


def build_trust_assessment(summary):
    alert_count = summary.get("alert_checks", 0)
    notice_count = summary.get("notice_checks", 0)
    if alert_count == 0:
        if notice_count:
            return {
                "level": "trusted",
                "summary": f"No hard alerts detected. {notice_count} notice(s) are present for review.",
            }
        return {
            "level": "trusted",
            "summary": "No active alerts detected in network, DNS, Wi-Fi, or internet probes.",
        }
    if alert_count == 1:
        return {
            "level": "suspicious",
            "summary": "One alert is active. Treat this network as suspicious until the finding is understood.",
        }
    return {
        "level": "untrusted",
        "summary": f"{alert_count} alerts are active. Treat this network as untrusted.",
    }


def indent_detail_line(line):
    return f"    {line.lstrip()}"


def print_wifi_stability_progress(current_step, total_steps, gateway_ip):
    message = (
        f"\rRunning Wi-Fi stability diagnostics: sample {current_step}/{total_steps} "
        f"against gateway {gateway_ip}..."
    )
    sys.stdout.write(message)
    if current_step >= total_steps:
        sys.stdout.write("\n")
    sys.stdout.flush()


def print_health_report(checks, summary):
    assessment = build_trust_assessment(summary)
    print("=== Network Health Check ===")
    print(
        f"Checks: {summary['total_checks']} | OK: {summary['ok_checks']} | Notices: {summary.get('notice_checks', 0)} | Alerts: {summary['alert_checks']}"
    )
    print(f"Trust assessment: {assessment['level']}")
    print(assessment["summary"])
    print(format_top_alert_summary(summary))
    for group_title, group_rows in group_checks(checks):
        print(f"\n{group_title}:")
        for check in group_rows:
            print(f"  {format_check_heading(check)}")
            print(f"    {check['summary']}")
            for line in format_check_details(check):
                print(indent_detail_line(line))
    print("============================")


def print_focus_health_report(checks, summary):
    assessment = build_trust_assessment(summary)
    print("=== Network Health Focus ===")
    print(f"Trust assessment: {assessment['level']}")
    print(assessment["summary"])
    print(format_top_alert_summary(summary))

    key_checks = [
        check
        for check in checks
        if check["status"] == "alert"
        or check["status"] == "notice"
        or check["name"] in {"gateway_identity", "gateway_fingerprint", "active_path", "dns_environment", "wifi_environment"}
    ]
    seen = set()
    for check in key_checks:
        if check["name"] in seen:
            continue
        seen.add(check["name"])
        print(f"\n{format_check_heading(check)}")
        print(f"  {check['summary']}")
        for line in format_check_details(check)[:6]:
            print(indent_detail_line(line))
    print("============================")


def build_wifi_debug_summary(checks):
    wifi_check = next((check for check in checks if check["name"] == "wifi_environment"), None)
    if wifi_check is None:
        return None

    details = wifi_check.get("details", {})
    nearby = details.get("nearby", {})
    networks = nearby.get("networks", [])
    hidden_count = sum(1 for network in networks if (network.get("ssid") or "<hidden>") == "<hidden>")
    missing_bssid_count = sum(1 for network in networks if not network.get("bssid"))
    missing_security_count = sum(1 for network in networks if not network.get("security"))

    likely_os_restriction = (
        nearby.get("available")
        and len(networks) > 0
        and hidden_count == len(networks)
        and missing_bssid_count == len(networks)
    )

    return {
        "backend": nearby.get("backend"),
        "available": nearby.get("available"),
        "reason": nearby.get("reason"),
        "network_count": len(networks),
        "hidden_count": hidden_count,
        "missing_bssid_count": missing_bssid_count,
        "missing_security_count": missing_security_count,
        "current_available": details.get("current", {}).get("available"),
        "current_reason": details.get("current", {}).get("reason"),
        "likely_os_restriction": likely_os_restriction,
        "sample_networks": networks[:5],
    }


def print_wifi_debug_report(checks):
    debug = build_wifi_debug_summary(checks)
    if debug is None:
        return

    print("\n=== Wi-Fi Debug ===")
    print(f"backend: {debug['backend'] or 'none'}")
    print(f"nearby_available: {debug['available']}")
    if debug.get("reason"):
        print(f"reason: {debug['reason']}")
    print(f"network_objects: {debug['network_count']}")
    print(f"hidden_ssid_objects: {debug['hidden_count']}")
    print(f"missing_bssid_objects: {debug['missing_bssid_count']}")
    print(f"missing_security_objects: {debug['missing_security_count']}")
    print(f"current_wifi_details_available: {debug['current_available']}")
    if debug.get("current_reason"):
        print(f"current_wifi_details_reason: {debug['current_reason']}")

    if debug["sample_networks"]:
        print("sample_networks:")
        for network in debug["sample_networks"]:
            print(
                "  - "
                f"ssid={network.get('ssid') or '<hidden>'}, "
                f"bssid={network.get('bssid') or '-'}, "
                f"channel={network.get('channel') or '-'}, "
                f"rssi={network.get('rssi') or '-'}, "
                f"security={network.get('security') or '-'}"
            )

    if debug["likely_os_restriction"]:
        print("diagnosis: CoreWLAN scan is returning only hidden/incomplete objects. This is likely a macOS privacy or API restriction, not just a formatter problem.")
    elif not debug["available"]:
        print("diagnosis: No nearby Wi-Fi backend returned data. Install the optional macOS backend or check OS support.")
    else:
        print("diagnosis: Nearby Wi-Fi scan returned usable objects. If the list still looks incomplete, investigate scan coverage or API filtering.")
    print("===================")


def print_alert_report(summary):
    print("=== Network Health Alerts ===")
    alerts = summary["alerts"]
    if not alerts:
        notices = summary.get("notices", [])
        if notices:
            print("No actionable health alerts detected.")
            print(f"Notices present: {len(notices)}")
            for check in notices:
                print(f"\n{format_status_badge('NOTICE')} {format_check_label(check['name'])}")
                print(check["summary"])
        else:
            print("No actionable health alerts detected.")
        print("=============================")
        return
    print(f"Alerts: {len(alerts)}")
    for check in alerts:
        print(f"\n{format_status_badge('ALERT')} {format_check_label(check['name'])}")
        print(check["summary"])
    print("=============================")


def build_health_markdown_report(scan_context, checks, summary):
    """Build a Markdown report for network health checks."""
    assessment = build_trust_assessment(summary)
    lines = [
        "# Network Health Report",
        "",
        "## Scan Context",
        "",
        render_markdown_table(
            ["Interface", "CIDR", "Trust", "Alerts", "Notices", "Total checks"],
            [[
                scan_context.get("interface"),
                scan_context.get("cidr"),
                assessment["level"],
                summary["alert_checks"],
                summary.get("notice_checks", 0),
                summary["total_checks"],
            ]],
        ),
        "",
        assessment["summary"],
        "",
        "## Health Checks",
        "",
        render_markdown_table(
            ["Check", "Status", "Summary"],
            [[format_check_label(check["name"]), check["status"], check["summary"]] for check in checks],
        ),
        "",
    ]
    return "\n".join(lines)


def build_parser():
    """Build the CLI parser for network health checks."""
    parser = argparse.ArgumentParser(
        description="Safe network health checks for untrusted Wi-Fi and guest networks."
    )
    parser.add_argument(
        "--iface",
        type=str,
        help="Network interface to inspect instead of automatic detection.",
    )
    parser.add_argument(
        "--cidr",
        type=str,
        help="Optional CIDR context for the report. No broad scanning is performed.",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        help="JSON report output path. Defaults to network_health_check_result.json.",
    )
    parser.add_argument(
        "--md-out",
        type=str,
        help="Markdown report output path. Disabled unless explicitly set.",
    )
    parser.add_argument(
        "--dns-domain",
        action="append",
        dest="dns_domains",
        help="Public domain to use for DNS consistency checks. Can be repeated.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5,
        help="Timeout in seconds for network probes. Defaults to 5.",
    )
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Print only actionable health alerts and exit 2 when alerts are present.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=DEFAULT_OUTPUT_FORMAT,
        choices=["full", "focus"],
        help="Console output format: full or focus. Defaults to full.",
    )
    parser.add_argument(
        "--debug-wifi",
        action="store_true",
        help="Print raw diagnostic summary for the macOS Wi-Fi backend.",
    )
    parser.add_argument(
        "--wifi-stability-seconds",
        type=int,
        default=0,
        help="Run short Wi-Fi stability diagnostics for the given number of seconds.",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        help="Optional webhook URL that receives actionable network health alerts.",
    )
    parser.add_argument(
        "--webhook-timeout",
        type=float,
        default=10,
        help="Webhook timeout in seconds. Defaults to 10.",
    )
    return parser


def parse_args():
    """Parse CLI arguments for network health checks."""
    return build_parser().parse_args()


def resolve_report_output_paths(args):
    """Resolve JSON and Markdown output paths from CLI arguments."""
    return {
        "json": args.json_out or JSON_OUTPUT_FILE,
        "markdown": args.md_out,
    }


def normalize_wifi_stability_seconds(raw_value):
    """Normalize the Wi-Fi stability duration to a safe numeric value."""
    if isinstance(raw_value, (int, float)):
        return raw_value
    return 0


def run_health_check_collection(args):
    """Collect scan context, run health checks, and build summary/payload data."""
    interface, cidr = resolve_scan_target(args.iface, args.cidr)
    scan_context = build_scan_context(interface=interface, cidr=cidr)
    wifi_stability_seconds = normalize_wifi_stability_seconds(
        getattr(args, "wifi_stability_seconds", 0)
    )
    checks = run_network_health_checks(
        dns_domains=args.dns_domains or DEFAULT_DNS_DOMAINS,
        timeout=args.timeout,
        wifi_stability_seconds=wifi_stability_seconds,
        wifi_stability_progress_callback=(
            print_wifi_stability_progress if wifi_stability_seconds > 0 else None
        ),
    )
    summary = build_health_summary(checks)
    trust_assessment = build_trust_assessment(summary)
    payload = {
        "scan_context": scan_context,
        "health_checks": checks,
        "health_summary": summary,
        "trust_assessment": trust_assessment,
    }
    return scan_context, checks, summary, payload


def render_health_report(args, checks, summary):
    """Render health report output and return the appropriate exit code."""
    if args.alerts_only:
        print_alert_report(summary)
        return 2 if summary["alert_checks"] else 0
    if args.output == "focus":
        print_focus_health_report(checks, summary)
    else:
        print_health_report(checks, summary)
    return 0


def maybe_send_health_webhook(webhook_url, timeout, scan_context, summary):
    """Send health alerts to a webhook when actionable checks are present."""
    if not webhook_url or not summary.get("alert_checks"):
        return False
    payload = build_alert_payload(
        source="network_health_check",
        scan_context=scan_context,
        alert_summary={
            "has_alerts": True,
            "has_notices": bool(summary.get("notice_checks", 0)),
            "alert_checks": summary.get("alert_checks", 0),
            "notice_checks": summary.get("notice_checks", 0),
            "total_checks": summary.get("total_checks", 0),
        },
        alerts={"health_alerts": summary.get("alerts", [])},
    )
    return send_webhook_payload(webhook_url, payload, timeout=timeout, label="Network health webhook alert")


def main():
    init(autoreset=True)
    args = parse_args()
    global MARKDOWN_OUTPUT_FILE
    output_paths = resolve_report_output_paths(args)
    MARKDOWN_OUTPUT_FILE = output_paths["markdown"]
    scan_context, checks, summary, payload = run_health_check_collection(args)
    save_json_report(output_paths["json"], payload, label="Network health report")
    if MARKDOWN_OUTPUT_FILE:
        save_markdown_report(
            MARKDOWN_OUTPUT_FILE,
            build_health_markdown_report(scan_context, checks, summary),
            label="Network health Markdown report",
        )
    maybe_send_health_webhook(
        args.webhook_url,
        args.webhook_timeout,
        scan_context,
        summary,
    )
    exit_code = render_health_report(args, checks, summary)
    if args.debug_wifi:
        print_wifi_debug_report(checks)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
