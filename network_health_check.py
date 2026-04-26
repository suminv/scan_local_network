import argparse
import sys

from arp_scanner import resolve_scan_target
from colorama import Fore, Style, init
from models import build_scan_context
from network_health import (
    DEFAULT_DNS_DOMAINS,
    build_health_summary,
    run_network_health_checks,
)
from reporting import save_json_report


JSON_OUTPUT_FILE = "network_health_check_result.json"
DEFAULT_OUTPUT_FORMAT = "full"
CHECK_GROUPS = [
    ("Network", ["gateway_identity", "gateway_fingerprint"]),
    ("DNS", ["dns_environment", "dns_"]),
    ("Wi-Fi", ["wifi_environment", "wifi_stability"]),
    ("Internet", ["captive_", "https_"]),
]
CHECK_LABELS = {
    "gateway_identity": "Gateway",
    "gateway_fingerprint": "Gateway fingerprint",
    "dns_environment": "DNS servers",
    "wifi_environment": "Wi-Fi environment",
    "wifi_stability": "Wi-Fi stability",
    "captive_gstatic_204": "Gstatic probe",
    "captive_apple_captive": "Apple probe",
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
    if name == "dns_environment":
        return format_dns_environment_details(details)
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
    if check["name"] in CHECK_LABELS:
        label = CHECK_LABELS[check["name"]]
    elif check["name"].startswith("dns_") and check["name"] != "dns_environment":
        label = check["name"][4:]
    else:
        label = check["name"].replace("_", " ")
    return f"{format_status_badge(status)} {label}"


def format_status_badge(status):
    if status == "OK":
        return f"{Fore.GREEN}[OK]{Style.RESET_ALL}"
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


def format_top_alert_summary(summary):
    alerts = summary.get("alerts", [])
    if not alerts:
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
        elif name.startswith("dns_"):
            labels.append(name[4:])
        else:
            labels.append(name.replace("_", " "))
    suffix = " ..." if len(alerts) > 4 else ""
    return f"Risk summary: {len(alerts)} alert(s) in {', '.join(labels)}{suffix}"


def build_trust_assessment(summary):
    alert_count = summary.get("alert_checks", 0)
    if alert_count == 0:
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
        f"Checks: {summary['total_checks']} | OK: {summary['ok_checks']} | Alerts: {summary['alert_checks']}"
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
        or check["name"] in {"gateway_identity", "gateway_fingerprint", "dns_environment", "wifi_environment"}
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
        print("No actionable health alerts detected.")
        print("=============================")
        return
    print(f"Alerts: {len(alerts)}")
    for check in alerts:
        print(f"\n{format_status_badge('ALERT')} {check['name']}")
        print(check["summary"])
    print("=============================")


def parse_args():
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
    return parser.parse_args()


def main():
    init(autoreset=True)
    args = parse_args()
    json_output_file = args.json_out or JSON_OUTPUT_FILE
    interface, cidr = resolve_scan_target(args.iface, args.cidr)
    raw_wifi_stability_seconds = getattr(args, "wifi_stability_seconds", 0)
    wifi_stability_seconds = (
        raw_wifi_stability_seconds
        if isinstance(raw_wifi_stability_seconds, (int, float))
        else 0
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
    payload = {
        "scan_context": build_scan_context(interface=interface, cidr=cidr),
        "health_checks": checks,
        "health_summary": summary,
    }
    save_json_report(json_output_file, payload, label="Network health report")
    if args.alerts_only:
        print_alert_report(summary)
    elif args.output == "focus":
        print_focus_health_report(checks, summary)
    else:
        print_health_report(checks, summary)
    if args.debug_wifi:
        print_wifi_debug_report(checks)
    sys.exit(2 if summary["alert_checks"] else 0)


if __name__ == "__main__":
    main()
