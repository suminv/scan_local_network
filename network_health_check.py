import argparse
from contextlib import nullcontext, redirect_stdout
from io import StringIO
import sys
import time

from alert_delivery import build_alert_payload, send_webhook_payload
from arp_scanner import resolve_scan_target
from colorama import Fore
from cli_progress import ProgressIndicator
from models import build_scan_context
from network_health import (
    DEFAULT_DNS_DOMAINS,
    DEFAULT_NETWORK_PROFILE,
    NETWORK_PROFILE_ALIASES,
    NETWORK_PROFILES,
    normalize_network_profile,
    build_health_summary,
    parse_wifi_number,
    run_network_health_checks,
)
from reporting import (
    colorize,
    format_section_heading,
    format_status_marker,
    print_output_files,
    print_scan_summary,
    render_markdown_table,
    save_json_report,
    save_markdown_report,
)


JSON_OUTPUT_FILE = "network_health_check_result.json"
MARKDOWN_OUTPUT_FILE = None
DEFAULT_OUTPUT_FORMAT = "full"
FOCUS_BASELINE_CHECKS = {"overall_trust_explanation", "gateway_identity"}


def parse_network_profile(value):
    """Accept two supported profiles plus deprecated aliases with strict typo handling."""
    if value not in NETWORK_PROFILES and value not in NETWORK_PROFILE_ALIASES:
        raise argparse.ArgumentTypeError("network profile must be home or untrusted")
    return normalize_network_profile(value)


FOCUS_CONTEXT_CHECKS = {
    "gateway_fingerprint",
    "gateway_reachability",
    "active_path",
    "dns_environment",
    "wifi_environment",
}
NOTICE_REPORT_LIMIT = 3
FOCUS_NOTICE_LIMIT = 4
FINDING_PRIORITY = {
    "active_path": 10,
    "gateway_reachability": 20,
    "gateway_exposure": 30,
    "local_peer_visibility": 40,
    "overall_trust_explanation": 55,
    "client_isolation_hint": 56,
    "dns_trust_reasoning": 60,
    "dns_environment": 65,
    "captive_trust_reasoning": 70,
    "https_trust_reasoning": 80,
    "wifi_stability": 90,
    "wifi_environment": 100,
    "gateway_fingerprint": 110,
}
CHECK_GROUPS = [
    ("Summary", ["overall_trust_explanation"]),
    ("Network", ["gateway_identity", "gateway_fingerprint", "gateway_exposure", "gateway_reachability", "local_peer_visibility", "client_isolation_hint", "active_path"]),
    ("DNS", ["dns_environment", "dns_trust_reasoning", "dns_"]),
    ("Wi-Fi", ["wifi_environment", "wifi_stability"]),
    ("Internet", ["captive_trust_reasoning", "captive_", "https_trust_reasoning", "https_"]),
]
CHECK_LABELS = {
    "overall_trust_explanation": "Overall trust explanation",
    "gateway_identity": "Gateway",
    "gateway_fingerprint": "Gateway fingerprint",
    "gateway_exposure": "Gateway exposure",
    "gateway_reachability": "Gateway reachability",
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
    "resolver_interface_mismatch": "DNS on different interface",
    "public_upstream": "public upstream DNS",
    "invalid": "invalid DNS",
    "unknown": "unknown",
}
WIFI_STATUS_LABELS = {
    "spairport_status_connected": "connected",
    "spairport_status_inactive": "inactive",
}
_health_progress_indicator = None
_wifi_stability_progress_indicator = None


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
        f"  MAC: {details.get('gateway_mac') or 'unavailable'}",
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
    if details.get("exposure_assessment"):
        lines.append(f"  assessment: {details['exposure_assessment']}")
    reachable = details.get("reachable_services", [])
    if not reachable:
        lines.append("  reachable local services: none detected")
        return lines
    lines.append("  reachable local services:")
    assessment = details.get("exposure_assessment")
    for service in reachable:
        if not service.get("risk"):
            risk_marker = ""
        elif assessment == "expected_home_admin_surface":
            risk_marker = " [expected]"
        elif assessment == "observed_unknown_profile":
            risk_marker = " [review]"
        elif assessment == "untrusted_network_admin_surface":
            risk_marker = " [sensitive]"
        else:
            risk_marker = " [alert]"
        lines.append(f"    - {service['port']}/tcp {service['label']}{risk_marker}")
        http_probe = service.get("http_probe") or {}
        if http_probe.get("url"):
            lines.append(f"      URL: {http_probe['url']}")
        if http_probe.get("status_code") is not None:
            lines.append(f"      status: {http_probe['status_code']}")
        if http_probe.get("content_type"):
            lines.append(f"      content type: {http_probe['content_type']}")
        if http_probe.get("server"):
            lines.append(f"      server: {http_probe['server']}")
        if http_probe.get("location"):
            lines.append(f"      location: {http_probe['location']}")
        if http_probe.get("title"):
            lines.append(f"      title: {http_probe['title']}")
        if http_probe.get("page_hint"):
            lines.append(f"      page hint: {http_probe['page_hint']}")
        if http_probe.get("error"):
            lines.append(f"      probe error: {http_probe['error']}")
    return lines


def format_gateway_reachability_details(details):
    ping = details.get("ping", {})
    lines = [
        f"  gateway: {details.get('gateway_ip')}",
        f"  interface: {details.get('interface')}",
        f"  level: {details.get('level')}",
    ]
    if ping.get("transmitted") is not None:
        lines.append(
            f"  ping: {ping.get('received')}/{ping.get('transmitted')} received"
        )
    if ping.get("loss_percent") is not None:
        lines.append(f"  packet loss: {ping['loss_percent']:.0f}%")
    if ping.get("avg_ms") is not None:
        lines.append(f"  average latency: {ping['avg_ms']:.1f} ms")
    return lines


def format_local_peer_visibility_details(details):
    lines = [
        f"  interface: {details.get('interface')}",
        f"  gateway: {details.get('gateway_ip')}",
    ]
    if details.get("observation_available") is not None:
        lines.append(
            f"  passive observation: {'available' if details['observation_available'] else 'unavailable'}"
        )
    if details.get("inference_confidence"):
        lines.append(f"  inference confidence: {details['inference_confidence']}")
    if details.get("evidence_sources"):
        lines.append(f"  evidence sources: {', '.join(details['evidence_sources'])}")
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    if details.get("visibility_assessment"):
        lines.append(f"  assessment: {details['visibility_assessment']}")
    peers = details.get("visible_peers", [])
    if not peers:
        lines.append("  visible peers: none")
        return lines
    lines.append("  visible peers:")
    for peer in peers[:8]:
        address_suffix = ""
        if peer.get("ipv6_addresses"):
            address_suffix = f" · IPv6: {', '.join(peer['ipv6_addresses'])}"
        elif peer.get("address_family") == "ipv6":
            address_suffix = " · IPv6"
        lines.append(f"    - {peer['ip']} ({peer['mac']}){address_suffix}")
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
    if details.get("peer_observation_available") is not None:
        lines.append(
            f"  passive peer data: {'available' if details['peer_observation_available'] else 'unavailable'}"
        )
    if details.get("inference_confidence"):
        lines.append(f"  inference confidence: {details['inference_confidence']}")
    if details.get("isolation_expected") is not None:
        lines.append(f"  isolation expected: {'yes' if details['isolation_expected'] else 'no'}")
    if details.get("isolation_assessment"):
        lines.append(f"  assessment: {details['isolation_assessment']}")
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
        lines.append(f"  active Wi-Fi interface: {details.get('wifi_interface')}")
    else:
        lines.append("  active Wi-Fi interface: none detected")
    if details.get("interpretation"):
        lines.append(f"  interpretation: {details['interpretation']}")
    if details.get("confidence"):
        lines.append(f"  confidence: {details['confidence']}")
    if details.get("evidence"):
        lines.append(f"  evidence: {details['evidence']}")
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


def format_overall_trust_explanation_details(details):
    lines = []
    if details.get("network_profile"):
        lines.append(f"  network profile: {details['network_profile']}")
    if details.get("context_note"):
        lines.append(f"  context: {details['context_note']}")
    if details.get("profile_expectation"):
        lines.append(f"  profile expectation: {details['profile_expectation']}")
    if details.get("local_segment"):
        lines.append(f"  local segment: {details['local_segment']}")
    if details.get("dns_path"):
        lines.append(f"  DNS path: {details['dns_path']}")
    if details.get("captive_path"):
        lines.append(f"  captive path: {details['captive_path']}")
    if details.get("https_path"):
        lines.append(f"  HTTPS path: {details['https_path']}")
    if details.get("active_path"):
        lines.append(f"  active path: {details['active_path']}")
    if details.get("gateway_reachability"):
        lines.append(f"  gateway reachability: {details['gateway_reachability']}")
    if details.get("affected_components"):
        lines.append(f"  affected components: {', '.join(details['affected_components'])}")
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
            security = format_wifi_security_label(network.get("security"))
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
    overlaps = analysis.get("channel_overlaps", [])
    if overlaps:
        lines.append("  potential channel overlap:")
        for overlap in overlaps[:5]:
            current_marker = " · includes current connection" if overlap.get("includes_current") else ""
            estimate_marker = " · estimated width" if overlap.get("width_estimated") else ""
            lines.append(
                f"    - {overlap['band']} ch {overlap['channel_a']}/{overlap.get('width_a_mhz', 20)}MHz "
                f"({overlap['ssid_a']}) with ch {overlap['channel_b']}/{overlap.get('width_b_mhz', 20)}MHz "
                f"({overlap['ssid_b']}) — {overlap['type']}{current_marker}{estimate_marker}"
            )

    current = details.get("current", {})
    current_interfaces = current.get("interfaces", {})
    if current_interfaces:
        interface_name, connection = next(iter(current_interfaces.items()))
        lines.append("  current connection:")
        lines.append(f"    - interface: {interface_name}")
        for label, key in (("SSID", "ssid"), ("BSSID", "bssid"), ("channel", "channel"), ("RSSI", "rssi"), ("noise", "noise"), ("security", "security"), ("tx rate", "tx_rate"), ("PHY mode", "phy_mode")):
            if connection.get(key) is not None:
                value = connection[key]
                if key == "security":
                    value = format_wifi_security_label(value)
                lines.append(f"    - {label}: {value}")
        signal = assess_wifi_signal(connection.get("rssi"), connection.get("noise"))
        if signal:
            lines.append(f"    - signal assessment: {signal['summary']} (SNR {signal['snr_db']:.0f} dB)")
    if current.get("available") is False and current.get("reason"):
        lines.append(f"  current: unavailable ({current['reason']})")
    return lines


def assess_wifi_signal(rssi, noise):
    """Classify current Wi-Fi radio quality from RSSI, noise, and derived SNR."""
    rssi_value = parse_wifi_number(rssi)
    noise_value = parse_wifi_number(noise)
    if rssi_value is None or noise_value is None:
        return None
    snr = rssi_value - noise_value
    if rssi_value >= -67 and snr >= 25:
        summary = "good signal and low noise"
    elif rssi_value >= -75 and snr >= 15:
        summary = "fair signal; usable but not strong"
    else:
        summary = "weak or noisy signal"
    return {"rssi_dbm": rssi_value, "noise_dbm": noise_value, "snr_db": snr, "summary": summary}


def format_domain_resolution_details(details):
    ips = details.get("ips", [])
    if not ips:
        return []
    return [f"  ips: {', '.join(ips)}"]


def format_http_probe_details(details):
    lines = [f"  status code: {details.get('status_code')}"]
    if details.get("location"):
        lines.append(f"  location: {details['location']}")
    return lines


def format_wifi_stability_details(details):
    lines = [
        f"  level: {details.get('level')}",
        f"  gateway: {details.get('gateway_ip')}",
        f"  samples: {details.get('sample_count')}",
    ]
    if details.get("confidence"):
        lines.append(f"  confidence: {details['confidence']}")
    if details.get("wifi_sample_count") is not None or details.get("ping_sample_count") is not None:
        lines.append(
            f"  coverage: Wi-Fi {details.get('wifi_sample_count', 0)}/{details.get('sample_count', 0)}"
            f" · ping {details.get('ping_sample_count', 0)}/{details.get('sample_count', 0)}"
        )
    if details.get("avg_rssi") is not None:
        lines.append(f"  average RSSI: {details['avg_rssi']:.0f} dBm")
    if details.get("avg_latency_ms") is not None:
        lines.append(f"  average gateway latency: {details['avg_latency_ms']:.1f} ms")
    if details.get("max_latency_ms") is not None:
        lines.append(f"  max gateway latency: {details['max_latency_ms']:.1f} ms")
    if details.get("max_loss_percent") is not None:
        lines.append(f"  max packet loss: {details['max_loss_percent']:.0f}%")
    if details.get("bssid_changes") is not None:
        lines.append(f"  BSSID changes: {details['bssid_changes']}")
    if details.get("reasons"):
        lines.append("  reasons:")
        for reason in details["reasons"]:
            lines.append(f"    - {reason}")
    if details.get("recommendation"):
        lines.append(f"  recommendation: {details['recommendation']}")
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
    if name == "gateway_reachability":
        return format_gateway_reachability_details(details)
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
    if name == "overall_trust_explanation":
        return format_overall_trust_explanation_details(details)
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
        return colorize(format_status_marker("ok"), Fore.GREEN)
    if status == "NOTICE":
        return colorize(format_status_marker("notice"), Fore.YELLOW)
    if status == "ALERT":
        return colorize(format_status_marker("alert"), Fore.RED)
    return colorize("[?]", Fore.YELLOW)


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
    alerts = prioritize_findings(summary.get("alerts", []))
    notices = prioritize_findings(summary.get("notices", []))
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
        elif name == "overall_trust_explanation":
            labels.append("Overall trust")
        else:
            labels.append(format_check_label(name))
    suffix = " ..." if len(alerts) > 4 else ""
    return f"Risk summary: {len(alerts)} alert(s) in {', '.join(labels)}{suffix}"


def format_top_notice_summary(summary):
    notices = prioritize_findings(summary.get("notices", []))
    if not notices:
        return None
    labels = [format_check_label(check["name"]) for check in notices[:4]]
    suffix = " ..." if len(notices) > 4 else ""
    return f"Notice areas: {', '.join(labels)}{suffix}"


def format_notice_reason_labels(summary, limit=3):
    notices = prioritize_findings(summary.get("notices", []))
    if not notices:
        return None
    labels = [format_check_label(check["name"]) for check in notices[:limit]]
    suffix = " ..." if len(notices) > limit else ""
    return f"Primary reasons: {', '.join(labels)}{suffix}"


def format_health_count_summary(summary, include_ok=False):
    parts = [f"Checks: {summary['total_checks']}"]
    if include_ok:
        parts.append(f"OK: {summary['ok_checks']}")
    parts.append(f"Notices: {summary.get('notice_checks', 0)}")
    parts.append(f"Alerts: {summary['alert_checks']}")
    return " | ".join(parts)


def get_finding_priority(check):
    name = check.get("name", "")
    if name.startswith("captive_") and name != "captive_trust_reasoning":
        return 75
    if name.startswith("https_") and name != "https_trust_reasoning":
        return 85
    if name.startswith("dns_") and name != "dns_environment":
        return 66
    return FINDING_PRIORITY.get(name, 500)


def prioritize_findings(checks):
    return sorted(
        checks,
        key=lambda check: (
            get_finding_priority(check),
            format_check_label(check.get("name", "")),
        ),
    )


def select_focus_checks(checks):
    """Return the compact operator-facing subset in a stable risk-first order."""
    alerts = prioritize_findings([check for check in checks if check["status"] == "alert"])
    notices = prioritize_findings([check for check in checks if check["status"] == "notice"])
    baseline = [
        check
        for check in checks
        if check["status"] == "ok" and check["name"] in FOCUS_BASELINE_CHECKS
    ]
    context = [
        check
        for check in checks
        if (
            check["status"] not in {"alert", "notice"}
            and check["name"] in FOCUS_CONTEXT_CHECKS
            and check.get("details")
            and check["status"] != "ok"
        )
    ]
    selected = alerts + notices[:FOCUS_NOTICE_LIMIT] + baseline + context
    deduped = []
    seen = set()
    for check in selected:
        if check["name"] in seen:
            continue
        seen.add(check["name"])
        deduped.append(check)
    hidden_notice_count = max(0, len(notices) - FOCUS_NOTICE_LIMIT)
    return deduped, hidden_notice_count


def build_trust_assessment(summary, scan_context=None):
    alert_count = summary.get("alert_checks", 0)
    notice_count = summary.get("notice_checks", 0)
    network_profile = format_network_profile_label(scan_context)
    notice_names = {check["name"] for check in summary.get("notices", [])}
    if alert_count == 0:
        if network_profile == "untrusted":
            local_segment_notice_count = len(
                notice_names.intersection(
                    {
                        "gateway_exposure",
                        "local_peer_visibility",
                        "client_isolation_hint",
                        "overall_trust_explanation",
                    }
                )
            )
            if local_segment_notice_count >= 2 and (
                "overall_trust_explanation" in notice_names
                or "client_isolation_hint" in notice_names
            ):
                reason_labels = format_notice_reason_labels(summary)
                reason_suffix = f" {reason_labels}." if reason_labels else ""
                return {
                    "level": "suspicious",
                    "summary": (
                        f"No hard alerts are active, but the local segment looks more exposed than expected "
                        f"for an untrusted network.{reason_suffix}"
                    ),
                }
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
    """Indent check details while preserving formatter-defined nesting."""
    if line.startswith("  "):
        return f"    {line[2:]}"
    return f"    {line}"


def format_network_profile_label(scan_context):
    if not scan_context:
        return None
    profile = scan_context.get("network_profile")
    if not profile:
        return None
    return normalize_network_profile(profile)


def build_health_summary_status(summary, assessment):
    """Map health counts and trust assessment to the shared summary status."""
    status_level = (
        "alert" if summary.get("alert_checks") else (
            "notice" if summary.get("notice_checks") else "ok"
        )
    )
    status_message = assessment["level"]
    if summary.get("notice_checks") and not summary.get("alert_checks"):
        status_message += f" · review {summary['notice_checks']} notice(s)"
    return status_level, status_message


def build_health_scan_summary_fields(scan_context, summary, *, include_ok):
    """Build relevant aligned fields for full and focus health reports."""
    scan_context = scan_context or {}
    duration_seconds = scan_context.get("duration_seconds")
    return [
        ("Target", scan_context.get("cidr")),
        ("Interface", scan_context.get("interface")),
        ("Profile", format_network_profile_label(scan_context)),
        (
            "Duration",
            f"{duration_seconds:.1f}s" if duration_seconds is not None else None,
        ),
        (
            "Checks",
            format_health_count_summary(summary, include_ok=include_ok).removeprefix(
                "Checks: "
            ),
        ),
    ]


def format_focus_recommendation(summary, assessment, scan_context=None):
    """Return one concise action line for the operator-facing focus report."""
    profile = format_network_profile_label(scan_context)
    if assessment.get("level") == "untrusted":
        return "Action: avoid sensitive activity until the active alerts are understood."
    if assessment.get("level") == "suspicious":
        if profile == "untrusted":
            return f"Action: treat this {profile} network as untrusted and review the listed exposure."
        return "Action: review the listed finding before trusting this network."
    if summary.get("notice_checks", 0):
        return "Action: review the notices; they may be expected for this network profile."
    return "Action: no active risk signals detected."


def get_focus_detail_limit(check):
    if check["name"] == "overall_trust_explanation":
        return 5
    if check["status"] == "alert":
        return 6
    if check["status"] == "notice":
        return 3
    return 2


def print_wifi_stability_progress(current_step, total_steps, gateway_ip):
    global _wifi_stability_progress_indicator
    if (
        _wifi_stability_progress_indicator is None
        or _wifi_stability_progress_indicator.total != total_steps
    ):
        _wifi_stability_progress_indicator = ProgressIndicator(
            "Wi-Fi stability", total_steps, unit="samples"
        )
    if current_step >= total_steps:
        _wifi_stability_progress_indicator.finish(f"gateway {gateway_ip}")
        _wifi_stability_progress_indicator = None
    else:
        _wifi_stability_progress_indicator.update(
            current_step,
            f"gateway {gateway_ip}",
        )


def print_health_progress(stage, current_step, total_steps):
    """Render the shared progress indicator without polluting the report."""
    global _health_progress_indicator
    if (
        _health_progress_indicator is None
        or _health_progress_indicator.total != total_steps
    ):
        _health_progress_indicator = ProgressIndicator(
            "Network health", total_steps, unit="steps"
        )
    if current_step < total_steps:
        _health_progress_indicator.update(current_step, stage, force=True)


def finish_health_progress():
    """Complete the shared progress line before the final report."""
    global _health_progress_indicator
    if _health_progress_indicator is not None:
        _health_progress_indicator.finish("completed")
        _health_progress_indicator = None


def fail_health_progress():
    """Terminate the shared progress line when collection fails."""
    global _health_progress_indicator
    if _health_progress_indicator is not None:
        _health_progress_indicator.fail()
        _health_progress_indicator = None


def print_health_report(checks, summary, scan_context=None):
    assessment = build_trust_assessment(summary, scan_context=scan_context)
    print_scan_summary(
        build_health_scan_summary_fields(scan_context, summary, include_ok=True),
        status=build_health_summary_status(summary, assessment),
    )
    print(assessment["summary"])
    print(format_top_alert_summary(summary))
    for group_title, group_rows in group_checks(checks):
        print(f"\n{group_title}:")
        for check in group_rows:
            print(f"  {format_check_heading(check)}")
            print(f"    {check['summary']}")
            for line in format_check_details(check):
                print(indent_detail_line(line))


def print_focus_health_report(checks, summary, scan_context=None):
    assessment = build_trust_assessment(summary, scan_context=scan_context)
    print_scan_summary(
        build_health_scan_summary_fields(scan_context, summary, include_ok=False),
        status=build_health_summary_status(summary, assessment),
    )
    print(assessment["summary"])
    print(format_top_alert_summary(summary))
    print(format_focus_recommendation(summary, assessment, scan_context=scan_context))

    key_checks, hidden_notice_count = select_focus_checks(checks)
    for check in key_checks:
        print(f"\n{format_check_heading(check)}")
        print(f"  {check['summary']}")
        for line in format_check_details(check)[: get_focus_detail_limit(check)]:
            print(indent_detail_line(line))
    if hidden_notice_count:
        print(f"\n... {hidden_notice_count} more notice(s); use --output full for complete detail")


def build_wifi_debug_summary(checks):
    wifi_check = next((check for check in checks if check["name"] == "wifi_environment"), None)
    if wifi_check is None:
        return None

    details = wifi_check.get("details", {})
    nearby = details.get("nearby", {})
    analysis = details.get("analysis", {})
    networks = nearby.get("networks", [])
    usable_networks = [
        network for network in networks
        if (
            (network.get("ssid") and network.get("ssid") != "<hidden>")
            or network.get("bssid")
            or network.get("security")
        )
    ]
    current = details.get("current", {})
    current_interfaces = current.get("interfaces", {})
    current_connection = None
    if current_interfaces:
        interface_name, interface_details = next(iter(current_interfaces.items()))
        current_connection = {
            "interface": interface_name,
            "ssid": interface_details.get("ssid"),
            "bssid": interface_details.get("bssid"),
            "channel": interface_details.get("channel"),
            "rssi": interface_details.get("rssi") or interface_details.get("agrctlrssi"),
            "noise": interface_details.get("noise") or interface_details.get("agrctlnoise"),
            "tx_rate": (
                interface_details.get("tx_rate")
                or interface_details.get("last_tx_rate")
                or interface_details.get("lasttxrate")
            ),
            "security": interface_details.get("security"),
            "phy_mode": interface_details.get("phy_mode") or interface_details.get("phymode"),
        }
        current_connection["signal"] = assess_wifi_signal(
            current_connection.get("rssi"), current_connection.get("noise")
        )
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
        "usable_network_count": len(usable_networks),
        "hidden_count": hidden_count,
        "missing_bssid_count": missing_bssid_count,
        "missing_security_count": missing_security_count,
        "current_available": current.get("available"),
        "current_reason": current.get("reason"),
        "current_source": current.get("source", "wdutil"),
        "current_connection": current_connection,
        "likely_os_restriction": likely_os_restriction,
        "sample_networks": usable_networks[:5],
        "channel_overlaps": analysis.get("channel_overlaps", []),
    }


def print_wifi_debug_report(checks):
    debug = build_wifi_debug_summary(checks)
    if debug is None:
        return

    print(f"\n{format_section_heading('Wi-Fi Debug')}")
    if debug.get("current_connection"):
        print("\nCurrent connection:")
        print(f"  Interface: {debug['current_connection'].get('interface') or '-'}")
        print(f"  SSID: {debug['current_connection'].get('ssid') or '<hidden>'}")
        print(f"  BSSID: {debug['current_connection'].get('bssid') or '-'}")
        print(f"  Channel: {debug['current_connection'].get('channel') or '-'}")
        print(f"  RSSI: {debug['current_connection'].get('rssi') or '-'}")
        print(f"  Noise: {debug['current_connection'].get('noise') or '-'}")
        print(f"  Security: {format_wifi_security_label(debug['current_connection'].get('security'))}")
        print(f"  Tx rate: {debug['current_connection'].get('tx_rate') or '-'}")
        print(f"  PHY mode: {debug['current_connection'].get('phy_mode') or '-'}")
        if debug['current_connection'].get("signal"):
            signal = debug['current_connection']["signal"]
            print(f"  Quality: {signal['summary']} · SNR {signal['snr_db']:.0f} dB")
    else:
        print("\nCurrent connection: unavailable")

    print("\nNearby networks:")
    if debug["sample_networks"]:
        for network in debug["sample_networks"]:
            print(
                f"  - {network.get('ssid') or '<hidden>'} · "
                f"BSSID {network.get('bssid') or '-'} · ch {network.get('channel') or '-'} · "
                f"RSSI {network.get('rssi') or '-'} · {format_wifi_security_label(network.get('security'))}"
            )
    else:
        if debug["available"] and debug["network_count"]:
            print(
                f"  Unavailable for analysis: macOS returned {debug['network_count']} "
                "incomplete record(s) without usable identity or security data."
            )
        elif debug.get("reason"):
            print(f"  Unavailable: {debug['reason']}")
        else:
            print("  No nearby networks were returned.")
    if debug["channel_overlaps"]:
        print("  Potential channel overlap:")
        for overlap in debug["channel_overlaps"][:5]:
            current_marker = " · current connection" if overlap.get("includes_current") else ""
            print(
                f"    - {overlap['band']} ch {overlap['channel_a']}/{overlap.get('width_a_mhz', 20)}MHz "
                f"({overlap['ssid_a']}) ↔ ch {overlap['channel_b']}/{overlap.get('width_b_mhz', 20)}MHz "
                f"({overlap['ssid_b']}){current_marker}"
            )



def format_wifi_security_label(value):
    if not value:
        return "unknown"
    normalized = str(value).lower()
    if "wpa2_personal" in normalized:
        return "WPA2 Personal"
    if "wpa3" in normalized:
        return "WPA3"
    if "wpa2" in normalized:
        return "WPA2"
    return str(value).replace("spairport_security_mode_", "").replace("_", " ").title()


def print_alert_report(summary, scan_context=None):
    network_profile = format_network_profile_label(scan_context)
    alerts = summary["alerts"]
    report_summary = dict(summary)
    report_summary.setdefault("alert_checks", len(alerts))
    report_summary.setdefault("notice_checks", len(report_summary.get("notices", [])))
    assessment = build_trust_assessment(report_summary, scan_context=scan_context)
    if "total_checks" in report_summary:
        summary_fields = build_health_scan_summary_fields(
            scan_context,
            report_summary,
            include_ok=False,
        )
    else:
        scan_context = scan_context or {}
        duration_seconds = scan_context.get("duration_seconds")
        summary_fields = [
            ("Target", scan_context.get("cidr")),
            ("Interface", scan_context.get("interface")),
            ("Profile", network_profile),
            (
                "Duration",
                f"{duration_seconds:.1f}s" if duration_seconds is not None else None,
            ),
        ]
    print_scan_summary(
        summary_fields,
        status=build_health_summary_status(report_summary, assessment),
    )
    if not alerts:
        notices = summary.get("notices", [])
        if notices:
            prioritized_notices = prioritize_findings(notices)
            print("No actionable health alerts detected.")
            print(assessment["summary"])
            notice_summary = format_top_notice_summary(summary)
            if notice_summary:
                print(f"{notice_summary} ({len(notices)} total)")
            print("Review notices:")
            for check in prioritized_notices[:NOTICE_REPORT_LIMIT]:
                print(f"- {format_check_label(check['name'])}: {check['summary']}")
            if len(notices) > NOTICE_REPORT_LIMIT:
                print(f"... {len(notices) - NOTICE_REPORT_LIMIT} more notice(s)")
        else:
            print("No actionable health alerts detected.")
        return
    print(assessment["summary"])
    print(format_top_alert_summary(report_summary))
    print(f"Alerts: {len(alerts)}")
    for check in alerts:
        print(f"\n{format_status_badge('ALERT')} {format_check_label(check['name'])}")
        print(check["summary"])


def build_health_markdown_report(scan_context, checks, summary):
    """Build a Markdown report for network health checks."""
    assessment = build_trust_assessment(summary, scan_context=scan_context)
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
        description="Safe network health checks for trusted home and untrusted networks."
    )
    parser.add_argument(
        "--iface",
        type=str,
        help="Interface context for the report. Health probes use the system default route.",
    )
    parser.add_argument(
        "--cidr",
        type=str,
        help="CIDR context for the report. No broad scanning is performed.",
    )
    parser.add_argument(
        "--network-profile",
        default=DEFAULT_NETWORK_PROFILE,
        type=parse_network_profile,
        choices=NETWORK_PROFILES,
        help="Interpret the network as home or untrusted. Defaults to untrusted.",
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
        "--verbose",
        action="store_true",
        help="Show setup and report-save details in addition to the selected report.",
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
    started_at = time.monotonic()
    interface, cidr = resolve_scan_target(args.iface, args.cidr)
    network_profile = normalize_network_profile(args.network_profile)
    scan_context = build_scan_context(
        interface=interface,
        cidr=cidr,
        network_profile=network_profile,
    )
    wifi_stability_seconds = normalize_wifi_stability_seconds(
        getattr(args, "wifi_stability_seconds", 0)
    )
    checks = run_network_health_checks(
        dns_domains=args.dns_domains or DEFAULT_DNS_DOMAINS,
        timeout=args.timeout,
        network_profile=network_profile,
        wifi_stability_seconds=wifi_stability_seconds,
        wifi_stability_progress_callback=(
            print_wifi_stability_progress if wifi_stability_seconds > 0 else None
        ),
        progress_callback=print_health_progress,
    )
    scan_context["duration_seconds"] = time.monotonic() - started_at
    summary = build_health_summary(checks)
    trust_assessment = build_trust_assessment(summary, scan_context=scan_context)
    payload = {
        "scan_context": scan_context,
        "health_checks": checks,
        "health_summary": summary,
        "trust_assessment": trust_assessment,
    }
    return scan_context, checks, summary, payload


def render_health_report(args, checks, summary, scan_context=None):
    """Render health report output and return the appropriate exit code."""
    if args.alerts_only:
        print_alert_report(summary, scan_context=scan_context)
        return 2 if summary["alert_checks"] else 0
    if args.output == "focus":
        print_focus_health_report(checks, summary, scan_context=scan_context)
    else:
        print_health_report(checks, summary, scan_context=scan_context)
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
    args = parse_args()
    if args.alerts_only and args.debug_wifi:
        print("Error: --debug-wifi cannot be combined with --alerts-only.", file=sys.stderr)
        sys.exit(1)
    global MARKDOWN_OUTPUT_FILE
    output_paths = resolve_report_output_paths(args)
    MARKDOWN_OUTPUT_FILE = output_paths["markdown"]
    quiet_output = nullcontext() if args.verbose else redirect_stdout(StringIO())
    try:
        with quiet_output:
            scan_context, checks, summary, payload = run_health_check_collection(args)
    except Exception:
        fail_health_progress()
        raise
    else:
        finish_health_progress()
    with redirect_stdout(StringIO()):
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
    exit_code = render_health_report(args, checks, summary, scan_context=scan_context)
    if args.debug_wifi:
        print_wifi_debug_report(checks)
    if args.verbose:
        print_output_files(
            [
                ("JSON", output_paths["json"]),
                ("Markdown", MARKDOWN_OUTPUT_FILE),
            ]
        )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
