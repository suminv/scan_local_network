import ipaddress
import json
import os
import platform
import re
import subprocess
import socket
import ssl
import time
import urllib.error
import urllib.request

import netifaces

from arp_scanner import LocalMacVendorLookup, get_vendor


DEFAULT_DNS_DOMAINS = ["example.com", "openai.com"]
DEFAULT_NETWORK_PROFILE = "untrusted"
NETWORK_PROFILES = ["home", "untrusted"]
NETWORK_PROFILE_ALIASES = {
    "auto": "untrusted",
    "guest": "untrusted",
    "travel": "untrusted",
    "public": "untrusted",
}
NETWORK_PROFILE_EXPECTATIONS = {
    "home": {
        "gateway_exposure": "often expected on a private/home LAN",
        "peer_visibility": "often normal on a private/home LAN",
        "client_isolation": "typical for a private/home LAN",
        "overall": "home LANs commonly expose peers and gateway-local services to trusted clients",
    },
    "untrusted": {
        "gateway_exposure": "untrusted networks should not expose gateway admin/web surfaces unnecessarily",
        "peer_visibility": "devices visible on an untrusted local segment must be treated as untrusted",
        "client_isolation": "client isolation is desirable but must not be assumed on an untrusted network",
        "overall": "untrusted networks require stricter local-exposure, DNS, and HTTPS expectations",
    },
}
NETWORK_PROFILE_LOCAL_POLICIES = {
    "home": {
        "posture": "trusted_private_lan",
        "isolation_expected": False,
        "isolation_desired": False,
        "recommended_action": "Treat visible peers as expected only when this is your trusted home network",
    },
    "untrusted": {
        "posture": "untrusted_network",
        "isolation_expected": False,
        "isolation_desired": True,
        "recommended_action": "Treat local peers as untrusted and prefer a trusted VPN for sensitive activity",
    },
}
DEFAULT_HTTP_PROBES = [
    {
        "name": "gstatic_204",
        "url": "http://connectivitycheck.gstatic.com/generate_204",
        "expected_status": 204,
        "expected_body_contains": None,
    },
    {
        "name": "apple_captive",
        "url": "http://captive.apple.com/hotspot-detect.html",
        "expected_status": 200,
        "expected_body_contains": "Success",
    },
]
DEFAULT_HTTPS_PROBES = [
    {
        "name": "example_https",
        "url": "https://example.com",
        "expected_statuses": [200],
    },
    {
        "name": "google_204_https",
        "url": "https://www.google.com/generate_204",
        "expected_statuses": [204],
    },
]
DEFAULT_GATEWAY_EXPOSURE_PROBES = [
    {"port": 53, "label": "DNS", "risk": False},
    {"port": 80, "label": "HTTP admin/web", "risk": True},
    {"port": 443, "label": "HTTPS admin/web", "risk": True},
    {"port": 8080, "label": "HTTP alt admin/web", "risk": True},
    {"port": 8443, "label": "HTTPS alt admin/web", "risk": True},
]
MACOS_AIRPORT_SCAN_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
AUXILIARY_WIFI_INTERFACES = {"awdl0", "llw0", "p2p0"}
ACTIVE_WIFI_STATUSES = {
    "spairport_status_active",
    "spairport_status_connected",
    "connected",
    "active",
}
WIFI_WEAK_RSSI_DBM = -75
WIFI_HIGH_GATEWAY_LATENCY_MS = 30
WIFI_UNSTABLE_PACKET_LOSS_PERCENT = 10


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def is_macos():
    return platform.system() == "Darwin"


def run_command(command):
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def get_corewlan_module():
    try:
        import CoreWLAN
    except ImportError as exc:
        return None, str(exc)
    return CoreWLAN, None


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def normalize_network_profile(network_profile):
    network_profile = NETWORK_PROFILE_ALIASES.get(network_profile, network_profile)
    if network_profile in NETWORK_PROFILES:
        return network_profile
    return DEFAULT_NETWORK_PROFILE


def get_profile_expectation(network_profile, topic):
    network_profile = normalize_network_profile(network_profile)
    return NETWORK_PROFILE_EXPECTATIONS.get(network_profile, {}).get(topic)


def get_profile_local_policy(network_profile):
    """Return normalized local-segment expectations for one network profile."""
    network_profile = normalize_network_profile(network_profile)
    return NETWORK_PROFILE_LOCAL_POLICIES[network_profile]


def is_untrusted_profile(network_profile):
    return normalize_network_profile(network_profile) == "untrusted"


def build_profile_context_note(network_profile, topic, fallback=None):
    expectation = get_profile_expectation(network_profile, topic)
    return expectation if expectation is not None else fallback


def build_check(name, status, summary, details=None):
    """Build a normalized health check result."""
    return {
        "name": name,
        "status": status,
        "summary": summary,
        "details": details or {},
    }


def build_probe_reasoning_details(
    hint_level,
    probe_count,
    alert_probe_count=0,
    affected_probes=None,
    context_note=None,
):
    """Build the common details payload for aggregate probe reasoning checks."""
    return {
        "hint_level": hint_level,
        "probe_count": probe_count,
        "alert_probe_count": alert_probe_count,
        "affected_probes": affected_probes or [],
        "context_note": context_note,
    }


def build_dns_reasoning_details(
    hint_level,
    nameservers=None,
    resolver_profile=None,
    risk_count=0,
    resolution_issue_count=0,
    affected_domains=None,
    context_note=None,
):
    """Build the common details payload for DNS trust reasoning checks."""
    return {
        "hint_level": hint_level,
        "nameservers": nameservers or [],
        "resolver_profile": resolver_profile or [],
        "risk_count": risk_count,
        "resolution_issue_count": resolution_issue_count,
        "affected_domains": affected_domains or [],
        "context_note": context_note,
    }


def get_alert_checks(checks):
    """Return checks that carry an actionable alert status."""
    return [check for check in checks if check.get("status") == "alert"]


def build_probe_trust_reasoning_check(
    *,
    name,
    checks,
    probe_prefix,
    no_probe_summary,
    normal_hint,
    normal_summary,
    normal_context_note,
    all_alert_hint,
    all_alert_summary,
    all_alert_context_note,
    partial_alert_hint,
    partial_alert_summary,
    partial_alert_context_note,
):
    """Build a common aggregate trust check for HTTP/HTTPS-style probes."""
    alerts = get_alert_checks(checks)
    if not checks:
        return build_check(
            name,
            "ok",
            no_probe_summary,
            build_probe_reasoning_details("no_probes", 0),
        )

    if not alerts:
        return build_check(
            name,
            "ok",
            normal_summary,
            build_probe_reasoning_details(
                normal_hint,
                len(checks),
                context_note=normal_context_note,
            ),
        )

    alert_names = [check["name"].replace(probe_prefix, "") for check in alerts]
    all_probes_alerted = len(alerts) == len(checks)
    return build_check(
        name,
        "alert",
        all_alert_summary if all_probes_alerted else partial_alert_summary,
        build_probe_reasoning_details(
            all_alert_hint if all_probes_alerted else partial_alert_hint,
            len(checks),
            alert_probe_count=len(alerts),
            affected_probes=alert_names,
            context_note=(
                all_alert_context_note
                if all_probes_alerted
                else partial_alert_context_note
            ),
        ),
    )


def get_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways["default"][netifaces.AF_INET]
    gateway_ip, interface = default_gateway[0], default_gateway[1]
    return gateway_ip, interface


def resolve_gateway_identity():
    gateway_ip, interface = get_default_gateway()
    try:
        hostname, _, _ = socket.gethostbyaddr(gateway_ip)
    except (socket.herror, socket.gaierror, OSError):
        hostname = None

    return build_check(
        "gateway_identity",
        "ok" if not is_public_ip(gateway_ip) else "alert",
        (
            f"Default gateway {gateway_ip} on {interface}"
            if hostname is None
            else f"Default gateway {gateway_ip} ({hostname}) on {interface}"
        ),
        {
            "gateway_ip": gateway_ip,
            "interface": interface,
            "hostname": hostname,
            "is_public_ip": is_public_ip(gateway_ip),
        },
    )


def extract_html_title(body):
    """Extract a short HTML title from a response body when available."""
    if not body:
        return None
    match = re.search(r"<title>\s*(.*?)\s*</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title or None


def extract_body_hint(body):
    """Return a compact fingerprint hint derived from a short HTML/body preview."""
    if not body:
        return None
    lowered = body.lower()
    if "<!doctype html" in lowered:
        if "serving your web app in a path other than the root" in lowered:
            return "single-page app shell"
        return "html document"
    if "<html" in lowered:
        return "html response"
    if body.lstrip().startswith("{"):
        return "json response"
    return None


def probe_tcp_service(host, port, timeout=2):
    """Return True when a TCP service accepts a connection on the target host/port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def inspect_gateway_http_surface(host, port, timeout=2):
    """Fetch lightweight HTTP/HTTPS metadata for a reachable gateway web surface."""
    scheme = "https" if port in [443, 8443] else "http"
    context = ssl._create_unverified_context() if scheme == "https" else None
    url = f"{scheme}://{host}:{port}/"
    try:
        response = fetch_url(url, timeout=timeout, context=context)
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        return {"url": url, "error": str(exc)}
    headers = response.get("headers", {})
    return {
        "url": url,
        "status_code": response.get("status_code"),
        "server": headers.get("Server"),
        "location": headers.get("Location"),
        "content_type": headers.get("Content-Type"),
        "title": extract_html_title(response.get("body")),
        "page_hint": extract_body_hint(response.get("body")),
        "body_preview": response.get("body"),
    }


def collect_gateway_exposure(timeout=2, probes=None):
    """Collect reachable service observations from the default gateway."""
    gateway_ip, interface = get_default_gateway()
    is_private_gateway = not is_public_ip(gateway_ip)
    reachable_services = []
    risky_services = []

    for probe in probes or DEFAULT_GATEWAY_EXPOSURE_PROBES:
        if not probe_tcp_service(gateway_ip, probe["port"], timeout=timeout):
            continue
        service = {
            "port": probe["port"],
            "label": probe["label"],
            "risk": probe["risk"],
        }
        if probe["port"] in [80, 443, 8080, 8443]:
            service["http_probe"] = inspect_gateway_http_surface(
                gateway_ip,
                probe["port"],
                timeout=timeout,
            )
        reachable_services.append(service)
        if probe["risk"]:
            risky_services.append(service)

    return {
        "gateway_ip": gateway_ip,
        "interface": interface,
        "is_private_gateway": is_private_gateway,
        "reachable_services": reachable_services,
        "risky_services": risky_services,
    }


def analyze_gateway_exposure(observation, network_profile=DEFAULT_NETWORK_PROFILE):
    """Interpret collected gateway services for the selected network profile."""
    network_profile = normalize_network_profile(network_profile)
    profile_policy = get_profile_local_policy(network_profile)
    gateway_ip = observation["gateway_ip"]
    interface = observation["interface"]
    is_private_gateway = observation["is_private_gateway"]
    reachable_services = observation.get("reachable_services", [])
    risky_services = observation.get("risky_services", [])

    if risky_services:
        if not is_private_gateway:
            status = "alert"
            summary = (
                f"Gateway exposes {len(risky_services)} local web/admin service(s) "
                f"to the client on {gateway_ip}"
            )
        else:
            status = "ok" if network_profile == "home" else "notice"
            if network_profile == "untrusted":
                summary = (
                    f"Private/local gateway exposes {len(risky_services)} local web/admin service(s) "
                    f"to the client on {gateway_ip}; treat this as sensitive on an untrusted network"
                )
            elif network_profile == "home":
                summary = (
                    f"Private/local gateway exposes {len(risky_services)} local web/admin service(s) "
                    f"to the client on {gateway_ip}; this is expected for the selected home profile"
                )
            else:
                summary = (
                    f"Private/local gateway exposes {len(risky_services)} local web/admin service(s) "
                    f"to the client on {gateway_ip}; this is often expected on a home LAN"
                )
    elif reachable_services:
        status = "ok"
        summary = (
            f"Gateway exposes {len(reachable_services)} expected local service(s) "
            f"to the client on {gateway_ip}"
        )
    else:
        status = "ok"
        summary = f"No common local gateway services responded on {gateway_ip}"

    return {
        "name": "gateway_exposure",
        "status": status,
        "summary": summary,
        "details": {
            "gateway_ip": gateway_ip,
            "interface": interface,
            "network_profile": network_profile,
            "profile_posture": profile_policy["posture"],
            "recommended_action": profile_policy["recommended_action"],
            "is_private_gateway": is_private_gateway,
            "context_note": (
                build_profile_context_note(network_profile, "gateway_exposure")
                if is_private_gateway and risky_services and is_untrusted_profile(network_profile)
                else (
                    build_profile_context_note(
                        network_profile,
                        "gateway_exposure",
                        fallback="often expected on a private/home LAN",
                    )
                    if is_private_gateway and risky_services
                    else None
                )
            ),
            "profile_expectation": build_profile_context_note(
                network_profile,
                "gateway_exposure",
            ),
            "exposure_assessment": (
                "public_gateway_surface"
                if risky_services and not is_private_gateway
                else "expected_home_admin_surface"
                if risky_services and network_profile == "home"
                else "untrusted_network_admin_surface"
                if risky_services and network_profile == "untrusted"
                else "observed_unknown_profile"
                if risky_services
                else "no_admin_surface_observed"
            ),
            "reachable_services": reachable_services,
            "risky_services": risky_services,
        },
    }


def build_gateway_exposure_check(timeout=2, probes=None, network_profile=DEFAULT_NETWORK_PROFILE):
    """Collect and interpret a bounded set of default-gateway services."""
    observation = collect_gateway_exposure(timeout=timeout, probes=probes)
    return analyze_gateway_exposure(observation, network_profile=network_profile)


def normalize_mac_address(value):
    """Normalize one- or two-digit MAC octets for display and identity matching."""
    text = str(value or "").strip().lower()
    parts = text.split(":")
    if len(parts) == 6 and all(re.fullmatch(r"[0-9a-f]{1,2}", part) for part in parts):
        return ":".join(part.zfill(2) for part in parts)
    return text


def parse_arp_cache_entries(raw_output):
    """Parse `arp -an` output into structured entries."""
    entries = []
    pattern = re.compile(
        r"\?\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>\S+)\s+on\s+(?P<interface>\S+)"
    )
    for line in raw_output.splitlines():
        match = pattern.search(line.strip())
        if not match:
            continue
        mac = match.group("mac")
        if mac == "(incomplete)":
            continue
        entries.append(
            {
                "ip": match.group("ip"),
                "mac": normalize_mac_address(mac),
                "interface": match.group("interface"),
            }
        )
    return entries


def parse_ipv6_neighbor_entries(raw_output):
    """Parse macOS `ndp -an` and Linux `ip -6 neigh` cache output."""
    entries = []
    mac_pattern = re.compile(r"^[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}$")
    linux_pattern = re.compile(
        r"^(?P<ip>\S+)\s+dev\s+(?P<interface>\S+)(?:\s+lladdr\s+(?P<mac>[0-9a-fA-F:]+))?(?P<rest>.*)$"
    )
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("neighbor"):
            continue

        linux_match = linux_pattern.match(line)
        if linux_match:
            mac = linux_match.group("mac")
            rest = linux_match.group("rest")
            if not mac or "FAILED" in rest or "INCOMPLETE" in rest:
                continue
            entries.append(
                {
                    "ip": linux_match.group("ip").split("%", 1)[0],
                    "mac": normalize_mac_address(mac),
                    "interface": linux_match.group("interface"),
                    "is_router": " router " in f" {rest.lower()} ",
                    "address_family": "ipv6",
                }
            )
            continue

        tokens = line.split()
        if not tokens:
            continue
        scoped_ip = tokens[0]
        ip_text, _, scoped_interface = scoped_ip.partition("%")
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if address.version != 6:
            continue
        mac_index = next(
            (index for index, token in enumerate(tokens) if mac_pattern.match(token)),
            None,
        )
        if mac_index is None:
            continue
        interface = scoped_interface or (
            tokens[mac_index + 1] if len(tokens) > mac_index + 1 else None
        )
        if not interface:
            continue
        flags = tokens[mac_index + 2 :]
        entries.append(
            {
                "ip": ip_text,
                "mac": normalize_mac_address(tokens[mac_index]),
                "interface": interface,
                "is_router": any(flag == "R" for flag in flags),
                "address_family": "ipv6",
            }
        )
    return entries


def collect_passive_neighbor_entries():
    """Read available IPv4 and IPv6 neighbor tables without sending traffic."""
    entries = []
    available_sources = []
    try:
        entries.extend(parse_arp_cache_entries(run_command(["arp", "-an"])))
        available_sources.append("arp")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    try:
        ipv6_output = run_command(["ndp", "-an"])
        entries.extend(parse_ipv6_neighbor_entries(ipv6_output))
        available_sources.append("ndp")
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            ipv6_output = run_command(["ip", "-6", "neigh", "show"])
            entries.extend(parse_ipv6_neighbor_entries(ipv6_output))
            available_sources.append("ip-neigh")
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    return {
        "available": bool(available_sources),
        "sources": available_sources,
        "entries": entries,
    }


def collect_local_interface_identities():
    """Collect this host's IP and MAC identities across every local interface."""
    local_ips = set()
    local_macs = set()
    try:
        interfaces = netifaces.interfaces()
    except (OSError, ValueError):
        interfaces = []

    for interface in interfaces:
        try:
            addresses = netifaces.ifaddresses(interface)
        except (OSError, ValueError):
            continue
        for family in (netifaces.AF_INET, netifaces.AF_INET6):
            for entry in addresses.get(family, []):
                address = normalize_ip_for_compare(entry.get("addr"))
                if address:
                    local_ips.add(address)
        for entry in addresses.get(netifaces.AF_LINK, []):
            mac = normalize_mac_address(entry.get("addr"))
            if mac:
                local_macs.add(mac)
    return {"ips": local_ips, "macs": local_macs}


def collect_local_peer_visibility():
    """Collect passive local-peer observations from OS neighbor caches."""
    gateway_ip, interface = get_default_gateway()
    is_private_gateway = not is_public_ip(gateway_ip)
    neighbor_observation = collect_passive_neighbor_entries()
    if not neighbor_observation["available"]:
        return {
            "available": False,
            "interface": interface,
            "gateway_ip": gateway_ip,
            "is_private_gateway": is_private_gateway,
            "evidence_sources": [],
            "visible_peers": [],
        }

    visible_peers = []
    peers_by_mac = {}
    local_identities = collect_local_interface_identities()
    excluded_local_entries = 0
    for entry in neighbor_observation["entries"]:
        if entry["interface"] != interface:
            continue
        if entry["ip"] == gateway_ip:
            continue
        try:
            ip_obj = ipaddress.ip_address(entry["ip"])
        except ValueError:
            continue
        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
            continue
        if entry.get("is_router"):
            continue
        if ip_obj.version == 4 and (ip_obj.is_link_local or not ip_obj.is_private):
            continue

        normalized_mac = normalize_mac_address(entry["mac"])
        if entry["ip"] in local_identities["ips"] or normalized_mac in local_identities["macs"]:
            excluded_local_entries += 1
            continue
        identity = normalized_mac
        existing = peers_by_mac.get(identity)
        if existing is None:
            peer = {
                "ip": entry["ip"],
                "mac": normalized_mac,
                "interface": entry["interface"],
            }
            if ip_obj.version == 6:
                peer["address_family"] = "ipv6"
            peers_by_mac[identity] = peer
            visible_peers.append(peer)
        elif ip_obj.version == 6:
            existing.setdefault("ipv6_addresses", []).append(entry["ip"])

    return {
        "available": True,
        "interface": interface,
        "gateway_ip": gateway_ip,
        "is_private_gateway": is_private_gateway,
        "evidence_sources": neighbor_observation["sources"],
        "excluded_local_entries": excluded_local_entries,
        "visible_peers": visible_peers,
    }


def analyze_local_peer_visibility(observation, network_profile=DEFAULT_NETWORK_PROFILE):
    """Interpret passive local-peer visibility for the selected profile."""
    network_profile = normalize_network_profile(network_profile)
    profile_policy = get_profile_local_policy(network_profile)
    interface = observation["interface"]
    gateway_ip = observation["gateway_ip"]
    is_private_gateway = observation["is_private_gateway"]
    visible_peers = observation.get("visible_peers", [])
    evidence_sources = observation.get("evidence_sources", ["arp"])

    if not observation.get("available", True):
        return {
            "name": "local_peer_visibility",
            "status": "notice" if is_untrusted_profile(network_profile) else "ok",
            "summary": (
                "Passive IPv4/IPv6 neighbor-cache inspection is unavailable; local peer visibility and client isolation cannot be assessed"
            ),
            "details": {
                "interface": interface,
                "gateway_ip": gateway_ip,
                "network_profile": network_profile,
                "profile_posture": profile_policy["posture"],
                "recommended_action": profile_policy["recommended_action"],
                "is_private_gateway": is_private_gateway,
                "observation_available": False,
                "evidence_sources": evidence_sources,
                "inference_confidence": "none",
                "visibility_assessment": "unavailable",
                "visible_peers": [],
            },
        }

    if visible_peers:
        status = "ok" if network_profile == "home" else "notice"
        if network_profile == "untrusted":
            summary = (
                f"Passive neighbor caches already show {len(visible_peers)} local peer(s) besides the gateway on {interface}; "
                "treat local peers as untrusted on this network"
            )
        elif network_profile == "home":
            summary = (
                f"Passive neighbor caches show {len(visible_peers)} local peer(s) besides the gateway on {interface}; "
                "peer visibility is normal for this home network profile"
            )
        else:
            summary = (
                f"Passive neighbor caches show {len(visible_peers)} local peer(s) besides the gateway on {interface}"
            )
    else:
        status = "ok"
        if network_profile == "untrusted":
            summary = (
                f"No local peers were observed in the passive neighbor caches on {interface}; "
                "do not assume this untrusted network isolates clients"
            )
        elif network_profile == "home":
            summary = (
                f"No additional local peers are currently visible in the passive neighbor caches on {interface}; "
                "client isolation is not expected for this home profile"
            )
        else:
            summary = (
                f"No additional local peers are currently visible in the passive neighbor caches on {interface}; "
                "absence of observations does not confirm client isolation"
            )

    return {
        "name": "local_peer_visibility",
        "status": status,
        "summary": summary,
        "details": {
            "interface": interface,
            "gateway_ip": gateway_ip,
            "network_profile": network_profile,
            "profile_posture": profile_policy["posture"],
            "recommended_action": profile_policy["recommended_action"],
            "is_private_gateway": is_private_gateway,
            "observation_available": True,
            "evidence_sources": evidence_sources,
            "inference_confidence": "observed" if visible_peers else "inconclusive",
            "context_note": (
                build_profile_context_note(network_profile, "peer_visibility")
                if visible_peers and is_untrusted_profile(network_profile)
                else (
                    build_profile_context_note(
                        network_profile,
                        "peer_visibility",
                        fallback="often normal on a private/home LAN",
                    )
                    if is_private_gateway and visible_peers
                    else None
                )
            ),
            "profile_expectation": build_profile_context_note(
                network_profile,
                "peer_visibility",
            ),
            "visibility_assessment": (
                "expected_home_visibility"
                if visible_peers and network_profile == "home"
                else "untrusted_network_visibility"
                if visible_peers and network_profile == "untrusted"
                else "observed_unknown_profile"
                if visible_peers
                else "no_peers_observed"
            ),
            "visible_peers": visible_peers,
        },
    }


def build_local_peer_visibility_check(network_profile=DEFAULT_NETWORK_PROFILE):
    """Collect and interpret passive local-peer visibility."""
    observation = collect_local_peer_visibility()
    return analyze_local_peer_visibility(
        observation,
        network_profile=network_profile,
    )


def build_client_isolation_hint_check(
    gateway_exposure_check,
    local_peer_visibility_check,
    network_profile=DEFAULT_NETWORK_PROFILE,
):
    """Summarize whether the current segment appears to expose peer devices to the client."""
    network_profile = normalize_network_profile(network_profile)
    profile_policy = get_profile_local_policy(network_profile)
    exposure_details = gateway_exposure_check.get("details", {})
    peer_details = local_peer_visibility_check.get("details", {})
    interface = peer_details.get("interface") or exposure_details.get("interface")
    gateway_ip = peer_details.get("gateway_ip") or exposure_details.get("gateway_ip")
    is_private_gateway = peer_details.get("is_private_gateway")
    if is_private_gateway is None:
        is_private_gateway = exposure_details.get("is_private_gateway")
    visible_peers = peer_details.get("visible_peers", [])
    peer_observation_available = peer_details.get("observation_available", True)
    risky_services = exposure_details.get("risky_services", [])

    if not peer_observation_available:
        status = "notice" if is_untrusted_profile(network_profile) else "ok"
        hint_level = "visibility_unavailable"
        summary = (
            f"Client isolation cannot be assessed on {interface} because passive peer visibility data is unavailable"
        )
    elif visible_peers:
        status = "ok" if network_profile == "home" else "notice"
        hint_level = "peer_visibility_detected"
        if network_profile == "untrusted":
            summary = (
                f"Local peers are already visible to this client on {interface}; on this untrusted network, "
                "treat the local segment as untrusted and assume client isolation is absent or relaxed"
            )
        elif network_profile == "home":
            summary = (
                f"Local peers are visible to this client on {interface}; client isolation is not expected "
                "for the selected home profile, so this is normal"
            )
        elif is_private_gateway:
            summary = (
                f"Local peers are already visible to this client on {interface}; this is typical "
                "for a private/home LAN, but select --network-profile home to mark it as expected"
            )
        else:
            summary = (
                f"Local peers are already visible to this client on {interface}; client isolation "
                "is likely absent or relaxed on the current segment"
            )
    elif risky_services:
        status = "ok"
        hint_level = "gateway_only_visibility"
        if is_untrusted_profile(network_profile):
            summary = (
                f"Only gateway-local services are visible on {interface}; no peers were observed, "
                "but passive ARP data does not confirm client isolation"
            )
        elif is_private_gateway:
            summary = (
                f"Only gateway-local services are visible on {interface}; no passive peer "
                "visibility has been observed yet on this private/home LAN"
            )
        else:
            summary = (
                f"Only gateway-local services are visible on {interface}; no passive peer "
                "visibility has been observed yet"
            )
    else:
        status = "ok"
        hint_level = "no_peer_visibility"
        summary = (
            f"No local peers were observed on {interface}; passive ARP evidence alone cannot confirm client isolation"
        )

    return {
        "name": "client_isolation_hint",
        "status": status,
        "summary": summary,
        "details": {
            "interface": interface,
            "gateway_ip": gateway_ip,
            "network_profile": network_profile,
            "profile_posture": profile_policy["posture"],
            "recommended_action": profile_policy["recommended_action"],
            "is_private_gateway": bool(is_private_gateway),
            "peer_observation_available": peer_observation_available,
            "inference_confidence": (
                "none"
                if not peer_observation_available
                else "observed"
                if visible_peers
                else "inconclusive"
            ),
            "hint_level": hint_level,
            "isolation_expected": profile_policy["isolation_expected"],
            "isolation_desired": profile_policy["isolation_desired"],
            "isolation_assessment": (
                "not_assessed"
                if not peer_observation_available
                else "not_expected_home"
                if visible_peers and network_profile == "home"
                else "untrusted_segment"
                if visible_peers and network_profile == "untrusted"
                else "unknown"
                if visible_peers
                else "possible_not_confirmed"
            ),
            "visible_peer_count": len(visible_peers),
            "visible_peers": visible_peers[:8],
            "risky_gateway_service_count": len(risky_services),
            "context_note": (
                build_profile_context_note(network_profile, "client_isolation")
                if hint_level == "peer_visibility_detected" and is_untrusted_profile(network_profile)
                else (
                    build_profile_context_note(
                        network_profile,
                        "client_isolation",
                        fallback="typical for a private/home LAN",
                    )
                    if is_private_gateway and hint_level == "peer_visibility_detected"
                    else None
                )
            ),
            "profile_expectation": build_profile_context_note(
                network_profile,
                "client_isolation",
            ),
        },
    }


def lookup_arp_mac(ip, interface=None):
    try:
        output = run_command(["arp", "-an"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    pattern = re.compile(
        r"^\?\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+|\(incomplete\))\s+on\s+(?P<iface>\S+)"
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        if match.group("ip") != ip:
            continue
        if interface and match.group("iface") != interface:
            continue
        mac = match.group("mac")
        if mac == "(incomplete)":
            return None
        return normalize_mac_address(mac)
    return None


def resolve_gateway_fingerprint(mac_lookup=None):
    gateway_ip, interface = get_default_gateway()
    gateway_mac = lookup_arp_mac(gateway_ip, interface=interface)
    vendor = "Unknown"
    if gateway_mac:
        mac_lookup = mac_lookup or LocalMacVendorLookup()
        vendor = get_vendor(gateway_mac, mac_lookup)

    return {
        "name": "gateway_fingerprint",
        "status": "ok" if gateway_mac else "alert",
        "summary": (
            f"Gateway MAC {gateway_mac} ({vendor}) detected for {gateway_ip}"
            if gateway_mac
            else f"Gateway MAC address for {gateway_ip} is not present in the local ARP cache"
        ),
        "details": {
            "gateway_ip": gateway_ip,
            "interface": interface,
            "gateway_mac": gateway_mac,
            "vendor": vendor,
        },
    }


def resolve_domain_ips(domain):
    infos = socket.getaddrinfo(domain, None)
    ips = sorted({item[4][0] for item in infos})
    return ips


def collect_dns_resolution_observations(domains=None):
    """Resolve configured domains and retain only raw addresses or errors."""
    observations = []
    for domain in domains or DEFAULT_DNS_DOMAINS:
        try:
            ips = resolve_domain_ips(domain)
        except socket.gaierror as exc:
            observations.append({"domain": domain, "error": str(exc)})
            continue
        observations.append({"domain": domain, "ips": ips})
    return observations


def analyze_dns_resolution_observation(observation):
    """Interpret one collected domain-resolution observation."""
    domain = observation["domain"]
    if observation.get("error") is not None:
        return build_check(
            f"dns_{domain}",
            "alert",
            f"DNS lookup failed for {domain}",
            {"domain": domain, "error": observation["error"]},
        )

    ips = observation.get("ips", [])
    public_ips = [ip for ip in ips if is_public_ip(ip)]
    if not public_ips:
        return build_check(
            f"dns_{domain}",
            "alert",
            f"{domain} resolved only to non-public addresses",
            {"domain": domain, "ips": ips},
        )

    return build_check(
        f"dns_{domain}",
        "ok",
        f"{domain} resolved to {len(public_ips)} public address(es)",
        {"domain": domain, "ips": ips},
    )


def run_dns_consistency_checks(domains=None):
    """Collect and interpret configured DNS resolution probes."""
    return [
        analyze_dns_resolution_observation(observation)
        for observation in collect_dns_resolution_observations(domains)
    ]


def parse_scutil_dns(raw_text):
    resolvers = []
    current = None
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if line.startswith("resolver #"):
            if current:
                resolvers.append(current)
            current = {"nameservers": []}
            continue
        if current is None:
            continue
        if line.startswith("nameserver["):
            _, value = line.split(":", 1)
            current["nameservers"].append(value.strip())
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()
    if current:
        resolvers.append(current)
    return resolvers


def parse_resolv_conf(raw_text):
    nameservers = []
    search_domains = []
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("nameserver "):
            nameservers.append(line.split(None, 1)[1].strip())
        elif line.startswith("search "):
            search_domains.extend(line.split()[1:])
    return {"nameservers": nameservers, "search_domains": search_domains}


def collect_dns_configuration():
    try:
        scutil_output = run_command(["scutil", "--dns"])
        resolvers = parse_scutil_dns(scutil_output)
        nameservers = []
        for resolver in resolvers:
            nameservers.extend(resolver.get("nameservers", []))
        nameservers = list(dict.fromkeys(nameservers))
        if nameservers:
            return {
                "source": "scutil",
                "nameservers": nameservers,
                "resolvers": resolvers,
            }
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
            resolv = parse_resolv_conf(handle.read())
    except OSError as exc:
        return {
            "source": "unavailable",
            "nameservers": [],
            "resolvers": [],
            "error": str(exc),
        }

    return {
        "source": "resolv.conf",
        "nameservers": resolv["nameservers"],
        "search_domains": resolv["search_domains"],
        "resolvers": [],
    }


def parse_interface_index(value):
    if not value:
        return None
    match = re.match(r"^(\d+)\s+\(([^)]+)\)$", value)
    if match:
        return {"index": int(match.group(1)), "interface": match.group(2)}
    return {"index": None, "interface": value}


def normalize_ip_for_compare(ip):
    return ip.split("%", 1)[0] if isinstance(ip, str) else ip


def get_interface_networks(interface):
    networks = []
    try:
        addresses = netifaces.ifaddresses(interface)
    except ValueError:
        return networks

    for family in [netifaces.AF_INET, netifaces.AF_INET6]:
        for entry in addresses.get(family, []):
            addr = normalize_ip_for_compare(entry.get("addr"))
            netmask = normalize_ip_for_compare(entry.get("netmask"))
            if not addr or not netmask:
                continue
            try:
                network = ipaddress.ip_network(f"{addr}/{netmask}", strict=False)
            except ValueError:
                continue
            networks.append(network)
    return networks


def is_on_interface_network(ip, interface):
    return is_on_networks(ip, get_interface_networks(interface))


def is_on_networks(ip, networks):
    """Return whether an address belongs to one of the supplied interface networks."""
    try:
        address = ipaddress.ip_address(normalize_ip_for_compare(ip))
    except ValueError:
        return False
    return any(address in network for network in networks)


def classify_dns_server(
    server,
    resolver=None,
    default_interface=None,
    gateway_ip=None,
    interface_networks=None,
):
    normalized_server = normalize_ip_for_compare(server)
    normalized_gateway = normalize_ip_for_compare(gateway_ip)
    if normalized_gateway and normalized_server == normalized_gateway:
        return {
            "server": server,
            "classification": "gateway_dns",
            "risk": False,
            "reason": "DNS server matches the default gateway address",
        }

    try:
        address = ipaddress.ip_address(normalized_server)
    except ValueError:
        return {
            "server": server,
            "classification": "invalid",
            "risk": True,
            "reason": "DNS server is not a valid IP address",
        }

    if resolver and default_interface:
        interface_info = parse_interface_index(resolver.get("if_index"))
        reach = resolver.get("reach", "")
        resolver_interface = interface_info.get("interface") if interface_info else None
        if (
            resolver_interface
            and resolver_interface != default_interface
            and "Reachable" in reach
        ):
            return {
                "server": server,
                "classification": "resolver_interface_mismatch",
                "risk": True,
                "severity": "notice",
                "reason": (
                    f"DNS resolver is associated with {resolver_interface}, while the default route "
                    f"uses {default_interface}; this may be intentional VPN or split-DNS routing"
                ),
            }

    if address.is_private or address.is_loopback or address.is_link_local:
        return {
            "server": server,
            "classification": "local_private",
            "risk": False,
            "reason": "DNS server is a private or link-local address",
        }

    if default_interface:
        networks = (
            get_interface_networks(default_interface)
            if interface_networks is None
            else interface_networks
        )
    else:
        networks = []
    if networks and is_on_networks(server, networks):
        return {
            "server": server,
            "classification": "on_link",
            "risk": False,
            "reason": f"DNS server is on-link for interface {default_interface}",
        }

    if resolver:
        interface_info = parse_interface_index(resolver.get("if_index"))
        reach = resolver.get("reach", "")
        if (
            interface_info
            and interface_info.get("interface") == default_interface
            and "Directly Reachable Address" in reach
        ):
            return {
                "server": server,
                "classification": "directly_reachable",
                "risk": False,
                "reason": f"DNS server is directly reachable on {default_interface}",
            }

    if address.is_global:
        return {
            "server": server,
            "classification": "public_upstream",
            "risk": True,
            "severity": "notice",
            "reason": "system resolver points directly at a global address",
        }

    return {
        "server": server,
        "classification": "unknown",
        "risk": False,
        "reason": "DNS server did not match a known risky pattern",
    }


def analyze_dns_servers(
    nameservers,
    resolvers=None,
    default_interface=None,
    gateway_ip=None,
    interface_networks=None,
):
    resolvers = resolvers or []
    risks = []
    classifications = []
    for server in nameservers:
        matching_resolver = next(
            (resolver for resolver in resolvers if server in resolver.get("nameservers", [])),
            None,
        )
        classification = classify_dns_server(
            server,
            resolver=matching_resolver,
            default_interface=default_interface,
            gateway_ip=gateway_ip,
            interface_networks=interface_networks,
        )
        classifications.append(classification)
        if classification["risk"]:
            risks.append(
                {
                    "type": classification["classification"],
                    "server": server,
                    "reason": classification["reason"],
                    "severity": classification.get("severity", "alert"),
                }
            )
    return {
        "server_count": len(nameservers),
        "classifications": classifications,
        "risks": risks,
    }


def collect_dns_environment_observation():
    """Collect resolver configuration and the active route context."""
    dns_config = collect_dns_configuration()
    gateway_ip, default_interface = get_default_gateway()
    return {
        "configuration": dns_config,
        "gateway_ip": gateway_ip,
        "default_interface": default_interface,
        "interface_networks": get_interface_networks(default_interface),
    }


def analyze_dns_environment(observation):
    """Classify a collected DNS configuration without reading system state."""
    dns_config = dict(observation["configuration"])
    nameservers = dns_config.get("nameservers", [])
    analysis = analyze_dns_servers(
        nameservers,
        resolvers=dns_config.get("resolvers", []),
        default_interface=observation.get("default_interface"),
        gateway_ip=observation.get("gateway_ip"),
        interface_networks=observation.get("interface_networks", []),
    )
    dns_config["analysis"] = analysis

    if not nameservers:
        return build_check(
            "dns_environment",
            "alert",
            "No DNS servers could be determined from the current environment",
            dns_config,
        )

    alert_risks = [risk for risk in analysis["risks"] if risk.get("severity", "alert") == "alert"]
    if alert_risks:
        return build_check(
            "dns_environment",
            "alert",
            f"DNS environment exposes {len(alert_risks)} risk signal(s)",
            dns_config,
        )

    if analysis["risks"]:
        return build_check(
            "dns_environment",
            "notice",
            f"DNS configuration contains {len(analysis['risks'])} resolver setting(s) to review",
            dns_config,
        )

    return build_check(
        "dns_environment",
        "ok",
        f"Detected {len(nameservers)} DNS server(s) from {dns_config['source']}",
        dns_config,
    )


def build_dns_environment_check():
    """Collect and interpret the current DNS environment."""
    observation = collect_dns_environment_observation()
    return analyze_dns_environment(observation)


def build_dns_trust_reasoning_check(dns_environment_check, dns_resolution_checks):
    """Summarize DNS trust posture from resolver classification and domain lookups."""
    details = dns_environment_check.get("details", {})
    analysis = details.get("analysis", {})
    classifications = analysis.get("classifications", [])
    nameservers = details.get("nameservers", [])
    classification_types = [item.get("classification") for item in classifications]
    resolution_alerts = get_alert_checks(dns_resolution_checks)
    risk_count = len(analysis.get("risks", []))

    if not nameservers:
        return build_check(
            "dns_trust_reasoning",
            "notice",
            "DNS trust cannot be assessed because no active DNS servers were detected",
            build_dns_reasoning_details("dns_unavailable"),
        )

    if resolution_alerts:
        return build_check(
            "dns_trust_reasoning",
            "alert",
            f"DNS trust is degraded: {len(resolution_alerts)} domain lookup issue(s) were observed",
            build_dns_reasoning_details(
                "resolution_failure",
                nameservers=nameservers,
                resolver_profile=classification_types,
                risk_count=risk_count,
                resolution_issue_count=len(resolution_alerts),
                affected_domains=[
                    check.get("details", {}).get("domain")
                    for check in resolution_alerts
                    if check.get("details", {}).get("domain")
                ],
                context_note="public name resolution did not behave normally",
            ),
        )

    if "resolver_interface_mismatch" in classification_types:
        return build_check(
            "dns_trust_reasoning",
            "notice",
            "DNS is reachable through a different interface than the current default route",
            build_dns_reasoning_details(
                "dns_route_mismatch",
                nameservers=nameservers,
                resolver_profile=classification_types,
                risk_count=risk_count,
                context_note="review active VPN, split-DNS, Ethernet, and Wi-Fi routing before treating this as suspicious",
            ),
        )

    if "public_upstream" in classification_types:
        local_classes = {"gateway_dns", "local_private", "on_link", "directly_reachable"}
        mixed_local_and_public = any(item in local_classes for item in classification_types)
        return build_check(
            "dns_trust_reasoning",
            "notice",
            (
                "DNS path mixes local/private and public upstream resolvers"
                if mixed_local_and_public
                else "System resolver points directly at public upstream DNS"
            ),
            build_dns_reasoning_details(
                "mixed_dns_path" if mixed_local_and_public else "public_upstream_dns_present",
                nameservers=nameservers,
                resolver_profile=classification_types,
                risk_count=risk_count,
                context_note="can be legitimate, but should be verified on an untrusted network",
            ),
        )

    if "gateway_dns" in classification_types:
        return build_check(
            "dns_trust_reasoning",
            "ok",
            "DNS path looks local and expected: the current gateway is acting as resolver",
            build_dns_reasoning_details(
                "gateway_dns_expected",
                nameservers=nameservers,
                resolver_profile=classification_types,
                risk_count=risk_count,
                context_note="typical for private/home LANs and many managed networks",
            ),
        )

    if any(item in {"local_private", "on_link", "directly_reachable"} for item in classification_types):
        return build_check(
            "dns_trust_reasoning",
            "ok",
            "DNS path looks local/on-link and does not currently show trust anomalies",
            build_dns_reasoning_details(
                "private_local_dns_expected",
                nameservers=nameservers,
                resolver_profile=classification_types,
                risk_count=risk_count,
                context_note="consistent with local or directly reachable resolvers",
            ),
        )

    return build_check(
        "dns_trust_reasoning",
        "ok",
        "DNS path does not currently show a strong trust signal in either direction",
        build_dns_reasoning_details(
            "dns_path_unclear",
            nameservers=nameservers,
            resolver_profile=classification_types,
            risk_count=risk_count,
        ),
    )


def fetch_url(url, timeout=5, context=None):
    handlers = [NoRedirectHandler]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={"User-Agent": "network-health-check/1.0"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(256).decode("utf-8", errors="replace")
            return {
                "url": url,
                "status_code": response.getcode(),
                "headers": dict(response.headers.items()),
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(256).decode("utf-8", errors="replace")
        return {
            "url": url,
            "status_code": exc.code,
            "headers": dict(exc.headers.items()),
            "body": body,
        }


def collect_captive_portal_observations(probes=None, timeout=5):
    """Collect raw HTTP connectivity-check responses."""
    observations = []
    for probe in probes or DEFAULT_HTTP_PROBES:
        try:
            response = fetch_url(probe["url"], timeout=timeout)
            observations.append({"probe": dict(probe), "response": response})
        except (urllib.error.URLError, OSError) as exc:
            observations.append({"probe": dict(probe), "error": str(exc)})
    return observations


def analyze_captive_portal_observation(
    observation,
    network_profile=DEFAULT_NETWORK_PROFILE,
):
    """Interpret one collected HTTP connectivity-check response."""
    network_profile = normalize_network_profile(network_profile)
    probe = observation["probe"]
    if observation.get("error") is not None:
        return build_check(
            f"captive_{probe['name']}",
            "alert",
            f"Connectivity probe failed for {probe['url']}",
            {
                "url": probe["url"],
                "error": observation["error"],
                "finding_kind": "transport_failure",
                "network_profile": network_profile,
            },
        )

    response = observation["response"]
    location = response["headers"].get("Location")
    body = response["body"]
    expected_status = probe["expected_status"]
    expected_body_contains = probe["expected_body_contains"]
    redirected = location is not None and 300 <= response["status_code"] < 400
    body_mismatch = (
        expected_body_contains is not None and expected_body_contains not in body
    )
    suspicious = response["status_code"] != expected_status or redirected or body_mismatch
    return build_check(
        f"captive_{probe['name']}",
        (
            "notice"
            if suspicious and network_profile == "untrusted"
            else "alert"
            if suspicious
            else "ok"
        ),
        (
            f"Captive-portal response detected for {probe['url']}; sign-in may be required"
            if suspicious and network_profile == "untrusted"
            else f"Unexpected captive-portal probe response for {probe['url']}"
            if suspicious
            else f"Connectivity probe looked normal for {probe['url']}"
        ),
        {
            "url": probe["url"],
            "status_code": response["status_code"],
            "location": location,
            "body_preview": body,
            "finding_kind": "unexpected_response" if suspicious else "expected_response",
            "network_profile": network_profile,
        },
    )


def run_captive_portal_checks(
    probes=None,
    timeout=5,
    network_profile=DEFAULT_NETWORK_PROFILE,
):
    """Collect and interpret HTTP captive-portal probes."""
    return [
        analyze_captive_portal_observation(
            observation,
            network_profile=network_profile,
        )
        for observation in collect_captive_portal_observations(
            probes=probes,
            timeout=timeout,
        )
    ]


def build_captive_trust_reasoning_check(
    captive_checks,
    network_profile=DEFAULT_NETWORK_PROFILE,
):
    """Summarize captive-portal probe results into one trust interpretation."""
    network_profile = normalize_network_profile(network_profile)
    alert_count = len(get_alert_checks(captive_checks))
    notice_checks = [check for check in captive_checks if check.get("status") == "notice"]
    finding_count = alert_count + len(notice_checks)
    affected_probes = [
        check["name"].replace("captive_", "")
        for check in captive_checks
        if check.get("status") in {"notice", "alert"}
    ]
    if network_profile == "untrusted" and notice_checks and not alert_count:
        all_affected = finding_count == len(captive_checks)
        return build_check(
            "captive_trust_reasoning",
            "notice",
            (
                "Captive portal detected on this untrusted network; complete the expected sign-in and run the check again"
                if all_affected
                else f"{finding_count} of {len(captive_checks)} captive-portal probe(s) suggest a sign-in page or partial HTTP interception"
            ),
            build_probe_reasoning_details(
                "likely_captive_portal" if all_affected else "partial_http_interception",
                len(captive_checks),
                alert_probe_count=finding_count,
                affected_probes=affected_probes,
                context_note=(
                    "a sign-in portal can be normal before Internet access is granted; HTTPS must behave normally after sign-in"
                ),
            ),
        )
    return build_probe_trust_reasoning_check(
        name="captive_trust_reasoning",
        checks=captive_checks,
        probe_prefix="captive_",
        no_probe_summary="No captive-portal probes were run",
        normal_hint="normal_internet_path",
        normal_summary="Captive-portal probes look normal; no HTTP interception is evident",
        normal_context_note="connectivity-check endpoints behaved as expected",
        all_alert_hint="likely_captive_portal",
        all_alert_summary="All captive-portal probes behaved unexpectedly; captive portal or broad HTTP interception is likely",
        all_alert_context_note="multiple independent connectivity checks were affected",
        partial_alert_hint="partial_http_interception",
        partial_alert_summary=(
            f"{alert_count} of {len(captive_checks)} captive-portal probe(s) behaved unexpectedly; "
            "partial interception or a portal edge case is possible"
        ),
        partial_alert_context_note="some HTTP checks were affected while others still looked normal",
    )


def probe_https_endpoint(url, timeout=5):
    context = ssl.create_default_context()
    return fetch_url(url, timeout=timeout, context=context)


def parse_system_profiler_wifi_json(raw_json):
    payload = json.loads(raw_json)
    sections = payload.get("SPAirPortDataType", [])
    if not sections:
        return {"software": {}, "interfaces": []}
    section = sections[0]
    interfaces = []
    current = {}
    for item in section.get("spairport_airport_interfaces", []):
        interface_name = item.get("_name")
        if interface_name in AUXILIARY_WIFI_INTERFACES:
            continue
        interfaces.append(
            {
                "name": interface_name,
                "status": item.get("spairport_status_information"),
                "card_type": item.get("spairport_wireless_card_type"),
                "country_code": item.get("spairport_wireless_country_code"),
                "firmware_version": item.get("spairport_wireless_firmware_version"),
                "locale": item.get("spairport_wireless_locale"),
                "supported_phy_modes": item.get("spairport_supported_phymodes"),
                "supported_channels": item.get("spairport_supported_channels", []),
            }
        )
        current_info = item.get("spairport_current_network_information") or {}
        if current_info:
            def find_value(tokens):
                stack = [current_info]
                while stack:
                    value = stack.pop()
                    if isinstance(value, dict):
                        for key, nested in value.items():
                            key_lower = str(key).lower().replace("_", " ")
                            if tokens == ("ssid",) and "bssid" in key_lower:
                                continue
                            if all(token in key_lower for token in tokens) and not isinstance(nested, (dict, list)):
                                return nested
                            if isinstance(nested, (dict, list)):
                                stack.append(nested)
                    elif isinstance(value, list):
                        stack.extend(value)
                return None

            signal_noise = find_value(("signal", "noise")) or ""
            signal_parts = str(signal_noise).split("/")
            current[interface_name] = {
                "ssid": find_value(("ssid",)) or current_info.get("_name"),
                "bssid": find_value(("bssid",)),
                "channel": find_value(("channel",)),
                "rssi": signal_parts[0].strip() if signal_parts else None,
                "noise": signal_parts[-1].strip() if len(signal_parts) > 1 else None,
                "tx_rate": find_value(("tx", "rate")),
                "security": find_value(("security",)),
                "phy_mode": find_value(("phy",)),
            }
    return {
        "software": section.get("spairport_software_information", {}),
        "interfaces": interfaces,
        "current": current,
    }


def collect_macos_wifi_inventory():
    profiler = parse_system_profiler_wifi_json(
        run_command(["system_profiler", "SPAirPortDataType", "-json"])
    )
    return {
        "platform": "macos",
        "software": profiler["software"],
        "interfaces": profiler["interfaces"],
        "current": profiler.get("current", {}),
    }


def parse_wdutil_info(raw_text):
    current_interface = None
    interface_data = {}
    for raw_line in raw_text.splitlines():
        line = raw_line.rstrip()
        interface_match = re.match(
            r"^\s+(?P<interface>(?:en|awdl|llw|p2p|bridge|utun)\d+):\s*$",
            line,
        )
        if interface_match:
            current_interface = interface_match.group("interface")
            interface_data.setdefault(current_interface, {})
            continue
        if current_interface is None:
            continue
        field_match = re.match(r"^\s{2,}(?P<key>[^:]+):\s*(?P<value>.+?)\s*$", line)
        if field_match:
            key = field_match.group("key").strip().lower().replace(" ", "_").replace("-", "_")
            interface_data[current_interface][key] = field_match.group("value").strip()
    return interface_data


def collect_macos_current_wifi_details():
    if os.geteuid() != 0:
        return {
            "available": False,
            "reason": "wdutil info requires sudo on macOS",
            "interfaces": {},
        }
    try:
        parsed = parse_wdutil_info(run_command(["wdutil", "info"]))
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {
            "available": False,
            "reason": str(exc),
            "interfaces": {},
        }
    parsed = {interface: details for interface, details in parsed.items() if details}
    if not parsed:
        return {
            "available": False,
            "reason": "wdutil returned no parseable Wi-Fi interface data",
            "interfaces": {},
        }
    return {"available": True, "reason": None, "interfaces": parsed}


def get_primary_wifi_interface_name(inventory, current_details):
    current_interfaces = current_details.get("interfaces", {})
    for interface_name, details in current_interfaces.items():
        if interface_name in AUXILIARY_WIFI_INTERFACES:
            continue
        if details:
            return interface_name
    for interface in inventory.get("interfaces", []):
        name = interface.get("name")
        if name and name not in AUXILIARY_WIFI_INTERFACES:
            return name
    return None


def get_active_wifi_interface_name(inventory, current_details):
    current_interfaces = current_details.get("interfaces", {})
    for interface_name, details in current_interfaces.items():
        if interface_name in AUXILIARY_WIFI_INTERFACES:
            continue
        if not details:
            continue
        if details.get("ssid") or details.get("bssid"):
            return interface_name

    for interface in inventory.get("interfaces", []):
        name = interface.get("name")
        status = interface.get("status")
        if not name or name in AUXILIARY_WIFI_INTERFACES:
            continue
        if status in ACTIVE_WIFI_STATUSES:
            return name
    return None


def build_current_wifi_snapshot(inventory, current_details):
    interface_name = get_primary_wifi_interface_name(inventory, current_details)
    interface_details = current_details.get("interfaces", {}).get(interface_name, {})
    if not interface_name:
        return None
    return {
        "interface": interface_name,
        "ssid": interface_details.get("ssid"),
        "bssid": interface_details.get("bssid"),
        "rssi": interface_details.get("agrctlrssi") or interface_details.get("rssi"),
        "channel": interface_details.get("channel"),
        "tx_rate": interface_details.get("last_tx_rate") or interface_details.get("lasttxrate"),
    }


def collect_active_path_observation(wifi_environment=None):
    """Collect default-route and active Wi-Fi interface state."""
    gateway_ip, default_interface = get_default_gateway()
    macos = is_macos()
    if macos and wifi_environment is None:
        wifi_environment = collect_wifi_environment()

    inventory = (wifi_environment or {}).get("inventory", {})
    current = (wifi_environment or {}).get("current", {})
    active_wifi_interface = (
        get_active_wifi_interface_name(inventory, current) if macos else None
    )
    return {
        "platform": "macos" if macos else platform.system().lower(),
        "gateway_ip": gateway_ip,
        "default_interface": default_interface,
        "active_wifi_interface": active_wifi_interface,
        "current_details_available": current.get("available", False),
        "current_details_source": current.get("source"),
    }


def analyze_active_path(observation):
    """Interpret collected route and Wi-Fi state without system calls."""
    gateway_ip = observation["gateway_ip"]
    default_interface = observation["default_interface"]
    active_wifi_interface = observation.get("active_wifi_interface")
    if observation.get("platform") != "macos":
        return {
            "name": "active_path",
            "status": "ok",
            "summary": f"Default route uses {default_interface}",
            "details": {
                "gateway_ip": gateway_ip,
                "default_interface": default_interface,
                "wifi_interface": None,
                "wifi_active": False,
            },
        }

    if active_wifi_interface and active_wifi_interface != default_interface:
        inventory_only = (
            not observation.get("current_details_available", False)
            or observation.get("current_details_source") == "system_profiler"
        )
        status = "ok" if inventory_only else "alert"
        evidence = "system_profiler inventory only" if inventory_only else "current Wi-Fi details"
        return {
            "name": "active_path",
            "status": status,
            "summary": (
                f"Default route uses non-Wi-Fi interface {default_interface} while Wi-Fi "
                f"{active_wifi_interface} remains connected; this commonly means Ethernet is preferred"
                if inventory_only
                else f"Wi-Fi interface {active_wifi_interface} is active, but the default route "
                f"currently uses {default_interface}; verify the intended route"
            ),
            "details": {
                "gateway_ip": gateway_ip,
                "default_interface": default_interface,
                "wifi_interface": active_wifi_interface,
                "wifi_active": True,
                "route_mismatch": True,
                "possible_dual_connectivity": True,
                "confidence": "low" if inventory_only else "high",
                "evidence": evidence,
                "route_assessment": (
                    "alternate_interface_preferred"
                    if inventory_only
                    else "confirmed_wifi_route_mismatch"
                ),
                "interpretation": (
                    "The system appears to prefer Ethernet or another interface while Wi-Fi remains associated"
                    if inventory_only
                    else "Wi-Fi is active on a different interface than the current default route"
                ),
            },
        }

    if active_wifi_interface:
        return {
            "name": "active_path",
            "status": "ok",
            "summary": f"Default route uses active Wi-Fi interface {active_wifi_interface}",
            "details": {
                "gateway_ip": gateway_ip,
                "default_interface": default_interface,
                "wifi_interface": active_wifi_interface,
                "wifi_active": True,
                "route_mismatch": False,
                "possible_dual_connectivity": False,
                "interpretation": "The active Wi-Fi interface also carries the default route",
            },
        }

    return {
        "name": "active_path",
        "status": "ok",
        "summary": f"No active Wi-Fi interface detected; default route uses {default_interface}",
            "details": {
                "gateway_ip": gateway_ip,
                "default_interface": default_interface,
                "wifi_interface": None,
                "wifi_active": False,
                "route_mismatch": False,
                "possible_dual_connectivity": False,
                "interpretation": "No active Wi-Fi interface was detected",
            },
    }


def build_active_path_check(wifi_environment=None):
    """Collect and interpret the active network path."""
    observation = collect_active_path_observation(wifi_environment)
    return analyze_active_path(observation)


def parse_ping_summary(raw_text):
    packet_match = re.search(
        r"(?P<tx>\d+)\s+packets transmitted,\s+(?P<rx>\d+)\s+packets received,\s+(?P<loss>[0-9.]+)% packet loss",
        raw_text,
    )
    rtt_match = re.search(
        r"(?:round-trip|rtt)\s+min/avg/max/(?:stddev|mdev)\s+=\s+([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)\s+ms",
        raw_text,
    )
    summary = {
        "transmitted": None,
        "received": None,
        "loss_percent": None,
        "min_ms": None,
        "avg_ms": None,
        "max_ms": None,
        "jitter_ms": None,
    }
    if packet_match:
        summary["transmitted"] = int(packet_match.group("tx"))
        summary["received"] = int(packet_match.group("rx"))
        summary["loss_percent"] = float(packet_match.group("loss"))
    if rtt_match:
        summary["min_ms"] = float(rtt_match.group(1))
        summary["avg_ms"] = float(rtt_match.group(2))
        summary["max_ms"] = float(rtt_match.group(3))
        summary["jitter_ms"] = float(rtt_match.group(4))
    return summary


def ping_host(host, count=3):
    try:
        output = run_command(["ping", "-n", "-c", str(count), host])
    except subprocess.CalledProcessError as exc:
        output = exc.stdout or exc.output or ""
    return parse_ping_summary(output)


def collect_gateway_reachability(ping_count=3):
    """Collect one bounded reachability observation for the default gateway."""
    gateway_ip, interface = get_default_gateway()
    ping_summary = ping_host(gateway_ip, count=ping_count)
    return {
        "gateway_ip": gateway_ip,
        "interface": interface,
        "ping": ping_summary,
    }


def analyze_gateway_reachability(observation):
    """Interpret a collected gateway reachability observation."""
    gateway_ip = observation["gateway_ip"]
    interface = observation["interface"]
    ping_summary = observation.get("ping", {})
    loss_percent = ping_summary.get("loss_percent")
    avg_ms = ping_summary.get("avg_ms")
    received = ping_summary.get("received")
    transmitted = ping_summary.get("transmitted")

    if transmitted is None or received is None:
        status = "alert"
        summary = f"Gateway reachability to {gateway_ip} on {interface} could not be measured"
        level = "unavailable"
    elif received == 0 or loss_percent == 100:
        status = "alert"
        summary = f"Default gateway {gateway_ip} did not respond to local reachability probes on {interface}"
        level = "unreachable"
    elif loss_percent and loss_percent >= 10:
        status = "alert"
        summary = f"Default gateway {gateway_ip} showed {loss_percent:.0f}% packet loss on {interface}"
        level = "lossy"
    elif loss_percent and loss_percent > 0:
        status = "notice"
        summary = f"Default gateway {gateway_ip} showed minor packet loss ({loss_percent:.0f}%) on {interface}"
        level = "degraded"
    elif avg_ms is not None and avg_ms >= 50:
        status = "notice"
        summary = f"Default gateway {gateway_ip} responded slowly on {interface} ({avg_ms:.1f} ms average)"
        level = "slow"
    else:
        status = "ok"
        summary = f"Default gateway {gateway_ip} is reachable on {interface}"
        level = "reachable"

    return build_check(
        "gateway_reachability",
        status,
        summary,
        {
            "gateway_ip": gateway_ip,
            "interface": interface,
            "level": level,
            "ping": ping_summary,
        },
    )


def build_gateway_reachability_check(ping_count=3):
    """Collect and interpret default-gateway reachability."""
    observation = collect_gateway_reachability(ping_count=ping_count)
    return analyze_gateway_reachability(observation)


def summarize_wifi_stability(samples, gateway_ip):
    bssids = [sample["wifi"].get("bssid") for sample in samples if sample.get("wifi")]
    bssids = [bssid for bssid in bssids if bssid]
    rssi_values = []
    latency_values = []
    loss_values = []
    for sample in samples:
        wifi = sample.get("wifi") or {}
        ping = sample.get("ping") or {}
        try:
            if wifi.get("rssi") is not None:
                rssi_values.append(float(wifi["rssi"]))
        except (TypeError, ValueError):
            pass
        try:
            if ping.get("avg_ms") is not None:
                latency_values.append(float(ping["avg_ms"]))
        except (TypeError, ValueError):
            pass
        try:
            if ping.get("loss_percent") is not None:
                loss_values.append(float(ping["loss_percent"]))
        except (TypeError, ValueError):
            pass

    bssid_changes = 0
    for previous, current in zip(bssids, bssids[1:]):
        if previous != current:
            bssid_changes += 1

    avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else None
    avg_latency = sum(latency_values) / len(latency_values) if latency_values else None
    max_loss = max(loss_values) if loss_values else 0.0
    max_latency = max(latency_values) if latency_values else None
    weak_signal = avg_rssi is not None and avg_rssi <= WIFI_WEAK_RSSI_DBM
    high_latency = (
        avg_latency is not None
        and avg_latency >= WIFI_HIGH_GATEWAY_LATENCY_MS
    )
    severe_loss = max_loss >= WIFI_UNSTABLE_PACKET_LOSS_PERCENT
    performance_impact = severe_loss or weak_signal or high_latency

    reasons = []
    if bssid_changes > 0:
        reasons.append(
            "BSSID changed once (possibly normal mesh roaming)"
            if bssid_changes == 1
            else f"BSSID changed {bssid_changes} time(s)"
        )
    if max_loss > 0:
        reasons.append(f"packet loss peaked at {max_loss:.0f}%")
    if weak_signal:
        reasons.append(f"weak average signal ({avg_rssi:.0f} dBm)")
    if high_latency:
        reasons.append(f"high average gateway latency ({avg_latency:.1f} ms)")

    usable_measurements = len(bssids) + len(rssi_values) + len(latency_values) + len(loss_values)
    if usable_measurements == 0:
        level = "unavailable"
    elif severe_loss or (bssid_changes > 1 and performance_impact):
        level = "unstable"
    elif bssid_changes > 1 or max_loss > 0 or weak_signal or high_latency:
        level = "degraded"
    elif bssid_changes == 1:
        level = "roaming"
    else:
        level = "stable"

    if level == "unstable":
        recommendation = (
            "Check mesh roaming and local interference; packet loss or repeated BSSID changes were observed."
        )
    elif level == "degraded":
        recommendation = (
            "Review signal strength, gateway latency, and packet loss before troubleshooting applications."
        )
    elif level == "roaming":
        recommendation = (
            "A single BSSID transition can be normal on a mesh network; investigate only if users noticed interruption."
        )
    elif level == "unavailable":
        recommendation = "No usable Wi-Fi or gateway measurements were returned during the sample window."
    else:
        recommendation = "No material Wi-Fi instability was observed during the sample window."

    confidence = (
        "high"
        if len(samples) >= 3 and len(latency_values) == len(samples) and len(rssi_values) == len(samples)
        else "limited"
    )

    return {
        "gateway_ip": gateway_ip,
        "sample_count": len(samples),
        "bssid_changes": bssid_changes,
        "avg_rssi": avg_rssi,
        "avg_latency_ms": avg_latency,
        "max_latency_ms": max_latency,
        "max_loss_percent": max_loss,
        "wifi_sample_count": len(rssi_values),
        "ping_sample_count": len(latency_values),
        "confidence": confidence,
        "reasons": reasons,
        "recommendation": recommendation,
        "level": level,
        "samples": samples,
    }


def build_wifi_stability_check(summary):
    """Convert a Wi-Fi stability summary into an operator-facing check."""
    gateway_ip = summary["gateway_ip"]
    level = summary["level"]
    if level == "stable":
        status = "ok"
        text = f"Wi-Fi link to gateway {gateway_ip} looked stable across {summary['sample_count']} sample(s)"
    elif level == "roaming":
        status = "notice"
        text = f"Wi-Fi link to gateway {gateway_ip} roamed once without measured degradation"
    elif level == "degraded":
        status = "notice"
        text = f"Wi-Fi link to gateway {gateway_ip} looked degraded: {', '.join(summary['reasons'])}"
    elif level == "unstable":
        status = "alert"
        text = f"Wi-Fi link to gateway {gateway_ip} looked unstable: {', '.join(summary['reasons'])}"
    else:
        status = "alert"
        text = "Wi-Fi stability diagnostics were unavailable"

    return build_check("wifi_stability", status, text, summary)


def run_wifi_stability_diagnostics(
    duration_seconds=20,
    interval_seconds=3,
    ping_count=3,
    progress_callback=None,
):
    if not is_macos():
        return None
    gateway_ip, _ = get_default_gateway()
    inventory = collect_macos_wifi_inventory()
    current_details = collect_macos_current_wifi_details()
    if not current_details.get("available"):
        return {
            "name": "wifi_stability",
            "status": "alert",
            "summary": "Wi-Fi stability diagnostics require current Wi-Fi details, which are unavailable in this context",
            "details": {
                "level": "unavailable",
                "reason": current_details.get("reason"),
                "gateway_ip": gateway_ip,
                "sample_count": 0,
                "samples": [],
                "recommendation": "Retry when current Wi-Fi details are available.",
            },
        }

    sample_count = max(1, int(duration_seconds / interval_seconds))
    samples = []
    for index in range(sample_count):
        if progress_callback is not None:
            progress_callback(index + 1, sample_count, gateway_ip)
        current_details = collect_macos_current_wifi_details()
        wifi_snapshot = build_current_wifi_snapshot(inventory, current_details)
        ping_summary = ping_host(gateway_ip, count=ping_count)
        samples.append(
            {
                "index": index,
                "wifi": wifi_snapshot,
                "ping": ping_summary,
            }
        )
        if index < sample_count - 1:
            time.sleep(interval_seconds)

    summary = summarize_wifi_stability(samples, gateway_ip)
    return build_wifi_stability_check(summary)


def extract_corewlan_network(network):
    ssid = network.ssid() if hasattr(network, "ssid") else None
    bssid = network.bssid() if hasattr(network, "bssid") else None
    rssi = network.rssiValue() if hasattr(network, "rssiValue") else None
    channel = None
    if hasattr(network, "wlanChannel"):
        wlan_channel = network.wlanChannel()
        if wlan_channel is not None and hasattr(wlan_channel, "channelNumber"):
            channel = str(wlan_channel.channelNumber())
    security = None
    if hasattr(network, "security"):
        security = str(network.security())
    return {
        "ssid": ssid or "<hidden>",
        "bssid": bssid,
        "rssi": str(rssi) if rssi is not None else "",
        "channel": channel or "",
        "security": security or "",
    }


def scan_corewlan_interface(interface):
    scan_method = getattr(interface, "scanForNetworksWithName_error_", None)
    if scan_method is None:
        return []
    result = scan_method(None, None)
    if isinstance(result, tuple):
        networks = result[0]
    else:
        networks = result
    return [extract_corewlan_network(network) for network in networks or []]


def collect_macos_nearby_wifi_networks_via_corewlan():
    corewlan, error = get_corewlan_module()
    if corewlan is None:
        return {
            "available": False,
            "reason": f"CoreWLAN backend unavailable: {error}",
            "backend": "corewlan",
            "networks": [],
        }
    try:
        client = corewlan.CWWiFiClient.sharedWiFiClient()
        interfaces = client.interfaces() or []
        networks = []
        for interface in interfaces:
            interface_name = interface.interfaceName() if hasattr(interface, "interfaceName") else None
            if interface_name in AUXILIARY_WIFI_INTERFACES:
                continue
            networks.extend(scan_corewlan_interface(interface))
    except Exception as exc:
        return {
            "available": False,
            "reason": f"CoreWLAN scan failed: {exc}",
            "backend": "corewlan",
            "networks": [],
        }
    unique_networks = []
    seen = set()
    for network in networks:
        key = (network.get("ssid"), network.get("bssid"))
        if key in seen:
            continue
        seen.add(key)
        unique_networks.append(network)
    return {
        "available": True,
        "reason": None,
        "backend": "corewlan",
        "networks": unique_networks,
    }


def parse_airport_scan_output(raw_text):
    networks = []
    lines = [line for line in raw_text.splitlines() if line.strip()]
    if len(lines) <= 1:
        return networks
    for line in lines[1:]:
        bssid_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if not bssid_match:
            continue
        bssid = bssid_match.group(1)
        ssid = line[: bssid_match.start()].strip()
        tail = line[bssid_match.end() :].strip()
        parts = tail.split()
        if len(parts) < 3:
            continue
        networks.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "rssi": parts[0],
                "channel": parts[1],
                "security": " ".join(parts[4:]) if len(parts) > 4 else "",
            }
        )
    return networks


def collect_macos_nearby_wifi_networks():
    corewlan_result = collect_macos_nearby_wifi_networks_via_corewlan()
    if corewlan_result["available"]:
        return corewlan_result
    if not os.path.exists(MACOS_AIRPORT_SCAN_PATH):
        return {
            "available": False,
            "reason": (
                f"{corewlan_result['reason']}; legacy airport scan binary is not present on this macOS version"
            ),
            "backend": "unavailable",
            "networks": [],
        }
    try:
        output = run_command([MACOS_AIRPORT_SCAN_PATH, "-s"])
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {
            "available": False,
            "reason": f"{corewlan_result['reason']}; {exc}",
            "backend": "airport",
            "networks": [],
        }
    return {
        "available": True,
        "reason": None,
        "backend": "airport",
        "networks": parse_airport_scan_output(output),
    }


def collect_wifi_environment():
    if not is_macos():
        return None
    return collect_macos_wifi_state()


def collect_macos_wifi_state():
    """Collect the current macOS Wi-Fi environment in one structured payload."""
    inventory = collect_macos_wifi_inventory()
    current = collect_macos_current_wifi_details()
    if not current.get("available") and inventory.get("current"):
        current = {
            "available": True,
            "reason": "wdutil unavailable; using system_profiler current network data",
            "source": "system_profiler",
            "interfaces": inventory["current"],
        }
    return {
        "platform": "macos",
        "inventory": inventory,
        "current": current,
        "nearby": collect_macos_nearby_wifi_networks(),
    }


def classify_wifi_security(security_text):
    normalized = (security_text or "").upper()
    if not normalized:
        return "unknown"
    if "NONE" in normalized or "OPEN" in normalized:
        return "open"
    if "WEP" in normalized:
        return "weak_legacy"
    if "WPA3" in normalized:
        return "strong"
    if "WPA2" in normalized or "WPA" in normalized:
        return "modern"
    return "unknown"


def parse_wifi_number(value):
    """Extract the first numeric value from a macOS Wi-Fi metric."""
    if isinstance(value, (int, float)):
        return float(value)
    match = re.search(r"-?\d+(?:\.\d+)?", str(value or ""))
    return float(match.group(0)) if match else None


def parse_wifi_channel(value):
    """Normalize a channel description into band, width, and center frequency."""
    text = str(value or "")
    channel_value = parse_wifi_number(text)
    if channel_value is None:
        return None
    channel = int(channel_value)
    band_match = re.search(r"(?P<band>2\.4|5|6)\s*GHz", text, re.IGNORECASE)
    band = f"{band_match.group('band')}GHz" if band_match else ("2.4GHz" if channel <= 14 else "5GHz")
    width_match = re.search(r"(?P<width>20|40|80|160|320)\s*MHz", text, re.IGNORECASE)
    width_mhz = int(width_match.group("width")) if width_match else 20
    if band == "2.4GHz":
        center_mhz = 2484 if channel == 14 else 2407 + (5 * channel)
    elif band == "6GHz":
        center_mhz = 5950 + (5 * channel)
    else:
        center_mhz = 5000 + (5 * channel)
    return {
        "channel": channel,
        "band": band,
        "width_mhz": width_mhz,
        "width_estimated": width_match is None,
        "center_mhz": center_mhz,
    }


def analyze_nearby_wifi_networks(networks, current_network=None):
    risks = []
    duplicate_ssids = []
    channel_overlaps = []
    by_ssid = {}

    analyzable_networks = [
        network
        for network in networks
        if (network.get("ssid") or "<hidden>") != "<hidden>"
        and bool(network.get("bssid"))
        and bool(network.get("security"))
    ]

    for network in analyzable_networks:
        ssid = network.get("ssid") or "<hidden>"
        by_ssid.setdefault(ssid, []).append(network)

        security_class = classify_wifi_security(network.get("security"))
        if security_class == "open":
            risks.append(
                {
                    "type": "open_network",
                    "ssid": ssid,
                    "bssid": network.get("bssid"),
                    "reason": "visible network does not advertise encryption",
                }
            )
        elif security_class == "weak_legacy":
            risks.append(
                {
                    "type": "weak_security",
                    "ssid": ssid,
                    "bssid": network.get("bssid"),
                    "reason": f"legacy security detected: {network.get('security')}",
                }
            )

        rssi = parse_wifi_number(network.get("rssi")) or 0
        if rssi and rssi <= -85:
            risks.append(
                {
                    "type": "very_low_signal",
                    "ssid": ssid,
                    "bssid": network.get("bssid"),
                    "reason": f"very weak signal ({rssi} dBm)",
                }
            )

    for ssid, entries in by_ssid.items():
        if len(entries) < 2:
            continue
        security_profiles = sorted({entry.get("security", "") for entry in entries})
        duplicate_ssids.append(
            {
                "ssid": ssid,
                "count": len(entries),
                "bssids": [entry.get("bssid") for entry in entries],
                "security_profiles": security_profiles,
            }
        )
        if len(security_profiles) > 1:
            risks.append(
                {
                    "type": "mixed_security_duplicate_ssid",
                    "ssid": ssid,
                    "reason": "same SSID is advertised with multiple BSSIDs and mixed security profiles",
                    "security_profiles": security_profiles,
                }
            )

    channel_networks = [(network, False) for network in analyzable_networks]
    if current_network:
        channel_networks.append((current_network, True))
    usable = []
    for network, is_current in channel_networks:
        channel = parse_wifi_channel(network.get("channel"))
        if channel:
            usable.append((network, is_current, channel))
    for index, (left, left_current, left_channel) in enumerate(usable):
        for right, right_current, right_channel in usable[index + 1 :]:
            if left_channel["band"] != right_channel["band"]:
                continue
            if left.get("bssid") and left.get("bssid") == right.get("bssid"):
                continue
            separation = abs(left_channel["center_mhz"] - right_channel["center_mhz"])
            overlap_span = (left_channel["width_mhz"] + right_channel["width_mhz"]) / 2
            if separation < overlap_span:
                channel_overlaps.append(
                    {
                        "band": left_channel["band"],
                        "channel_a": left_channel["channel"],
                        "channel_b": right_channel["channel"],
                        "width_a_mhz": left_channel["width_mhz"],
                        "width_b_mhz": right_channel["width_mhz"],
                        "width_estimated": left_channel["width_estimated"] or right_channel["width_estimated"],
                        "ssid_a": left.get("ssid") or "<hidden>",
                        "ssid_b": right.get("ssid") or "<hidden>",
                        "rssi_a": left.get("rssi"),
                        "rssi_b": right.get("rssi"),
                        "includes_current": left_current or right_current,
                        "type": "same channel" if separation == 0 else "overlapping channel widths",
                    }
                )

    return {
        "visible_network_count": len(networks),
        "analyzable_network_count": len(analyzable_networks),
        "duplicate_ssids": duplicate_ssids,
        "channel_overlaps": channel_overlaps,
        "limited_scan": (
            len(networks) > 0 and not analyzable_networks
        ),
        "risks": risks,
    }


def build_wifi_environment_analysis(wifi_environment):
    """Attach a nearby-network analysis block to the collected Wi-Fi state."""
    nearby_networks = wifi_environment["nearby"]["networks"]
    current_interfaces = wifi_environment.get("current", {}).get("interfaces", {})
    current_network = None
    if current_interfaces:
        _, current_network = next(iter(current_interfaces.items()))
    analysis = (
        analyze_nearby_wifi_networks(nearby_networks, current_network=current_network)
        if nearby_networks
        else {
            "visible_network_count": 0,
            "analyzable_network_count": 0,
            "duplicate_ssids": [],
            "channel_overlaps": [],
            "limited_scan": False,
            "risks": [],
        }
    )
    enriched = dict(wifi_environment)
    enriched["analysis"] = analysis
    return enriched


def summarize_wifi_environment(wifi_environment):
    """Return status and summary text for the collected Wi-Fi environment."""
    interfaces = wifi_environment["inventory"]["interfaces"]
    nearby = wifi_environment["nearby"]
    analysis = wifi_environment["analysis"]
    nearby_networks = nearby["networks"]

    if not interfaces:
        return "alert", "No Wi-Fi interfaces detected on macOS"
    if analysis["limited_scan"]:
        return (
            "ok",
            f"Wi-Fi inventory collected, but nearby scan looks restricted by macOS "
            f"({analysis['visible_network_count']} incomplete object(s))",
        )
    if analysis["risks"]:
        return (
            "alert",
            f"Wi-Fi environment shows {len(analysis['risks'])} risk signal(s) across "
            f"{analysis['visible_network_count']} visible network(s)",
        )
    if not nearby["available"]:
        return "ok", "Wi-Fi interfaces detected; nearby SSID inventory is unavailable on this macOS setup"
    return (
        "ok",
        f"Wi-Fi inventory collected for {len(interfaces)} interface(s) and "
        f"{len(nearby_networks)} nearby network(s)",
    )


def analyze_wifi_environment(wifi_environment, platform_name=None):
    """Interpret a collected Wi-Fi environment without platform commands."""
    if wifi_environment is None:
        return build_check(
            "wifi_environment",
            "ok",
            "Wi-Fi environment inspection is only implemented for macOS in this version",
            {"platform": platform_name or platform.system()},
        )

    wifi = build_wifi_environment_analysis(wifi_environment)
    status, summary = summarize_wifi_environment(wifi)

    return build_check("wifi_environment", status, summary, wifi)


def build_wifi_environment_check():
    """Collect and interpret the current Wi-Fi environment."""
    wifi_environment = collect_wifi_environment()
    return analyze_wifi_environment(
        wifi_environment,
        platform_name=platform.system(),
    )


def collect_https_tls_observations(probes=None, timeout=5):
    """Collect certificate-validated HTTPS responses and transport errors."""
    observations = []
    for probe in probes or DEFAULT_HTTPS_PROBES:
        try:
            response = probe_https_endpoint(probe["url"], timeout=timeout)
            observations.append({"probe": dict(probe), "response": response})
        except ssl.SSLError as exc:
            observations.append(
                {"probe": dict(probe), "error_kind": "tls", "error": str(exc)}
            )
        except (urllib.error.URLError, OSError) as exc:
            observations.append(
                {
                    "probe": dict(probe),
                    "error_kind": "transport",
                    "error": str(exc),
                }
            )
    return observations


def analyze_https_tls_observation(observation):
    """Interpret one collected HTTPS response or transport error."""
    probe = observation["probe"]
    error_kind = observation.get("error_kind")
    if error_kind == "tls":
        return build_check(
            f"https_{probe['name']}",
            "alert",
            f"TLS verification failed for {probe['url']}",
            {"url": probe["url"], "error": observation["error"]},
        )
    if error_kind == "transport":
        return build_check(
            f"https_{probe['name']}",
            "alert",
            f"HTTPS probe failed for {probe['url']}",
            {"url": probe["url"], "error": observation["error"]},
        )

    response = observation["response"]
    suspicious = response["status_code"] not in probe["expected_statuses"]
    return build_check(
        f"https_{probe['name']}",
        "alert" if suspicious else "ok",
        (
            f"Unexpected HTTPS response for {probe['url']}"
            if suspicious
            else f"HTTPS probe succeeded for {probe['url']}"
        ),
        {"url": probe["url"], "status_code": response["status_code"]},
    )


def run_https_tls_checks(probes=None, timeout=5):
    """Collect and interpret certificate-validated HTTPS probes."""
    return [
        analyze_https_tls_observation(observation)
        for observation in collect_https_tls_observations(
            probes=probes,
            timeout=timeout,
        )
    ]


def build_https_trust_reasoning_check(https_checks):
    """Summarize HTTPS/TLS probe results into one trust interpretation."""
    alerts = get_alert_checks(https_checks)
    alert_count = len(alerts)

    alert_names = [check["name"].replace("https_", "") for check in alerts]
    tls_failures = [
        check for check in alerts if "TLS verification failed" in check.get("summary", "")
    ]

    if tls_failures:
        return {
            "name": "https_trust_reasoning",
            "status": "alert",
            "summary": (
                f"{len(tls_failures)} HTTPS probe(s) failed certificate validation; TLS interception or trust problems are possible"
            ),
            "details": build_probe_reasoning_details(
                "certificate_validation_failure",
                len(https_checks),
                alert_probe_count=len(alerts),
                affected_probes=alert_names,
                context_note="certificate validation should normally succeed on a healthy internet path",
            ),
        }

    return build_probe_trust_reasoning_check(
        name="https_trust_reasoning",
        checks=https_checks,
        probe_prefix="https_",
        no_probe_summary="No HTTPS/TLS probes were run",
        normal_hint="normal_https_path",
        normal_summary="HTTPS/TLS probes look normal; certificate-validated web access appears healthy",
        normal_context_note="TLS validation and expected HTTPS responses both succeeded",
        all_alert_hint="broad_https_failure",
        all_alert_summary="All HTTPS probes failed or returned unexpected responses; secure web access looks degraded",
        all_alert_context_note="this can indicate broader connectivity problems, interception, or upstream filtering",
        partial_alert_hint="partial_https_failure",
        partial_alert_summary=(
            f"{alert_count} of {len(https_checks)} HTTPS probe(s) failed or returned unexpected responses; "
            "selective HTTPS disruption is possible"
        ),
        partial_alert_context_note="some HTTPS endpoints still behaved normally while others did not",
    )


def collect_overall_trust_signals(
    client_isolation_hint_check,
    dns_trust_reasoning_check,
    captive_trust_reasoning_check,
    https_trust_reasoning_check,
    active_path_check=None,
    gateway_reachability_check=None,
    network_profile=DEFAULT_NETWORK_PROFILE,
):
    """Extract the normalized signal set used by the overall trust explanation."""
    network_profile = normalize_network_profile(network_profile)
    local_details = client_isolation_hint_check.get("details", {})
    dns_details = dns_trust_reasoning_check.get("details", {})
    captive_details = captive_trust_reasoning_check.get("details", {})
    https_details = https_trust_reasoning_check.get("details", {})

    affected_components = []
    component_findings = []
    component_checks = [
        ("DNS", dns_trust_reasoning_check),
        ("Captive portal", captive_trust_reasoning_check),
        ("HTTPS", https_trust_reasoning_check),
        ("Active path", active_path_check),
        ("Gateway reachability", gateway_reachability_check),
    ]
    for label, check in component_checks:
        if check and check.get("status") in {"notice", "alert"}:
            affected_components.append(label)
            component_findings.append(
                {"component": label, "status": check["status"]}
            )

    return {
        "local_hint": local_details.get("hint_level"),
        "network_profile": network_profile,
        "profile_expectation": get_profile_expectation(network_profile, "overall"),
        "risky_gateway_service_count": local_details.get("risky_gateway_service_count", 0),
        "is_private_gateway": local_details.get("is_private_gateway", False),
        "dns_hint": dns_details.get("hint_level"),
        "captive_hint": captive_details.get("hint_level"),
        "https_hint": https_details.get("hint_level"),
        "active_path_status": active_path_check.get("status") if active_path_check else None,
        "gateway_reachability_status": (
            gateway_reachability_check.get("status") if gateway_reachability_check else None
        ),
        "affected_components": affected_components,
        "component_findings": component_findings,
    }


def classify_overall_trust_signals(signals):
    """Choose the operator-facing status, summary, and context from normalized signals."""
    affected_components = signals["affected_components"]
    local_hint = signals["local_hint"]
    network_profile = signals["network_profile"]
    risky_gateway_service_count = signals["risky_gateway_service_count"]
    is_private_gateway = signals["is_private_gateway"]

    if affected_components:
        alert_components = [
            item["component"]
            for item in signals.get("component_findings", [])
            if item["status"] == "alert"
        ]
        return {
            "status": "notice",
            "summary": (
                f"Internet trust path needs review: "
                f"{'alerts' if alert_components else 'notices'} are active in "
                f"{', '.join(affected_components)}"
            ),
            "context_note": "check the reasoning sections below to see whether the issue is local-path, DNS, captive, or HTTPS related",
        }
    if local_hint == "visibility_unavailable" and is_untrusted_profile(network_profile):
        return {
            "status": "notice",
            "summary": (
                f"Internet trust path looks healthy, but local peer visibility could not be assessed "
                f"for this {network_profile} network"
            ),
            "context_note": "unavailable passive evidence must not be treated as proof of client isolation",
        }
    if (
        local_hint == "gateway_only_visibility"
        and is_untrusted_profile(network_profile)
        and risky_gateway_service_count > 0
    ):
        summary = (
            "Internet trust path looks healthy, but this untrusted network exposes gateway-local "
            "admin/web surfaces; avoid trusting the local segment"
        )
        return {
            "status": "notice",
            "summary": summary,
            "context_note": get_profile_expectation(network_profile, "overall"),
        }
    if local_hint == "peer_visibility_detected" and is_untrusted_profile(network_profile):
        summary = (
            "Internet trust path looks healthy, but local peers are visible on this untrusted network; "
            "treat nearby devices as untrusted"
        )
        return {
            "status": "notice",
            "summary": summary,
            "context_note": get_profile_expectation(network_profile, "overall"),
        }
    if local_hint == "peer_visibility_detected" and is_private_gateway:
        return {
            "status": "ok",
            "summary": "Internet trust path looks healthy and the local segment behaves like a typical private/home LAN",
            "context_note": "peer visibility and gateway web surfaces are expected on many home LANs",
        }
    if local_hint == "peer_visibility_detected":
        return {
            "status": "notice",
            "summary": "Internet trust path looks healthy, but the local segment appears openly visible to nearby peers",
            "context_note": "this can be fine on a trusted home LAN, but deserves attention on an untrusted network",
        }
    return {
        "status": "ok",
        "summary": "Internet trust path looks healthy and the local segment does not currently show strong trust anomalies",
        "context_note": "DNS, captive-portal, and HTTPS checks all behaved normally",
    }


def build_overall_trust_details(signals, decision):
    """Build the stable details payload for the overall trust explanation."""
    return {
        "local_segment": signals["local_hint"],
        "network_profile": signals["network_profile"],
        "profile_expectation": signals["profile_expectation"],
        "risky_gateway_service_count": signals["risky_gateway_service_count"],
        "dns_path": signals["dns_hint"],
        "captive_path": signals["captive_hint"],
        "https_path": signals["https_hint"],
        "active_path": signals["active_path_status"],
        "gateway_reachability": signals["gateway_reachability_status"],
        "affected_components": signals["affected_components"],
        "component_findings": signals.get("component_findings", []),
        "context_note": decision["context_note"],
    }


def build_overall_trust_explanation_check(
    client_isolation_hint_check,
    dns_trust_reasoning_check,
    captive_trust_reasoning_check,
    https_trust_reasoning_check,
    active_path_check=None,
    gateway_reachability_check=None,
    network_profile=DEFAULT_NETWORK_PROFILE,
):
    """Build one short human-oriented explanation across local, DNS, captive, and HTTPS trust layers."""
    signals = collect_overall_trust_signals(
        client_isolation_hint_check,
        dns_trust_reasoning_check,
        captive_trust_reasoning_check,
        https_trust_reasoning_check,
        active_path_check=active_path_check,
        gateway_reachability_check=gateway_reachability_check,
        network_profile=network_profile,
    )
    decision = classify_overall_trust_signals(signals)
    return build_check(
        "overall_trust_explanation",
        decision["status"],
        decision["summary"],
        build_overall_trust_details(signals, decision),
    )


def collect_local_segment_checks(*, timeout=5, network_profile=DEFAULT_NETWORK_PROFILE):
    """Collect gateway and local-segment trust checks as one composable bundle."""
    network_profile = normalize_network_profile(network_profile)
    gateway_identity_check = resolve_gateway_identity()
    gateway_fingerprint_check = resolve_gateway_fingerprint()
    gateway_exposure_check = build_gateway_exposure_check(
        timeout=timeout,
        network_profile=network_profile,
    )
    local_peer_visibility_check = build_local_peer_visibility_check(
        network_profile=network_profile,
    )
    client_isolation_hint_check = build_client_isolation_hint_check(
        gateway_exposure_check,
        local_peer_visibility_check,
        network_profile=network_profile,
    )
    return {
        "gateway_identity": gateway_identity_check,
        "gateway_fingerprint": gateway_fingerprint_check,
        "gateway_exposure": gateway_exposure_check,
        "local_peer_visibility": local_peer_visibility_check,
        "client_isolation_hint": client_isolation_hint_check,
    }


def collect_internet_path_checks(
    *,
    dns_domains=None,
    timeout=5,
    network_profile=DEFAULT_NETWORK_PROFILE,
):
    """Collect DNS, captive-portal, and HTTPS trust checks as one composable bundle."""
    network_profile = normalize_network_profile(network_profile)
    dns_environment_check = build_dns_environment_check()
    dns_resolution_checks = run_dns_consistency_checks(dns_domains)
    dns_trust_reasoning_check = build_dns_trust_reasoning_check(
        dns_environment_check,
        dns_resolution_checks,
    )
    captive_checks = run_captive_portal_checks(
        timeout=timeout,
        network_profile=network_profile,
    )
    captive_trust_reasoning_check = build_captive_trust_reasoning_check(
        captive_checks,
        network_profile=network_profile,
    )
    https_checks = run_https_tls_checks(timeout=timeout)
    https_trust_reasoning_check = build_https_trust_reasoning_check(https_checks)
    return {
        "dns_environment": dns_environment_check,
        "dns_resolution_checks": dns_resolution_checks,
        "dns_trust_reasoning": dns_trust_reasoning_check,
        "captive_checks": captive_checks,
        "captive_trust_reasoning": captive_trust_reasoning_check,
        "https_checks": https_checks,
        "https_trust_reasoning": https_trust_reasoning_check,
    }


def collect_wifi_path_checks():
    """Collect Wi-Fi environment and active-route checks as one bundle."""
    wifi_environment_check = build_wifi_environment_check()
    active_path_check = build_active_path_check(wifi_environment_check.get("details"))
    return {
        "wifi_environment": wifi_environment_check,
        "active_path": active_path_check,
    }


def compose_network_health_checks(
    local_segment,
    gateway_reachability_check,
    internet_path,
    wifi_path,
    *,
    network_profile=DEFAULT_NETWORK_PROFILE,
    wifi_stability_check=None,
):
    """Compose collected check bundles into the stable report order."""
    active_path_check = wifi_path["active_path"]
    overall_trust_check = build_overall_trust_explanation_check(
        local_segment["client_isolation_hint"],
        internet_path["dns_trust_reasoning"],
        internet_path["captive_trust_reasoning"],
        internet_path["https_trust_reasoning"],
        active_path_check=active_path_check,
        gateway_reachability_check=gateway_reachability_check,
        network_profile=network_profile,
    )
    checks = [
        local_segment["gateway_identity"],
        local_segment["gateway_fingerprint"],
        local_segment["gateway_exposure"],
        gateway_reachability_check,
        local_segment["local_peer_visibility"],
        local_segment["client_isolation_hint"],
        internet_path["dns_environment"],
        internet_path["dns_trust_reasoning"],
        wifi_path["wifi_environment"],
        active_path_check,
        *internet_path["dns_resolution_checks"],
        *internet_path["captive_checks"],
        internet_path["captive_trust_reasoning"],
        *internet_path["https_checks"],
        internet_path["https_trust_reasoning"],
        overall_trust_check,
    ]
    if wifi_stability_check is not None:
        checks.append(wifi_stability_check)
    return checks


def run_network_health_checks(
    *,
    dns_domains=None,
    timeout=5,
    network_profile=DEFAULT_NETWORK_PROFILE,
    wifi_stability_seconds=0,
    wifi_stability_progress_callback=None,
    progress_callback=None,
):
    network_profile = normalize_network_profile(network_profile)
    progress_steps = 5
    if progress_callback:
        progress_callback("local network", 1, progress_steps)
    local_segment = collect_local_segment_checks(
        timeout=timeout,
        network_profile=network_profile,
    )
    if progress_callback:
        progress_callback("gateway reachability", 2, progress_steps)
    gateway_reachability_check = build_gateway_reachability_check()
    if progress_callback:
        progress_callback("internet and DNS", 3, progress_steps)
    internet_path = collect_internet_path_checks(
        dns_domains=dns_domains,
        timeout=timeout,
        network_profile=network_profile,
    )
    if progress_callback:
        progress_callback("Wi-Fi environment", 4, progress_steps)
    wifi_path = collect_wifi_path_checks()
    stability_check = None
    if wifi_stability_seconds and wifi_stability_seconds > 0:
        stability_check = run_wifi_stability_diagnostics(
            duration_seconds=wifi_stability_seconds,
            progress_callback=wifi_stability_progress_callback,
        )
    checks = compose_network_health_checks(
        local_segment,
        gateway_reachability_check,
        internet_path,
        wifi_path,
        network_profile=network_profile,
        wifi_stability_check=stability_check,
    )
    if progress_callback:
        progress_callback("finalizing report", 5, progress_steps)
    return checks


def build_health_summary(checks):
    total = len(checks)
    alerts = [check for check in checks if check["status"] == "alert"]
    notices = [check for check in checks if check["status"] == "notice"]
    oks = [check for check in checks if check["status"] == "ok"]
    return {
        "total_checks": total,
        "ok_checks": len(oks),
        "notice_checks": len(notices),
        "alert_checks": len(alerts),
        "notices": notices,
        "alerts": alerts,
    }
