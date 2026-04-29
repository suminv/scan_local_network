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
ACTIVE_WIFI_STATUSES = {"spairport_status_active", "connected", "active"}


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

    return {
        "name": "gateway_identity",
        "status": "ok" if not is_public_ip(gateway_ip) else "alert",
        "summary": (
            f"Default gateway {gateway_ip} on {interface}"
            if hostname is None
            else f"Default gateway {gateway_ip} ({hostname}) on {interface}"
        ),
        "details": {
            "gateway_ip": gateway_ip,
            "interface": interface,
            "hostname": hostname,
            "is_public_ip": is_public_ip(gateway_ip),
        },
    }


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


def build_gateway_exposure_check(timeout=2, probes=None):
    """Inspect only the default gateway for a small set of local services."""
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

    if risky_services:
        if not is_private_gateway:
            status = "alert"
            summary = (
                f"Gateway exposes {len(risky_services)} local web/admin service(s) "
                f"to the client on {gateway_ip}"
            )
        else:
            status = "notice"
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
            "is_private_gateway": is_private_gateway,
            "context_note": (
                "often expected on a private/home LAN"
                if is_private_gateway and risky_services
                else None
            ),
            "reachable_services": reachable_services,
            "risky_services": risky_services,
        },
    }


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
                "mac": mac,
                "interface": match.group("interface"),
            }
        )
    return entries


def build_local_peer_visibility_check():
    """Inspect the passive ARP cache for visible local peers on the current interface."""
    gateway_ip, interface = get_default_gateway()
    is_private_gateway = not is_public_ip(gateway_ip)
    try:
        entries = parse_arp_cache_entries(run_command(["arp", "-an"]))
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {
            "name": "local_peer_visibility",
            "status": "ok",
            "summary": "ARP cache inspection is unavailable on this platform/setup",
            "details": {"interface": interface, "gateway_ip": gateway_ip, "visible_peers": []},
        }

    visible_peers = []
    for entry in entries:
        if entry["interface"] != interface:
            continue
        if entry["ip"] == gateway_ip:
            continue
        try:
            ip_obj = ipaddress.ip_address(entry["ip"])
        except ValueError:
            continue
        if ip_obj.version != 4 or ip_obj.is_loopback or ip_obj.is_link_local:
            continue
        if not ip_obj.is_private:
            continue
        visible_peers.append(entry)

    if visible_peers:
        status = "notice"
        summary = (
            f"ARP cache shows {len(visible_peers)} local peer(s) besides the gateway on {interface}"
        )
    else:
        status = "ok"
        summary = f"No additional local peers are currently visible in ARP cache on {interface}"

    return {
        "name": "local_peer_visibility",
        "status": status,
        "summary": summary,
        "details": {
            "interface": interface,
            "gateway_ip": gateway_ip,
            "is_private_gateway": is_private_gateway,
            "context_note": (
                "often normal on a private/home LAN"
                if is_private_gateway and visible_peers
                else None
            ),
            "visible_peers": visible_peers,
        },
    }


def build_client_isolation_hint_check(gateway_exposure_check, local_peer_visibility_check):
    """Summarize whether the current segment appears to expose peer devices to the client."""
    exposure_details = gateway_exposure_check.get("details", {})
    peer_details = local_peer_visibility_check.get("details", {})
    interface = peer_details.get("interface") or exposure_details.get("interface")
    gateway_ip = peer_details.get("gateway_ip") or exposure_details.get("gateway_ip")
    is_private_gateway = peer_details.get("is_private_gateway")
    if is_private_gateway is None:
        is_private_gateway = exposure_details.get("is_private_gateway")
    visible_peers = peer_details.get("visible_peers", [])
    risky_services = exposure_details.get("risky_services", [])

    if visible_peers:
        status = "notice"
        hint_level = "peer_visibility_detected"
        if is_private_gateway:
            summary = (
                f"Local peers are already visible to this client on {interface}; this is typical "
                "for a private/home LAN and suggests client isolation is not enforced"
            )
        else:
            summary = (
                f"Local peers are already visible to this client on {interface}; client isolation "
                "is likely absent or relaxed on the current segment"
            )
    elif risky_services:
        status = "ok"
        hint_level = "gateway_only_visibility"
        if is_private_gateway:
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
            f"No local peer visibility is currently evident on {interface}; client isolation may "
            "be present or peer traffic has not been observed yet"
        )

    return {
        "name": "client_isolation_hint",
        "status": status,
        "summary": summary,
        "details": {
            "interface": interface,
            "gateway_ip": gateway_ip,
            "is_private_gateway": bool(is_private_gateway),
            "hint_level": hint_level,
            "visible_peer_count": len(visible_peers),
            "visible_peers": visible_peers[:8],
            "risky_gateway_service_count": len(risky_services),
            "context_note": (
                "typical for a private/home LAN"
                if is_private_gateway and hint_level == "peer_visibility_detected"
                else None
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
        return mac
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


def run_dns_consistency_checks(domains=None):
    checks = []
    for domain in domains or DEFAULT_DNS_DOMAINS:
        try:
            ips = resolve_domain_ips(domain)
        except socket.gaierror as exc:
            checks.append(
                {
                    "name": f"dns_{domain}",
                    "status": "alert",
                    "summary": f"DNS lookup failed for {domain}",
                    "details": {"domain": domain, "error": str(exc)},
                }
            )
            continue

        public_ips = [ip for ip in ips if is_public_ip(ip)]
        if not public_ips:
            checks.append(
                {
                    "name": f"dns_{domain}",
                    "status": "alert",
                    "summary": f"{domain} resolved only to non-public addresses",
                    "details": {"domain": domain, "ips": ips},
                }
            )
            continue

        checks.append(
            {
                "name": f"dns_{domain}",
                "status": "ok",
                "summary": f"{domain} resolved to {len(public_ips)} public address(es)",
                "details": {"domain": domain, "ips": ips},
            }
        )
    return checks


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
    try:
        address = ipaddress.ip_address(normalize_ip_for_compare(ip))
    except ValueError:
        return False
    return any(address in network for network in get_interface_networks(interface))


def classify_dns_server(server, resolver=None, default_interface=None, gateway_ip=None):
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

    if address.is_private or address.is_loopback or address.is_link_local:
        return {
            "server": server,
            "classification": "local_private",
            "risk": False,
            "reason": "DNS server is a private or link-local address",
        }

    if default_interface and is_on_interface_network(server, default_interface):
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
            "reason": "system resolver points directly at a global address",
        }

    return {
        "server": server,
        "classification": "unknown",
        "risk": False,
        "reason": "DNS server did not match a known risky pattern",
    }


def analyze_dns_servers(nameservers, resolvers=None, default_interface=None, gateway_ip=None):
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
        )
        classifications.append(classification)
        if classification["risk"]:
            risks.append(
                {
                    "type": classification["classification"],
                    "server": server,
                    "reason": classification["reason"],
                }
            )
    return {
        "server_count": len(nameservers),
        "classifications": classifications,
        "risks": risks,
    }


def build_dns_environment_check():
    dns_config = collect_dns_configuration()
    nameservers = dns_config.get("nameservers", [])
    gateway_ip, default_interface = get_default_gateway()
    analysis = analyze_dns_servers(
        nameservers,
        resolvers=dns_config.get("resolvers", []),
        default_interface=default_interface,
        gateway_ip=gateway_ip,
    )
    dns_config["analysis"] = analysis

    if not nameservers:
        return {
            "name": "dns_environment",
            "status": "alert",
            "summary": "No DNS servers could be determined from the current environment",
            "details": dns_config,
        }

    if analysis["risks"]:
        return {
            "name": "dns_environment",
            "status": "alert",
            "summary": f"DNS environment exposes {len(analysis['risks'])} risk signal(s)",
            "details": dns_config,
        }

    return {
        "name": "dns_environment",
        "status": "ok",
        "summary": f"Detected {len(nameservers)} DNS server(s) from {dns_config['source']}",
        "details": dns_config,
    }


def build_dns_trust_reasoning_check(dns_environment_check, dns_resolution_checks):
    """Summarize DNS trust posture from resolver classification and domain lookups."""
    details = dns_environment_check.get("details", {})
    analysis = details.get("analysis", {})
    classifications = analysis.get("classifications", [])
    nameservers = details.get("nameservers", [])
    classification_types = [item.get("classification") for item in classifications]
    resolution_alerts = [check for check in dns_resolution_checks if check.get("status") == "alert"]
    risk_count = len(analysis.get("risks", []))

    if not nameservers:
        return {
            "name": "dns_trust_reasoning",
            "status": "alert",
            "summary": "DNS trust cannot be assessed because no active DNS servers were detected",
            "details": {
                "hint_level": "dns_unavailable",
                "nameservers": [],
                "resolver_profile": [],
                "risk_count": 0,
                "resolution_issue_count": 0,
                "affected_domains": [],
                "context_note": None,
            },
        }

    if resolution_alerts:
        return {
            "name": "dns_trust_reasoning",
            "status": "alert",
            "summary": f"DNS trust is degraded: {len(resolution_alerts)} domain lookup issue(s) were observed",
            "details": {
                "hint_level": "resolution_failure",
                "nameservers": nameservers,
                "resolver_profile": classification_types,
                "risk_count": risk_count,
                "resolution_issue_count": len(resolution_alerts),
                "affected_domains": [
                    check.get("details", {}).get("domain")
                    for check in resolution_alerts
                    if check.get("details", {}).get("domain")
                ],
                "context_note": "public name resolution did not behave normally",
            },
        }

    if "public_upstream" in classification_types:
        local_classes = {"gateway_dns", "local_private", "on_link", "directly_reachable"}
        mixed_local_and_public = any(item in local_classes for item in classification_types)
        return {
            "name": "dns_trust_reasoning",
            "status": "alert",
            "summary": (
                "DNS path mixes local/private and public upstream resolvers"
                if mixed_local_and_public
                else "System resolver points directly at public upstream DNS"
            ),
            "details": {
                "hint_level": "mixed_dns_path" if mixed_local_and_public else "public_upstream_dns_present",
                "nameservers": nameservers,
                "resolver_profile": classification_types,
                "risk_count": risk_count,
                "resolution_issue_count": 0,
                "affected_domains": [],
                "context_note": "can be legitimate, but is less typical for private/home LANs and some guest networks",
            },
        }

    if "gateway_dns" in classification_types:
        return {
            "name": "dns_trust_reasoning",
            "status": "ok",
            "summary": "DNS path looks local and expected: the current gateway is acting as resolver",
            "details": {
                "hint_level": "gateway_dns_expected",
                "nameservers": nameservers,
                "resolver_profile": classification_types,
                "risk_count": risk_count,
                "resolution_issue_count": 0,
                "affected_domains": [],
                "context_note": "typical for private/home LANs and many managed networks",
            },
        }

    if any(item in {"local_private", "on_link", "directly_reachable"} for item in classification_types):
        return {
            "name": "dns_trust_reasoning",
            "status": "ok",
            "summary": "DNS path looks local/on-link and does not currently show trust anomalies",
            "details": {
                "hint_level": "private_local_dns_expected",
                "nameservers": nameservers,
                "resolver_profile": classification_types,
                "risk_count": risk_count,
                "resolution_issue_count": 0,
                "affected_domains": [],
                "context_note": "consistent with local or directly reachable resolvers",
            },
        }

    return {
        "name": "dns_trust_reasoning",
        "status": "ok",
        "summary": "DNS path does not currently show a strong trust signal in either direction",
        "details": {
            "hint_level": "dns_path_unclear",
            "nameservers": nameservers,
            "resolver_profile": classification_types,
            "risk_count": risk_count,
            "resolution_issue_count": 0,
            "affected_domains": [],
            "context_note": None,
        },
    }


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


def run_captive_portal_checks(probes=None, timeout=5):
    checks = []
    for probe in probes or DEFAULT_HTTP_PROBES:
        response = fetch_url(probe["url"], timeout=timeout)
        location = response["headers"].get("Location")
        body = response["body"]
        expected_status = probe["expected_status"]
        expected_body_contains = probe["expected_body_contains"]
        redirected = location is not None and 300 <= response["status_code"] < 400
        body_mismatch = (
            expected_body_contains is not None and expected_body_contains not in body
        )
        suspicious = response["status_code"] != expected_status or redirected or body_mismatch
        checks.append(
            {
                "name": f"captive_{probe['name']}",
                "status": "alert" if suspicious else "ok",
                "summary": (
                    f"Unexpected captive-portal probe response for {probe['url']}"
                    if suspicious
                    else f"Connectivity probe looked normal for {probe['url']}"
                ),
                "details": {
                    "url": probe["url"],
                    "status_code": response["status_code"],
                    "location": location,
                    "body_preview": body,
                },
            }
        )
    return checks


def build_captive_trust_reasoning_check(captive_checks):
    """Summarize captive-portal probe results into one trust interpretation."""
    alerts = [check for check in captive_checks if check.get("status") == "alert"]
    if not captive_checks:
        return {
            "name": "captive_trust_reasoning",
            "status": "ok",
            "summary": "No captive-portal probes were run",
            "details": {
                "hint_level": "no_probes",
                "probe_count": 0,
                "alert_probe_count": 0,
                "affected_probes": [],
                "context_note": None,
            },
        }

    if not alerts:
        return {
            "name": "captive_trust_reasoning",
            "status": "ok",
            "summary": "Captive-portal probes look normal; no HTTP interception is evident",
            "details": {
                "hint_level": "normal_internet_path",
                "probe_count": len(captive_checks),
                "alert_probe_count": 0,
                "affected_probes": [],
                "context_note": "connectivity-check endpoints behaved as expected",
            },
        }

    alert_names = [check["name"].replace("captive_", "") for check in alerts]
    if len(alerts) == len(captive_checks):
        hint_level = "likely_captive_portal"
        summary = (
            f"All captive-portal probes behaved unexpectedly; captive portal or broad HTTP interception is likely"
        )
        context_note = "multiple independent connectivity checks were affected"
    else:
        hint_level = "partial_http_interception"
        summary = (
            f"{len(alerts)} of {len(captive_checks)} captive-portal probe(s) behaved unexpectedly; partial interception or a portal edge case is possible"
        )
        context_note = "some HTTP checks were affected while others still looked normal"

    return {
        "name": "captive_trust_reasoning",
        "status": "alert",
        "summary": summary,
        "details": {
            "hint_level": hint_level,
            "probe_count": len(captive_checks),
            "alert_probe_count": len(alerts),
            "affected_probes": alert_names,
            "context_note": context_note,
        },
    }


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
    return {
        "software": section.get("spairport_software_information", {}),
        "interfaces": interfaces,
    }


def collect_macos_wifi_inventory():
    profiler = parse_system_profiler_wifi_json(
        run_command(["system_profiler", "SPAirPortDataType", "-json"])
    )
    return {
        "platform": "macos",
        "software": profiler["software"],
        "interfaces": profiler["interfaces"],
    }


def parse_wdutil_info(raw_text):
    current_interface = None
    interface_data = {}
    for raw_line in raw_text.splitlines():
        line = raw_line.rstrip()
        interface_match = re.match(r"^\s{8}([A-Za-z0-9]+):\s*$", line)
        if interface_match:
            current_interface = interface_match.group(1)
            interface_data.setdefault(current_interface, {})
            continue
        if current_interface is None:
            continue
        field_match = re.match(r"^\s{10}([^:]+):\s*(.+?)\s*$", line)
        if field_match:
            key = field_match.group(1).strip().lower().replace(" ", "_")
            interface_data[current_interface][key] = field_match.group(2).strip()
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
    return {
        "available": True,
        "reason": None,
        "interfaces": parsed,
    }


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


def build_active_path_check(wifi_environment=None):
    gateway_ip, default_interface = get_default_gateway()
    if not is_macos():
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

    if wifi_environment is None:
        wifi_environment = collect_wifi_environment()

    inventory = (wifi_environment or {}).get("inventory", {})
    current = (wifi_environment or {}).get("current", {})
    active_wifi_interface = get_active_wifi_interface_name(inventory, current)

    if active_wifi_interface and active_wifi_interface != default_interface:
        return {
            "name": "active_path",
            "status": "alert",
            "summary": (
                f"Active Wi-Fi interface {active_wifi_interface} is present, but the default route "
                f"currently uses {default_interface}"
            ),
            "details": {
                "gateway_ip": gateway_ip,
                "default_interface": default_interface,
                "wifi_interface": active_wifi_interface,
                "wifi_active": True,
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
        },
    }


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
        if ping.get("avg_ms") is not None:
            latency_values.append(float(ping["avg_ms"]))
        if ping.get("loss_percent") is not None:
            loss_values.append(float(ping["loss_percent"]))

    bssid_changes = 0
    for previous, current in zip(bssids, bssids[1:]):
        if previous != current:
            bssid_changes += 1

    avg_rssi = sum(rssi_values) / len(rssi_values) if rssi_values else None
    avg_latency = sum(latency_values) / len(latency_values) if latency_values else None
    max_loss = max(loss_values) if loss_values else 0.0

    reasons = []
    if bssid_changes > 0:
        reasons.append(f"BSSID changed {bssid_changes} time(s)")
    if max_loss > 0:
        reasons.append(f"packet loss peaked at {max_loss:.0f}%")
    if avg_rssi is not None and avg_rssi <= -75:
        reasons.append(f"weak average signal ({avg_rssi:.0f} dBm)")
    if avg_latency is not None and avg_latency >= 30:
        reasons.append(f"high average gateway latency ({avg_latency:.1f} ms)")

    if bssid_changes > 1 or max_loss >= 10:
        level = "unstable"
    elif reasons:
        level = "degraded"
    else:
        level = "stable"

    return {
        "gateway_ip": gateway_ip,
        "sample_count": len(samples),
        "bssid_changes": bssid_changes,
        "avg_rssi": avg_rssi,
        "avg_latency_ms": avg_latency,
        "max_loss_percent": max_loss,
        "reasons": reasons,
        "level": level,
        "samples": samples,
    }


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
    level = summary["level"]
    if level == "stable":
        status = "ok"
        text = f"Wi-Fi link to gateway {gateway_ip} looked stable across {summary['sample_count']} sample(s)"
    elif level == "degraded":
        status = "alert"
        text = f"Wi-Fi link to gateway {gateway_ip} looked degraded: {', '.join(summary['reasons'])}"
    elif level == "unstable":
        status = "alert"
        text = f"Wi-Fi link to gateway {gateway_ip} looked unstable: {', '.join(summary['reasons'])}"
    else:
        status = "alert"
        text = "Wi-Fi stability diagnostics were unavailable"

    return {
        "name": "wifi_stability",
        "status": status,
        "summary": text,
        "details": summary,
    }


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
    return {
        "platform": "macos",
        "inventory": collect_macos_wifi_inventory(),
        "current": collect_macos_current_wifi_details(),
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


def analyze_nearby_wifi_networks(networks):
    risks = []
    duplicate_ssids = []
    by_ssid = {}

    for network in networks:
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

        try:
            rssi = int(network.get("rssi", "0"))
        except ValueError:
            rssi = 0
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

    return {
        "visible_network_count": len(networks),
        "duplicate_ssids": duplicate_ssids,
        "limited_scan": (
            len(networks) > 0
            and all((network.get("ssid") or "<hidden>") == "<hidden>" for network in networks)
            and all(not network.get("bssid") for network in networks)
            and all(not network.get("security") for network in networks)
        ),
        "risks": risks,
    }


def build_wifi_environment_analysis(wifi_environment):
    """Attach a nearby-network analysis block to the collected Wi-Fi state."""
    nearby_networks = wifi_environment["nearby"]["networks"]
    analysis = (
        analyze_nearby_wifi_networks(nearby_networks)
        if nearby_networks
        else {
            "visible_network_count": 0,
            "duplicate_ssids": [],
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


def build_wifi_environment_check():
    wifi = collect_wifi_environment()
    if wifi is None:
        return {
            "name": "wifi_environment",
            "status": "ok",
            "summary": "Wi-Fi environment inspection is only implemented for macOS in this version",
            "details": {"platform": platform.system()},
        }

    wifi = build_wifi_environment_analysis(wifi)
    status, summary = summarize_wifi_environment(wifi)

    return {
        "name": "wifi_environment",
        "status": status,
        "summary": summary,
        "details": wifi,
    }


def run_https_tls_checks(probes=None, timeout=5):
    checks = []
    for probe in probes or DEFAULT_HTTPS_PROBES:
        try:
            response = probe_https_endpoint(probe["url"], timeout=timeout)
            expected_statuses = probe["expected_statuses"]
            suspicious = response["status_code"] not in expected_statuses
            checks.append(
                {
                    "name": f"https_{probe['name']}",
                    "status": "alert" if suspicious else "ok",
                    "summary": (
                        f"Unexpected HTTPS response for {probe['url']}"
                        if suspicious
                        else f"HTTPS probe succeeded for {probe['url']}"
                    ),
                    "details": {
                        "url": probe["url"],
                        "status_code": response["status_code"],
                    },
                }
            )
        except ssl.SSLError as exc:
            checks.append(
                {
                    "name": f"https_{probe['name']}",
                    "status": "alert",
                    "summary": f"TLS verification failed for {probe['url']}",
                    "details": {"url": probe["url"], "error": str(exc)},
                }
            )
        except (urllib.error.URLError, OSError) as exc:
            checks.append(
                {
                    "name": f"https_{probe['name']}",
                    "status": "alert",
                    "summary": f"HTTPS probe failed for {probe['url']}",
                    "details": {"url": probe["url"], "error": str(exc)},
                }
            )
    return checks


def build_https_trust_reasoning_check(https_checks):
    """Summarize HTTPS/TLS probe results into one trust interpretation."""
    alerts = [check for check in https_checks if check.get("status") == "alert"]
    if not https_checks:
        return {
            "name": "https_trust_reasoning",
            "status": "ok",
            "summary": "No HTTPS/TLS probes were run",
            "details": {
                "hint_level": "no_probes",
                "probe_count": 0,
                "alert_probe_count": 0,
                "affected_probes": [],
                "context_note": None,
            },
        }

    if not alerts:
        return {
            "name": "https_trust_reasoning",
            "status": "ok",
            "summary": "HTTPS/TLS probes look normal; certificate-validated web access appears healthy",
            "details": {
                "hint_level": "normal_https_path",
                "probe_count": len(https_checks),
                "alert_probe_count": 0,
                "affected_probes": [],
                "context_note": "TLS validation and expected HTTPS responses both succeeded",
            },
        }

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
            "details": {
                "hint_level": "certificate_validation_failure",
                "probe_count": len(https_checks),
                "alert_probe_count": len(alerts),
                "affected_probes": alert_names,
                "context_note": "certificate validation should normally succeed on a healthy internet path",
            },
        }

    if len(alerts) == len(https_checks):
        hint_level = "broad_https_failure"
        summary = "All HTTPS probes failed or returned unexpected responses; secure web access looks degraded"
        context_note = "this can indicate broader connectivity problems, interception, or upstream filtering"
    else:
        hint_level = "partial_https_failure"
        summary = (
            f"{len(alerts)} of {len(https_checks)} HTTPS probe(s) failed or returned unexpected responses; selective HTTPS disruption is possible"
        )
        context_note = "some HTTPS endpoints still behaved normally while others did not"

    return {
        "name": "https_trust_reasoning",
        "status": "alert",
        "summary": summary,
        "details": {
            "hint_level": hint_level,
            "probe_count": len(https_checks),
            "alert_probe_count": len(alerts),
            "affected_probes": alert_names,
            "context_note": context_note,
        },
    }


def build_overall_trust_explanation_check(
    client_isolation_hint_check,
    dns_trust_reasoning_check,
    captive_trust_reasoning_check,
    https_trust_reasoning_check,
    active_path_check=None,
):
    """Build one short human-oriented explanation across local, DNS, captive, and HTTPS trust layers."""
    local_details = client_isolation_hint_check.get("details", {})
    dns_details = dns_trust_reasoning_check.get("details", {})
    captive_details = captive_trust_reasoning_check.get("details", {})
    https_details = https_trust_reasoning_check.get("details", {})

    local_hint = local_details.get("hint_level")
    dns_hint = dns_details.get("hint_level")
    captive_hint = captive_details.get("hint_level")
    https_hint = https_details.get("hint_level")
    is_private_gateway = local_details.get("is_private_gateway", False)

    affected_components = []
    if dns_trust_reasoning_check.get("status") == "alert":
        affected_components.append("DNS")
    if captive_trust_reasoning_check.get("status") == "alert":
        affected_components.append("Captive portal")
    if https_trust_reasoning_check.get("status") == "alert":
        affected_components.append("HTTPS")
    if active_path_check and active_path_check.get("status") == "alert":
        affected_components.append("Active path")

    if affected_components:
        status = "notice"
        summary = (
            f"Internet trust path needs review: signals are active in {', '.join(affected_components)}"
        )
        context_note = "check the reasoning sections below to see whether the issue is local-path, DNS, captive, or HTTPS related"
    elif local_hint == "peer_visibility_detected" and is_private_gateway:
        status = "ok"
        summary = "Internet trust path looks healthy and the local segment behaves like a typical private/home LAN"
        context_note = "peer visibility and gateway web surfaces are expected on many home LANs"
    elif local_hint == "peer_visibility_detected":
        status = "notice"
        summary = "Internet trust path looks healthy, but the local segment appears openly visible to nearby peers"
        context_note = "this can be fine on trusted LANs, but deserves attention on guest or public networks"
    else:
        status = "ok"
        summary = "Internet trust path looks healthy and the local segment does not currently show strong trust anomalies"
        context_note = "DNS, captive-portal, and HTTPS checks all behaved normally"

    return {
        "name": "overall_trust_explanation",
        "status": status,
        "summary": summary,
        "details": {
            "local_segment": local_hint,
            "dns_path": dns_hint,
            "captive_path": captive_hint,
            "https_path": https_hint,
            "active_path": active_path_check.get("status") if active_path_check else None,
            "affected_components": affected_components,
            "context_note": context_note,
        },
    }


def run_network_health_checks(
    *,
    dns_domains=None,
    timeout=5,
    wifi_stability_seconds=0,
    wifi_stability_progress_callback=None,
):
    gateway_identity_check = resolve_gateway_identity()
    gateway_fingerprint_check = resolve_gateway_fingerprint()
    gateway_exposure_check = build_gateway_exposure_check(timeout=timeout)
    local_peer_visibility_check = build_local_peer_visibility_check()
    client_isolation_hint_check = build_client_isolation_hint_check(
        gateway_exposure_check,
        local_peer_visibility_check,
    )
    dns_environment_check = build_dns_environment_check()
    dns_resolution_checks = run_dns_consistency_checks(dns_domains)
    dns_trust_reasoning_check = build_dns_trust_reasoning_check(
        dns_environment_check,
        dns_resolution_checks,
    )
    captive_checks = run_captive_portal_checks(timeout=timeout)
    captive_trust_reasoning_check = build_captive_trust_reasoning_check(captive_checks)
    https_checks = run_https_tls_checks(timeout=timeout)
    https_trust_reasoning_check = build_https_trust_reasoning_check(https_checks)
    checks = [
        gateway_identity_check,
        gateway_fingerprint_check,
        gateway_exposure_check,
        local_peer_visibility_check,
        client_isolation_hint_check,
        dns_environment_check,
        dns_trust_reasoning_check,
    ]
    wifi_environment_check = build_wifi_environment_check()
    checks.append(wifi_environment_check)
    active_path_check = build_active_path_check(wifi_environment_check.get("details"))
    checks.append(active_path_check)
    checks.extend(dns_resolution_checks)
    checks.extend(captive_checks)
    checks.append(captive_trust_reasoning_check)
    checks.extend(https_checks)
    checks.append(https_trust_reasoning_check)
    checks.append(
        build_overall_trust_explanation_check(
            client_isolation_hint_check,
            dns_trust_reasoning_check,
            captive_trust_reasoning_check,
            https_trust_reasoning_check,
            active_path_check=active_path_check,
        )
    )
    if wifi_stability_seconds and wifi_stability_seconds > 0:
        stability_check = run_wifi_stability_diagnostics(
            duration_seconds=wifi_stability_seconds,
            progress_callback=wifi_stability_progress_callback,
        )
        if stability_check is not None:
            checks.append(stability_check)
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
