"""Optional public-IP and approximate IP-geolocation lookup."""

import ipaddress
import json
import urllib.request


DEFAULT_LOOKUP_URL = "https://ipwho.is/"
MAX_RESPONSE_BYTES = 256 * 1024
USER_AGENT = "network-health-check/1.0"


def collect_public_ip(
    *,
    url=DEFAULT_LOOKUP_URL,
    timeout=10,
    opener=urllib.request.urlopen,
):
    """Fetch public IP and geolocation data from one HTTPS endpoint."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )
    with opener(request, timeout=timeout) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("public-IP response exceeds the size limit")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("public-IP service returned an invalid response")
    if payload.get("success") is False:
        message = payload.get("message") or "lookup failed"
        raise ValueError(f"public-IP service error: {message}")
    return payload


def _normalize_asn(connection):
    asn = connection.get("asn")
    if asn is None:
        return None
    text = str(asn).upper()
    return text if text.startswith("AS") else f"AS{text}"


def analyze_public_ip(observation):
    """Validate and normalize a public-IP lookup result."""
    raw_ip = observation.get("ip")
    try:
        address = ipaddress.ip_address(raw_ip)
    except (TypeError, ValueError):
        return {
            "name": "public_ip",
            "status": "notice",
            "summary": "Public IP lookup returned an invalid address",
            "details": {
                "provider": "ipwho.is",
                "public_ip": raw_ip,
                "approximate_location": True,
            },
        }

    connection = observation.get("connection") or {}
    timezone = observation.get("timezone") or {}
    location = {
        "city": observation.get("city"),
        "region": observation.get("region"),
        "country": observation.get("country"),
        "country_code": observation.get("country_code"),
        "continent": observation.get("continent"),
    }
    location_parts = [
        value
        for value in (location["city"], location["region"], location["country"])
        if value
    ]
    summary = f"Public IPv{address.version}: {address}"
    if location_parts:
        summary += f" · approximate location: {', '.join(location_parts)}"
    details = {
        "provider": "ipwho.is",
        "public_ip": str(address),
        "ip_version": address.version,
        "is_global": address.is_global,
        "approximate_location": True,
        "location": location,
        "timezone": timezone.get("id"),
        "isp": connection.get("isp"),
        "asn": _normalize_asn(connection),
    }
    if not address.is_global:
        return {
            "name": "public_ip",
            "status": "notice",
            "summary": f"IP lookup returned non-public address {address}",
            "details": details,
        }
    return {
        "name": "public_ip",
        "status": "ok",
        "summary": summary,
        "details": details,
    }


def build_public_ip_check(**kwargs):
    """Build a normalized check while keeping lookup errors non-fatal."""
    try:
        observation = collect_public_ip(**kwargs)
    except Exception as exc:
        return {
            "name": "public_ip",
            "status": "notice",
            "summary": "Public IP and location lookup was unavailable",
            "details": {
                "provider": "ipwho.is",
                "approximate_location": True,
                "error": str(exc),
            },
        }
    return analyze_public_ip(observation)
