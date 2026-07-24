"""Local known-device configuration and conservative policy evaluation."""

import json
import os
import re


DEFAULT_CONFIG = {
    "known_devices": {},
    "policies": {
        "alert_on_unknown_device": True,
        "alert_on_unexpected_port": True,
        "alert_on_ssh_key_change": True,
        "alert_on_http_identity_change": True,
        "alert_on_tls_expiry": True,
    },
}
FORBIDDEN_CREDENTIAL_KEYS = {
    "api_key",
    "apikey",
    "credential",
    "credentials",
    "password",
    "private_key",
    "secret",
    "token",
}
SUPPORTED_POLICIES = set(DEFAULT_CONFIG["policies"])
MAC_ADDRESS_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def reject_credentials(value):
    """Reject credential-like keys at any depth in a policy document."""
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in FORBIDDEN_CREDENTIAL_KEYS:
                raise ValueError("Policy config must not contain credentials.")
            reject_credentials(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_credentials(nested)


def load_policy_config(path):
    """Load and validate an optional JSON policy file; return defaults when absent."""
    if not path:
        return DEFAULT_CONFIG.copy()
    if not os.path.exists(path):
        raise ValueError(f"Policy config file was not found: {path}")
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    validate_policy_config(config)
    merged = DEFAULT_CONFIG.copy()
    merged["known_devices"] = config.get("known_devices", {})
    merged["policies"] = {**DEFAULT_CONFIG["policies"], **config.get("policies", {})}
    return merged


def validate_policy_config(config):
    """Validate the small JSON schema and reject credential-like fields."""
    if not isinstance(config, dict):
        raise ValueError("Policy config must be a JSON object.")
    reject_credentials(config)
    known_devices = config.get("known_devices", {})
    if not isinstance(known_devices, dict):
        raise ValueError("known_devices must be an object keyed by MAC address.")
    for mac, device in known_devices.items():
        if not isinstance(mac, str) or not MAC_ADDRESS_PATTERN.fullmatch(mac):
            raise ValueError(f"Invalid MAC address in known_devices: {mac}")
        if not isinstance(device, dict):
            raise ValueError(f"Known device {mac} must be an object.")
        name = device.get("name")
        if name is not None and not isinstance(name, str):
            raise ValueError(f"name for {mac} must be a string.")
        ports = device.get("expected_ports", [])
        if not isinstance(ports, list) or any(
            not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
            for port in ports
        ):
            raise ValueError(f"expected_ports for {mac} must be a list of integers.")
        fingerprint = device.get("expected_ssh_fingerprint")
        if fingerprint is not None and not isinstance(fingerprint, str):
            raise ValueError(f"expected_ssh_fingerprint for {mac} must be a string.")
        expected_http = device.get("expected_http", {})
        if not isinstance(expected_http, dict):
            raise ValueError(f"expected_http for {mac} must be an object keyed by port.")
        for port, identity in expected_http.items():
            try:
                port_number = int(port)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"expected_http for {mac} contains an invalid port: {port}"
                ) from exc
            if not 1 <= port_number <= 65535 or not isinstance(identity, dict):
                raise ValueError(
                    f"expected_http for {mac} must map valid ports to objects."
                )
    policies = config.get("policies", {})
    if not isinstance(policies, dict):
        raise ValueError("policies must be an object.")
    unsupported = set(policies) - SUPPORTED_POLICIES
    if unsupported:
        raise ValueError(
            f"Unsupported policy option(s): {', '.join(sorted(unsupported))}"
        )
    if any(not isinstance(value, bool) for value in policies.values()):
        raise ValueError("Policy options must be true or false.")
    return config


def evaluate_device_policies(devices, config):
    """Return policy findings for the observed devices without changing scan data."""
    known_devices = {
        mac.lower(): value for mac, value in config.get("known_devices", {}).items()
    }
    policies = config.get("policies", {})
    findings = []
    for device in devices:
        mac = (device.get("mac") or "").lower()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        known = known_devices.get(mac)
        if known is None:
            if policies.get("alert_on_unknown_device", True):
                observed_ports = [
                    {
                        "port": port_info["port"],
                        "service": port_info.get("service", "Unknown"),
                    }
                    for port_info in device.get("open_ports", [])
                ]
                findings.append(
                    {
                        "type": "unknown_device",
                        "ip": device["ip"],
                        "mac": mac,
                        "observed_ports": observed_ports,
                    }
                )
            continue
        expected_ports = set(known.get("expected_ports", []))
        if policies.get("alert_on_unexpected_port", True):
            for port_info in device.get("open_ports", []):
                if port_info["port"] not in expected_ports:
                    findings.append(
                        {
                            "type": "unexpected_port",
                            "ip": device["ip"],
                            "mac": mac,
                            "name": known.get("name"),
                            "port": port_info["port"],
                        }
                    )
        expected_fingerprint = known.get("expected_ssh_fingerprint")
        for port_info in device.get("open_ports", []):
            fingerprint = (port_info.get("ssh") or {}).get("fingerprint_sha256")
            if (
                policies.get("alert_on_ssh_key_change", True)
                and expected_fingerprint
                and fingerprint
                and fingerprint != expected_fingerprint
            ):
                findings.append(
                    {
                        "type": "ssh_key_changed",
                        "ip": device["ip"],
                        "mac": mac,
                        "name": known.get("name"),
                        "port": port_info["port"],
                    }
                )
            expected_http = known.get("expected_http", {}).get(str(port_info["port"]))
            observed_http = port_info.get("http") or {}
            if (
                policies.get("alert_on_http_identity_change", True)
                and expected_http
            ):
                mismatch = any(
                    observed_http.get(key) != value
                    for key, value in expected_http.items()
                )
                if mismatch:
                    findings.append(
                        {
                            "type": "http_identity_changed",
                            "ip": device["ip"],
                            "mac": mac,
                            "name": known.get("name"),
                            "port": port_info["port"],
                        }
                    )
            tls = port_info.get("tls") or {}
            certificate_status = tls.get("certificate_status")
            if (
                policies.get("alert_on_tls_expiry", True)
                and certificate_status in {"expired", "expiring_soon"}
            ):
                findings.append(
                    {
                        "type": "tls_expiry",
                        "ip": device["ip"],
                        "mac": mac,
                        "name": known.get("name"),
                        "port": port_info["port"],
                        "certificate_status": certificate_status,
                        "not_after": tls.get("not_after"),
                    }
                )
    return findings


def build_baseline_config(devices):
    """Build a reviewable known-device baseline from one complete LAN scan."""
    known_devices = {}
    for device in sorted(devices, key=lambda item: item["ip"]):
        mac = (device.get("mac") or "").lower()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        vendor = device.get("vendor") or "Unknown vendor"
        known_devices[mac] = {
            "name": f"{vendor} ({device['ip']})",
            "expected_ports": sorted(
                port_info["port"] for port_info in device.get("open_ports", [])
            ),
        }
        for port_info in device.get("open_ports", []):
            ssh_info = port_info.get("ssh") or {}
            if ssh_info.get("fingerprint_sha256"):
                known_devices[mac]["expected_ssh_fingerprint"] = ssh_info[
                    "fingerprint_sha256"
                ]
            http_info = port_info.get("http") or {}
            if http_info:
                known_devices[mac].setdefault("expected_http", {})[
                    str(port_info["port"])
                ] = {
                    key: http_info[key]
                    for key in ("status", "title", "server")
                    if key in http_info
                }
    return {
        "known_devices": known_devices,
        "policies": DEFAULT_CONFIG["policies"].copy(),
    }


def save_policy_config(path, config):
    """Persist a validated policy config without embedding credentials."""
    validate_policy_config(config)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, sort_keys=True)
