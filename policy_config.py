"""Local known-device configuration and conservative policy evaluation."""

import json
import os


DEFAULT_CONFIG = {
    "known_devices": {},
    "policies": {
        "alert_on_unknown_device": True,
        "alert_on_unexpected_port": True,
        "alert_on_ssh_key_change": True,
    },
}


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
    if any(key in config for key in ("password", "private_key", "token")):
        raise ValueError("Policy config must not contain credentials.")
    known_devices = config.get("known_devices", {})
    if not isinstance(known_devices, dict):
        raise ValueError("known_devices must be an object keyed by MAC address.")
    for mac, device in known_devices.items():
        if not isinstance(mac, str) or len(mac.split(":")) != 6:
            raise ValueError(f"Invalid MAC address in known_devices: {mac}")
        if not isinstance(device, dict):
            raise ValueError(f"Known device {mac} must be an object.")
        if any(key in device for key in ("password", "private_key", "token")):
            raise ValueError("Policy config must not contain credentials.")
        ports = device.get("expected_ports", [])
        if not isinstance(ports, list) or any(not isinstance(port, int) for port in ports):
            raise ValueError(f"expected_ports for {mac} must be a list of integers.")
        fingerprint = device.get("expected_ssh_fingerprint")
        if fingerprint is not None and not isinstance(fingerprint, str):
            raise ValueError(f"expected_ssh_fingerprint for {mac} must be a string.")
        expected_http = device.get("expected_http", {})
        if not isinstance(expected_http, dict):
            raise ValueError(f"expected_http for {mac} must be an object keyed by port.")


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
                findings.append({"type": "unknown_device", "ip": device["ip"], "mac": mac})
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
            if expected_fingerprint and fingerprint and fingerprint != expected_fingerprint:
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
            if expected_http and observed_http:
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
