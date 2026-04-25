import socket


def resolve_hostname(ip):
    """Resolve a reverse-DNS hostname for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return None
    if not hostname or hostname == ip:
        return None
    return hostname


def enrich_devices_with_hostnames(devices):
    """Attach reverse-DNS hostnames to device dictionaries when available."""
    for device in devices:
        hostname = resolve_hostname(device["ip"])
        if hostname:
            device["hostname"] = hostname
    return devices
