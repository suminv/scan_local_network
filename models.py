def build_scan_context(interface=None, cidr=None):
    """Create a normalized scan-context dictionary."""
    return {
        "interface": interface,
        "cidr": cidr,
    }


def build_device_snapshot(
    *,
    ip,
    mac,
    vendor="Unknown",
    hostname=None,
    first_seen=None,
    last_seen=None,
    open_ports=None,
):
    """Create a normalized device snapshot dictionary."""
    device = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
    }
    if hostname is not None:
        device["hostname"] = hostname
    if first_seen is not None:
        device["first_seen"] = first_seen
    if last_seen is not None:
        device["last_seen"] = last_seen
    if open_ports is not None:
        device["open_ports"] = open_ports
    return device


def build_port_snapshot(*, mac, ip, port, service="Unknown", tls=None, hostname=None):
    """Create a normalized port observation dictionary."""
    snapshot = {
        "mac": mac,
        "ip": ip,
        "port": port,
        "service": service,
    }
    if tls is not None:
        snapshot["tls"] = tls
    if hostname is not None:
        snapshot["hostname"] = hostname
    return snapshot
