"""System DNS lookups isolated in a killable process with a hard timeout."""
import json
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

DNS_TIMEOUT_SECONDS = 3
# Use the system resolver (including VPN/split DNS), without modifying global
# socket timeouts. A thread alone cannot cancel a blocked getaddrinfo call.
_LOOKUP_CODE = """
import json, socket, sys
mode, target = sys.argv[1:]
try:
    if mode == 'reverse':
        result = socket.gethostbyaddr(target)[0]
    else:
        result = sorted({item[4][0] for item in socket.getaddrinfo(target, None)})
    print(json.dumps(result))
except OSError as exc:
    print(json.dumps({'error': str(exc)}))
"""


def system_dns_lookup(target, mode, timeout=DNS_TIMEOUT_SECONDS):
    try:
        result = subprocess.run(
            [sys.executable, '-I', '-c', _LOOKUP_CODE, mode, target],
            check=True, capture_output=True, text=True, timeout=timeout,
        )
        value = json.loads(result.stdout)
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        raise socket.gaierror(f'DNS lookup unavailable ({type(exc).__name__})') from exc
    if isinstance(value, dict):
        raise socket.gaierror(value['error'])
    return value


def resolve_hostname(ip):
    """Resolve a reverse-DNS hostname within a bounded time."""
    try:
        hostname = system_dns_lookup(ip, 'reverse')
    except OSError:
        return None
    return hostname if hostname and hostname != ip else None


def enrich_devices_with_hostnames(devices):
    """Resolve small batches concurrently, bounding process count and queued work."""
    with ThreadPoolExecutor(max_workers=8) as executor:
        for offset in range(0, len(devices), 8):
            batch = devices[offset:offset + 8]
            for device, hostname in zip(batch, executor.map(resolve_hostname, [item['ip'] for item in batch])):
                if hostname:
                    device['hostname'] = hostname
    return devices
