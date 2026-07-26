"""Optional diagnostics for the active Tailscale exit-node path."""

import json
import re
import shutil
import statistics
import subprocess


DERP_PATTERN = re.compile(r"via DERP\(([^)]+)\) in ([0-9.]+)ms", re.IGNORECASE)
PEER_RELAY_PATTERN = re.compile(
    r"via peer-relay\(([^)]+)\) in ([0-9.]+)ms",
    re.IGNORECASE,
)
DIRECT_PATTERN = re.compile(r"via (?!DERP|peer-relay)(\S+) in ([0-9.]+)ms", re.IGNORECASE)


def _run(command, *, timeout, runner=subprocess.run):
    return runner(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def collect_tailscale_status(*, tailscale_path=None, timeout=5, runner=subprocess.run):
    """Read Tailscale status JSON and locate the active exit node."""
    tailscale_path = tailscale_path or shutil.which("tailscale")
    if not tailscale_path:
        return {
            "available": False,
            "reason": "tailscale CLI is unavailable",
            "backend_state": None,
            "exit_node": None,
        }
    completed = _run(
        [tailscale_path, "status", "--json"],
        timeout=timeout,
        runner=runner,
    )
    payload = json.loads(completed.stdout)
    peers = payload.get("Peer") or {}
    active_exit_nodes = [
        peer
        for peer in peers.values()
        if peer.get("ExitNode") and peer.get("Active")
    ]
    exit_node = active_exit_nodes[0] if active_exit_nodes else None
    return {
        "available": True,
        "reason": None,
        "tailscale_path": tailscale_path,
        "backend_state": payload.get("BackendState"),
        "exit_node": exit_node,
        "multiple_active_exit_nodes": len(active_exit_nodes) > 1,
    }


def _exit_node_target(exit_node):
    addresses = exit_node.get("TailscaleIPs") or []
    if addresses:
        return addresses[0]
    addresses = exit_node.get("Addrs") or []
    if addresses:
        return addresses[0]
    return None


def parse_tailscale_ping_output(output):
    """Parse direct, peer-relay, and DERP samples from ``tailscale ping``."""
    samples = []
    for line in output.splitlines():
        match = DERP_PATTERN.search(line)
        if match:
            samples.append(
                {
                    "path": "derp",
                    "relay": match.group(1),
                    "latency_ms": float(match.group(2)),
                }
            )
            continue
        match = PEER_RELAY_PATTERN.search(line)
        if match:
            samples.append(
                {
                    "path": "peer_relay",
                    "relay": match.group(1),
                    "latency_ms": float(match.group(2)),
                }
            )
            continue
        match = DIRECT_PATTERN.search(line)
        if match:
            samples.append(
                {
                    "path": "direct",
                    "endpoint": match.group(1),
                    "latency_ms": float(match.group(2)),
                }
            )
    return samples


def collect_tailscale_exit_node_ping(
    exit_node,
    *,
    tailscale_path,
    count=5,
    timeout=15,
    runner=subprocess.run,
):
    """Run DISCO pings to an active exit node."""
    target = _exit_node_target(exit_node)
    if not target:
        raise ValueError("active exit node has no Tailscale IP")
    command = [tailscale_path, "ping", "--c", str(count), target]
    completed = runner(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = "\n".join(value for value in (completed.stdout, completed.stderr) if value)
    samples = parse_tailscale_ping_output(output)
    if completed.returncode and not samples:
        raise subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return {
        "target": target,
        "requested_samples": count,
        "samples": samples,
        "direct_connection_not_established": (
            "direct connection not established" in output.lower()
        ),
    }


def _summarize_samples(samples):
    latencies = [sample["latency_ms"] for sample in samples]
    paths = [sample["path"] for sample in samples]
    if "direct" in paths:
        selected_path = "direct"
    elif "peer_relay" in paths:
        selected_path = "peer_relay"
    elif "derp" in paths:
        selected_path = "derp"
    else:
        selected_path = "unavailable"
    selected_samples = [
        sample for sample in samples if sample["path"] == selected_path
    ]
    relays = sorted(
        {
            sample["relay"]
            for sample in selected_samples
            if sample.get("relay")
        }
    )
    return {
        "path": selected_path,
        "sample_count": len(samples),
        "latency_min_ms": min(latencies) if latencies else None,
        "latency_avg_ms": statistics.mean(latencies) if latencies else None,
        "latency_median_ms": statistics.median(latencies) if latencies else None,
        "latency_max_ms": max(latencies) if latencies else None,
        "relays": relays,
    }


def analyze_tailscale_exit_node(status, ping=None):
    """Build a normalized health check from status and ping observations."""
    if not status.get("available"):
        return {
            "name": "tailscale_exit_node",
            "status": "notice",
            "summary": "Tailscale diagnostics are unavailable",
            "details": {
                "available": False,
                "reason": status.get("reason"),
            },
        }
    backend_state = status.get("backend_state")
    if backend_state != "Running":
        state_text = backend_state or "unknown"
        return {
            "name": "tailscale_exit_node",
            "status": "notice",
            "summary": f"Tailscale is not running (backend state: {state_text})",
            "details": {
                "available": True,
                "backend_state": backend_state,
                "exit_node_active": False,
            },
        }
    exit_node = status.get("exit_node")
    if not exit_node:
        return {
            "name": "tailscale_exit_node",
            "status": "ok",
            "summary": "Tailscale is running without an active exit node",
            "details": {
                "available": True,
                "backend_state": backend_state,
                "exit_node_active": False,
            },
        }
    identity = {
        "hostname": exit_node.get("HostName"),
        "dns_name": exit_node.get("DNSName"),
        "tailscale_ip": _exit_node_target(exit_node),
        "online": exit_node.get("Online"),
        "os": exit_node.get("OS"),
    }
    if ping is None:
        return {
            "name": "tailscale_exit_node",
            "status": "notice",
            "summary": "Active Tailscale exit node found, but path diagnostics failed",
            "details": {
                "available": True,
                "backend_state": status.get("backend_state"),
                "exit_node_active": True,
                "exit_node": identity,
            },
        }
    sample_summary = _summarize_samples(ping.get("samples", []))
    path = sample_summary["path"]
    details = {
        "available": True,
        "backend_state": status.get("backend_state"),
        "exit_node_active": True,
        "exit_node": identity,
        "path": path,
        "relays": sample_summary["relays"],
        "sample_count": sample_summary["sample_count"],
        "requested_samples": ping.get("requested_samples"),
        "latency_min_ms": sample_summary["latency_min_ms"],
        "latency_avg_ms": sample_summary["latency_avg_ms"],
        "latency_median_ms": sample_summary["latency_median_ms"],
        "latency_max_ms": sample_summary["latency_max_ms"],
        "direct_connection_not_established": ping.get(
            "direct_connection_not_established", False
        ),
        "samples": ping.get("samples", []),
    }
    hostname = identity.get("hostname") or identity.get("dns_name") or "exit node"
    average = sample_summary["latency_avg_ms"]
    latency_text = f", {average:.0f} ms average" if average is not None else ""
    if path == "direct":
        return {
            "name": "tailscale_exit_node",
            "status": "ok",
            "summary": f"Tailscale exit node {hostname} uses a direct path{latency_text}",
            "details": details,
        }
    if path == "peer_relay":
        return {
            "name": "tailscale_exit_node",
            "status": "notice",
            "summary": f"Tailscale exit node {hostname} uses a peer relay{latency_text}",
            "details": details,
        }
    if path == "derp":
        relay = ", ".join(sample_summary["relays"]) or "unknown"
        return {
            "name": "tailscale_exit_node",
            "status": "notice",
            "summary": (
                f"Tailscale exit node {hostname} uses DERP({relay})"
                f"{latency_text}; direct connection was not established"
            ),
            "details": details,
        }
    return {
        "name": "tailscale_exit_node",
        "status": "notice",
        "summary": f"Tailscale exit node {hostname} did not return usable ping samples",
        "details": details,
    }


def build_tailscale_exit_node_check(
    *,
    count=5,
    status_timeout=5,
    ping_timeout=15,
    runner=subprocess.run,
):
    """Detect and diagnose the current Tailscale exit node."""
    try:
        status = collect_tailscale_status(
            timeout=status_timeout,
            runner=runner,
        )
    except Exception as exc:
        return analyze_tailscale_exit_node(
            {
                "available": False,
                "reason": str(exc),
            }
        )
    if not status.get("exit_node"):
        return analyze_tailscale_exit_node(status)
    try:
        ping = collect_tailscale_exit_node_ping(
            status["exit_node"],
            tailscale_path=status["tailscale_path"],
            count=count,
            timeout=ping_timeout,
            runner=runner,
        )
    except Exception as exc:
        check = analyze_tailscale_exit_node(status)
        check["details"]["error"] = str(exc)
        return check
    return analyze_tailscale_exit_node(status, ping)
