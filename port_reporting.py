import json

from colorama import Fore, Style

from reporting import (
    build_report_payload,
    print_change_report,
    render_markdown_table,
    save_csv_report,
    save_json_report,
    save_markdown_report,
)

DEFAULT_OUTPUT_FORMAT = "grouped"


def count_open_ports(results):
    """Count open port observations across all scanned devices."""
    return sum(len(device.get("open_ports", [])) for device in results)


def normalize_service_entry(port, service):
    """Normalize a raw service banner into a display label and detail string."""
    raw_service = (service or "").strip()
    if not raw_service:
        if port == 443:
            return "TLS", "open port, no banner"
        if port in [80, 8080]:
            return "WEB", "open port, no banner"
        return "OPEN", "open port, no banner"

    lowered = raw_service.lower()

    if raw_service.startswith("SSH"):
        details = raw_service[raw_service.find("(") + 1 : -1] if "(" in raw_service and raw_service.endswith(")") else raw_service
        return "SSH", details

    if raw_service.startswith("FTP"):
        details = raw_service[raw_service.find("(") + 1 : -1] if "(" in raw_service and raw_service.endswith(")") else raw_service
        return "FTP", details

    if raw_service.startswith("HTTP"):
        if "(" in raw_service and raw_service.endswith(")"):
            details = raw_service[raw_service.find("(") + 1 : -1]
            if details.lower().startswith("server:"):
                details = details.split(":", 1)[1].strip()
        else:
            details = "HTTP response detected"
        return ("HTTPS" if port == 443 else "HTTP"), details

    if raw_service.startswith("TLS"):
        if "(" in raw_service and raw_service.endswith(")"):
            details = raw_service[raw_service.find("(") + 1 : -1]
            return "TLS", details
        return "TLS", "TLS service detected"

    if lowered == "unknown":
        if port == 443:
            return "TLS", "open port, no banner"
        if port in [80, 8080]:
            return "WEB", "open port, no banner"
        return "OPEN", "open port, no banner"

    if lowered == "error grabbing banner":
        if port == 443:
            return "TLS", "banner grab failed"
        if port in [80, 8080]:
            return "WEB", "banner grab failed"
        return "OPEN", "banner grab failed"

    if lowered.startswith("tls handshake failed"):
        details = raw_service[raw_service.find("(") + 1 : -1] if "(" in raw_service and raw_service.endswith(")") else raw_service
        return "TLS", details

    if port == 443:
        return "TLS", raw_service
    return "OPEN", raw_service


def format_tls_metadata(tls_info):
    """Render structured TLS metadata into a concise human-readable string."""
    if not tls_info:
        return "none"
    parts = []
    if tls_info.get("protocol"):
        parts.append(tls_info["protocol"])
    if tls_info.get("common_name"):
        parts.append(f"CN={tls_info['common_name']}")
    if tls_info.get("issuer"):
        parts.append(f"issuer={tls_info['issuer']}")
    if tls_info.get("not_before"):
        parts.append(f"from={tls_info['not_before']}")
    if tls_info.get("not_after"):
        parts.append(f"until={tls_info['not_after']}")
    if tls_info.get("certificate_status"):
        parts.append(f"status={tls_info['certificate_status']}")
    if tls_info.get("cipher"):
        parts.append(tls_info["cipher"])
    if tls_info.get("handshake_error"):
        parts.append(f"error={tls_info['handshake_error']}")
    return ", ".join(parts) if parts else "present"


def get_tls_alert_marker(tls_info):
    """Return a compact visual marker for actionable TLS certificate states."""
    if not tls_info:
        return ""
    status = tls_info.get("certificate_status")
    if status == "expired":
        return "TLS! expired"
    if status == "expiring_soon":
        return "TLS! expiring"
    return ""


def format_port_diff_host(row):
    """Render the host identity for a port diff row."""
    hostname = row.get("hostname")
    if hostname:
        return f"{row['ip']} [{hostname}] ({row['mac']})"
    return f"{row['ip']} ({row['mac']})"


def build_port_csv_rows(results):
    """Build CSV rows for port scan snapshot export."""
    rows = []
    for device in results:
        for port_info in device.get("open_ports", []):
            rows.append(
                [
                    device["ip"],
                    device.get("hostname", ""),
                    device["mac"],
                    device.get("vendor", "Unknown"),
                    port_info["port"],
                    port_info.get("service", "Unknown"),
                    json.dumps(port_info.get("tls"), sort_keys=True)
                    if port_info.get("tls") is not None
                    else "",
                ]
            )
    return rows


def build_port_markdown_report(results, diff_summary):
    """Build a Markdown report for port scan output."""
    lines = [
        "# Port Scan Report",
        "",
        f"Devices scanned: **{len(results)}**",
        f"Open port observations: **{count_open_ports(results)}**",
        "",
    ]

    if results:
        snapshot_rows = []
        for device in results:
            for port_info in device.get("open_ports", []):
                snapshot_rows.append(
                    [
                        device["ip"],
                        device.get("hostname", "-") or "-",
                        device["mac"],
                        device.get("vendor", "Unknown"),
                        port_info["port"],
                        port_info.get("service", "Unknown"),
                        format_tls_metadata(port_info.get("tls")),
                    ]
                )
        if snapshot_rows:
            lines.extend(
                [
                    "## Open Ports",
                    "",
                    render_markdown_table(
                        ["IP", "Hostname", "MAC", "Vendor", "Port", "Service", "TLS"],
                        snapshot_rows,
                    ),
                    "",
                ]
            )

    lines.extend(["## Port Changes Since Last Scan", ""])
    if diff_summary is None:
        lines.extend(["No previous port scan snapshot available.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            f"- New ports: `{len(diff_summary['new_ports'])}`",
            f"- Closed ports: `{len(diff_summary['closed_ports'])}`",
            f"- Service changes: `{len(diff_summary['service_changes'])}`",
            f"- TLS changes: `{len(diff_summary.get('tls_changes', []))}`",
            "",
        ]
    )

    section_specs = [
        (
            "New open ports",
            diff_summary["new_ports"],
            ["Host", "Port", "Service"],
            lambda row: [format_port_diff_host(row), f"{row['port']}/tcp", row.get("service", "Unknown")],
        ),
        (
            "Closed ports",
            diff_summary["closed_ports"],
            ["Host", "Port", "Service"],
            lambda row: [format_port_diff_host(row), f"{row['port']}/tcp", row.get("service", "Unknown")],
        ),
        (
            "Service changes",
            diff_summary["service_changes"],
            ["Host", "Port", "Previous", "Current"],
            lambda row: [format_port_diff_host(row), f"{row['port']}/tcp", row["old_service"], row["new_service"]],
        ),
        (
            "TLS metadata changes",
            diff_summary.get("tls_changes", []),
            ["Host", "Port", "Previous TLS", "Current TLS"],
            lambda row: [
                format_port_diff_host(row),
                f"{row['port']}/tcp",
                format_tls_metadata(row.get("old_tls")),
                format_tls_metadata(row.get("new_tls")),
            ],
        ),
    ]
    for title, rows, headers, row_builder in section_specs:
        if not rows:
            continue
        lines.extend(
            [
                f"### {title}",
                "",
                render_markdown_table(headers, [row_builder(row) for row in rows]),
                "",
            ]
        )

    return "\n".join(lines)


def save_port_scan_results(
    results,
    diff_summary,
    json_output_file,
    csv_output_file=None,
    markdown_output_file=None,
):
    """Save the port scan snapshot and diff summary to JSON/CSV."""
    payload = build_report_payload("devices", results, "port_diff_summary", diff_summary)
    save_json_report(json_output_file, payload, label="Port scan results")
    if csv_output_file:
        save_csv_report(
            csv_output_file,
            ["ip", "hostname", "mac", "vendor", "port", "service", "tls_json"],
            build_port_csv_rows(results),
            label="Port scan CSV report",
        )
    if markdown_output_file:
        save_markdown_report(
            markdown_output_file,
            build_port_markdown_report(results, diff_summary),
            label="Port scan Markdown report",
        )


def print_port_diff_summary(diff_summary):
    """Print changes between the current and previous port scan."""
    if diff_summary is None:
        print_change_report(
            title="=== Port Changes Since Last Scan ===",
            border="===================================",
            unavailable_message="No previous port scan snapshot available.",
        )
        return

    new_ports = diff_summary["new_ports"]
    closed_ports = diff_summary["closed_ports"]
    service_changes = diff_summary["service_changes"]
    tls_changes = diff_summary.get("tls_changes", [])
    if not any([new_ports, closed_ports, service_changes, tls_changes]):
        print_change_report(
            title="=== Port Changes Since Last Scan ===",
            border="===================================",
            empty_message="No port-level changes detected since last scan.",
        )
        return

    print_change_report(
        title="=== Port Changes Since Last Scan ===",
        border="===================================",
        summary_line=(
            f"New ports: {len(new_ports)} | Closed ports: {len(closed_ports)} | Service changes: {len(service_changes)} | TLS changes: {len(tls_changes)}"
        ),
        sections=[
            {
                "title": "New open ports",
                "rows": new_ports,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row.get('service', 'Unknown')}"
                    for row in rows
                ],
            },
            {
                "title": "Closed ports",
                "rows": closed_ports,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row.get('service', 'Unknown')}"
                    for row in rows
                ],
            },
            {
                "title": "Service changes",
                "rows": service_changes,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row['old_service']} -> {row['new_service']}"
                    for row in rows
                ],
            },
            {
                "title": "TLS metadata changes",
                "rows": tls_changes,
                "formatter": lambda rows: [
                    (
                        f"  {format_port_diff_host(row)} {row['port']}/tcp "
                        f"{format_tls_metadata(row.get('old_tls'))} -> {format_tls_metadata(row.get('new_tls'))}"
                    )
                    for row in rows
                ],
            },
        ],
    )


def print_port_alert_summary(results, diff_summary):
    """Print only actionable findings for scheduled/quiet monitoring runs."""
    observations = build_port_observations(results)
    tls_alert_rows = [
        row
        for row in observations
        if (row.get("tls") or {}).get("certificate_status") in ["expired", "expiring_soon"]
    ]
    new_ports = [] if diff_summary is None else diff_summary.get("new_ports", [])
    service_changes = [] if diff_summary is None else diff_summary.get("service_changes", [])
    tls_changes = [] if diff_summary is None else diff_summary.get("tls_changes", [])

    if not any([tls_alert_rows, new_ports, service_changes, tls_changes]):
        print_change_report(
            title="=== Alerts ===",
            border="=============",
            empty_message="No actionable alerts detected.",
        )
        return

    print_change_report(
        title="=== Alerts ===",
        border="=============",
        summary_line=(
            " | ".join(
                [
                    f"TLS alerts: {len(tls_alert_rows)}",
                    f"New ports: {len(new_ports)}",
                    f"Service changes: {len(service_changes)}",
                    f"TLS changes: {len(tls_changes)}",
                ]
            )
        ),
        sections=[
            {
                "title": "TLS certificate alerts",
                "rows": tls_alert_rows,
                "formatter": lambda rows: [
                    (
                        f"  {format_port_diff_host(row)} {row['port']}/tcp "
                        f"{get_tls_alert_marker(row.get('tls'))} | {row['details']}"
                    )
                    for row in rows
                ],
            },
            {
                "title": "New open ports",
                "rows": new_ports,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row.get('service', 'Unknown')}"
                    for row in rows
                ],
            },
            {
                "title": "Service changes",
                "rows": service_changes,
                "formatter": lambda rows: [
                    f"  {format_port_diff_host(row)} {row['port']}/tcp {row['old_service']} -> {row['new_service']}"
                    for row in rows
                ],
            },
            {
                "title": "TLS metadata changes",
                "rows": tls_changes,
                "formatter": lambda rows: [
                    (
                        f"  {format_port_diff_host(row)} {row['port']}/tcp "
                        f"{format_tls_metadata(row.get('old_tls'))} -> {format_tls_metadata(row.get('new_tls'))}"
                    )
                    for row in rows
                ],
            },
        ],
    )


def has_port_alerts(results, diff_summary):
    """Return True when the current run contains actionable port alerts."""
    observations = build_port_observations(results)
    tls_alert_rows = [
        row
        for row in observations
        if (row.get("tls") or {}).get("certificate_status") in ["expired", "expiring_soon"]
    ]
    new_ports = [] if diff_summary is None else diff_summary.get("new_ports", [])
    service_changes = [] if diff_summary is None else diff_summary.get("service_changes", [])
    tls_changes = [] if diff_summary is None else diff_summary.get("tls_changes", [])
    return any([tls_alert_rows, new_ports, service_changes, tls_changes])


def format_device_heading(device):
    """Build a compact device heading for terminal output."""
    vendor = device.get("vendor", "Unknown")
    mac = device.get("mac", "Unknown")
    hostname = device.get("hostname")
    if hostname:
        return f"{device['ip']}  {hostname}  {vendor}  {mac}"
    return f"{device['ip']}  {vendor}  {mac}"


def build_port_result_lines(results):
    """Build structured display lines for grouped console output."""
    device_lines = []
    for device in sorted(results, key=lambda x: x["ip"]):
        open_ports = device.get("open_ports", [])
        if not open_ports:
            continue
        rows = []
        for port_info in open_ports:
            service_label, details = normalize_service_entry(
                port_info["port"],
                port_info.get("service", "Unknown"),
            )
            alert_marker = get_tls_alert_marker(port_info.get("tls"))
            line = f"  {port_info['port']}/tcp".ljust(12)
            line += service_label.ljust(8)
            detail_parts = []
            if alert_marker:
                detail_parts.append(alert_marker)
            if details:
                detail_parts.append(details)
            if detail_parts:
                line += " | ".join(detail_parts)
            rows.append(line)
        device_lines.append((format_device_heading(device), rows))
    return device_lines


def build_port_observations(results):
    """Flatten results into normalized rows for display-specific renderers."""
    observations = []
    for device in sorted(results, key=lambda x: x["ip"]):
        for port_info in device.get("open_ports", []):
            service_label, details = normalize_service_entry(
                port_info["port"],
                port_info.get("service", "Unknown"),
            )
            observations.append(
                {
                    "ip": device["ip"],
                    "hostname": device.get("hostname"),
                    "vendor": device.get("vendor", "Unknown"),
                    "mac": device.get("mac", "Unknown"),
                    "port": port_info["port"],
                    "service_label": service_label,
                    "details": details,
                    "tls": port_info.get("tls"),
                }
            )
    return observations


def print_port_scan_summary(results):
    """Print the shared top-line summary for all console formats."""
    print(f"\n{Fore.CYAN}--- Scan Results ---{Style.RESET_ALL}")
    open_device_count = sum(1 for device in results if device.get("open_ports"))
    open_port_count = count_open_ports(results)
    print(
        f"{len(results)} devices scanned | {open_device_count} with open ports | {open_port_count} open ports total"
    )


def print_grouped_port_scan_results(results):
    """Print grouped port scan results by device."""
    device_lines = build_port_result_lines(results)
    if not device_lines:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )
        return

    for heading, port_lines in device_lines:
        print(f"\n{Fore.GREEN}{heading}{Style.RESET_ALL}")
        for line in port_lines:
            port_part, service_part = line[:12], line[12:]
            print(f"{port_part}{Fore.YELLOW}{service_part}{Style.RESET_ALL}")


def print_table_port_scan_results(results):
    """Print normalized port scan results in a flat table."""
    observations = build_port_observations(results)
    if not observations:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )
        return

    header = f"{'IP':<15} {'Hostname':<24} {'Vendor':<28} {'MAC':<17} {'Port':<8} {'Service':<8} Details"
    print(f"\n{Fore.GREEN}{header}{Style.RESET_ALL}")
    for row in observations:
        hostname = (row.get("hostname") or "-")[:24]
        vendor = row["vendor"][:28]
        alert_marker = get_tls_alert_marker(row.get("tls"))
        details_parts = []
        if alert_marker:
            details_parts.append(alert_marker)
        if row["details"]:
            details_parts.append(row["details"])
        details = " | ".join(details_parts) if details_parts else "-"
        port_display = f"{row['port']}/tcp"
        line = (
            f"{row['ip']:<15} {hostname:<24} {vendor:<28} {row['mac']:<17} "
            f"{port_display:<8} {row['service_label']:<8} {details}"
        )
        print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")


def _format_focus_host_lines(rows):
    """Format condensed host lines for focus mode sections."""
    lines = []
    by_host = {}
    for row in rows:
        key = (row["ip"], row.get("hostname"), row["vendor"], row["mac"])
        by_host.setdefault(key, []).append(row)

    for (ip, hostname, vendor, mac), host_rows in sorted(by_host.items(), key=lambda item: item[0][0]):
        ports = ", ".join(f"{entry['port']}/{entry['service_label']}" for entry in sorted(host_rows, key=lambda entry: entry["port"]))
        details = "; ".join(
            entry["details"] for entry in sorted(host_rows, key=lambda entry: entry["port"]) if entry["details"]
        )
        suffix = f" | {details}" if details else ""
        hostname_part = f"  {hostname}" if hostname else ""
        lines.append(f"  {ip}{hostname_part}  {vendor}  {mac}  {ports}{suffix}")
    return lines


def print_focus_port_scan_results(results):
    """Print scan results grouped by operator-relevant categories."""
    observations = build_port_observations(results)
    if not observations:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )
        return

    tls_alerts = []
    interesting = []
    web_only = []
    unidentified_web = []

    by_host = {}
    for row in observations:
        key = (row["ip"], row.get("hostname"), row["vendor"], row["mac"])
        by_host.setdefault(key, []).append(row)

    for host_rows in by_host.values():
        service_labels = {row["service_label"] for row in host_rows}
        has_tls_alert = any(
            row.get("tls", {}).get("certificate_status") in ["expired", "expiring_soon"]
            for row in host_rows
            if row.get("tls")
        )
        has_interesting = any(
            row["port"] not in [80, 443, 8080] or row["service_label"] in ["SSH", "FTP"]
            for row in host_rows
        )
        has_unidentified_web = any(
            row["service_label"] in ["WEB", "TLS"] and row["details"] in ["open port, no banner", "banner grab failed"]
            for row in host_rows
        )

        if has_tls_alert:
            tls_alerts.extend(host_rows)
        elif has_interesting:
            interesting.extend(host_rows)
        elif has_unidentified_web:
            unidentified_web.extend(host_rows)
        elif service_labels.issubset({"HTTP", "HTTPS", "WEB", "TLS"}):
            web_only.extend(host_rows)
        else:
            interesting.extend(host_rows)

    sections = [
        ("TLS certificate alerts", tls_alerts),
        ("Interesting hosts", interesting),
        ("Web-only hosts", web_only),
        ("Unidentified web endpoints", unidentified_web),
    ]
    printed_any = False
    for title, rows in sections:
        if not rows:
            continue
        printed_any = True
        print(f"\n{Fore.GREEN}{title}:{Style.RESET_ALL}")
        for line in _format_focus_host_lines(rows):
            print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
    if not printed_any:
        print(
            f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}"
        )


def print_port_scan_results(results, output_format=DEFAULT_OUTPUT_FORMAT):
    """Print human-readable port scan results."""
    print_port_scan_summary(results)
    if output_format == "table":
        print_table_port_scan_results(results)
        return
    if output_format == "focus":
        print_focus_port_scan_results(results)
        return
    print_grouped_port_scan_results(results)
