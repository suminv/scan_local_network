import csv
import json
import os


STATUS_MARKERS = {
    "ok": "[OK]",
    "notice": "[~]",
    "alert": "[!]",
}


def format_section_heading(title):
    """Return the shared compact heading used by terminal reports."""
    normalized = str(title).strip().strip("=- ").strip()
    return f"--- {normalized} ---"


def print_section_heading(title, *, leading_blank=False):
    """Print one consistently formatted terminal report heading."""
    if leading_blank:
        print()
    print(format_section_heading(title))


def format_status_marker(status):
    """Return the shared compact marker for a result status."""
    return STATUS_MARKERS.get(str(status).lower(), f"[{str(status).upper()}]")


def format_scan_summary_lines(fields, status=None):
    """Format available scan metadata into a compact aligned summary."""
    rows = [(str(label), str(value)) for label, value in fields if value not in (None, "")]
    if status:
        level, message = status
        rows.append(("Status", f"{format_status_marker(level)} {message}"))
    if not rows:
        return []
    label_width = max(len(label) for label, _ in rows)
    return [f"{label.ljust(label_width)}: {value}" for label, value in rows]


def print_scan_summary(fields, status=None, *, leading_blank=False):
    """Print the shared top-level summary used by all scanners."""
    print_section_heading("Scan Summary", leading_blank=leading_blank)
    for line in format_scan_summary_lines(fields, status=status):
        print(line)


def build_report_payload(snapshot_key, snapshot, diff_key, diff_summary):
    """Build a consistent JSON payload for scan reports."""
    return {
        snapshot_key: snapshot,
        diff_key: diff_summary,
    }


def save_json_report(file_path, payload, label="Results"):
    """Persist a JSON payload and print where it was written."""
    directory = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(directory, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4)
    print(f"{label} saved to {file_path}")


def save_csv_report(file_path, headers, rows, label="Results"):
    """Persist tabular rows as CSV and print where it was written."""
    directory = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(directory, exist_ok=True)
    with open(file_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"{label} saved to {file_path}")


def render_markdown_table(headers, rows):
    """Render a simple GitHub-flavored Markdown table."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        normalized = [str(cell).replace("\n", " ").strip() for cell in row]
        lines.append("| " + " | ".join(normalized) + " |")
    return "\n".join(lines)


def save_markdown_report(file_path, content, label="Results"):
    """Persist Markdown content and print where it was written."""
    directory = os.path.dirname(os.path.abspath(file_path))
    os.makedirs(directory, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"{label} saved to {file_path}")


def print_change_report(
    *,
    title,
    unavailable_message=None,
    empty_message=None,
    summary_line=None,
    sections=None,
):
    """Print a structured console report for diff-like changes."""
    sections = sections or []
    print(format_section_heading(title))
    if unavailable_message is not None:
        print(unavailable_message)
        return
    if empty_message is not None:
        print(empty_message)
        return
    if summary_line:
        print(summary_line)
    for section in sections:
        rows = section["rows"]
        if not rows:
            continue
        print(f"\n{section['title']}:")
        for line in section["formatter"](rows):
            print(line)
