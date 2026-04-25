import csv
import json
import os


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


def print_change_report(
    *,
    title,
    border,
    unavailable_message=None,
    empty_message=None,
    summary_line=None,
    sections=None,
):
    """Print a structured console report for diff-like changes."""
    sections = sections or []
    print(title)
    if unavailable_message is not None:
        print(unavailable_message)
        print(border)
        return
    if empty_message is not None:
        print(empty_message)
        print(border)
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
    print(border)
