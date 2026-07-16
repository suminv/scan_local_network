import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

import reporting


class ReportingTests(unittest.TestCase):
    def test_shared_console_style_formats_headings_and_statuses(self):
        self.assertEqual(reporting.format_section_heading("=== Scan Results ==="), "--- Scan Results ---")
        self.assertEqual(reporting.format_section_heading("Wi-Fi Debug"), "--- Wi-Fi Debug ---")
        self.assertEqual(reporting.format_status_marker("ok"), "[OK]")
        self.assertEqual(reporting.format_status_marker("notice"), "[~]")
        self.assertEqual(reporting.format_status_marker("alert"), "[!]")

    def test_scan_summary_omits_empty_fields_and_aligns_status(self):
        lines = reporting.format_scan_summary_lines(
            [("Target", "192.168.2.0/24"), ("Duration", None), ("Devices", 27)],
            status=("notice", "review changes"),
        )

        self.assertEqual(
            lines,
            [
                "Target : 192.168.2.0/24",
                "Devices: 27",
                "Status : [~] review changes",
            ],
        )

    def test_output_files_omits_missing_paths_and_aligns_labels(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            reporting.print_output_files(
                [("JSON", "result.json"), ("CSV", None), ("Markdown", "result.md")]
            )

        output = buffer.getvalue()
        self.assertIn("--- Output Files ---", output)
        self.assertIn("JSON    : result.json", output)
        self.assertIn("Markdown: result.md", output)
        self.assertNotIn("CSV", output)

    def test_build_report_payload_uses_consistent_keys(self):
        payload = reporting.build_report_payload(
            "devices",
            [{"ip": "192.168.2.10"}],
            "arp_diff_summary",
            {"new_devices": []},
        )

        self.assertEqual(
            payload,
            {
                "devices": [{"ip": "192.168.2.10"}],
                "arp_diff_summary": {"new_devices": []},
            },
        )

    def test_save_json_report_creates_parent_directory_and_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "reports", "result.json")
            reporting.save_json_report(path, {"ok": True}, label="Test report")

            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)

            self.assertEqual(payload, {"ok": True})

    def test_save_csv_report_creates_parent_directory_and_writes_rows(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "reports", "result.csv")
            reporting.save_csv_report(
                path,
                ["ip", "hostname"],
                [["192.168.2.10", "nas.local"]],
                label="CSV report",
            )

            with open(path, "r", encoding="utf-8") as handle:
                contents = handle.read()

            self.assertIn("ip,hostname", contents)
            self.assertIn("192.168.2.10,nas.local", contents)

    def test_render_markdown_table_formats_gfm_rows(self):
        table = reporting.render_markdown_table(
            ["IP", "Hostname"],
            [["192.168.2.10", "nas.local"]],
        )

        self.assertIn("| IP | Hostname |", table)
        self.assertIn("| --- | --- |", table)
        self.assertIn("| 192.168.2.10 | nas.local |", table)

    def test_save_markdown_report_creates_parent_directory_and_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "reports", "result.md")
            reporting.save_markdown_report(path, "# Title\n", label="Markdown report")

            with open(path, "r", encoding="utf-8") as handle:
                contents = handle.read()

            self.assertEqual(contents, "# Title\n")

    def test_print_change_report_renders_title_summary_and_sections(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            reporting.print_change_report(
                title="=== Example ===",
                summary_line="New: 1",
                sections=[
                    {
                        "title": "New items",
                        "rows": [{"value": 1}],
                        "formatter": lambda rows: [f"  item={rows[0]['value']}"],
                    }
                ],
            )

        output = buffer.getvalue()
        self.assertIn("--- Example ---", output)
        self.assertIn("New: 1", output)
        self.assertIn("New items:", output)
        self.assertIn("item=1", output)
        self.assertNotIn("===========", output)


if __name__ == "__main__":
    unittest.main()
