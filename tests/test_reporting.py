import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

import reporting


class ReportingTests(unittest.TestCase):
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

    def test_print_change_report_renders_title_summary_and_sections(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            reporting.print_change_report(
                title="=== Example ===",
                border="===========",
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
        self.assertIn("=== Example ===", output)
        self.assertIn("New: 1", output)
        self.assertIn("New items:", output)
        self.assertIn("item=1", output)


if __name__ == "__main__":
    unittest.main()
