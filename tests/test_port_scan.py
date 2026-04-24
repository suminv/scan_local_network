import unittest
from types import SimpleNamespace
import tempfile
import json
import os

import port_scan


class PortScanTests(unittest.TestCase):
    def test_parse_ports_returns_defaults_when_empty(self):
        self.assertEqual(port_scan.parse_ports(None), port_scan.DEFAULT_PORTS)

    def test_parse_ports_supports_ranges_and_deduplicates(self):
        self.assertEqual(
            port_scan.parse_ports("80,22,20-22"),
            [20, 21, 22, 80],
        )

    def test_parse_ports_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            port_scan.parse_ports("80,abc")

    def test_parse_ports_rejects_out_of_range_ports(self):
        with self.assertRaises(ValueError):
            port_scan.parse_ports("0,80")
        with self.assertRaises(ValueError):
            port_scan.parse_ports("65536")

    def test_parse_ports_rejects_reversed_ranges(self):
        with self.assertRaises(ValueError):
            port_scan.parse_ports("100-1")

    def test_parse_ports_rejects_empty_entries(self):
        with self.assertRaises(ValueError):
            port_scan.parse_ports("22,,80")

    def test_parse_ports_rejects_malformed_ranges(self):
        with self.assertRaises(ValueError):
            port_scan.parse_ports("20-")
        with self.assertRaises(ValueError):
            port_scan.parse_ports("20-30-40")

    def test_flatten_port_results_expands_device_rows(self):
        rows = port_scan.flatten_port_results(
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "open_ports": [
                        {"port": 22, "service": "SSH"},
                        {"port": 80, "service": "HTTP"},
                    ],
                },
                {
                    "mac": "bb:bb:bb:bb:bb:bb",
                    "ip": "192.168.2.20",
                    "open_ports": [],
                },
            ]
        )

        self.assertEqual(
            rows,
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 22,
                    "service": "SSH",
                },
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 80,
                    "service": "HTTP",
                },
            ],
        )

    def test_count_open_ports_sums_across_devices(self):
        count = port_scan.count_open_ports(
            [
                {"open_ports": [{"port": 22}, {"port": 80}]},
                {"open_ports": []},
                {"open_ports": [{"port": 443}]},
            ]
        )
        self.assertEqual(count, 3)

    def test_discover_devices_to_scan_uses_target_without_discovery(self):
        args = SimpleNamespace(target="192.168.2.10", iface=None, cidr=None)

        devices, scan_context = port_scan.discover_devices_to_scan(
            args,
            mac_lookup=None,
        )

        self.assertEqual(
            devices,
            [{"ip": "192.168.2.10", "mac": "00:00:00:00:00:00", "vendor": "N/A"}],
        )
        self.assertEqual(scan_context["interface"], None)
        self.assertEqual(scan_context["cidr"], "192.168.2.10")

    def test_save_port_scan_results_writes_snapshot_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = os.path.join(tmp_dir, "reports", "port_scan_result.json")

            port_scan.save_port_scan_results(
                results=[
                    {
                        "ip": "192.168.2.10",
                        "mac": "aa:aa:aa:aa:aa:aa",
                        "vendor": "Vendor A",
                        "open_ports": [{"port": 22, "service": "SSH"}],
                    }
                ],
                diff_summary={
                    "new_ports": [
                        {
                            "mac": "aa:aa:aa:aa:aa:aa",
                            "ip": "192.168.2.10",
                            "port": 22,
                            "service": "SSH",
                        }
                    ],
                    "closed_ports": [],
                    "service_changes": [],
                },
                json_output_file=json_path,
            )

            with open(json_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)

            self.assertEqual(payload["devices"][0]["ip"], "192.168.2.10")
            self.assertEqual(payload["port_diff_summary"]["new_ports"][0]["port"], 22)


if __name__ == "__main__":
    unittest.main()
