import unittest

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


if __name__ == "__main__":
    unittest.main()
