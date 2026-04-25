import unittest

import models


class ModelTests(unittest.TestCase):
    def test_build_scan_context_sets_interface_and_cidr(self):
        self.assertEqual(
            models.build_scan_context(interface="en0", cidr="192.168.2.0/24"),
            {"interface": "en0", "cidr": "192.168.2.0/24"},
        )

    def test_build_device_snapshot_keeps_optional_fields_only_when_given(self):
        device = models.build_device_snapshot(
            ip="192.168.2.10",
            mac="aa:aa:aa:aa:aa:aa",
            vendor="Vendor A",
            hostname="nas.local",
            first_seen="2026-01-01T00:00:00",
            open_ports=[{"port": 22, "service": "SSH"}],
        )

        self.assertEqual(device["ip"], "192.168.2.10")
        self.assertEqual(device["vendor"], "Vendor A")
        self.assertEqual(device["hostname"], "nas.local")
        self.assertIn("first_seen", device)
        self.assertIn("open_ports", device)
        self.assertNotIn("last_seen", device)

    def test_build_port_snapshot_uses_consistent_keys(self):
        self.assertEqual(
            models.build_port_snapshot(
                mac="aa:aa:aa:aa:aa:aa",
                ip="192.168.2.10",
                hostname="nas.local",
                port=22,
                service="SSH",
            ),
            {
                "mac": "aa:aa:aa:aa:aa:aa",
                "ip": "192.168.2.10",
                "hostname": "nas.local",
                "port": 22,
                "service": "SSH",
            },
        )


if __name__ == "__main__":
    unittest.main()
