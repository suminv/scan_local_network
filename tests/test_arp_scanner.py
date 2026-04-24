import os
import sqlite3
import tempfile
import unittest
from unittest import mock
import json

import arp_scanner


class ArpScannerTests(unittest.TestCase):
    def test_validate_ip_range_normalizes_host_to_network(self):
        self.assertEqual(
            arp_scanner.validate_ip_range("192.168.2.45/24"),
            "192.168.2.0/24",
        )

    def test_resolve_scan_target_uses_interface_override(self):
        with mock.patch("arp_scanner.netifaces.interfaces", return_value=["en0", "lo0"]):
            interface, ip_range = arp_scanner.resolve_scan_target(
                interface_override="en0",
                ip_range_override="192.168.2.45/24",
            )

        self.assertEqual(interface, "en0")
        self.assertEqual(ip_range, "192.168.2.0/24")

    def test_resolve_scan_target_rejects_unknown_interface(self):
        with mock.patch("arp_scanner.netifaces.interfaces", return_value=["en0", "lo0"]):
            with self.assertRaises(RuntimeError):
                arp_scanner.resolve_scan_target(interface_override="ovs_eth0")

    def test_init_db_migrates_existing_devices_table(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            conn = sqlite3.connect(path)
            conn.execute(
                """
                CREATE TABLE devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    vendor TEXT,
                    first_seen TEXT
                )
                """
            )
            conn.commit()
            conn.close()

            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                columns = conn.execute("PRAGMA table_info(devices)").fetchall()
                tables = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
                conn.close()

            column_names = [column[1] for column in columns]
            self.assertIn("last_seen", column_names)
            self.assertIn(("scan_runs",), tables)
            self.assertIn(("scan_run_devices",), tables)
            self.assertIn(("scan_run_ports",), tables)
        finally:
            os.remove(path)

    def test_init_db_creates_parent_directory_for_custom_db_path(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "nested", "arp_scan.db")

            with mock.patch.object(arp_scanner, "DB_FILE", db_path):
                conn = arp_scanner.init_db()
                conn.close()

            self.assertTrue(os.path.exists(db_path))

    def test_create_and_finalize_scan_run(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                run_id = arp_scanner.create_scan_run(conn, "en0", "192.168.2.0/24")
                arp_scanner.finalize_scan_run(
                    conn,
                    run_id,
                    status="success",
                    device_count=3,
                    new_device_count=1,
                )
                row = conn.execute(
                    """
                    SELECT scan_type, interface, cidr, status, device_count, new_device_count
                    FROM scan_runs
                    WHERE id = ?
                    """,
                    (run_id,),
                ).fetchone()
                conn.close()

            self.assertEqual(
                row,
                ("arp", "en0", "192.168.2.0/24", "success", 3, 1),
            )
        finally:
            os.remove(path)

    def test_create_scan_run_supports_multiple_scan_types(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                run_id = arp_scanner.create_scan_run(
                    conn,
                    interface=None,
                    ip_range="192.168.2.10",
                    scan_type="port",
                )
                arp_scanner.finalize_scan_run(conn, run_id, status="success", device_count=1)
                row = conn.execute(
                    "SELECT scan_type, cidr, status, device_count FROM scan_runs WHERE id = ?",
                    (run_id,),
                ).fetchone()
                conn.close()

            self.assertEqual(row, ("port", "192.168.2.10", "success", 1))
        finally:
            os.remove(path)

    def test_save_scan_run_devices_and_load_previous_snapshot(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                run1 = arp_scanner.create_scan_run(conn, "en0", "192.168.2.0/24")
                arp_scanner.save_scan_run_devices(
                    conn,
                    run1,
                    [
                        {"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.2.10", "vendor": "Vendor A"},
                        {"mac": "bb:bb:bb:bb:bb:bb", "ip": "192.168.2.20", "vendor": "Vendor B"},
                    ],
                )
                arp_scanner.finalize_scan_run(conn, run1, "success", 2, 0)

                run2 = arp_scanner.create_scan_run(conn, "en0", "192.168.2.0/24")
                previous_devices = arp_scanner.load_previous_scan_devices(conn, run2)
                conn.close()

            self.assertEqual(
                previous_devices,
                [
                    {"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.2.10", "vendor": "Vendor A"},
                    {"mac": "bb:bb:bb:bb:bb:bb", "ip": "192.168.2.20", "vendor": "Vendor B"},
                ],
            )
        finally:
            os.remove(path)

    def test_save_scan_run_ports_persists_open_port_snapshot(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                run_id = arp_scanner.create_scan_run(
                    conn,
                    interface="en0",
                    ip_range="192.168.2.0/24",
                    scan_type="port",
                )
                arp_scanner.save_scan_run_ports(
                    conn,
                    run_id,
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
                    ],
                )
                rows = conn.execute(
                    """
                    SELECT mac, ip, port, service
                    FROM scan_run_ports
                    WHERE scan_run_id = ?
                    ORDER BY ip, port
                    """,
                    (run_id,),
                ).fetchall()
                conn.close()

            self.assertEqual(
                rows,
                [
                    ("aa:aa:aa:aa:aa:aa", "192.168.2.10", 22, "SSH"),
                    ("aa:aa:aa:aa:aa:aa", "192.168.2.10", 80, "HTTP"),
                ],
            )
        finally:
            os.remove(path)

    def test_load_previous_scan_ports_returns_last_successful_port_snapshot(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                run1 = arp_scanner.create_scan_run(
                    conn, "en0", "192.168.2.0/24", scan_type="port"
                )
                arp_scanner.save_scan_run_ports(
                    conn,
                    run1,
                    [
                        {
                            "mac": "aa:aa:aa:aa:aa:aa",
                            "ip": "192.168.2.10",
                            "open_ports": [{"port": 22, "service": "SSH"}],
                        }
                    ],
                )
                arp_scanner.finalize_scan_run(conn, run1, "success", 1, 0)

                run2 = arp_scanner.create_scan_run(
                    conn, "en0", "192.168.2.0/24", scan_type="port"
                )
                previous_ports = arp_scanner.load_previous_scan_ports(conn, run2)
                conn.close()

            self.assertEqual(
                previous_ports,
                [
                    {
                        "mac": "aa:aa:aa:aa:aa:aa",
                        "ip": "192.168.2.10",
                        "port": 22,
                        "service": "SSH",
                    }
                ],
            )
        finally:
            os.remove(path)

    def test_build_scan_diff_detects_new_returned_missing_and_ip_changes(self):
        diff = arp_scanner.build_scan_diff(
            [
                {"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.2.10", "vendor": "Vendor A"},
                {"mac": "bb:bb:bb:bb:bb:bb", "ip": "192.168.2.20", "vendor": "Vendor B"},
            ],
            [
                {"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.2.11", "vendor": "Vendor A"},
                {"mac": "bb:bb:bb:bb:bb:bb", "ip": "192.168.2.20", "vendor": "Vendor B"},
                {"mac": "cc:cc:cc:cc:cc:cc", "ip": "192.168.2.30", "vendor": "Vendor C"},
                {"mac": "dd:dd:dd:dd:dd:dd", "ip": "192.168.2.40", "vendor": "Vendor D"},
            ],
            known_macs={"dd:dd:dd:dd:dd:dd"},
        )

        self.assertEqual(
            diff["new_devices"],
            [{"mac": "cc:cc:cc:cc:cc:cc", "ip": "192.168.2.30", "vendor": "Vendor C"}],
        )
        self.assertEqual(
            diff["returned_devices"],
            [{"mac": "dd:dd:dd:dd:dd:dd", "ip": "192.168.2.40", "vendor": "Vendor D"}],
        )
        self.assertEqual(
            diff["missing_devices"],
            [],
        )
        self.assertEqual(
            diff["ip_changes"],
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "vendor": "Vendor A",
                    "old_ip": "192.168.2.10",
                    "new_ip": "192.168.2.11",
                }
            ],
        )

    def test_build_scan_diff_detects_missing_devices(self):
        diff = arp_scanner.build_scan_diff(
            [
                {"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.2.10", "vendor": "Vendor A"},
                {"mac": "bb:bb:bb:bb:bb:bb", "ip": "192.168.2.20", "vendor": "Vendor B"},
            ],
            [
                {"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.2.10", "vendor": "Vendor A"},
            ],
        )

        self.assertEqual(
            diff["missing_devices"],
            [{"mac": "bb:bb:bb:bb:bb:bb", "ip": "192.168.2.20", "vendor": "Vendor B"}],
        )
        self.assertEqual(
            diff["new_devices"],
            [],
        )
        self.assertEqual(
            diff["returned_devices"],
            [],
        )
        self.assertEqual(
            diff["ip_changes"],
            [],
        )

    def test_build_port_scan_diff_detects_new_closed_and_service_changes(self):
        diff = arp_scanner.build_port_scan_diff(
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 22,
                    "service": "SSH",
                },
                {
                    "mac": "bb:bb:bb:bb:bb:bb",
                    "ip": "192.168.2.20",
                    "port": 80,
                    "service": "HTTP",
                },
            ],
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 22,
                    "service": "OpenSSH",
                },
                {
                    "mac": "cc:cc:cc:cc:cc:cc",
                    "ip": "192.168.2.30",
                    "port": 443,
                    "service": "HTTPS",
                },
            ],
        )

        self.assertEqual(
            diff["new_ports"],
            [
                {
                    "mac": "cc:cc:cc:cc:cc:cc",
                    "ip": "192.168.2.30",
                    "port": 443,
                    "service": "HTTPS",
                }
            ],
        )
        self.assertEqual(
            diff["closed_ports"],
            [
                {
                    "mac": "bb:bb:bb:bb:bb:bb",
                    "ip": "192.168.2.20",
                    "port": 80,
                    "service": "HTTP",
                }
            ],
        )
        self.assertEqual(
            diff["service_changes"],
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 22,
                    "old_service": "SSH",
                    "new_service": "OpenSSH",
                }
            ],
        )

    def test_process_scan_results_updates_existing_and_marks_new_devices(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                conn.execute(
                    """
                    INSERT INTO devices (mac, ip, vendor, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "aa:bb:cc:dd:ee:ff",
                        "192.168.2.10",
                        "Old Vendor",
                        "2026-01-01T00:00:00",
                        "2026-01-01T00:00:00",
                    ),
                )
                conn.commit()

                fake_lookup = mock.Mock()
                fake_lookup.lookup.side_effect = ["Existing Vendor", "New Vendor"]

                table_data, json_output, new_devices = arp_scanner.process_scan_results(
                    [
                        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.2.20"},
                        {"mac": "11:22:33:44:55:66", "ip": "192.168.2.30"},
                    ],
                    fake_lookup,
                    {"aa:bb:cc:dd:ee:ff"},
                    conn,
                )

                existing_row = conn.execute(
                    "SELECT ip, vendor, last_seen FROM devices WHERE mac = ?",
                    ("aa:bb:cc:dd:ee:ff",),
                ).fetchone()
                conn.close()

            self.assertEqual(len(table_data), 2)
            self.assertEqual(len(json_output), 2)
            self.assertEqual(len(new_devices), 1)
            self.assertEqual(new_devices[0]["mac"], "11:22:33:44:55:66")
            self.assertIn("first_seen", new_devices[0])
            self.assertIn("last_seen", new_devices[0])
            self.assertEqual(existing_row[0], "192.168.2.20")
            self.assertEqual(existing_row[1], "Existing Vendor")
            self.assertIsNotNone(existing_row[2])
        finally:
            os.remove(path)

    def test_save_and_report_results_writes_json_to_custom_path(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "arp_scan.db")
            json_path = os.path.join(tmp_dir, "reports", "arp_scan_result.json")

            with mock.patch.object(arp_scanner, "DB_FILE", db_path), mock.patch.object(
                arp_scanner, "JSON_OUTPUT_FILE", json_path
            ):
                conn = arp_scanner.init_db()
                arp_scanner.save_and_report_results(
                    conn,
                    [
                        {
                            "ip": "192.168.2.10",
                            "mac": "aa:bb:cc:dd:ee:ff",
                            "vendor": "Vendor A",
                        }
                    ],
                    [],
                    {
                        "new_devices": [],
                        "returned_devices": [],
                        "missing_devices": [],
                        "ip_changes": [],
                    },
                )
                conn.close()

            with open(json_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)

            self.assertEqual(payload["devices"][0]["ip"], "192.168.2.10")
            self.assertEqual(payload["arp_diff_summary"]["new_devices"], [])
            self.assertEqual(payload["arp_diff_summary"]["returned_devices"], [])


if __name__ == "__main__":
    unittest.main()
