import os
import sqlite3
import tempfile
import unittest
from unittest import mock
import json
from contextlib import redirect_stdout
from io import StringIO

import arp_scanner


class ArpScannerTests(unittest.TestCase):
    def test_parse_args_supports_webhook_flags(self):
        with mock.patch(
            "sys.argv",
            [
                "arp_scanner.py",
                "--webhook-url",
                "https://example.test/webhook",
                "--webhook-timeout",
                "5",
            ],
        ):
            args = arp_scanner.parse_args()

        self.assertEqual(args.webhook_url, "https://example.test/webhook")
        self.assertEqual(args.webhook_timeout, 5.0)

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
            verify_conn = sqlite3.connect(path)
            scan_run_device_columns = verify_conn.execute(
                "PRAGMA table_info(scan_run_devices)"
            ).fetchall()
            scan_run_port_columns = verify_conn.execute(
                "PRAGMA table_info(scan_run_ports)"
            ).fetchall()
            verify_conn.close()
            self.assertIn(
                "hostname",
                [column[1] for column in scan_run_device_columns],
            )
            self.assertIn(
                "hostname",
                [column[1] for column in scan_run_port_columns],
            )
            self.assertIn(
                "tls_json",
                [column[1] for column in scan_run_port_columns],
            )
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
                        {
                            "mac": "aa:aa:aa:aa:aa:aa",
                            "ip": "192.168.2.10",
                            "vendor": "Vendor A",
                            "hostname": "nas.local",
                        },
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
                    {
                        "mac": "aa:aa:aa:aa:aa:aa",
                        "ip": "192.168.2.10",
                        "vendor": "Vendor A",
                        "hostname": "nas.local",
                    },
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
                            "hostname": "nas.local",
                            "open_ports": [
                                {"port": 22, "service": "SSH"},
                                {
                                    "port": 80,
                                    "service": "HTTP",
                                    "tls": {"protocol": "TLSv1.3"},
                                },
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
                    SELECT mac, ip, hostname, port, service, tls_json
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
                    ("aa:aa:aa:aa:aa:aa", "192.168.2.10", "nas.local", 22, "SSH", None),
                    (
                        "aa:aa:aa:aa:aa:aa",
                        "192.168.2.10",
                        "nas.local",
                        80,
                        "HTTP",
                        json.dumps({"protocol": "TLSv1.3"}, sort_keys=True),
                    ),
                ],
            )
        finally:
            os.remove(path)

    def test_maybe_send_arp_webhook_skips_when_no_alerts(self):
        sent = arp_scanner.maybe_send_arp_webhook(
            "https://example.test/webhook",
            10,
            "en0",
            "192.168.2.0/24",
            {
                "new_devices": [],
                "returned_devices": [],
                "missing_devices": [],
                "ip_changes": [],
                "hostname_changes": [],
            },
        )

        self.assertFalse(sent)

    def test_maybe_send_arp_webhook_sends_expected_payload(self):
        diff_summary = {
            "new_devices": [{"ip": "192.168.2.10", "mac": "aa:aa:aa:aa:aa:aa"}],
            "returned_devices": [],
            "missing_devices": [],
            "ip_changes": [],
            "hostname_changes": [],
        }

        with mock.patch("arp_scanner.send_webhook_payload", return_value=True) as sender:
            sent = arp_scanner.maybe_send_arp_webhook(
                "https://example.test/webhook",
                8,
                "en0",
                "192.168.2.0/24",
                diff_summary,
            )

        self.assertTrue(sent)
        payload = sender.call_args.args[1]
        self.assertEqual(sender.call_args.args[0], "https://example.test/webhook")
        self.assertEqual(payload["source"], "arp_scanner")
        self.assertEqual(payload["scan_context"]["interface"], "en0")
        self.assertEqual(payload["alert_summary"]["new_devices"], 1)
        self.assertEqual(payload["alerts"], diff_summary)
        self.assertEqual(sender.call_args.kwargs["timeout"], 8)

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
                            "hostname": "nas.local",
                            "open_ports": [
                                {
                                    "port": 22,
                                    "service": "SSH",
                                    "tls": {"protocol": "TLSv1.3"},
                                }
                            ],
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
                        "hostname": "nas.local",
                        "port": 22,
                        "service": "SSH",
                        "tls": {"protocol": "TLSv1.3"},
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

    def test_build_scan_diff_detects_hostname_changes(self):
        diff = arp_scanner.build_scan_diff(
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "vendor": "Vendor A",
                    "hostname": "old.local",
                }
            ],
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "vendor": "Vendor A",
                    "hostname": "new.local",
                }
            ],
        )

        self.assertEqual(
            diff["hostname_changes"],
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "vendor": "Vendor A",
                    "old_hostname": "old.local",
                    "new_hostname": "new.local",
                }
            ],
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
                    "hostname": "web.local",
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
                    "hostname": "web.local",
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
        self.assertEqual(diff["tls_changes"], [])

    def test_build_port_scan_diff_detects_tls_metadata_changes(self):
        diff = arp_scanner.build_port_scan_diff(
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 443,
                    "service": "TLS (TLSv1.2, CN=old.local, OLD_CIPHER)",
                    "tls": {
                        "protocol": "TLSv1.2",
                        "common_name": "old.local",
                        "cipher": "OLD_CIPHER",
                    },
                }
            ],
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 443,
                    "service": "TLS (TLSv1.3, CN=new.local, NEW_CIPHER)",
                    "tls": {
                        "protocol": "TLSv1.3",
                        "common_name": "new.local",
                        "cipher": "NEW_CIPHER",
                    },
                }
            ],
        )

        self.assertEqual(
            diff["tls_changes"],
            [
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "port": 443,
                    "old_tls": {
                        "protocol": "TLSv1.2",
                        "common_name": "old.local",
                        "cipher": "OLD_CIPHER",
                    },
                    "new_tls": {
                        "protocol": "TLSv1.3",
                        "common_name": "new.local",
                        "cipher": "NEW_CIPHER",
                    },
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

    def test_process_scan_results_resolves_hostnames_when_enabled(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            with mock.patch.object(arp_scanner, "DB_FILE", path):
                conn = arp_scanner.init_db()
                fake_lookup = mock.Mock()
                fake_lookup.lookup.return_value = "Vendor A"

                with mock.patch(
                    "arp_scanner.enrich_devices_with_hostnames",
                    side_effect=lambda devices: devices[0].update({"hostname": "nas.local"}) or devices,
                ):
                    table_data, json_output, new_devices = arp_scanner.process_scan_results(
                        [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.2.20"}],
                        fake_lookup,
                        set(),
                        conn,
                        resolve_hostnames=True,
                    )
                conn.close()

            self.assertEqual(table_data[0], ["192.168.2.20", "nas.local", "aa:bb:cc:dd:ee:ff", "Vendor A"])
            self.assertEqual(json_output[0]["hostname"], "nas.local")
            self.assertEqual(new_devices[0]["hostname"], "nas.local")
        finally:
            os.remove(path)

    def test_save_and_report_results_writes_json_to_custom_path(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "arp_scan.db")
            json_path = os.path.join(tmp_dir, "reports", "arp_scan_result.json")
            csv_path = os.path.join(tmp_dir, "reports", "arp_scan_result.csv")
            markdown_path = os.path.join(tmp_dir, "reports", "arp_scan_result.md")

            with mock.patch.object(arp_scanner, "DB_FILE", db_path), mock.patch.object(
                arp_scanner, "JSON_OUTPUT_FILE", json_path
            ):
                conn = arp_scanner.init_db()
                arp_scanner.save_and_report_results(
                    conn,
                    [
                        {
                            "ip": "192.168.2.10",
                            "hostname": "nas.local",
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
                        "hostname_changes": [],
                    },
                    csv_output_file=csv_path,
                    markdown_output_file=markdown_path,
                )
                conn.close()

            with open(json_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            with open(csv_path, "r", encoding="utf-8") as handle:
                csv_contents = handle.read()
            with open(markdown_path, "r", encoding="utf-8") as handle:
                markdown_contents = handle.read()

            self.assertEqual(payload["devices"][0]["ip"], "192.168.2.10")
            self.assertEqual(payload["devices"][0]["hostname"], "nas.local")
            self.assertEqual(payload["arp_diff_summary"]["new_devices"], [])
            self.assertEqual(payload["arp_diff_summary"]["returned_devices"], [])
            self.assertIn("ip,hostname,mac,vendor,first_seen,last_seen", csv_contents)
            self.assertIn("192.168.2.10,nas.local,aa:bb:cc:dd:ee:ff,Vendor A", csv_contents)
            self.assertIn("# ARP Scan Report", markdown_contents)
            self.assertIn("## Devices", markdown_contents)
            self.assertIn("| IP | Hostname | MAC | Vendor |", markdown_contents)

    def test_print_diff_summary_renders_hostname_changes(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            arp_scanner.print_diff_summary(
                {
                    "new_devices": [],
                    "returned_devices": [],
                    "missing_devices": [],
                    "ip_changes": [],
                    "hostname_changes": [
                        {
                            "ip": "192.168.2.10",
                            "old_hostname": "old.local",
                            "new_hostname": "new.local",
                            "mac": "aa:aa:aa:aa:aa:aa",
                            "vendor": "Vendor A",
                        }
                    ],
                }
            )

        output = buffer.getvalue()
        self.assertIn("Hostname changes: 1", output)
        self.assertIn("Hostname changes:", output)
        self.assertIn("old.local", output)
        self.assertIn("new.local", output)

    def test_print_alert_summary_renders_actionable_findings(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            arp_scanner.print_alert_summary(
                {
                    "new_devices": [
                        {
                            "ip": "192.168.2.30",
                            "hostname": "nas.local",
                            "mac": "11:22:33:44:55:66",
                            "vendor": "Vendor A",
                        }
                    ],
                    "returned_devices": [],
                    "missing_devices": [],
                    "ip_changes": [],
                    "hostname_changes": [],
                }
            )

        output = buffer.getvalue()
        self.assertIn("=== Alerts ===", output)
        self.assertIn("New: 1", output)
        self.assertIn("New devices:", output)
        self.assertIn("nas.local", output)

    def test_print_alert_summary_reports_when_no_alerts_exist(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            arp_scanner.print_alert_summary(
                {
                    "new_devices": [],
                    "returned_devices": [],
                    "missing_devices": [],
                    "ip_changes": [],
                    "hostname_changes": [],
                }
            )

        output = buffer.getvalue()
        self.assertIn("No actionable alerts detected.", output)

    def test_has_alerts_detects_new_devices(self):
        self.assertTrue(
            arp_scanner.has_alerts(
                {
                    "new_devices": [{"ip": "192.168.2.30"}],
                    "returned_devices": [],
                    "missing_devices": [],
                    "ip_changes": [],
                    "hostname_changes": [],
                }
            )
        )

    def test_has_alerts_detects_hostname_changes(self):
        self.assertTrue(
            arp_scanner.has_alerts(
                {
                    "new_devices": [],
                    "returned_devices": [],
                    "missing_devices": [],
                    "ip_changes": [],
                    "hostname_changes": [{"ip": "192.168.2.10"}],
                }
            )
        )

    def test_has_alerts_returns_false_for_empty_diff(self):
        self.assertFalse(
            arp_scanner.has_alerts(
                {
                    "new_devices": [],
                    "returned_devices": [],
                    "missing_devices": [],
                    "ip_changes": [],
                    "hostname_changes": [],
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
