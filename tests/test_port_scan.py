import unittest
from types import SimpleNamespace
import tempfile
import json
import os
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from unittest import mock

import arp_scanner
import port_scan
import port_reporting
import service_detection


class PortScanTests(unittest.TestCase):
    def test_parse_ports_returns_defaults_when_empty(self):
        self.assertEqual(
            port_scan.parse_ports(None),
            [22, 80, 443, 3000, 5000, 8000, 8080, 8443],
        )

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
                    "hostname": "nas.local",
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
                    "hostname": "nas.local",
                    "port": 22,
                    "service": "SSH",
                },
                {
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "ip": "192.168.2.10",
                    "hostname": "nas.local",
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

    def test_normalize_service_entry_maps_unknown_web_ports_to_clear_status(self):
        self.assertEqual(
            port_scan.normalize_service_entry(80, "Unknown"),
            ("WEB", "open port, no banner"),
        )
        self.assertEqual(
            port_scan.normalize_service_entry(443, "Unknown"),
            ("TLS", "open port, no banner"),
        )

    def test_normalize_service_entry_extracts_http_and_ssh_details(self):
        self.assertEqual(
            port_scan.normalize_service_entry(22, "SSH (SSH-2.0-OpenSSH_8.4)"),
            ("SSH", "SSH-2.0-OpenSSH_8.4"),
        )
        self.assertEqual(
            port_scan.normalize_service_entry(443, "HTTP (Server: openresty/1.17.8.1)"),
            ("HTTPS", "openresty/1.17.8.1"),
        )

    def test_normalize_service_entry_extracts_tls_details(self):
        self.assertEqual(
            port_scan.normalize_service_entry(
                443,
                "TLS (TLSv1.3, CN=example.local, TLS_AES_256_GCM_SHA384)",
            ),
            ("TLS", "TLSv1.3, CN=example.local, TLS_AES_256_GCM_SHA384"),
        )

    def test_extract_certificate_common_name_returns_none_without_subject(self):
        self.assertIsNone(port_scan.extract_certificate_common_name({}))
        self.assertIsNone(port_scan.extract_certificate_organization({}))

    def test_build_certificate_validity_status_classifies_expiry(self):
        with mock.patch(
            "service_detection.get_current_utc",
            return_value=datetime(2026, 4, 25, tzinfo=timezone.utc),
        ):
            self.assertEqual(
                port_scan.build_certificate_validity_status(
                    "Apr 24 00:00:00 2026 GMT"
                ),
                "expired",
            )
            self.assertEqual(
                port_scan.build_certificate_validity_status(
                    "May 01 00:00:00 2026 GMT"
                ),
                "expiring_soon",
            )
            self.assertEqual(
                port_scan.build_certificate_validity_status(
                    "Jun 30 00:00:00 2026 GMT"
                ),
                "valid",
            )

    def test_get_tls_service_banner_returns_tls_metadata(self):
        raw_socket = mock.MagicMock()
        raw_socket.__enter__.return_value = raw_socket
        raw_socket.__exit__.return_value = None

        tls_socket = mock.MagicMock()
        tls_socket.__enter__.return_value = tls_socket
        tls_socket.__exit__.return_value = None
        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.getpeercert.return_value = {
            "subject": ((("commonName", "example.local"),),),
            "issuer": ((("organizationName", "Example CA"),),),
            "notBefore": "Apr 25 00:00:00 2026 GMT",
            "notAfter": "Apr 25 00:00:00 2027 GMT",
        }
        tls_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        context = mock.MagicMock()
        context.wrap_socket.return_value = tls_socket

        with mock.patch("service_detection.socket.create_connection", return_value=raw_socket):
            with mock.patch("service_detection.ssl.create_default_context", return_value=context):
                with mock.patch(
                    "service_detection.get_current_utc",
                    return_value=datetime(2026, 4, 25, tzinfo=timezone.utc),
                ):
                    service_info = port_scan.get_tls_service_details("192.168.2.10", 443)

        self.assertEqual(
            service_info["service"],
            "TLS (TLSv1.3, CN=example.local, TLS_AES_256_GCM_SHA384)",
        )
        self.assertEqual(
            service_info["tls"],
            {
                "protocol": "TLSv1.3",
                "common_name": "example.local",
                "issuer": "Example CA",
                "not_before": "Apr 25 00:00:00 2026 GMT",
                "not_after": "Apr 25 00:00:00 2027 GMT",
                "certificate_status": "valid",
                "cipher": "TLS_AES_256_GCM_SHA384",
            },
        )

    def test_scan_ports_for_device_uses_structured_service_details(self):
        device = {
            "ip": "192.168.2.10",
            "mac": "aa:aa:aa:aa:aa:aa",
            "vendor": "Vendor A",
        }

        with mock.patch("port_scan.scan_single_port", return_value=443):
            with mock.patch(
                "port_scan.get_service_details",
                return_value={
                    "service": "TLS (TLSv1.3, CN=example.local, TLS_AES_256_GCM_SHA384)",
                    "tls": {
                        "protocol": "TLSv1.3",
                        "common_name": "example.local",
                        "cipher": "TLS_AES_256_GCM_SHA384",
                    },
                },
            ):
                result = port_scan.scan_ports_for_device(device, [443])

        self.assertEqual(
            result["open_ports"],
            [
                {
                    "port": 443,
                    "service": "TLS (TLSv1.3, CN=example.local, TLS_AES_256_GCM_SHA384)",
                    "tls": {
                        "protocol": "TLSv1.3",
                        "common_name": "example.local",
                        "cipher": "TLS_AES_256_GCM_SHA384",
                    },
                }
            ],
        )

    def test_get_service_details_falls_back_to_plaintext_when_tls_handshake_fails(self):
        with mock.patch(
            "service_detection.get_tls_service_details",
            return_value={
                "service": "TLS handshake failed (WRONG_VERSION_NUMBER)",
                "tls": {"handshake_error": "WRONG_VERSION_NUMBER"},
            },
        ):
            with mock.patch(
                "service_detection.get_plaintext_service_banner",
                return_value="HTTP (Server: openresty/1.17.8.1)",
            ):
                service_info = port_scan.get_service_details("192.168.2.10", 443)

        self.assertEqual(
            service_info,
            {"service": "HTTP (Server: openresty/1.17.8.1)"},
        )

    def test_get_service_banner_returns_legacy_string_wrapper(self):
        with mock.patch(
            "service_detection.get_service_details",
            return_value={"service": "TLS (TLSv1.3, CN=example.local)"},
        ):
            banner = port_scan.get_service_banner("192.168.2.10", 443)

        self.assertEqual(banner, "TLS (TLSv1.3, CN=example.local)")

    def test_print_port_scan_results_renders_summary_and_normalized_services(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            port_scan.print_port_scan_results(
                [
                    {
                        "ip": "192.168.2.10",
                        "mac": "00:1d:c0:79:ee:86",
                        "hostname": "envoy.local",
                        "vendor": "Enphase Energy",
                        "open_ports": [
                            {"port": 22, "service": "SSH (SSH-2.0-OpenSSH_8.4)"},
                            {"port": 443, "service": "HTTP (Server: openresty/1.17.8.1)"},
                        ],
                    },
                    {
                        "ip": "192.168.2.1",
                        "mac": "40:3f:8c:c6:39:37",
                        "vendor": "TP-LINK TECHNOLOGIES CO.,LTD.",
                        "open_ports": [{"port": 80, "service": "Unknown"}],
                    },
                ]
            )

        output = buffer.getvalue()
        self.assertIn("2 devices scanned | 2 with open ports | 3 open ports total", output)
        self.assertIn("192.168.2.10  envoy.local  Enphase Energy  00:1d:c0:79:ee:86", output)
        self.assertIn("22/tcp", output)
        self.assertIn("SSH", output)
        self.assertIn("SSH-2.0-OpenSSH_8.4", output)
        self.assertIn("HTTPS", output)
        self.assertIn("openresty/1.17.8.1", output)
        self.assertIn("WEB", output)
        self.assertIn("open port, no banner", output)

    def test_print_port_scan_results_grouped_shows_tls_alert_marker(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            port_scan.print_port_scan_results(
                [
                    {
                        "ip": "192.168.2.40",
                        "mac": "10:10:10:10:10:10",
                        "vendor": "Example TLS Appliance",
                        "open_ports": [
                            {
                                "port": 443,
                                "service": "TLS (TLSv1.2, CN=expired.local, OLD_CIPHER)",
                                "tls": {
                                    "protocol": "TLSv1.2",
                                    "common_name": "expired.local",
                                    "certificate_status": "expired",
                                    "cipher": "OLD_CIPHER",
                                },
                            }
                        ],
                    }
                ]
            )

        output = buffer.getvalue()
        self.assertIn("TLS! expired", output)
        self.assertIn("expired.local", output)

    def test_print_port_scan_results_supports_table_output(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            port_scan.print_port_scan_results(
                [
                    {
                        "ip": "192.168.2.10",
                        "mac": "00:1d:c0:79:ee:86",
                        "hostname": "soon.local",
                        "vendor": "Enphase Energy",
                        "open_ports": [
                            {
                                "port": 443,
                                "service": "TLS (TLSv1.3, CN=soon.local, NEW_CIPHER)",
                                "tls": {
                                    "protocol": "TLSv1.3",
                                    "common_name": "soon.local",
                                    "certificate_status": "expiring_soon",
                                    "cipher": "NEW_CIPHER",
                                },
                            }
                        ],
                    }
                ],
                output_format="table",
            )

        output = buffer.getvalue()
        self.assertIn("IP", output)
        self.assertIn("Hostname", output)
        self.assertIn("Vendor", output)
        self.assertIn("192.168.2.10", output)
        self.assertIn("soon.local", output)
        self.assertIn("443/tcp", output)
        self.assertIn("TLS", output)
        self.assertIn("TLS! expiring", output)

    def test_print_port_scan_results_supports_focus_output(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            port_scan.print_port_scan_results(
                [
                    {
                        "ip": "192.168.2.10",
                        "mac": "00:1d:c0:79:ee:86",
                        "hostname": "envoy.local",
                        "vendor": "Enphase Energy",
                        "open_ports": [{"port": 22, "service": "SSH (SSH-2.0-OpenSSH_8.4)"}],
                    },
                    {
                        "ip": "192.168.2.45",
                        "mac": "90:09:d0:83:de:d5",
                        "vendor": "Synology Incorporated",
                        "open_ports": [{"port": 443, "service": "HTTP (Server: nginx)"}],
                    },
                    {
                        "ip": "192.168.2.40",
                        "mac": "10:10:10:10:10:10",
                        "vendor": "Example TLS Appliance",
                        "open_ports": [
                            {
                                "port": 443,
                                "service": "TLS (TLSv1.2, CN=expired.local, OLD_CIPHER)",
                                "tls": {
                                    "protocol": "TLSv1.2",
                                    "common_name": "expired.local",
                                    "certificate_status": "expired",
                                    "cipher": "OLD_CIPHER",
                                },
                            }
                        ],
                    },
                    {
                        "ip": "192.168.2.1",
                        "mac": "40:3f:8c:c6:39:37",
                        "vendor": "TP-LINK TECHNOLOGIES CO.,LTD.",
                        "open_ports": [{"port": 80, "service": "Unknown"}],
                    },
                ],
                output_format="focus",
            )

        output = buffer.getvalue()
        self.assertIn("TLS certificate alerts:", output)
        self.assertIn("Interesting hosts:", output)
        self.assertIn("Web-only hosts:", output)
        self.assertIn("Unidentified web endpoints:", output)
        self.assertIn("envoy.local", output)
        self.assertIn("192.168.2.40", output)
        self.assertIn("expired.local", output)
        self.assertIn("22/SSH", output)
        self.assertIn("443/HTTPS", output)
        self.assertIn("80/WEB", output)

    def test_print_port_diff_summary_renders_tls_changes(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            port_scan.print_port_diff_summary(
                arp_scanner.build_port_scan_diff(
                    [
                        {
                            "mac": "aa:aa:aa:aa:aa:aa",
                            "ip": "192.168.2.10",
                            "port": 443,
                            "service": "TLS (TLSv1.2, CN=old.local, OLD_CIPHER)",
                            "tls": {
                                "protocol": "TLSv1.2",
                                "common_name": "old.local",
                                "certificate_status": "expiring_soon",
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
                                "certificate_status": "valid",
                                "cipher": "NEW_CIPHER",
                            },
                        }
                    ],
                )
            )

        output = buffer.getvalue()
        self.assertIn("TLS changes: 1", output)
        self.assertIn("TLS metadata changes:", output)
        self.assertIn("TLSv1.2, CN=old.local, status=expiring_soon, OLD_CIPHER", output)
        self.assertIn("TLSv1.3, CN=new.local, status=valid, NEW_CIPHER", output)

    def test_print_port_diff_summary_includes_hostname_when_available(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            port_scan.print_port_diff_summary(
                {
                    "new_ports": [
                        {
                            "ip": "192.168.2.10",
                            "hostname": "nas.local",
                            "mac": "aa:aa:aa:aa:aa:aa",
                            "port": 5000,
                            "service": "HTTP",
                        }
                    ],
                    "closed_ports": [],
                    "service_changes": [],
                    "tls_changes": [],
                }
            )

        output = buffer.getvalue()
        self.assertIn("192.168.2.10 [nas.local] (aa:aa:aa:aa:aa:aa) 5000/tcp HTTP", output)

    def test_print_port_alert_summary_renders_actionable_findings(self):
        buffer = StringIO()
        results = [
            {
                "ip": "192.168.2.40",
                "hostname": "expired.local",
                "mac": "10:10:10:10:10:10",
                "vendor": "Example TLS Appliance",
                "open_ports": [
                    {
                        "port": 443,
                        "service": "TLS (TLSv1.2, CN=expired.local, OLD_CIPHER)",
                        "tls": {
                            "protocol": "TLSv1.2",
                            "common_name": "expired.local",
                            "certificate_status": "expired",
                            "cipher": "OLD_CIPHER",
                        },
                    }
                ],
            }
        ]
        diff_summary = {
            "new_ports": [
                {
                    "ip": "192.168.2.40",
                    "hostname": "expired.local",
                    "mac": "10:10:10:10:10:10",
                    "port": 443,
                    "service": "TLS (TLSv1.2, CN=expired.local, OLD_CIPHER)",
                }
            ],
            "closed_ports": [],
            "service_changes": [],
            "tls_changes": [],
        }

        with redirect_stdout(buffer):
            port_reporting.print_port_alert_summary(results, diff_summary)

        output = buffer.getvalue()
        self.assertIn("=== Alerts ===", output)
        self.assertIn("TLS alerts: 1", output)
        self.assertIn("TLS certificate alerts:", output)
        self.assertIn("TLS! expired", output)
        self.assertIn("New open ports:", output)

    def test_print_port_alert_summary_reports_when_no_alerts_exist(self):
        buffer = StringIO()
        results = [
            {
                "ip": "192.168.2.10",
                "hostname": "web.local",
                "mac": "aa:aa:aa:aa:aa:aa",
                "vendor": "Vendor A",
                "open_ports": [{"port": 80, "service": "HTTP"}],
            }
        ]
        diff_summary = {
            "new_ports": [],
            "closed_ports": [],
            "service_changes": [],
            "tls_changes": [],
        }

        with redirect_stdout(buffer):
            port_reporting.print_port_alert_summary(results, diff_summary)

        output = buffer.getvalue()
        self.assertIn("No actionable alerts detected.", output)

    def test_has_port_alerts_detects_tls_alerts(self):
        results = [
            {
                "ip": "192.168.2.40",
                "hostname": "expired.local",
                "mac": "10:10:10:10:10:10",
                "vendor": "Example TLS Appliance",
                "open_ports": [
                    {
                        "port": 443,
                        "service": "TLS",
                        "tls": {"certificate_status": "expired"},
                    }
                ],
            }
        ]

        self.assertTrue(
            port_reporting.has_port_alerts(
                results,
                {
                    "new_ports": [],
                    "closed_ports": [],
                    "service_changes": [],
                    "tls_changes": [],
                },
            )
        )

    def test_has_port_alerts_detects_service_changes(self):
        self.assertTrue(
            port_reporting.has_port_alerts(
                [],
                {
                    "new_ports": [],
                    "closed_ports": [],
                    "service_changes": [
                        {
                            "ip": "192.168.2.10",
                            "port": 443,
                            "old_service": "HTTP",
                            "new_service": "TLS",
                        }
                    ],
                    "tls_changes": [],
                },
            )
        )

    def test_has_port_alerts_returns_false_without_actionable_findings(self):
        self.assertFalse(
            port_reporting.has_port_alerts(
                [],
                {
                    "new_ports": [],
                    "closed_ports": [],
                    "service_changes": [],
                    "tls_changes": [],
                },
            )
        )

    def test_discover_devices_to_scan_uses_target_without_discovery(self):
        args = SimpleNamespace(
            target="192.168.2.10",
            iface=None,
            cidr=None,
            resolve_hostnames=False,
        )

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

    def test_discover_devices_to_scan_resolves_target_hostname_when_enabled(self):
        args = SimpleNamespace(
            target="192.168.2.10",
            iface=None,
            cidr=None,
            resolve_hostnames=True,
        )

        with mock.patch(
            "port_scan.enrich_devices_with_hostnames",
            side_effect=lambda devices: devices[0].update({"hostname": "nas.local"}) or devices,
        ):
            devices, _ = port_scan.discover_devices_to_scan(args, mac_lookup=None)

        self.assertEqual(devices[0]["hostname"], "nas.local")

    def test_save_port_scan_results_writes_snapshot_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = os.path.join(tmp_dir, "reports", "port_scan_result.json")
            csv_path = os.path.join(tmp_dir, "reports", "port_scan_result.csv")

            port_scan.save_port_scan_results(
                results=[
                    {
                        "ip": "192.168.2.10",
                        "hostname": "nas.local",
                        "mac": "aa:aa:aa:aa:aa:aa",
                        "vendor": "Vendor A",
                        "open_ports": [
                            {
                                "port": 22,
                                "service": "SSH",
                                "tls": {"protocol": "TLSv1.3"},
                            }
                        ],
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
                    "tls_changes": [],
                },
                json_output_file=json_path,
                csv_output_file=csv_path,
            )

            with open(json_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            with open(csv_path, "r", encoding="utf-8") as handle:
                csv_contents = handle.read()

            self.assertEqual(payload["devices"][0]["ip"], "192.168.2.10")
            self.assertEqual(payload["port_diff_summary"]["new_ports"][0]["port"], 22)
            self.assertEqual(
                payload["devices"][0]["open_ports"][0]["tls"]["protocol"],
                "TLSv1.3",
            )
            self.assertIn("ip,hostname,mac,vendor,port,service,tls_json", csv_contents)
            self.assertIn("192.168.2.10,nas.local,aa:aa:aa:aa:aa:aa,Vendor A,22,SSH", csv_contents)


if __name__ == "__main__":
    unittest.main()
