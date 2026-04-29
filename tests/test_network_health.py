import ipaddress
import json
import os
import ssl
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest import mock

import network_health
import network_health_check


class NetworkHealthTests(unittest.TestCase):
    def test_build_parser_supports_markdown_and_focus_flags(self):
        parser = network_health_check.build_parser()

        args = parser.parse_args(["--md-out", "health.md", "--output", "focus"])

        self.assertEqual(args.md_out, "health.md")
        self.assertEqual(args.output, "focus")

    def test_build_parser_supports_webhook_flags(self):
        parser = network_health_check.build_parser()

        args = parser.parse_args(
            ["--webhook-url", "https://example.test/webhook", "--webhook-timeout", "9"]
        )

        self.assertEqual(args.webhook_url, "https://example.test/webhook")
        self.assertEqual(args.webhook_timeout, 9.0)

    def test_get_corewlan_module_returns_import_error_when_unavailable(self):
        original_import = __import__

        def fake_import(name, *args, **kwargs):
            if name == "CoreWLAN":
                raise ImportError("No module named CoreWLAN")
            return original_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            module, error = network_health.get_corewlan_module()

        self.assertIsNone(module)
        self.assertIn("No module named CoreWLAN", error)

    def test_lookup_arp_mac_returns_matching_interface_entry(self):
        with mock.patch(
            "network_health.run_command",
            return_value=(
                "? (192.168.2.1) at 40:3f:8c:c6:39:37 on en0 ifscope [ethernet]\n"
                "? (192.168.2.1) at 48:29:52:5d:78:b0 on en1 ifscope [ethernet]\n"
            ),
        ):
            mac = network_health.lookup_arp_mac("192.168.2.1", interface="en1")

        self.assertEqual(mac, "48:29:52:5d:78:b0")

    def test_resolve_gateway_fingerprint_uses_arp_cache_and_vendor_lookup(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.1", "en1")):
            with mock.patch("network_health.lookup_arp_mac", return_value="40:3f:8c:c6:39:37"):
                with mock.patch("network_health.LocalMacVendorLookup") as lookup_cls:
                    with mock.patch("network_health.get_vendor", return_value="TP-LINK TECHNOLOGIES CO.,LTD."):
                        result = network_health.resolve_gateway_fingerprint()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["details"]["gateway_mac"], "40:3f:8c:c6:39:37")
        self.assertEqual(result["details"]["vendor"], "TP-LINK TECHNOLOGIES CO.,LTD.")
        lookup_cls.assert_called_once()

    def test_build_gateway_exposure_check_marks_dns_only_as_ok(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.1", "en0")):
            with mock.patch(
                "network_health.probe_tcp_service",
                side_effect=lambda host, port, timeout=2: port == 53,
            ):
                result = network_health.build_gateway_exposure_check(timeout=3)

        self.assertEqual(result["name"], "gateway_exposure")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["details"]["reachable_services"][0]["port"], 53)
        self.assertEqual(result["details"]["risky_services"], [])

    def test_extract_html_title_returns_clean_title(self):
        title = network_health.extract_html_title(
            "<html><head><title>\n Router Admin \n</title></head></html>"
        )

        self.assertEqual(title, "Router Admin")

    def test_extract_body_hint_detects_spa_shell(self):
        hint = network_health.extract_body_hint(
            "<!DOCTYPE html><html><head><!-- If you are serving your web app in a path other than the root --></head></html>"
        )

        self.assertEqual(hint, "single-page app shell")

    def test_build_gateway_exposure_check_captures_http_probe_details(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.1", "en0")):
            with mock.patch(
                "network_health.probe_tcp_service",
                side_effect=lambda host, port, timeout=2: port == 80,
            ):
                with mock.patch(
                    "network_health.inspect_gateway_http_surface",
                    return_value={
                        "url": "http://192.168.2.1:80/",
                        "status_code": 200,
                        "content_type": "text/html",
                        "server": "nginx",
                        "location": None,
                        "title": "Router Admin",
                        "page_hint": "single-page app shell",
                    },
                ):
                    result = network_health.build_gateway_exposure_check(timeout=3)

        service = result["details"]["reachable_services"][0]
        self.assertEqual(service["http_probe"]["status_code"], 200)
        self.assertEqual(service["http_probe"]["content_type"], "text/html")
        self.assertEqual(service["http_probe"]["server"], "nginx")
        self.assertEqual(service["http_probe"]["title"], "Router Admin")
        self.assertEqual(service["http_probe"]["page_hint"], "single-page app shell")
        self.assertEqual(result["status"], "notice")

    def test_build_gateway_exposure_check_alerts_on_gateway_web_admin_service(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.1", "en0")):
            with mock.patch(
                "network_health.probe_tcp_service",
                side_effect=lambda host, port, timeout=2: port in [53, 443],
            ):
                result = network_health.build_gateway_exposure_check(timeout=3)

        self.assertEqual(result["status"], "notice")
        self.assertIn("Private/local gateway exposes", result["summary"])
        self.assertEqual(result["details"]["risky_services"][0]["port"], 443)

    def test_build_gateway_exposure_check_alerts_on_public_gateway_web_admin_service(self):
        with mock.patch("network_health.get_default_gateway", return_value=("8.8.8.8", "en0")):
            with mock.patch(
                "network_health.probe_tcp_service",
                side_effect=lambda host, port, timeout=2: port == 443,
            ):
                result = network_health.build_gateway_exposure_check(timeout=3)

        self.assertEqual(result["status"], "alert")
        self.assertIn("Gateway exposes 1 local web/admin service", result["summary"])

    def test_parse_arp_cache_entries_extracts_completed_rows(self):
        entries = network_health.parse_arp_cache_entries(
            "? (192.168.2.1) at 40:3f:8c:c6:39:37 on en0 ifscope [ethernet]\n"
            "? (192.168.2.20) at (incomplete) on en0 ifscope [ethernet]\n"
            "? (192.168.2.21) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
        )

        self.assertEqual(
            entries,
            [
                {"ip": "192.168.2.1", "mac": "40:3f:8c:c6:39:37", "interface": "en0"},
                {"ip": "192.168.2.21", "mac": "aa:bb:cc:dd:ee:ff", "interface": "en0"},
            ],
        )

    def test_build_local_peer_visibility_check_marks_visible_private_peers_as_notice(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.1", "en0")):
            with mock.patch(
                "network_health.run_command",
                return_value=(
                    "? (192.168.2.1) at 40:3f:8c:c6:39:37 on en0 ifscope [ethernet]\n"
                    "? (192.168.2.22) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
                    "? (10.0.0.8) at 11:22:33:44:55:66 on en1 ifscope [ethernet]\n"
                ),
            ):
                result = network_health.build_local_peer_visibility_check()

        self.assertEqual(result["status"], "notice")
        self.assertEqual(result["details"]["visible_peers"][0]["ip"], "192.168.2.22")

    def test_build_local_peer_visibility_check_marks_empty_cache_ok(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.1", "en0")):
            with mock.patch("network_health.run_command", return_value=""):
                result = network_health.build_local_peer_visibility_check()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["details"]["visible_peers"], [])

    def test_parse_scutil_dns_extracts_nameservers(self):
        resolvers = network_health.parse_scutil_dns(
            """
DNS configuration

resolver #1
  search domain[0] : local
  nameserver[0] : 192.168.2.1
  nameserver[1] : 1.1.1.1
"""
        )

        self.assertEqual(resolvers[0]["nameservers"], ["192.168.2.1", "1.1.1.1"])

    def test_parse_resolv_conf_extracts_nameservers_and_search(self):
        parsed = network_health.parse_resolv_conf(
            """
# comment
search local lan
nameserver 192.168.2.1
nameserver 1.1.1.1
"""
        )

        self.assertEqual(parsed["nameservers"], ["192.168.2.1", "1.1.1.1"])
        self.assertEqual(parsed["search_domains"], ["local", "lan"])

    def test_collect_dns_configuration_falls_back_to_resolv_conf(self):
        with mock.patch(
            "network_health.run_command",
            side_effect=subprocess.CalledProcessError(1, ["scutil", "--dns"]),
        ):
            with mock.patch(
                "builtins.open",
                mock.mock_open(read_data="nameserver 192.168.2.1\n"),
            ):
                config = network_health.collect_dns_configuration()

        self.assertEqual(config["source"], "resolv.conf")
        self.assertEqual(config["nameservers"], ["192.168.2.1"])

    def test_analyze_dns_servers_flags_public_resolvers(self):
        analysis = network_health.analyze_dns_servers(
            ["192.168.2.1", "1.1.1.1"],
            default_interface="en0",
            gateway_ip="192.168.2.254",
        )

        self.assertEqual(analysis["server_count"], 2)
        self.assertTrue(any(risk["server"] == "1.1.1.1" for risk in analysis["risks"]))
        self.assertTrue(any(item["classification"] == "public_upstream" for item in analysis["classifications"]))

    def test_analyze_dns_servers_treats_on_link_ipv6_resolver_as_local(self):
        with mock.patch(
            "network_health.get_interface_networks",
            return_value=[ipaddress.ip_network("2a02:a469:abc1:0::/64")],
        ):
            analysis = network_health.analyze_dns_servers(
                ["2a02:a469:abc1:0:4a29:52ff:fe5d:78b0"],
                resolvers=[
                    {
                        "nameservers": ["2a02:a469:abc1:0:4a29:52ff:fe5d:78b0"],
                        "if_index": "4 (en0)",
                        "reach": "0x00020002 (Reachable,Directly Reachable Address)",
                    }
                ],
                default_interface="en0",
                gateway_ip="192.168.2.254",
            )

        self.assertEqual(analysis["risks"], [])
        self.assertEqual(analysis["classifications"][0]["classification"], "on_link")

    def test_build_dns_environment_check_marks_public_dns_as_alert(self):
        with mock.patch(
            "network_health.collect_dns_configuration",
            return_value={"source": "scutil", "nameservers": ["192.168.2.1", "1.1.1.1"], "resolvers": []},
        ):
            with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.254", "en0")):
                result = network_health.build_dns_environment_check()

        self.assertEqual(result["status"], "alert")
        self.assertIn("risk signal", result["summary"])

    def test_build_dns_environment_check_keeps_on_link_dns_ok(self):
        with mock.patch(
            "network_health.collect_dns_configuration",
            return_value={
                "source": "scutil",
                "nameservers": ["2a02:a469:abc1:0:4a29:52ff:fe5d:78b0", "192.168.2.254"],
                "resolvers": [
                    {
                        "nameservers": ["2a02:a469:abc1:0:4a29:52ff:fe5d:78b0", "192.168.2.254"],
                        "if_index": "4 (en0)",
                        "reach": "0x00020002 (Reachable,Directly Reachable Address)",
                    }
                ],
            },
        ):
            with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.254", "en0")):
                with mock.patch(
                    "network_health.get_interface_networks",
                    return_value=[
                        ipaddress.ip_network("192.168.2.0/24"),
                        ipaddress.ip_network("2a02:a469:abc1:0::/64"),
                    ],
                ):
                    result = network_health.build_dns_environment_check()

        self.assertEqual(result["status"], "ok")
        self.assertIn("Detected 2 DNS server", result["summary"])

    def test_parse_ping_summary_extracts_loss_and_latency(self):
        summary = network_health.parse_ping_summary(
            """
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 4.123/6.789/9.456/1.111 ms
"""
        )

        self.assertEqual(summary["transmitted"], 3)
        self.assertEqual(summary["received"], 3)
        self.assertEqual(summary["loss_percent"], 0.0)
        self.assertEqual(summary["avg_ms"], 6.789)

    def test_summarize_wifi_stability_marks_unstable_on_bssid_changes_and_loss(self):
        summary = network_health.summarize_wifi_stability(
            [
                {
                    "wifi": {"bssid": "aa:aa:aa:aa:aa:aa", "rssi": "-60"},
                    "ping": {"avg_ms": 5.0, "loss_percent": 0.0},
                },
                {
                    "wifi": {"bssid": "bb:bb:bb:bb:bb:bb", "rssi": "-78"},
                    "ping": {"avg_ms": 45.0, "loss_percent": 20.0},
                },
                {
                    "wifi": {"bssid": "cc:cc:cc:cc:cc:cc", "rssi": "-80"},
                    "ping": {"avg_ms": 55.0, "loss_percent": 0.0},
                },
            ],
            gateway_ip="192.168.2.254",
        )

        self.assertEqual(summary["level"], "unstable")
        self.assertEqual(summary["bssid_changes"], 2)
        self.assertTrue(summary["reasons"])

    def test_run_wifi_stability_diagnostics_reports_progress(self):
        progress_calls = []

        with mock.patch("network_health.is_macos", return_value=True):
            with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.254", "en0")):
                with mock.patch(
                    "network_health.collect_macos_wifi_inventory",
                    return_value={"interfaces": [{"name": "en1"}]},
                ):
                    with mock.patch(
                        "network_health.collect_macos_current_wifi_details",
                        return_value={"available": True, "interfaces": {"en1": {"bssid": "aa:aa:aa:aa:aa:aa", "agrctlrssi": "-60"}}},
                    ):
                        with mock.patch(
                            "network_health.ping_host",
                            return_value={"avg_ms": 5.0, "loss_percent": 0.0},
                        ):
                            with mock.patch("network_health.time.sleep"):
                                result = network_health.run_wifi_stability_diagnostics(
                                    duration_seconds=6,
                                    interval_seconds=3,
                                    progress_callback=lambda current, total, gateway: progress_calls.append(
                                        (current, total, gateway)
                                    ),
                                )

        self.assertEqual(result["name"], "wifi_stability")
        self.assertEqual(progress_calls, [(1, 2, "192.168.2.254"), (2, 2, "192.168.2.254")])

    def test_get_active_wifi_interface_name_prefers_current_wifi_details(self):
        interface_name = network_health.get_active_wifi_interface_name(
            {"interfaces": [{"name": "en1", "status": "spairport_status_inactive"}]},
            {"interfaces": {"en1": {"ssid": "Hotel WiFi", "bssid": "11:22:33:44:55:66"}}},
        )

        self.assertEqual(interface_name, "en1")

    def test_build_active_path_check_alerts_on_dual_connected_macos_mismatch(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.254", "en0")):
            with mock.patch("network_health.is_macos", return_value=True):
                result = network_health.build_active_path_check(
                    {
                        "inventory": {
                            "interfaces": [
                                {"name": "en1", "status": "spairport_status_active"},
                            ]
                        },
                        "current": {
                            "available": True,
                            "interfaces": {
                                "en1": {"ssid": "Hotel WiFi", "bssid": "11:22:33:44:55:66"}
                            },
                        },
                    }
                )

        self.assertEqual(result["name"], "active_path")
        self.assertEqual(result["status"], "alert")
        self.assertIn("default route currently uses en0", result["summary"])
        self.assertEqual(result["details"]["wifi_interface"], "en1")

    def test_build_active_path_check_marks_active_wifi_route_ok_when_aligned(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.254", "en1")):
            with mock.patch("network_health.is_macos", return_value=True):
                result = network_health.build_active_path_check(
                    {
                        "inventory": {
                            "interfaces": [
                                {"name": "en1", "status": "spairport_status_active"},
                            ]
                        },
                        "current": {
                            "available": True,
                            "interfaces": {
                                "en1": {"ssid": "Hotel WiFi", "bssid": "11:22:33:44:55:66"}
                            },
                        },
                    }
                )

        self.assertEqual(result["status"], "ok")
        self.assertIn("Default route uses active Wi-Fi interface en1", result["summary"])

    def test_maybe_send_health_webhook_skips_when_no_alerts(self):
        sent = network_health_check.maybe_send_health_webhook(
            "https://example.test/webhook",
            10,
            {"interface": "en0", "cidr": "192.168.2.0/24"},
            {"alert_checks": 0, "total_checks": 4, "alerts": []},
        )

        self.assertFalse(sent)

    def test_maybe_send_health_webhook_sends_expected_payload(self):
        summary = {
            "alert_checks": 1,
            "notice_checks": 1,
            "total_checks": 4,
            "alerts": [{"name": "active_path", "status": "alert", "summary": "Default route mismatch"}],
        }

        with mock.patch("network_health_check.send_webhook_payload", return_value=True) as sender:
            sent = network_health_check.maybe_send_health_webhook(
                "https://example.test/webhook",
                12,
                {"interface": "en0", "cidr": "192.168.2.0/24"},
                summary,
            )

        self.assertTrue(sent)
        payload = sender.call_args.args[1]
        self.assertEqual(payload["source"], "network_health_check")
        self.assertEqual(payload["alert_summary"]["alert_checks"], 1)
        self.assertEqual(payload["alert_summary"]["notice_checks"], 1)
        self.assertTrue(payload["alert_summary"]["has_notices"])
        self.assertEqual(payload["alerts"]["health_alerts"], summary["alerts"])
        self.assertEqual(sender.call_args.kwargs["timeout"], 12)

    def test_parse_system_profiler_wifi_json_extracts_interfaces(self):
        parsed = network_health.parse_system_profiler_wifi_json(
            json.dumps(
                {
                    "SPAirPortDataType": [
                        {
                            "spairport_software_information": {"spairport_corewlan_version": "16.0"},
                            "spairport_airport_interfaces": [
                                {
                                    "_name": "en1",
                                    "spairport_status_information": "spairport_status_active",
                                    "spairport_wireless_country_code": "NL",
                                    "spairport_supported_channels": ["1 (2GHz)", "36 (5GHz)"],
                                },
                                {
                                    "_name": "awdl0",
                                }
                            ],
                        }
                    ]
                }
            )
        )

        self.assertEqual(parsed["software"]["spairport_corewlan_version"], "16.0")
        self.assertEqual(len(parsed["interfaces"]), 1)
        self.assertEqual(parsed["interfaces"][0]["name"], "en1")
        self.assertEqual(parsed["interfaces"][0]["country_code"], "NL")

    def test_parse_wdutil_info_extracts_interface_fields(self):
        parsed = network_health.parse_wdutil_info(
            """
Wi-Fi:

      Interfaces:
        en1:
          MAC Address: aa:bb:cc:dd:ee:ff
          SSID: Hotel WiFi
          BSSID: 11:22:33:44:55:66
"""
        )

        self.assertEqual(parsed["en1"]["ssid"], "Hotel WiFi")
        self.assertEqual(parsed["en1"]["bssid"], "11:22:33:44:55:66")

    def test_parse_airport_scan_output_extracts_visible_networks(self):
        networks = network_health.parse_airport_scan_output(
            """
                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                       Hotel WiFi 11:22:33:44:55:66 -70  6       Y  NL WPA2(PSK/AES/AES)
                       CafeGuest aa:bb:cc:dd:ee:ff -80  44      Y  NL WPA3(PSK/AES/AES)
"""
        )

        self.assertEqual(networks[0]["ssid"], "Hotel WiFi")
        self.assertEqual(networks[0]["bssid"], "11:22:33:44:55:66")
        self.assertEqual(networks[1]["channel"], "44")

    def test_collect_macos_nearby_wifi_networks_via_corewlan_extracts_unique_networks(self):
        class FakeChannel:
            def __init__(self, number):
                self._number = number

            def channelNumber(self):
                return self._number

        class FakeNetwork:
            def __init__(self, ssid, bssid, rssi, channel, security):
                self._ssid = ssid
                self._bssid = bssid
                self._rssi = rssi
                self._channel = FakeChannel(channel)
                self._security = security

            def ssid(self):
                return self._ssid

            def bssid(self):
                return self._bssid

            def rssiValue(self):
                return self._rssi

            def wlanChannel(self):
                return self._channel

            def security(self):
                return self._security

        class FakeInterface:
            def __init__(self, name, networks):
                self._name = name
                self._networks = networks

            def interfaceName(self):
                return self._name

            def scanForNetworksWithName_error_(self, *_args):
                return (self._networks, None)

        fake_corewlan = mock.Mock()
        fake_corewlan.CWWiFiClient.sharedWiFiClient.return_value.interfaces.return_value = [
            FakeInterface(
                "en1",
                [
                    FakeNetwork("Hotel WiFi", "11:22:33:44:55:66", -70, 6, "WPA2"),
                    FakeNetwork("Hotel WiFi", "11:22:33:44:55:66", -70, 6, "WPA2"),
                ],
            ),
            FakeInterface("awdl0", [FakeNetwork("Ignored", "aa:bb:cc:dd:ee:ff", -50, 44, "WPA3")]),
        ]

        with mock.patch("network_health.get_corewlan_module", return_value=(fake_corewlan, None)):
            result = network_health.collect_macos_nearby_wifi_networks_via_corewlan()

        self.assertTrue(result["available"])
        self.assertEqual(result["backend"], "corewlan")
        self.assertEqual(len(result["networks"]), 1)
        self.assertEqual(result["networks"][0]["ssid"], "Hotel WiFi")

    def test_collect_macos_nearby_wifi_networks_falls_back_when_corewlan_unavailable(self):
        with mock.patch(
            "network_health.collect_macos_nearby_wifi_networks_via_corewlan",
            return_value={
                "available": False,
                "reason": "CoreWLAN backend unavailable: No module named CoreWLAN",
                "backend": "corewlan",
                "networks": [],
            },
        ):
            with mock.patch("network_health.os.path.exists", return_value=False):
                result = network_health.collect_macos_nearby_wifi_networks()

        self.assertFalse(result["available"])
        self.assertEqual(result["backend"], "unavailable")
        self.assertIn("CoreWLAN backend unavailable", result["reason"])

    def test_collect_macos_wifi_state_combines_inventory_current_and_nearby(self):
        with mock.patch(
            "network_health.collect_macos_wifi_inventory",
            return_value={"interfaces": [{"name": "en1"}], "software": {}},
        ):
            with mock.patch(
                "network_health.collect_macos_current_wifi_details",
                return_value={"available": True, "interfaces": {"en1": {"ssid": "Hotel WiFi"}}},
            ):
                with mock.patch(
                    "network_health.collect_macos_nearby_wifi_networks",
                    return_value={"available": True, "backend": "corewlan", "networks": []},
                ):
                    state = network_health.collect_macos_wifi_state()

        self.assertEqual(state["platform"], "macos")
        self.assertEqual(state["inventory"]["interfaces"][0]["name"], "en1")
        self.assertTrue(state["current"]["available"])
        self.assertEqual(state["nearby"]["backend"], "corewlan")

    def test_classify_wifi_security_distinguishes_profiles(self):
        self.assertEqual(network_health.classify_wifi_security("WPA3(PSK/AES/AES)"), "strong")
        self.assertEqual(network_health.classify_wifi_security("WPA2(PSK/AES/AES)"), "modern")
        self.assertEqual(network_health.classify_wifi_security("WEP"), "weak_legacy")
        self.assertEqual(network_health.classify_wifi_security("NONE"), "open")
        self.assertEqual(network_health.classify_wifi_security(""), "unknown")

    def test_analyze_nearby_wifi_networks_detects_open_and_duplicate_risks(self):
        analysis = network_health.analyze_nearby_wifi_networks(
            [
                {
                    "ssid": "Hotel WiFi",
                    "bssid": "11:22:33:44:55:66",
                    "rssi": "-70",
                    "channel": "6",
                    "security": "NONE",
                },
                {
                    "ssid": "CafeGuest",
                    "bssid": "aa:bb:cc:dd:ee:ff",
                    "rssi": "-88",
                    "channel": "44",
                    "security": "WPA2(PSK/AES/AES)",
                },
                {
                    "ssid": "CafeGuest",
                    "bssid": "aa:bb:cc:dd:ee:00",
                    "rssi": "-60",
                    "channel": "149",
                    "security": "WPA3(PSK/AES/AES)",
                },
            ]
        )

        self.assertEqual(analysis["visible_network_count"], 3)
        self.assertEqual(len(analysis["duplicate_ssids"]), 1)
        self.assertFalse(analysis["limited_scan"])
        self.assertTrue(any(risk["type"] == "open_network" for risk in analysis["risks"]))
        self.assertTrue(any(risk["type"] == "very_low_signal" for risk in analysis["risks"]))
        self.assertTrue(any(risk["type"] == "mixed_security_duplicate_ssid" for risk in analysis["risks"]))

    def test_analyze_nearby_wifi_networks_does_not_flag_unknown_hidden_network_as_open(self):
        analysis = network_health.analyze_nearby_wifi_networks(
            [
                {
                    "ssid": "<hidden>",
                    "bssid": None,
                    "rssi": "-66",
                    "channel": "6",
                    "security": "",
                }
            ]
        )

        self.assertEqual(analysis["visible_network_count"], 1)
        self.assertTrue(analysis["limited_scan"])
        self.assertFalse(any(risk["type"] == "open_network" for risk in analysis["risks"]))

    def test_build_wifi_environment_analysis_adds_empty_default_analysis(self):
        wifi_environment = {
            "inventory": {"interfaces": [{"name": "en1"}]},
            "current": {"available": False, "interfaces": {}},
            "nearby": {"available": False, "networks": []},
        }

        enriched = network_health.build_wifi_environment_analysis(wifi_environment)

        self.assertEqual(enriched["analysis"]["visible_network_count"], 0)
        self.assertEqual(enriched["analysis"]["risks"], [])

    def test_summarize_wifi_environment_marks_unavailable_nearby_as_ok(self):
        status, summary = network_health.summarize_wifi_environment(
            {
                "inventory": {"interfaces": [{"name": "en1"}]},
                "current": {"available": False, "interfaces": {}},
                "nearby": {"available": False, "networks": []},
                "analysis": {
                    "visible_network_count": 0,
                    "duplicate_ssids": [],
                    "limited_scan": False,
                    "risks": [],
                },
            }
        )

        self.assertEqual(status, "ok")
        self.assertIn("nearby SSID inventory is unavailable", summary)

    def test_build_wifi_environment_check_handles_non_macos(self):
        with mock.patch("network_health.is_macos", return_value=False):
            result = network_health.build_wifi_environment_check()

        self.assertEqual(result["name"], "wifi_environment")
        self.assertEqual(result["status"], "ok")

    def test_build_wifi_environment_check_marks_unavailable_nearby_inventory_ok(self):
        with mock.patch("network_health.is_macos", return_value=True):
            with mock.patch(
                "network_health.collect_macos_wifi_inventory",
                return_value={"interfaces": [{"name": "en1"}], "software": {}},
            ):
                with mock.patch(
                    "network_health.collect_macos_current_wifi_details",
                    return_value={"available": False, "reason": "sudo required", "interfaces": {}},
                ):
                    with mock.patch(
                        "network_health.collect_macos_nearby_wifi_networks",
                        return_value={"available": False, "reason": "not present", "networks": []},
                    ):
                        result = network_health.build_wifi_environment_check()

        self.assertEqual(result["status"], "ok")
        self.assertIn("nearby SSID inventory is unavailable", result["summary"])

    def test_build_wifi_environment_check_marks_limited_scan_as_ok_with_restricted_summary(self):
        with mock.patch("network_health.is_macos", return_value=True):
            with mock.patch(
                "network_health.collect_macos_wifi_inventory",
                return_value={"interfaces": [{"name": "en1"}], "software": {}},
            ):
                with mock.patch(
                    "network_health.collect_macos_current_wifi_details",
                    return_value={"available": False, "reason": "sudo required", "interfaces": {}},
                ):
                    with mock.patch(
                        "network_health.collect_macos_nearby_wifi_networks",
                        return_value={
                            "available": True,
                            "reason": None,
                            "backend": "corewlan",
                            "networks": [
                                {
                                    "ssid": "<hidden>",
                                    "bssid": None,
                                    "rssi": "-68",
                                    "channel": "6",
                                    "security": "",
                                }
                            ],
                        },
                    ):
                        result = network_health.build_wifi_environment_check()

        self.assertEqual(result["status"], "ok")
        self.assertIn("restricted by macOS", result["summary"])

    def test_build_wifi_environment_check_marks_detected_wifi_risks_as_alert(self):
        with mock.patch("network_health.is_macos", return_value=True):
            with mock.patch(
                "network_health.collect_macos_wifi_inventory",
                return_value={"interfaces": [{"name": "en1"}], "software": {}},
            ):
                with mock.patch(
                    "network_health.collect_macos_current_wifi_details",
                    return_value={"available": False, "reason": "sudo required", "interfaces": {}},
                ):
                    with mock.patch(
                        "network_health.collect_macos_nearby_wifi_networks",
                        return_value={
                            "available": True,
                            "reason": None,
                            "networks": [
                                {
                                    "ssid": "Hotel WiFi",
                                    "bssid": "11:22:33:44:55:66",
                                    "rssi": "-70",
                                    "channel": "6",
                                    "security": "NONE",
                                }
                            ],
                        },
                    ):
                        result = network_health.build_wifi_environment_check()

        self.assertEqual(result["status"], "alert")
        self.assertIn("risk signal", result["summary"])
        self.assertTrue(result["details"]["analysis"]["risks"])

    def test_run_network_health_checks_includes_active_path_alert(self):
        with mock.patch("network_health.resolve_gateway_identity", return_value={"name": "gateway_identity", "status": "ok"}):
            with mock.patch("network_health.resolve_gateway_fingerprint", return_value={"name": "gateway_fingerprint", "status": "ok"}):
                with mock.patch("network_health.build_gateway_exposure_check", return_value={"name": "gateway_exposure", "status": "ok"}):
                    with mock.patch("network_health.build_local_peer_visibility_check", return_value={"name": "local_peer_visibility", "status": "ok"}):
                        with mock.patch("network_health.build_dns_environment_check", return_value={"name": "dns_environment", "status": "ok"}):
                            with mock.patch(
                                "network_health.build_wifi_environment_check",
                                return_value={
                                    "name": "wifi_environment",
                                    "status": "ok",
                                    "details": {
                                        "inventory": {"interfaces": [{"name": "en1", "status": "spairport_status_active"}]},
                                        "current": {"available": True, "interfaces": {"en1": {"ssid": "Hotel WiFi"}}},
                                    },
                                },
                            ):
                                with mock.patch(
                                    "network_health.build_active_path_check",
                                    return_value={"name": "active_path", "status": "alert", "summary": "mismatch"},
                                ):
                                    with mock.patch("network_health.run_dns_consistency_checks", return_value=[]):
                                        with mock.patch("network_health.run_captive_portal_checks", return_value=[]):
                                            with mock.patch("network_health.run_https_tls_checks", return_value=[]):
                                                checks = network_health.run_network_health_checks()

        self.assertTrue(any(check["name"] == "active_path" and check["status"] == "alert" for check in checks))
        self.assertTrue(any(check["name"] == "gateway_exposure" for check in checks))
        self.assertTrue(any(check["name"] == "local_peer_visibility" for check in checks))

    def test_resolve_gateway_identity_marks_private_gateway_ok(self):
        with mock.patch("network_health.get_default_gateway", return_value=("192.168.2.1", "en0")):
            with mock.patch("network_health.socket.gethostbyaddr", side_effect=OSError):
                result = network_health.resolve_gateway_identity()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["details"]["gateway_ip"], "192.168.2.1")

    def test_run_dns_consistency_checks_flags_non_public_answers(self):
        with mock.patch("network_health.resolve_domain_ips", return_value=["192.168.2.10"]):
            results = network_health.run_dns_consistency_checks(["example.com"])

        self.assertEqual(results[0]["status"], "alert")
        self.assertIn("non-public", results[0]["summary"])

    def test_run_captive_portal_checks_flags_redirects(self):
        with mock.patch(
            "network_health.fetch_url",
            return_value={
                "status_code": 302,
                "headers": {"Location": "http://login.hotel.example/"},
                "body": "",
            },
        ):
            results = network_health.run_captive_portal_checks(
                [{"name": "probe", "url": "http://probe.test", "expected_status": 204, "expected_body_contains": None}]
            )

        self.assertEqual(results[0]["status"], "alert")
        self.assertIn("Unexpected captive-portal probe response", results[0]["summary"])

    def test_run_https_tls_checks_flags_ssl_failures(self):
        with mock.patch("network_health.probe_https_endpoint", side_effect=ssl.SSLError("verify failed")):
            results = network_health.run_https_tls_checks(
                [{"name": "probe", "url": "https://example.com", "expected_statuses": [200]}]
            )

        self.assertEqual(results[0]["status"], "alert")
        self.assertIn("TLS verification failed", results[0]["summary"])

    def test_build_health_summary_counts_alerts(self):
        summary = network_health.build_health_summary(
            [
                {"name": "a", "status": "ok"},
                {"name": "n", "status": "notice"},
                {"name": "b", "status": "alert"},
            ]
        )

        self.assertEqual(summary["total_checks"], 3)
        self.assertEqual(summary["ok_checks"], 1)
        self.assertEqual(summary["notice_checks"], 1)
        self.assertEqual(summary["alert_checks"], 1)

    def test_print_alert_report_reports_empty_state(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            network_health_check.print_alert_report({"alerts": []})

        self.assertIn("No actionable health alerts detected.", buffer.getvalue())

    def test_print_alert_report_includes_notices_without_escalating(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            network_health_check.print_alert_report(
                {
                    "alerts": [],
                    "notices": [
                        {
                            "name": "gateway_exposure",
                            "status": "notice",
                            "summary": "Private/local gateway exposes 2 local web/admin service(s) to the client on 192.168.2.254",
                        }
                    ],
                }
            )

        output = buffer.getvalue()
        self.assertIn("No actionable health alerts detected.", output)
        self.assertIn("Notices present: 1", output)
        self.assertIn("Gateway exposure", output)
        self.assertIn("[~]", output)

    def test_resolve_report_output_paths_uses_defaults_and_optional_overrides(self):
        args = mock.Mock(json_out=None, md_out="health.md")

        paths = network_health_check.resolve_report_output_paths(args)

        self.assertEqual(paths["json"], network_health_check.JSON_OUTPUT_FILE)
        self.assertEqual(paths["markdown"], "health.md")

    def test_normalize_wifi_stability_seconds_rejects_non_numeric_values(self):
        self.assertEqual(network_health_check.normalize_wifi_stability_seconds("5"), 0)
        self.assertEqual(network_health_check.normalize_wifi_stability_seconds(12), 12)

    def test_render_health_report_returns_alert_exit_code_in_alerts_only_mode(self):
        args = mock.Mock(alerts_only=True, output="full")
        summary = {"alert_checks": 1, "alerts": [{"name": "dns_environment", "summary": "risk"}]}

        with mock.patch("network_health_check.print_alert_report") as print_alert_report:
            exit_code = network_health_check.render_health_report(args, [], summary)

        print_alert_report.assert_called_once_with(summary)
        self.assertEqual(exit_code, 2)

    def test_run_health_check_collection_builds_payload_from_context_and_checks(self):
        args = mock.Mock(
            iface=None,
            cidr=None,
            dns_domains=None,
            timeout=5,
            wifi_stability_seconds=0,
        )

        with mock.patch(
            "network_health_check.resolve_scan_target",
            return_value=("en0", "192.168.2.0/24"),
        ):
            with mock.patch(
                "network_health_check.run_network_health_checks",
                return_value=[{"name": "gateway_identity", "status": "ok", "summary": "ok"}],
            ):
                scan_context, checks, summary, payload = network_health_check.run_health_check_collection(args)

        self.assertEqual(scan_context["interface"], "en0")
        self.assertEqual(checks[0]["name"], "gateway_identity")
        self.assertEqual(summary["alert_checks"], 0)
        self.assertEqual(payload["scan_context"]["cidr"], "192.168.2.0/24")

    def test_print_alert_report_uses_human_labels(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            network_health_check.print_alert_report(
                {
                    "alerts": [
                        {
                            "name": "active_path",
                            "summary": "Active Wi-Fi interface en1 is present, but the default route currently uses en0",
                        },
                        {
                            "name": "https_example_https",
                            "summary": "TLS verification failed for https://example.com",
                        },
                    ]
                }
            )

        output = buffer.getvalue()
        self.assertIn("Active path", output)
        self.assertIn("HTTPS", output)
        self.assertNotIn("https_example_https", output)

    def test_format_top_alert_summary_uses_human_labels_for_active_path(self):
        summary = network_health_check.format_top_alert_summary(
            {
                "alerts": [
                    {"name": "active_path"},
                    {"name": "dns_environment"},
                    {"name": "https_example_https"},
                ]
            }
        )

        self.assertEqual(summary, "Risk summary: 3 alert(s) in Active path, DNS, HTTPS")

    def test_main_writes_json_report(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = os.path.join(tmp_dir, "health.json")
            markdown_path = os.path.join(tmp_dir, "health.md")
            with mock.patch(
                "network_health_check.parse_args",
                return_value=mock.Mock(
                    iface=None,
                    cidr=None,
                    json_out=output_path,
                    md_out=markdown_path,
                    dns_domains=None,
                    timeout=5,
                    alerts_only=False,
                    output="full",
                    debug_wifi=False,
                    wifi_stability_seconds=0,
                ),
            ):
                with mock.patch(
                    "network_health_check.resolve_scan_target",
                    return_value=("en0", "192.168.2.0/24"),
                ):
                    with mock.patch(
                        "network_health_check.run_network_health_checks",
                        return_value=[{"name": "gateway_identity", "status": "ok", "summary": "ok", "details": {}}],
                    ):
                        with self.assertRaises(SystemExit) as exit_ctx:
                            network_health_check.main()

            self.assertEqual(exit_ctx.exception.code, 0)
            with open(output_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            with open(markdown_path, "r", encoding="utf-8") as handle:
                markdown = handle.read()
            self.assertEqual(payload["scan_context"]["interface"], "en0")
            self.assertEqual(payload["health_summary"]["alert_checks"], 0)
            self.assertEqual(payload["trust_assessment"]["level"], "trusted")
            self.assertIn("# Network Health Report", markdown)
            self.assertIn("## Health Checks", markdown)
            self.assertIn("| Check | Status | Summary |", markdown)
            self.assertIn("No active alerts detected in network, DNS, Wi-Fi, or internet probes.", markdown)

    def test_build_trust_assessment_maps_alert_counts(self):
        self.assertEqual(
            network_health_check.build_trust_assessment({"alert_checks": 0})["level"],
            "trusted",
        )
        self.assertEqual(
            network_health_check.build_trust_assessment({"alert_checks": 0, "notice_checks": 1})["level"],
            "trusted",
        )
        self.assertEqual(
            network_health_check.build_trust_assessment({"alert_checks": 1})["level"],
            "suspicious",
        )
        self.assertEqual(
            network_health_check.build_trust_assessment({"alert_checks": 3})["level"],
            "untrusted",
        )

    def test_print_health_report_formats_dns_without_raw_resolver_dump(self):
        buffer = StringIO()
        checks = [
            {
                "name": "gateway_identity",
                "status": "ok",
                "summary": "Default gateway 192.168.2.254 on en0",
                "details": {"interface": "en0", "is_public_ip": False},
            },
            {
                "name": "dns_environment",
                "status": "ok",
                "summary": "Detected 2 DNS server(s) from scutil",
                "details": {
                    "source": "scutil",
                    "nameservers": ["2a02:a469:abc1:0:4a29:52ff:fe5d:78b0", "192.168.2.254"],
                    "resolvers": [{"nameservers": ["raw", "dump"]}],
                    "analysis": {
                        "classifications": [
                            {
                                "server": "2a02:a469:abc1:0:4a29:52ff:fe5d:78b0",
                                "classification": "directly_reachable",
                            },
                            {
                                "server": "192.168.2.254",
                                "classification": "gateway_dns",
                            },
                        ],
                        "risks": [],
                    },
                },
            }
        ]
        summary = {"total_checks": 2, "ok_checks": 2, "notice_checks": 0, "alert_checks": 0, "alerts": [], "notices": []}

        with redirect_stdout(buffer):
            network_health_check.print_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("Network:", output)
        self.assertIn("DNS:", output)
        self.assertIn("Trust assessment: trusted", output)
        self.assertIn("Risk summary: no active alerts", output)
        self.assertIn("resolver classes:", output)
        self.assertIn("[on-link DNS]", output)
        self.assertNotIn("{'nameservers': ['raw', 'dump']}", output)

    def test_print_health_report_renders_gateway_exposure_check(self):
        buffer = StringIO()
        checks = [
            {
                "name": "gateway_exposure",
                "status": "alert",
                "summary": "Gateway exposes 1 local web/admin service(s) to the client on 192.168.2.1",
                "details": {
                    "gateway_ip": "192.168.2.1",
                    "interface": "en0",
                    "reachable_services": [
                        {
                            "port": 443,
                            "label": "HTTPS admin/web",
                            "risk": True,
                            "http_probe": {
                                "url": "https://192.168.2.1:443/",
                                "status_code": 302,
                                "content_type": "text/html",
                                "server": "lighttpd",
                                "location": "/login",
                                "title": "Router Login",
                                "page_hint": "html document",
                            },
                        }
                    ],
                    "risky_services": [{"port": 443, "label": "HTTPS admin/web", "risk": True}],
                },
            }
        ]
        summary = {"total_checks": 1, "ok_checks": 0, "notice_checks": 1, "alert_checks": 0, "alerts": [], "notices": checks}

        with redirect_stdout(buffer):
            network_health_check.print_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("Gateway exposure", output)
        self.assertIn("443/tcp HTTPS admin/web [alert]", output)
        self.assertIn("url: https://192.168.2.1:443/", output)
        self.assertIn("content_type: text/html", output)
        self.assertIn("server: lighttpd", output)
        self.assertIn("location: /login", output)
        self.assertIn("title: Router Login", output)
        self.assertIn("page_hint: html document", output)
        self.assertIn("Notices: 1", output)

    def test_print_health_report_renders_local_peer_visibility_check(self):
        buffer = StringIO()
        checks = [
            {
                "name": "local_peer_visibility",
                "status": "notice",
                "summary": "ARP cache shows 2 local peer(s) besides the gateway on en0",
                "details": {
                    "interface": "en0",
                    "gateway_ip": "192.168.2.1",
                    "visible_peers": [
                        {"ip": "192.168.2.22", "mac": "aa:bb:cc:dd:ee:ff"},
                        {"ip": "192.168.2.23", "mac": "11:22:33:44:55:66"},
                    ],
                },
            }
        ]
        summary = {"total_checks": 1, "ok_checks": 0, "notice_checks": 1, "alert_checks": 0, "alerts": [], "notices": checks}

        with redirect_stdout(buffer):
            network_health_check.print_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("Local peer visibility", output)
        self.assertIn("192.168.2.22 (aa:bb:cc:dd:ee:ff)", output)
        self.assertIn("[~]", output)

    def test_print_health_report_formats_wifi_nearby_networks_compactly(self):
        buffer = StringIO()
        checks = [
            {
                "name": "wifi_environment",
                "status": "notice",
                "summary": "Wi-Fi environment shows 1 risk signal(s) across 1 visible network(s)",
                "details": {
                    "inventory": {
                        "interfaces": [
                            {
                                "name": "en1",
                                "status": "spairport_status_connected",
                                "country_code": "NL",
                                "supported_phy_modes": "802.11 a/b/g/n/ac",
                            }
                        ]
                    },
                    "nearby": {
                        "available": True,
                        "backend": "corewlan",
                        "networks": [
                            {
                                "ssid": "<hidden>",
                                "bssid": None,
                                "rssi": "-68",
                                "channel": "6",
                                "security": "",
                            }
                        ],
                    },
                    "analysis": {
                        "risks": [
                            {
                                "type": "open_network",
                                "ssid": "<hidden>",
                                "reason": "visible network does not advertise encryption",
                            }
                        ]
                    },
                    "current": {
                        "available": False,
                        "reason": "wdutil info requires sudo on macOS",
                    },
                },
            }
        ]
        summary = {"total_checks": 1, "ok_checks": 0, "alert_checks": 1, "alerts": checks}

        with redirect_stdout(buffer):
            network_health_check.print_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("Wi-Fi:", output)
        self.assertIn("Risk summary: 1 alert(s) in Wi-Fi", output)
        self.assertIn("nearby: 1 network(s) via corewlan", output)
        self.assertIn("ch 6", output)
        self.assertIn("open network", output)
        self.assertNotIn("'networks':", output)

    def test_print_focus_health_report_shows_assessment_and_key_checks(self):
        buffer = StringIO()
        checks = [
            {
                "name": "gateway_identity",
                "status": "ok",
                "summary": "Default gateway 192.168.2.254 on en0",
                "details": {"interface": "en0", "hostname": "router.local", "is_public_ip": False},
            },
            {
                "name": "wifi_environment",
                "status": "notice",
                "summary": "Wi-Fi environment shows 1 risk signal(s) across 1 visible network(s)",
                "details": {
                    "inventory": {"interfaces": [{"name": "en1", "status": "connected", "country_code": "NL", "supported_phy_modes": "802.11ac"}]},
                    "nearby": {"available": True, "backend": "corewlan", "networks": [{"ssid": "<hidden>", "bssid": None, "rssi": "-68", "channel": "6", "security": ""}]},
                    "analysis": {"risks": [{"type": "open_network", "ssid": "<hidden>", "reason": "visible network does not advertise encryption"}]},
                    "current": {"available": False, "reason": "wdutil info requires sudo on macOS"},
                },
            },
        ]
        summary = {"total_checks": 2, "ok_checks": 1, "notice_checks": 1, "alert_checks": 0, "alerts": [], "notices": [checks[1]]}

        with redirect_stdout(buffer):
            network_health_check.print_focus_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("=== Network Health Focus ===", output)
        self.assertIn("Trust assessment: trusted", output)
        self.assertIn("Wi-Fi environment", output)
        self.assertIn("[~]", output)
        self.assertIn("Gateway", output)
        self.assertIn("[OK]", output)

    def test_print_health_report_renders_active_path_check(self):
        buffer = StringIO()
        checks = [
            {
                "name": "active_path",
                "status": "alert",
                "summary": "Active Wi-Fi interface en1 is present, but the default route currently uses en0",
                "details": {
                    "default_interface": "en0",
                    "gateway_ip": "192.168.2.254",
                    "wifi_interface": "en1",
                    "wifi_active": True,
                },
            }
        ]
        summary = {"total_checks": 1, "ok_checks": 0, "alert_checks": 1, "alerts": checks}

        with redirect_stdout(buffer):
            network_health_check.print_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("Active path", output)
        self.assertIn("default interface: en0", output)
        self.assertIn("active wifi interface: en1", output)

    def test_build_wifi_debug_summary_detects_likely_os_restriction(self):
        checks = [
            {
                "name": "wifi_environment",
                "status": "ok",
                "summary": "Wi-Fi inventory collected",
                "details": {
                    "nearby": {
                        "available": True,
                        "backend": "corewlan",
                        "reason": None,
                        "networks": [
                            {
                                "ssid": "<hidden>",
                                "bssid": None,
                                "channel": "2",
                                "rssi": "-56",
                                "security": "",
                            }
                        ],
                    },
                    "current": {"available": True, "reason": None},
                },
            }
        ]

        debug = network_health_check.build_wifi_debug_summary(checks)

        self.assertEqual(debug["backend"], "corewlan")
        self.assertEqual(debug["network_count"], 1)
        self.assertEqual(debug["hidden_count"], 1)
        self.assertTrue(debug["likely_os_restriction"])

    def test_print_wifi_stability_progress_updates_single_line_and_finishes_with_newline(self):
        buffer = StringIO()
        with mock.patch("sys.stdout", buffer):
            network_health_check.print_wifi_stability_progress(1, 2, "192.168.2.254")
            network_health_check.print_wifi_stability_progress(2, 2, "192.168.2.254")

        output = buffer.getvalue()
        self.assertIn("\rRunning Wi-Fi stability diagnostics: sample 1/2", output)
        self.assertIn("sample 2/2", output)
        self.assertTrue(output.endswith("\n"))

    def test_print_health_report_shows_restricted_nearby_scan_without_fake_network_listing(self):
        buffer = StringIO()
        checks = [
            {
                "name": "wifi_environment",
                "status": "ok",
                "summary": "Wi-Fi inventory collected, but nearby scan looks restricted by macOS (1 incomplete object(s))",
                "details": {
                    "inventory": {
                        "interfaces": [
                            {
                                "name": "en1",
                                "status": "spairport_status_connected",
                                "country_code": "NL",
                                "supported_phy_modes": "802.11 a/b/g/n/ac",
                            }
                        ]
                    },
                    "nearby": {
                        "available": True,
                        "backend": "corewlan",
                        "networks": [
                            {
                                "ssid": "<hidden>",
                                "bssid": None,
                                "rssi": "-68",
                                "channel": "6",
                                "security": "",
                            }
                        ],
                    },
                    "analysis": {
                        "visible_network_count": 1,
                        "duplicate_ssids": [],
                        "limited_scan": True,
                        "risks": [],
                    },
                    "current": {
                        "available": True,
                        "reason": None,
                    },
                },
            }
        ]
        summary = {"total_checks": 1, "ok_checks": 1, "alert_checks": 0, "alerts": []}

        with redirect_stdout(buffer):
            network_health_check.print_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("restricted by macOS/CoreWLAN", output)
        self.assertIn("hidden/incomplete objects only", output)
        self.assertNotIn("<hidden> | ch 6", output)

    def test_print_health_report_formats_wifi_stability_section(self):
        buffer = StringIO()
        checks = [
            {
                "name": "wifi_stability",
                "status": "alert",
                "summary": "Wi-Fi link to gateway 192.168.2.254 looked unstable: BSSID changed 2 time(s), packet loss peaked at 20%",
                "details": {
                    "level": "unstable",
                    "gateway_ip": "192.168.2.254",
                    "sample_count": 3,
                    "avg_rssi": -73.0,
                    "avg_latency_ms": 35.0,
                    "max_loss_percent": 20.0,
                    "bssid_changes": 2,
                    "reasons": ["BSSID changed 2 time(s)", "packet loss peaked at 20%"],
                },
            }
        ]
        summary = {"total_checks": 1, "ok_checks": 0, "alert_checks": 1, "alerts": checks}

        with redirect_stdout(buffer):
            network_health_check.print_health_report(checks, summary)

        output = buffer.getvalue()
        self.assertIn("Wi-Fi stability", output)
        self.assertIn("avg gateway latency", output)
        self.assertIn("BSSID changes: 2", output)

    def test_print_wifi_debug_report_renders_diagnosis(self):
        buffer = StringIO()
        checks = [
            {
                "name": "wifi_environment",
                "status": "ok",
                "summary": "Wi-Fi inventory collected",
                "details": {
                    "nearby": {
                        "available": True,
                        "backend": "corewlan",
                        "reason": None,
                        "networks": [
                            {
                                "ssid": "<hidden>",
                                "bssid": None,
                                "channel": "2",
                                "rssi": "-56",
                                "security": "",
                            }
                        ],
                    },
                    "current": {"available": False, "reason": "wdutil info requires sudo on macOS"},
                },
            }
        ]

        with redirect_stdout(buffer):
            network_health_check.print_wifi_debug_report(checks)

        output = buffer.getvalue()
        self.assertIn("=== Wi-Fi Debug ===", output)
        self.assertIn("backend: corewlan", output)
        self.assertIn("hidden_ssid_objects: 1", output)
        self.assertIn("likely a macOS privacy or API restriction", output)
