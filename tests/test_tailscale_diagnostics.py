import json
import unittest
from unittest import mock

import tailscale_diagnostics


class TailscaleDiagnosticsTests(unittest.TestCase):
    def test_collect_status_finds_active_exit_node(self):
        exit_node = {
            "HostName": "exit-nl",
            "ExitNode": True,
            "Active": True,
            "Online": True,
            "TailscaleIPs": ["100.64.0.2"],
        }
        runner = mock.Mock(
            return_value=mock.Mock(
                stdout=json.dumps(
                    {
                        "BackendState": "Running",
                        "Peer": {
                            "node-key": exit_node,
                            "other-key": {"ExitNode": False, "Active": True},
                        },
                    }
                ),
                stderr="",
            )
        )

        status = tailscale_diagnostics.collect_tailscale_status(
            tailscale_path="/usr/bin/tailscale",
            runner=runner,
        )

        self.assertTrue(status["available"])
        self.assertEqual(status["exit_node"], exit_node)
        self.assertEqual(status["backend_state"], "Running")

    def test_parse_ping_output_recognizes_all_path_types(self):
        samples = tailscale_diagnostics.parse_tailscale_ping_output(
            "\n".join(
                [
                    "pong from node (100.64.0.2) via DERP(ams) in 65ms",
                    "pong from node (100.64.0.2) via peer-relay(198.51.100.1:40000:vni:1) in 35ms",
                    "pong from node (100.64.0.2) via 203.0.113.5:41641 in 21ms",
                ]
            )
        )

        self.assertEqual(
            [sample["path"] for sample in samples],
            ["derp", "peer_relay", "direct"],
        )
        self.assertEqual(samples[0]["relay"], "ams")
        self.assertEqual(samples[2]["latency_ms"], 21)

    def test_ping_accepts_derp_samples_when_cli_returns_one(self):
        runner = mock.Mock(
            return_value=mock.Mock(
                returncode=1,
                stdout=(
                    "pong from exit (100.64.0.2) via DERP(ams) in 65ms\n"
                    "pong from exit (100.64.0.2) via DERP(ams) in 55ms\n"
                ),
                stderr="direct connection not established\n",
            )
        )

        result = tailscale_diagnostics.collect_tailscale_exit_node_ping(
            {"TailscaleIPs": ["100.64.0.2"]},
            tailscale_path="/usr/bin/tailscale",
            count=2,
            runner=runner,
        )

        self.assertEqual(len(result["samples"]), 2)
        self.assertTrue(result["direct_connection_not_established"])

    def test_analyze_derp_path_returns_notice_and_latency_summary(self):
        status = {
            "available": True,
            "backend_state": "Running",
            "exit_node": {
                "HostName": "exit-nl",
                "Online": True,
                "TailscaleIPs": ["100.64.0.2"],
            },
        }
        ping = {
            "requested_samples": 3,
            "direct_connection_not_established": True,
            "samples": [
                {"path": "derp", "relay": "ams", "latency_ms": 45},
                {"path": "derp", "relay": "ams", "latency_ms": 60},
                {"path": "derp", "relay": "ams", "latency_ms": 75},
            ],
        }

        check = tailscale_diagnostics.analyze_tailscale_exit_node(status, ping)

        self.assertEqual(check["status"], "notice")
        self.assertEqual(check["details"]["path"], "derp")
        self.assertEqual(check["details"]["latency_avg_ms"], 60)
        self.assertEqual(check["details"]["relays"], ["ams"])
        self.assertIn("DERP(ams)", check["summary"])

    def test_analyze_direct_path_returns_ok(self):
        status = {
            "available": True,
            "backend_state": "Running",
            "exit_node": {
                "HostName": "exit-home",
                "TailscaleIPs": ["100.64.0.3"],
            },
        }
        ping = {
            "requested_samples": 2,
            "samples": [
                {"path": "derp", "relay": "fra", "latency_ms": 50},
                {"path": "direct", "endpoint": "203.0.113.5:41641", "latency_ms": 20},
            ],
        }

        check = tailscale_diagnostics.analyze_tailscale_exit_node(status, ping)

        self.assertEqual(check["status"], "ok")
        self.assertEqual(check["details"]["path"], "direct")

    def test_no_active_exit_node_is_ok(self):
        check = tailscale_diagnostics.analyze_tailscale_exit_node(
            {
                "available": True,
                "backend_state": "Running",
                "exit_node": None,
            }
        )

        self.assertEqual(check["status"], "ok")
        self.assertFalse(check["details"]["exit_node_active"])

    def test_stopped_backend_is_notice(self):
        check = tailscale_diagnostics.analyze_tailscale_exit_node(
            {
                "available": True,
                "backend_state": "Stopped",
                "exit_node": None,
            }
        )

        self.assertEqual(check["status"], "notice")
        self.assertEqual(
            check["summary"],
            "Tailscale is not running (backend state: Stopped)",
        )
        self.assertFalse(check["details"]["exit_node_active"])


if __name__ == "__main__":
    unittest.main()
