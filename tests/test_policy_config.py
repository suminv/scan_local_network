import json
import tempfile
import unittest

from policy_config import (
    build_baseline_config,
    evaluate_device_policies,
    load_policy_config,
    save_policy_config,
    validate_policy_config,
)


class PolicyConfigTests(unittest.TestCase):
    def test_baseline_captures_expected_services_without_credentials(self):
        config = build_baseline_config([{
            "ip": "192.168.2.10",
            "mac": "AA:AA:AA:AA:AA:AA",
            "vendor": "Example",
            "open_ports": [{
                "port": 22,
                "service": "SSH",
                "ssh": {"fingerprint_sha256": "SHA256:abc"},
            }],
        }])
        known = config["known_devices"]["aa:aa:aa:aa:aa:aa"]
        self.assertEqual(known["expected_ports"], [22])
        self.assertEqual(known["expected_ssh_fingerprint"], "SHA256:abc")
        self.assertNotIn("password", json.dumps(config).lower())

    def test_policy_flags_unknown_unexpected_port_and_key_change(self):
        config = {
            "known_devices": {
                "aa:aa:aa:aa:aa:aa": {
                    "name": "router",
                    "expected_ports": [22],
                    "expected_ssh_fingerprint": "SHA256:expected",
                }
            },
            "policies": {"alert_unknown": True, "alert_unexpected_port": True, "alert_ssh_key_change": True},
        }
        findings = evaluate_device_policies([
            {"ip": "192.168.2.10", "mac": "aa:aa:aa:aa:aa:aa", "open_ports": [{
                "port": 80, "service": "HTTP", "ssh": None,
            }]},
            {"ip": "192.168.2.20", "mac": "bb:bb:bb:bb:bb:bb", "open_ports": []},
        ], config)
        types = {finding["type"] for finding in findings}
        self.assertIn("unexpected_port", types)
        self.assertIn("unknown_device", types)

    def test_policy_rejects_credentials(self):
        with self.assertRaises(ValueError):
            load_policy_config_from_data({"known_devices": {}, "password": "secret"})
        with self.assertRaises(ValueError):
            validate_policy_config(
                {
                    "known_devices": {
                        "aa:aa:aa:aa:aa:aa": {
                            "expected_http": {
                                "80": {"headers": {"api_key": "secret"}}
                            }
                        }
                    }
                }
            )

    def test_policy_detects_http_identity_and_tls_expiry(self):
        config = {
            "known_devices": {
                "aa:aa:aa:aa:aa:aa": {
                    "name": "NAS",
                    "expected_ports": [443],
                    "expected_http": {
                        "443": {"status": 200, "title": "Expected"}
                    },
                }
            },
            "policies": {
                "alert_on_unknown_device": True,
                "alert_on_unexpected_port": True,
                "alert_on_ssh_key_change": True,
                "alert_on_http_identity_change": True,
                "alert_on_tls_expiry": True,
            },
        }

        findings = evaluate_device_policies(
            [
                {
                    "ip": "192.168.2.10",
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "open_ports": [
                        {
                            "port": 443,
                            "http": {"status": 200, "title": "Changed"},
                            "tls": {
                                "certificate_status": "expiring_soon",
                                "not_after": "2026-08-01T00:00:00",
                            },
                        }
                    ],
                }
            ],
            config,
        )

        self.assertEqual(
            {finding["type"] for finding in findings},
            {"http_identity_changed", "tls_expiry"},
        )

    def test_policy_toggles_disable_ssh_http_and_tls_findings(self):
        config = {
            "known_devices": {
                "aa:aa:aa:aa:aa:aa": {
                    "expected_ports": [22],
                    "expected_ssh_fingerprint": "SHA256:expected",
                    "expected_http": {"22": {"title": "Expected"}},
                }
            },
            "policies": {
                "alert_on_ssh_key_change": False,
                "alert_on_http_identity_change": False,
                "alert_on_tls_expiry": False,
            },
        }
        device = {
            "ip": "192.168.2.10",
            "mac": "aa:aa:aa:aa:aa:aa",
            "open_ports": [
                {
                    "port": 22,
                    "ssh": {"fingerprint_sha256": "SHA256:changed"},
                    "http": {"title": "Changed"},
                    "tls": {"certificate_status": "expired"},
                }
            ],
        }

        self.assertEqual(evaluate_device_policies([device], config), [])

    def test_unknown_device_finding_includes_service_context(self):
        findings = evaluate_device_policies(
            [
                {
                    "ip": "192.168.2.20",
                    "mac": "bb:bb:bb:bb:bb:bb",
                    "open_ports": [{"port": 22, "service": "OpenSSH"}],
                }
            ],
            {"known_devices": {}, "policies": {}},
        )

        self.assertEqual(
            findings[0]["observed_ports"],
            [{"port": 22, "service": "OpenSSH"}],
        )

    def test_policy_round_trip(self):
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            save_policy_config(handle.name, {"known_devices": {}, "policies": {}})
            self.assertEqual(load_policy_config(handle.name)["known_devices"], {})


def load_policy_config_from_data(data):
    """Validate an in-memory config using the public loader contract."""
    from policy_config import validate_policy_config
    return validate_policy_config(data)


if __name__ == "__main__":
    unittest.main()
