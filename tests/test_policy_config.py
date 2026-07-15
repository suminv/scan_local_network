import json
import tempfile
import unittest

from policy_config import (
    build_baseline_config,
    evaluate_device_policies,
    load_policy_config,
    save_policy_config,
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
