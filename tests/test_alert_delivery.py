import json
import unittest
from unittest import mock

import alert_delivery


class AlertDeliveryTests(unittest.TestCase):
    def test_build_alert_payload_uses_consistent_structure(self):
        payload = alert_delivery.build_alert_payload(
            source="arp_scanner",
            scan_context={"interface": "en0", "cidr": "192.168.2.0/24"},
            alert_summary={"has_alerts": True, "new_devices": 1},
            alerts={"new_devices": [{"ip": "192.168.2.10"}]},
        )

        self.assertEqual(payload["source"], "arp_scanner")
        self.assertEqual(payload["scan_context"]["interface"], "en0")
        self.assertEqual(payload["alert_summary"]["new_devices"], 1)
        self.assertEqual(payload["alerts"]["new_devices"][0]["ip"], "192.168.2.10")
        self.assertIn("generated_at", payload)

    def test_send_webhook_payload_posts_json_body(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = None
        response.status = 202

        with mock.patch("alert_delivery.urllib.request.urlopen", return_value=response) as urlopen:
            sent = alert_delivery.send_webhook_payload(
                "https://example.test/webhook",
                {"ok": True},
                timeout=7,
                label="Test webhook alert",
            )

        self.assertTrue(sent)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.test/webhook")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data.decode("utf-8")), {"ok": True})
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 7)

    def test_send_webhook_payload_returns_false_on_error(self):
        with mock.patch(
            "alert_delivery.urllib.request.urlopen",
            side_effect=RuntimeError("connection failed"),
        ):
            sent = alert_delivery.send_webhook_payload(
                "https://example.test/webhook",
                {"ok": True},
            )

        self.assertFalse(sent)


if __name__ == "__main__":
    unittest.main()
