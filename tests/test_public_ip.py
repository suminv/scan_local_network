import json
import unittest
from unittest import mock

import public_ip


class FakeResponse:
    def __init__(self, payload):
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, _size=-1):
        return self.body


class PublicIpTests(unittest.TestCase):
    def test_collect_public_ip_requests_json_over_https(self):
        opener = mock.Mock(
            return_value=FakeResponse({"success": True, "ip": "8.8.8.8"})
        )

        result = public_ip.collect_public_ip(opener=opener, timeout=4)

        self.assertEqual(result["ip"], "8.8.8.8")
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, "https://ipwho.is/")
        self.assertEqual(request.headers["Accept"], "application/json")
        self.assertEqual(opener.call_args.kwargs["timeout"], 4)

    def test_analyze_public_ip_normalizes_location_and_connection(self):
        check = public_ip.analyze_public_ip(
            {
                "success": True,
                "ip": "8.8.8.8",
                "type": "IPv4",
                "continent": "North America",
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "city": "Mountain View",
                "timezone": {"id": "America/Los_Angeles"},
                "connection": {"asn": 15169, "isp": "Google LLC"},
            }
        )

        self.assertEqual(check["name"], "public_ip")
        self.assertEqual(check["status"], "ok")
        self.assertEqual(check["details"]["ip_version"], 4)
        self.assertEqual(check["details"]["asn"], "AS15169")
        self.assertIn("Mountain View, California, United States", check["summary"])

    def test_analyze_public_ip_marks_non_public_address_as_notice(self):
        check = public_ip.analyze_public_ip(
            {"success": True, "ip": "192.168.1.10"}
        )

        self.assertEqual(check["status"], "notice")
        self.assertFalse(check["details"]["is_global"])

    def test_build_public_ip_check_keeps_lookup_failure_non_fatal(self):
        with mock.patch(
            "public_ip.collect_public_ip",
            side_effect=OSError("service unavailable"),
        ):
            check = public_ip.build_public_ip_check()

        self.assertEqual(check["status"], "notice")
        self.assertEqual(check["details"]["error"], "service unavailable")


if __name__ == "__main__":
    unittest.main()
