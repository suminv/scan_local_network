import unittest
from unittest import mock

import hostname_lookup


class HostnameLookupTests(unittest.TestCase):
    def test_resolve_hostname_returns_none_on_lookup_error(self):
        with mock.patch("hostname_lookup.socket.gethostbyaddr", side_effect=OSError):
            self.assertIsNone(hostname_lookup.resolve_hostname("192.168.2.10"))

    def test_enrich_devices_with_hostnames_sets_hostname_when_found(self):
        devices = [{"ip": "192.168.2.10", "mac": "aa:aa:aa:aa:aa:aa"}]
        with mock.patch(
            "hostname_lookup.resolve_hostname",
            return_value="nas.local",
        ):
            result = hostname_lookup.enrich_devices_with_hostnames(devices)

        self.assertEqual(result[0]["hostname"], "nas.local")


if __name__ == "__main__":
    unittest.main()
