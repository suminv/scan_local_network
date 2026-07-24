import unittest
import subprocess
from unittest import mock

import internet_speed


class FakeResponse:
    def __init__(self, body=b"", headers=None):
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, _size=-1):
        body, self.body = self.body, b""
        return body


class InternetSpeedTests(unittest.TestCase):
    def test_measure_download_reports_decimal_mbps(self):
        opener = mock.Mock(
            return_value=FakeResponse(
                b"x" * 1_000_000,
                {"CF-Ray": "abc-FRA"},
            )
        )
        with mock.patch("internet_speed.time.perf_counter", side_effect=[10, 12]):
            result = internet_speed.measure_download(
                byte_count=1_000_000,
                opener=opener,
            )

        self.assertEqual(result["bytes"], 1_000_000)
        self.assertEqual(result["mbps"], 4)
        request = opener.call_args.args[0]
        self.assertIn("bytes=1000000", request.full_url)

    def test_measure_upload_posts_requested_payload(self):
        opener = mock.Mock(return_value=FakeResponse())
        with mock.patch("internet_speed.time.perf_counter", side_effect=[10, 11]):
            result = internet_speed.measure_upload(
                byte_count=250_000,
                opener=opener,
            )

        request = opener.call_args.args[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(len(request.data), 250_000)
        self.assertEqual(result["mbps"], 2)

    def test_measure_download_retries_smaller_payload_after_timeout(self):
        recovered = {
            "bytes": 2_500_000,
            "duration_seconds": 2,
            "mbps": 10,
            "headers": {},
        }
        with mock.patch(
            "internet_speed.measure_download",
            side_effect=[TimeoutError("read timed out"), recovered],
        ) as measure:
            result = internet_speed.measure_download_with_fallback(
                byte_count=10_000_000,
            )

        self.assertEqual(
            [call.kwargs["byte_count"] for call in measure.call_args_list],
            [10_000_000, 2_500_000],
        )
        self.assertTrue(result["fallback_used"])
        self.assertEqual(result["requested_bytes"], 10_000_000)
        self.assertEqual(result["bytes"], 2_500_000)
        self.assertIn("error", result["attempts"][0])

    def test_measure_download_does_not_retry_non_timeout_error(self):
        with mock.patch(
            "internet_speed.measure_download",
            side_effect=OSError("certificate failure"),
        ) as measure:
            with self.assertRaisesRegex(OSError, "certificate failure"):
                internet_speed.measure_download_with_fallback()

        measure.assert_called_once()

    def test_measure_download_with_curl_parses_metrics(self):
        completed = mock.Mock(
            stdout="200 625000 0.500000",
            stderr="",
        )
        with mock.patch(
            "internet_speed.subprocess.run",
            return_value=completed,
        ) as run:
            result = internet_speed.measure_download_with_curl(
                byte_count=625_000,
                timeout=8,
                curl_path="/usr/bin/curl",
            )

        self.assertEqual(result["bytes"], 625_000)
        self.assertEqual(result["mbps"], 10)
        self.assertEqual(result["backend"], "curl")
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/curl")
        self.assertIn("bytes=625000", command[-1])
        self.assertEqual(run.call_args.kwargs["timeout"], 13)

    def test_curl_download_retries_smaller_payload_after_timeout(self):
        recovered = {
            "bytes": 2_500_000,
            "duration_seconds": 4,
            "mbps": 5,
            "headers": {},
            "backend": "curl",
        }
        timeout = subprocess.CalledProcessError(
            28,
            ["curl"],
            stderr="curl: (28) Operation timed out",
        )
        with mock.patch(
            "internet_speed.measure_download_with_curl",
            side_effect=[timeout, recovered],
        ) as measure:
            result = internet_speed.measure_download_with_curl_fallback(
                byte_count=10_000_000,
            )

        self.assertEqual(
            [call.kwargs["byte_count"] for call in measure.call_args_list],
            [10_000_000, 2_500_000],
        )
        self.assertTrue(result["fallback_used"])
        self.assertEqual(result["backend"], "curl")

    def test_measure_download_compatible_uses_urllib_without_curl(self):
        fallback = {
            "bytes": 625_000,
            "duration_seconds": 0.5,
            "mbps": 10,
            "headers": {},
        }
        with mock.patch("internet_speed.shutil.which", return_value=None):
            with mock.patch(
                "internet_speed.measure_download_with_fallback",
                return_value=fallback,
            ) as measure:
                result = internet_speed.measure_download_compatible(
                    byte_count=625_000,
                )

        measure.assert_called_once()
        self.assertEqual(result["backend"], "urllib")

    def test_collect_internet_speed_keeps_partial_results(self):
        latency = {
            "latency_ms": 12.5,
            "jitter_ms": 1.2,
            "headers": {"CF-Ray": "abc-FRA"},
        }
        with mock.patch("internet_speed.measure_latency", return_value=latency):
            with mock.patch(
                "internet_speed.measure_download_compatible",
                side_effect=OSError("download failed"),
            ):
                with mock.patch(
                    "internet_speed.measure_upload",
                    return_value={"mbps": 8.0, "bytes": 1_000_000, "headers": {}},
                ):
                    result = internet_speed.collect_internet_speed()

        self.assertEqual(result["server_location"], "FRA")
        self.assertIn("latency", result["observations"])
        self.assertIn("upload", result["observations"])
        self.assertEqual(result["errors"]["download"], "download failed")

    def test_analyze_internet_speed_builds_complete_check(self):
        check = internet_speed.analyze_internet_speed(
            {
                "provider": "Cloudflare",
                "server_location": "FRA",
                "errors": {},
                "observations": {
                    "latency": {"latency_ms": 14.25, "jitter_ms": 1.0},
                    "download": {"mbps": 123.45, "bytes": 10_000_000},
                    "upload": {"mbps": 45.67, "bytes": 2_000_000},
                },
            }
        )

        self.assertEqual(check["name"], "internet_speed")
        self.assertEqual(check["status"], "ok")
        self.assertIn("123.5 Mbps down", check["summary"])
        self.assertEqual(check["details"]["server_location"], "FRA")

    def test_analyze_internet_speed_marks_unavailable_as_notice(self):
        check = internet_speed.analyze_internet_speed(
            {
                "provider": "Cloudflare",
                "errors": {"latency": "timeout"},
                "observations": {},
            }
        )

        self.assertEqual(check["status"], "notice")
        self.assertEqual(check["details"]["completed_measurements"], [])

    def test_analyze_internet_speed_marks_fallback_result_as_notice(self):
        check = internet_speed.analyze_internet_speed(
            {
                "provider": "Cloudflare",
                "errors": {},
                "observations": {
                    "latency": {"latency_ms": 25.0, "jitter_ms": 2.0},
                    "download": {
                        "mbps": 12.0,
                        "bytes": 2_500_000,
                        "requested_bytes": 10_000_000,
                        "fallback_used": True,
                    },
                    "upload": {"mbps": 5.0, "bytes": 2_000_000},
                },
            }
        )

        self.assertEqual(check["status"], "notice")
        self.assertTrue(check["details"]["download_fallback_used"])
        self.assertIn("reduced payload", check["summary"])


if __name__ == "__main__":
    unittest.main()
