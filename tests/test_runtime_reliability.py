from concurrent.futures import Future
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import alert_delivery
import hostname_lookup
import network_health
import port_scan
import reporting


class RuntimeReliabilityTests(unittest.TestCase):
    def test_failed_report_write_preserves_previous_report_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'report.json'
            path.write_text('{"previous": true}')
            with self.assertRaises(TypeError):
                reporting.save_json_report(path, {'invalid': object()})
            self.assertEqual(json.loads(path.read_text()), {'previous': True})
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_webhook_never_logs_secret_url_even_in_exception(self):
        url = 'https://user:password@example.test/secret-token?key=private'
        for fail in [False, True]:
            response = mock.MagicMock()
            response.__enter__.return_value.status = 200
            output = StringIO()
            with mock.patch('alert_delivery.urllib.request.urlopen', return_value=response,
                            side_effect=OSError(url) if fail else None), \
                 redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(alert_delivery.send_webhook_payload(url, {}), not fail)
            self.assertIn('example.test', output.getvalue())
            for secret in ['password', 'secret-token', 'private']:
                self.assertNotIn(secret, output.getvalue())

    def test_probe_queue_does_not_submit_entire_port_range(self):
        class Executor:
            count = 0
            def submit(self, function, item):
                self.count += 1
                future = Future()
                future.set_result(function(item))
                return future
        executor = Executor()
        results = port_scan.bounded_results(executor, lambda item: item, range(65535), limit=20)
        next(results)
        self.assertEqual(executor.count, 20)
        results.close()

    def test_dns_timeout_terminates_real_child_process(self):
        # Exercise actual subprocess timeout/cleanup without sending DNS traffic.
        with mock.patch.object(hostname_lookup, '_LOOKUP_CODE', 'import time; time.sleep(10)'):
            with self.assertRaises(OSError):
                hostname_lookup.system_dns_lookup('example.test', 'forward', timeout=0.05)

    def test_dns_worker_decodes_system_resolver_result(self):
        response = subprocess.CompletedProcess([], 0, stdout='["192.0.2.1"]')
        with mock.patch('hostname_lookup.subprocess.run', return_value=response) as run:
            self.assertEqual(hostname_lookup.system_dns_lookup('example.test', 'forward'), ['192.0.2.1'])
        self.assertEqual(run.call_args.kwargs['timeout'], 3)
        self.assertEqual(run.call_args.args[0][-2:], ['forward', 'example.test'])

    def test_command_timeout_and_wifi_unavailable_status(self):
        with mock.patch('network_health.subprocess.run', side_effect=subprocess.TimeoutExpired('test', 10)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                network_health.run_command(['test'])
        self.assertEqual(run.call_args.kwargs['timeout'], 10)
        with mock.patch('network_health.collect_wifi_environment', side_effect=subprocess.TimeoutExpired('test', 10)):
            check = network_health.build_wifi_environment_check()
        self.assertEqual(check['status'], 'notice')
        self.assertFalse(check['details']['available'])
