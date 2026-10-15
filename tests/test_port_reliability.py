from contextlib import ExitStack, redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import arp_scanner
import port_scan
from scapy.layers.inet import IP, TCP


class PortReliabilityTests(unittest.TestCase):
    def test_probe_distinguishes_open_closed_filtered_and_error(self):
        cases = [(IP()/TCP(flags='SA'), 'open'), (IP()/TCP(flags='RA'), 'closed'),
                 (None, 'filtered')]
        for response, expected in cases:
            with self.subTest(state=expected), \
                 mock.patch('port_scan.sr1', return_value=response) as probe, \
                 mock.patch('port_scan.send') as send:
                self.assertEqual(port_scan.scan_single_port('192.0.2.1', 443)['state'], expected)
                self.assertEqual(probe.call_count, 1)
                self.assertEqual(send.call_count, int(expected == 'open'))
        with mock.patch('port_scan.sr1', side_effect=OSError('interface unavailable')):
            result = port_scan.scan_single_port('192.0.2.1', 443)
        self.assertEqual(result['state'], 'error')
        self.assertIn('interface unavailable', result['error'])

    def test_only_confirmed_refusal_is_reported_as_closed(self):
        old = [{'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.0.2.1', 'port': port}
               for port in [22, 443]]
        diff = arp_scanner.build_port_scan_diff(old, [], observed_macs=[old[0]['mac']],
                    confirmed_closed_ports={(old[0]['mac'], 22)})
        self.assertEqual(diff['closed_ports'], [old[0]])

    def test_partial_main_preserves_baseline_and_does_not_write_policy_baseline(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            db = str(Path(directory)/'history.db')
            baseline = str(Path(directory)/'baseline.json')
            stack.enter_context(mock.patch.object(arp_scanner, 'DB_FILE', db))
            conn = arp_scanner.init_db()
            previous_id = arp_scanner.create_scan_run(conn, 'en0', '192.0.2.0/24',
                            scan_type=arp_scanner.SCAN_TYPE_PORT, ports=[443], resolve_hostnames=False)
            old = {'mac':'aa:bb:cc:dd:ee:ff', 'ip':'192.0.2.1', 'vendor':'Test',
                   'open_ports':[{'port':443, 'service':'HTTPS'}]}
            arp_scanner.save_scan_run_ports(conn, previous_id, [old])
            arp_scanner.finalize_scan_run(conn, previous_id, status='success')
            conn.close()
            args = port_scan.build_parser().parse_args(['--network-profile', 'home', '--ports', '443',
                    '--db-file', db, '--json-out', str(Path(directory)/'report.json'),
                    '--write-baseline', baseline])
            result = {**old, 'open_ports':[], 'port_observations':[{'port':443, 'state':'error'}]}
            for name, value in [('os.geteuid', 0), ('parse_args', args), ('update_vendor_database', None),
                                ('discover_devices_to_scan', ([old], {'interface':'en0','cidr':'192.0.2.0/24'})),
                                ('run_port_scan', [result])]:
                stack.enter_context(mock.patch('port_scan.'+name, return_value=value))
            stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
                port_scan.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertIn('incomplete', stderr.getvalue())
            self.assertFalse(Path(baseline).exists())
            conn = arp_scanner.init_db()
            self.addCleanup(conn.close)
            latest, status = conn.execute('SELECT id, status FROM scan_runs ORDER BY id DESC LIMIT 1').fetchone()
            self.assertEqual(status, 'partial')
            self.assertEqual(arp_scanner.find_previous_compatible_port_scan_id(conn, latest), previous_id)
            next_id = arp_scanner.create_scan_run(conn, 'en0', '192.0.2.0/24',
                            scan_type=arp_scanner.SCAN_TYPE_PORT, ports=[443], resolve_hostnames=False)
            self.assertEqual(arp_scanner.find_previous_compatible_port_scan_id(conn, next_id), previous_id)
            import json
            report = json.loads((Path(directory)/'report.json').read_text())
            self.assertEqual(report['port_diff_summary']['closed_ports'], [])
            self.assertEqual(report['devices'][0]['port_observations'][0]['state'], 'error')
