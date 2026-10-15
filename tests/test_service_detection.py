import base64
from datetime import datetime, timezone
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import service_detection as services


def make_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.local')])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example CA')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime(2026, 4, 25, tzinfo=timezone.utc))
            .not_valid_after(datetime(2027, 4, 25, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256()))
    return key, cert


class ServiceDetectionTests(unittest.TestCase):
    def test_real_unverified_tls_handshake_preserves_certificate_metadata(self):
        key, cert = make_certificate()
        with tempfile.TemporaryDirectory() as directory:
            cert_path, key_path = Path(directory)/'cert.pem', Path(directory)/'key.pem'
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
            client = client_context.wrap_bio(ci, co, server_hostname='example.local')
            server = server_context.wrap_bio(si, so, server_side=True)
            done = set()
            for _ in range(20):
                for name, endpoint in [('client', client), ('server', server)]:
                    try:
                        endpoint.do_handshake()
                        done.add(name)
                    except ssl.SSLWantReadError:
                        pass
                if co.pending:
                    si.write(co.read())
                if so.pending:
                    ci.write(so.read())
                if len(done) == 2:
                    break
            self.assertEqual(len(done), 2)
            self.assertEqual(client.getpeercert(), {})
            raw = mock.MagicMock()
            context = mock.Mock()
            wrapped = mock.MagicMock()
            wrapped.__enter__.return_value = client
            context.wrap_socket.return_value = wrapped
            with mock.patch.object(services.socket, 'create_connection', return_value=raw), \
                 mock.patch.object(services.ssl, 'create_default_context', return_value=context), \
                 mock.patch.object(services, 'get_current_utc', return_value=datetime(2028, 1, 1, tzinfo=timezone.utc)):
                result = services.get_tls_service_details('127.0.0.1', 443)
            self.assertEqual(result['tls']['common_name'], 'example.local')
            self.assertEqual(result['tls']['issuer'], 'Example CA')
            self.assertEqual(result['tls']['certificate_status'], 'expired')

    def test_ssh_port_and_order_independence(self):
        lines = [f'[host]:2222 {kind} {base64.b64encode(key).decode()}'
                 for kind, key in [('ssh-rsa', b'rsa-key'), ('ssh-ed25519', b'ed-key')]]
        with mock.patch.object(services.subprocess, 'run') as run:
            run.return_value.stdout = '\n'.join(lines)
            first = services.get_ssh_host_key_details('192.0.2.1', 2222)
            self.assertEqual(run.call_args.args[0][1:3], ['-p', '2222'])
            run.return_value.stdout = '\n'.join(reversed(lines))
            second = services.get_ssh_host_key_details('192.0.2.1', 2222)
        self.assertEqual(first, second)
        self.assertEqual(first['key_type'], 'ssh-ed25519')
        self.assertEqual(len(first['host_keys']), 2)

    def test_ssh_detection_forwards_nonstandard_port(self):
        with mock.patch.object(services, 'get_plaintext_service_banner', return_value='SSH (test)'), \
             mock.patch.object(services, 'get_ssh_host_key_details', return_value=None) as lookup:
            services.get_service_details('192.0.2.1', 2222)
        lookup.assert_called_once_with('192.0.2.1', 2222)

    def test_key_comparison_handles_legacy_data_and_missing_algorithms(self):
        old = {'key_type': 'ssh-rsa', 'fingerprint_sha256': 'old'}
        self.assertFalse(services.ssh_identity_changed(old, {'host_keys': {'ssh-rsa': 'old', 'ssh-ed25519': 'other'}}))
        self.assertFalse(services.ssh_identity_changed(old, {'host_keys': {'ssh-ed25519': 'other'}}))
        self.assertFalse(services.ssh_identity_changed(old, None))
        self.assertTrue(services.ssh_identity_changed(old, {'host_keys': {'ssh-rsa': 'new'}}))

    def test_policy_baseline_compares_keys_per_port_and_algorithm(self):
        from policy_config import build_baseline_config, evaluate_device_policies, validate_policy_config
        device = {'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.0.2.1', 'open_ports': [
            {'port': 22, 'ssh': {'key_type': 'ssh-ed25519', 'fingerprint_sha256': 'one',
                                'host_keys': {'ssh-ed25519': 'one', 'ssh-rsa': 'rsa'}}},
            {'port': 2222, 'ssh': {'key_type': 'ssh-ed25519', 'fingerprint_sha256': 'two',
                                  'host_keys': {'ssh-ed25519': 'two'}}}]}
        config = build_baseline_config([device])
        validate_policy_config(config)
        self.assertEqual(evaluate_device_policies([device], config), [])
        device['open_ports'][0]['ssh'] = {'key_type': 'ssh-rsa', 'fingerprint_sha256': 'rsa',
                                         'host_keys': {'ssh-rsa': 'rsa'}}
        self.assertEqual(evaluate_device_policies([device], config), [])
        device['open_ports'][1]['ssh']['host_keys']['ssh-ed25519'] = 'changed'
        findings = evaluate_device_policies([device], config)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'ssh_key_changed')
        self.assertEqual(findings[0]['port'], 2222)
