import socket
import ssl
from datetime import datetime, timedelta, timezone

BANNER_TIMEOUT_SECONDS = 2
CERT_EXPIRY_WARNING_DAYS = 30


def extract_certificate_common_name(cert):
    """Extract the certificate common name from a peer certificate dict."""
    if not cert:
        return None
    for name_group in cert.get("subject", []):
        for key, value in name_group:
            if key == "commonName":
                return value
    return None


def extract_certificate_organization(cert):
    """Extract the certificate organization from issuer metadata."""
    if not cert:
        return None
    for name_group in cert.get("issuer", []):
        for key, value in name_group:
            if key == "organizationName":
                return value
    return None


def get_current_utc():
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def parse_certificate_time(value):
    """Parse OpenSSL-style certificate timestamps."""
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(
        tzinfo=timezone.utc
    )


def build_certificate_validity_status(not_after):
    """Classify certificate validity based on the expiry timestamp."""
    expiry = parse_certificate_time(not_after)
    if expiry is None:
        return None
    now = get_current_utc()
    if expiry <= now:
        return "expired"
    if expiry <= now + timedelta(days=CERT_EXPIRY_WARNING_DAYS):
        return "expiring_soon"
    return "valid"


def build_service_result(service, tls=None):
    """Build a normalized in-memory service observation."""
    result = {"service": service}
    if tls is not None:
        result["tls"] = tls
    return result


def get_tls_service_details(ip, port):
    """Probe a TLS service and return basic handshake metadata when available."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=BANNER_TIMEOUT_SECONDS) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=ip) as tls_socket:
                details = []
                version = tls_socket.version()
                if version:
                    details.append(version)
                tls_details = {}
                if version:
                    tls_details["protocol"] = version
                peer_cert = tls_socket.getpeercert()
                cert_common_name = extract_certificate_common_name(peer_cert)
                if cert_common_name:
                    details.append(f"CN={cert_common_name}")
                    tls_details["common_name"] = cert_common_name
                issuer_org = extract_certificate_organization(peer_cert)
                if issuer_org:
                    tls_details["issuer"] = issuer_org
                valid_from = peer_cert.get("notBefore")
                if valid_from:
                    tls_details["not_before"] = valid_from
                valid_until = peer_cert.get("notAfter")
                if valid_until:
                    tls_details["not_after"] = valid_until
                    validity_status = build_certificate_validity_status(valid_until)
                    if validity_status:
                        tls_details["certificate_status"] = validity_status
                cipher = tls_socket.cipher()
                if cipher and cipher[0]:
                    details.append(cipher[0])
                    tls_details["cipher"] = cipher[0]
                if details:
                    return build_service_result(
                        f"TLS ({', '.join(details)})",
                        tls=tls_details or None,
                    )
                return build_service_result("TLS", tls=tls_details or None)
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", None) or exc.__class__.__name__
        return build_service_result(
            f"TLS handshake failed ({reason})",
            tls={"handshake_error": str(reason)},
        )
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return build_service_result("Error grabbing banner")


def get_plaintext_service_banner(ip, port):
    """Grab a plaintext service banner or HTTP response when possible."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT_SECONDS)
            s.connect((ip, port))

            if port in [80, 8080, 443]:
                s.sendall(b"GET / HTTP/1.0\nHost: %b\n\n" % ip.encode())

            banner = s.recv(1024)
            banner_str = banner.decode("utf-8", errors="ignore").strip()

            if not banner_str:
                return "Unknown"

            if "SSH" in banner_str:
                return f"SSH ({banner_str.splitlines()[0]})"
            if "FTP" in banner_str.splitlines()[0]:
                return f"FTP ({banner_str.splitlines()[0]})"
            if "HTTP" in banner_str:
                server_line = next(
                    (
                        line
                        for line in banner_str.splitlines()
                        if line.lower().startswith("server:")
                    ),
                    None,
                )
                if server_line:
                    return f"HTTP ({server_line.strip()})"
                return "HTTP"

            return banner_str.splitlines()[0]

    except (socket.timeout, ConnectionRefusedError):
        return "Unknown"
    except Exception:
        return "Error grabbing banner"


def get_service_details(ip, port):
    """Identify a service on an open port using protocol-aware probes."""
    if port == 443:
        tls_result = get_tls_service_details(ip, port)
        if tls_result and not tls_result["service"].startswith("TLS handshake failed"):
            return tls_result

        plaintext_result = get_plaintext_service_banner(ip, port)
        if plaintext_result not in ["Unknown", "Error grabbing banner"]:
            return build_service_result(plaintext_result)
        if tls_result is not None:
            return tls_result
        return build_service_result(plaintext_result)

    return build_service_result(get_plaintext_service_banner(ip, port))


def get_service_banner(ip, port):
    """Backward-compatible wrapper that returns only the service label string."""
    return get_service_details(ip, port)["service"]
