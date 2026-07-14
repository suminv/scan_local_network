import base64
import hashlib
import http.client
import re
import socket
import ssl
import subprocess
from datetime import datetime, timedelta, timezone

BANNER_TIMEOUT_SECONDS = 2
CERT_EXPIRY_WARNING_DAYS = 30
HTTP_BODY_LIMIT_BYTES = 64 * 1024
WEB_PORTS = {80, 3000, 5000, 8000, 8080, 8443}


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


def build_service_result(service, tls=None, http=None, ssh=None):
    """Build a normalized in-memory service observation."""
    result = {"service": service}
    if tls is not None:
        result["tls"] = tls
    if http is not None:
        result["http"] = http
    if ssh is not None:
        result["ssh"] = ssh
    return result


def extract_html_title(body):
    """Extract a compact HTML title from a bounded response body."""
    match = re.search(r"<title[^>]*>\s*(.*?)\s*</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160] or None


def get_http_service_details(ip, port, *, use_tls=False):
    """Perform one bounded unauthenticated request without following redirects."""
    connection_type = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    kwargs = {"timeout": BANNER_TIMEOUT_SECONDS}
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs["context"] = context
    connection = connection_type(ip, port, **kwargs)
    try:
        connection.request(
            "GET",
            "/",
            headers={"Host": ip, "User-Agent": "scan-local-network/1.0", "Connection": "close"},
        )
        response = connection.getresponse()
        body = response.read(HTTP_BODY_LIMIT_BYTES).decode("utf-8", errors="ignore")
        details = {"status": response.status, "reason": response.reason or ""}
        for header, key in (("Server", "server"), ("Content-Type", "content_type"), ("Location", "location")):
            value = response.getheader(header)
            if value:
                details[key] = value
        title = extract_html_title(body)
        if title:
            details["title"] = title
        label = "HTTPS" if use_tls else "HTTP"
        return build_service_result(f"{label} ({response.status} {response.reason})", http=details)
    except (OSError, socket.timeout, http.client.HTTPException, ssl.SSLError):
        return None
    finally:
        connection.close()


def get_ssh_host_key_details(ip):
    """Read SSH host keys with OpenSSH ssh-keyscan; no authentication is attempted."""
    try:
        completed = subprocess.run(
            ["ssh-keyscan", "-T", str(BANNER_TIMEOUT_SECONDS), "-t", "ed25519,ecdsa,rsa", ip],
            check=False,
            capture_output=True,
            text=True,
            timeout=BANNER_TIMEOUT_SECONDS + 1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            digest = hashlib.sha256(base64.b64decode(parts[2])).digest()
        except (ValueError, TypeError):
            continue
        fingerprint = base64.b64encode(digest).decode("ascii").rstrip("=")
        return {"key_type": parts[1], "fingerprint_sha256": f"SHA256:{fingerprint}"}
    return None


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
            http_result = get_http_service_details(ip, port, use_tls=True)
            if http_result:
                http_result["tls"] = tls_result.get("tls")
                return http_result
            return tls_result

        plaintext_result = get_plaintext_service_banner(ip, port)
        if plaintext_result not in ["Unknown", "Error grabbing banner"]:
            return build_service_result(plaintext_result)
        if tls_result is not None:
            return tls_result
        return build_service_result(plaintext_result)

    if port in WEB_PORTS:
        http_result = get_http_service_details(ip, port)
        if http_result:
            return http_result

    banner = get_plaintext_service_banner(ip, port)
    if banner.startswith("SSH"):
        return build_service_result(banner, ssh=get_ssh_host_key_details(ip))
    if banner == "Unknown":
        http_result = get_http_service_details(ip, port)
        if http_result:
            return http_result
    return build_service_result(banner)


def get_service_banner(ip, port):
    """Backward-compatible wrapper that returns only the service label string."""
    return get_service_details(ip, port)["service"]
