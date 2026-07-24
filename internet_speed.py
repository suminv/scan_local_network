"""Small, dependency-free Internet speed test used by ``scan-health``.

The implementation intentionally runs only when requested by the caller.  It
uses Cloudflare's public download and upload measurement endpoints and keeps
raw observations separate from the health-check interpretation.
"""

import statistics
import socket
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down"
DEFAULT_UPLOAD_URL = "https://speed.cloudflare.com/__up"
DEFAULT_DOWNLOAD_BYTES = 10_000_000
DEFAULT_UPLOAD_BYTES = 2_000_000
DEFAULT_LATENCY_SAMPLES = 5
READ_CHUNK_BYTES = 256 * 1024
USER_AGENT = "network-health-check/1.0"
MIN_FALLBACK_DOWNLOAD_BYTES = 250_000


def _measurement_url(url, **params):
    """Add measurement parameters and a cache-busting request id."""
    parsed = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query.update({key: str(value) for key, value in params.items()})
    query["request_id"] = uuid.uuid4().hex
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
    )


def _read_response(response):
    transferred = 0
    read_chunk = getattr(response, "read1", response.read)
    while True:
        chunk = read_chunk(READ_CHUNK_BYTES)
        if not chunk:
            return transferred
        transferred += len(chunk)


def _open_timed(request, *, timeout, opener):
    started_at = time.perf_counter()
    with opener(request, timeout=timeout) as response:
        transferred = _read_response(response)
        headers = dict(response.headers.items())
    return {
        "duration_seconds": time.perf_counter() - started_at,
        "bytes": transferred,
        "headers": headers,
    }


def measure_latency(
    *,
    url=DEFAULT_DOWNLOAD_URL,
    samples=DEFAULT_LATENCY_SAMPLES,
    timeout=10,
    opener=urllib.request.urlopen,
):
    """Measure HTTPS request latency using zero-byte download requests."""
    points = []
    headers = {}
    for _ in range(samples):
        request = urllib.request.Request(
            _measurement_url(url, bytes=0),
            headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"},
        )
        observation = _open_timed(request, timeout=timeout, opener=opener)
        points.append(observation["duration_seconds"] * 1000)
        headers = observation["headers"]
    jitter_ms = 0.0
    if len(points) > 1:
        jitter_ms = statistics.mean(
            abs(current - previous)
            for previous, current in zip(points, points[1:])
        )
    return {
        "latency_ms": statistics.median(points),
        "jitter_ms": jitter_ms,
        "samples_ms": points,
        "headers": headers,
    }


def measure_download(
    *,
    byte_count=DEFAULT_DOWNLOAD_BYTES,
    url=DEFAULT_DOWNLOAD_URL,
    timeout=20,
    opener=urllib.request.urlopen,
):
    """Download a fixed payload and return the measured application throughput."""
    request = urllib.request.Request(
        _measurement_url(url, bytes=byte_count),
        headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"},
    )
    observation = _open_timed(request, timeout=timeout, opener=opener)
    duration = observation["duration_seconds"]
    observation["mbps"] = (
        observation["bytes"] * 8 / duration / 1_000_000 if duration > 0 else None
    )
    return observation


def measure_download_with_curl(
    *,
    byte_count=DEFAULT_DOWNLOAD_BYTES,
    url=DEFAULT_DOWNLOAD_URL,
    timeout=20,
    curl_path=None,
):
    """Measure download throughput with curl's HTTP/TLS implementation."""
    curl_path = curl_path or shutil.which("curl")
    if not curl_path:
        raise FileNotFoundError("curl executable is unavailable")
    measurement_url = _measurement_url(url, bytes=byte_count)
    completed = subprocess.run(
        [
            curl_path,
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--output",
            "/dev/null",
            "--max-time",
            str(timeout),
            "--user-agent",
            USER_AGENT,
            "--header",
            "Cache-Control: no-cache",
            "--write-out",
            "%{http_code} %{size_download} %{time_total}",
            measurement_url,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout + 5,
    )
    fields = completed.stdout.strip().split()
    if len(fields) != 3:
        raise ValueError("curl returned an invalid speed-test result")
    status_code, transferred, duration = fields
    transferred = int(float(transferred))
    duration = float(duration)
    if int(status_code) < 200 or int(status_code) >= 300:
        raise ValueError(f"curl download returned HTTP {status_code}")
    return {
        "duration_seconds": duration,
        "bytes": transferred,
        "mbps": transferred * 8 / duration / 1_000_000 if duration > 0 else None,
        "headers": {},
        "backend": "curl",
    }


def _curl_error_message(error):
    stderr = getattr(error, "stderr", None)
    if stderr:
        return stderr.strip()
    return str(error)


def _is_curl_timeout(error):
    return (
        isinstance(error, subprocess.TimeoutExpired)
        or (
            isinstance(error, subprocess.CalledProcessError)
            and error.returncode == 28
        )
        or _is_timeout_error(error)
    )


def measure_download_with_curl_fallback(
    *,
    byte_count=DEFAULT_DOWNLOAD_BYTES,
    url=DEFAULT_DOWNLOAD_URL,
    timeout=20,
    curl_path=None,
):
    """Retry curl download timeouts with progressively smaller payloads."""
    attempts = []
    for candidate in _fallback_download_sizes(byte_count):
        try:
            observation = measure_download_with_curl(
                byte_count=candidate,
                url=url,
                timeout=timeout,
                curl_path=curl_path,
            )
        except Exception as exc:
            attempts.append(
                {"bytes": candidate, "error": _curl_error_message(exc)}
            )
            if not _is_curl_timeout(exc):
                raise
            continue
        observation["requested_bytes"] = byte_count
        observation["fallback_used"] = candidate != byte_count
        observation["attempts"] = attempts + [
            {
                "bytes": candidate,
                "duration_seconds": observation["duration_seconds"],
                "mbps": observation["mbps"],
            }
        ]
        return observation
    errors = "; ".join(
        f"{attempt['bytes']} bytes: {attempt['error']}" for attempt in attempts
    )
    raise TimeoutError(f"download timed out for all payload sizes ({errors})")


def _is_timeout_error(error):
    """Return whether an exception represents a network read/connect timeout."""
    if isinstance(error, (TimeoutError, socket.timeout)):
        return True
    if isinstance(error, urllib.error.URLError):
        return isinstance(error.reason, (TimeoutError, socket.timeout))
    return "timed out" in str(error).lower()


def _fallback_download_sizes(requested_bytes):
    """Build progressively smaller unique payload sizes for timeout recovery."""
    sizes = [requested_bytes]
    candidate = requested_bytes
    for _ in range(2):
        candidate = max(MIN_FALLBACK_DOWNLOAD_BYTES, candidate // 4)
        if candidate not in sizes:
            sizes.append(candidate)
        if candidate == MIN_FALLBACK_DOWNLOAD_BYTES:
            break
    return sizes


def measure_download_with_fallback(
    *,
    byte_count=DEFAULT_DOWNLOAD_BYTES,
    url=DEFAULT_DOWNLOAD_URL,
    timeout=20,
    opener=urllib.request.urlopen,
):
    """Retry timed-out downloads with smaller payloads.

    A reduced payload is less representative of sustained throughput, so the
    returned observation retains every attempt and marks fallback use.
    """
    attempts = []
    for candidate in _fallback_download_sizes(byte_count):
        try:
            observation = measure_download(
                byte_count=candidate,
                url=url,
                timeout=timeout,
                opener=opener,
            )
        except Exception as exc:
            attempts.append({"bytes": candidate, "error": str(exc)})
            if not _is_timeout_error(exc):
                raise
            continue
        observation["requested_bytes"] = byte_count
        observation["fallback_used"] = candidate != byte_count
        observation["attempts"] = attempts + [
            {
                "bytes": candidate,
                "duration_seconds": observation["duration_seconds"],
                "mbps": observation["mbps"],
            }
        ]
        return observation
    errors = "; ".join(
        f"{attempt['bytes']} bytes: {attempt['error']}" for attempt in attempts
    )
    raise TimeoutError(f"download timed out for all payload sizes ({errors})")


def measure_download_compatible(
    *,
    byte_count=DEFAULT_DOWNLOAD_BYTES,
    url=DEFAULT_DOWNLOAD_URL,
    timeout=20,
    opener=urllib.request.urlopen,
):
    """Use curl when available and retain urllib as a portable fallback."""
    curl_path = shutil.which("curl")
    if curl_path:
        return measure_download_with_curl_fallback(
            byte_count=byte_count,
            url=url,
            timeout=timeout,
            curl_path=curl_path,
        )
    result = measure_download_with_fallback(
        byte_count=byte_count,
        url=url,
        timeout=timeout,
        opener=opener,
    )
    result.setdefault("backend", "urllib")
    return result


def measure_upload(
    *,
    byte_count=DEFAULT_UPLOAD_BYTES,
    url=DEFAULT_UPLOAD_URL,
    timeout=20,
    opener=urllib.request.urlopen,
):
    """Upload a fixed payload and return the measured application throughput."""
    request = urllib.request.Request(
        _measurement_url(url),
        data=b"\0" * byte_count,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/octet-stream",
            "Cache-Control": "no-cache",
        },
        method="POST",
    )
    started_at = time.perf_counter()
    with opener(request, timeout=timeout) as response:
        _read_response(response)
        headers = dict(response.headers.items())
    duration = time.perf_counter() - started_at
    return {
        "duration_seconds": duration,
        "bytes": byte_count,
        "mbps": byte_count * 8 / duration / 1_000_000 if duration > 0 else None,
        "headers": headers,
    }


def _cloudflare_location(headers):
    ray = headers.get("cf-ray") or headers.get("CF-Ray")
    if not ray or "-" not in ray:
        return None
    return ray.rsplit("-", 1)[-1]


def collect_internet_speed(
    *,
    download_bytes=DEFAULT_DOWNLOAD_BYTES,
    upload_bytes=DEFAULT_UPLOAD_BYTES,
    latency_samples=DEFAULT_LATENCY_SAMPLES,
    timeout=20,
    opener=urllib.request.urlopen,
):
    """Collect independent latency, download, and upload observations."""
    result = {
        "provider": "Cloudflare",
        "download_url": DEFAULT_DOWNLOAD_URL,
        "upload_url": DEFAULT_UPLOAD_URL,
        "requested_download_bytes": download_bytes,
        "requested_upload_bytes": upload_bytes,
        "latency_samples": latency_samples,
        "errors": {},
    }
    observations = {}
    stages = (
        (
            "latency",
            lambda: measure_latency(
                samples=latency_samples,
                timeout=timeout,
                opener=opener,
            ),
        ),
        (
            "download",
            lambda: measure_download_compatible(
                byte_count=download_bytes,
                timeout=timeout,
                opener=opener,
            ),
        ),
        (
            "upload",
            lambda: measure_upload(
                byte_count=upload_bytes,
                timeout=timeout,
                opener=opener,
            ),
        ),
    )
    for name, measurement in stages:
        try:
            observations[name] = measurement()
        except Exception as exc:
            result["errors"][name] = str(exc)
    result["observations"] = observations
    headers = next(
        (
            observation.get("headers", {})
            for observation in observations.values()
            if observation.get("headers")
        ),
        {},
    )
    result["server_location"] = _cloudflare_location(headers)
    return result


def analyze_internet_speed(observation):
    """Convert raw observations into a normalized health check."""
    measurements = observation.get("observations", {})
    latency = measurements.get("latency", {})
    download = measurements.get("download", {})
    upload = measurements.get("upload", {})
    completed = [
        name
        for name, value in (
            ("latency", latency.get("latency_ms")),
            ("download", download.get("mbps")),
            ("upload", upload.get("mbps")),
        )
        if value is not None
    ]
    details = {
        "provider": observation.get("provider"),
        "server_location": observation.get("server_location"),
        "latency_ms": latency.get("latency_ms"),
        "jitter_ms": latency.get("jitter_ms"),
        "download_mbps": download.get("mbps"),
        "upload_mbps": upload.get("mbps"),
        "download_bytes": download.get("bytes"),
        "download_requested_bytes": download.get("requested_bytes"),
        "download_fallback_used": bool(download.get("fallback_used")),
        "download_attempts": download.get("attempts", []),
        "download_backend": download.get("backend", "urllib"),
        "upload_bytes": upload.get("bytes"),
        "completed_measurements": completed,
        "errors": observation.get("errors", {}),
    }
    if len(completed) == 3:
        if download.get("fallback_used"):
            return {
                "name": "internet_speed",
                "status": "notice",
                "summary": (
                    f"Internet speed: {download['mbps']:.1f} Mbps down, "
                    f"{upload['mbps']:.1f} Mbps up, "
                    f"{latency['latency_ms']:.1f} ms latency "
                    "(download used a reduced payload after timeout)"
                ),
                "details": details,
            }
        return {
            "name": "internet_speed",
            "status": "ok",
            "summary": (
                f"Internet speed: {download['mbps']:.1f} Mbps down, "
                f"{upload['mbps']:.1f} Mbps up, {latency['latency_ms']:.1f} ms latency"
            ),
            "details": details,
        }
    if completed:
        return {
            "name": "internet_speed",
            "status": "notice",
            "summary": (
                "Internet speed test completed partially "
                f"({len(completed)}/3 measurements available)"
            ),
            "details": details,
        }
    return {
        "name": "internet_speed",
        "status": "notice",
        "summary": "Internet speed test was unavailable",
        "details": details,
    }


def build_internet_speed_check(**kwargs):
    """Collect and analyze one optional Internet speed test."""
    return analyze_internet_speed(collect_internet_speed(**kwargs))
