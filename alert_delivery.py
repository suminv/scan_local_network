import json
import sys
import urllib.request
from datetime import datetime, timezone


def build_alert_payload(*, source, scan_context=None, alert_summary=None, alerts=None):
    """Build a consistent webhook payload for actionable alerts."""
    return {
        "source": source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_context": scan_context or {},
        "alert_summary": alert_summary or {},
        "alerts": alerts or {},
    }


def send_webhook_payload(webhook_url, payload, timeout=10, label="Webhook alert"):
    """Send a JSON payload to a webhook endpoint and return True on success."""
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
        print(f"{label} delivered to {webhook_url} (HTTP {status})")
        return True
    except Exception as exc:
        print(f"Warning: Failed to deliver {label.lower()}: {exc}", file=sys.stderr)
        return False
