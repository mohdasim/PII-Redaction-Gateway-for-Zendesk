"""Webhook authentication for incoming Zendesk requests.

Supports two authentication methods:
1. HMAC-SHA256 signature verification (Zendesk webhook signing)
2. API key in X-API-Key header (simpler fallback)
"""

from __future__ import annotations

import hashlib
import hmac

from src.utils.logger import get_logger

logger = get_logger(__name__)


def verify_webhook(event: dict, webhook_secret: str) -> bool:
    """Verify an incoming webhook request is authentic.

    Checks for HMAC signature first, then falls back to API key check.

    Args:
        event: API Gateway Lambda proxy event.
        webhook_secret: The shared secret for verification.

    Returns:
        True if the request is authenticated, False otherwise.
    """
    if not webhook_secret:
        logger.warning("No webhook secret configured — accepting all requests")
        return True

    headers = event.get("headers") or {}
    # API Gateway may lowercase header names
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    # Method 1: HMAC-SHA256 signature (Zendesk webhook signing)
    signature = normalized_headers.get("x-zendesk-webhook-signature", "")
    if signature:
        body = event.get("body", "")
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        return _verify_hmac(body, signature, webhook_secret)

    # Method 2: API key header
    api_key = normalized_headers.get("x-api-key", "")
    if api_key:
        return hmac.compare_digest(api_key, webhook_secret)

    logger.warning("No authentication header found in request")
    return False


def _verify_hmac(body: str, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    try:
        expected = hmac.new(
            key=secret.encode("utf-8"),
            msg=body.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception as e:
        logger.warning(f"HMAC verification error: {e}")
        return False
