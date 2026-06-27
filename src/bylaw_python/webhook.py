# Bylaw ALCV — Webhook verification helper

from __future__ import annotations

import hashlib
import hmac


def verify_webhook(body: bytes | str, signature: str, secret: str) -> bool:
    """Verify the HMAC-SHA256 signature on an inbound Bylaw webhook.

    The Vault signs every delivery with ``X-Bylaw-Signature: sha256=<hex>``.
    Pass the raw request body, that header value, and your endpoint's signing
    secret to verify authenticity before processing the event.

    Args:
        body: Raw request body (bytes or str).  Use the unparsed body exactly
            as received — do not re-encode from a parsed JSON object.
        signature: Value of the ``X-Bylaw-Signature`` header.
        secret: Signing secret for this webhook endpoint (from the dashboard).

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.

    Example::

        from flask import request
        import bylaw_python as bylaw

        @app.route("/webhook", methods=["POST"])
        def handle_webhook():
            if not bylaw.verify_webhook(request.data, request.headers["X-Bylaw-Signature"], SECRET):
                return "Forbidden", 403
            event = request.get_json()
            ...
    """
    if isinstance(body, str):
        body = body.encode("utf-8")

    if signature.startswith("sha256="):
        signature = signature[len("sha256="):]

    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
