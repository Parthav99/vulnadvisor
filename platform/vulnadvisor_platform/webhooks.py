"""GitHub webhook HMAC verification (pure, testable)."""

import hashlib
import hmac


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Return ``True`` iff ``signature_header`` is GitHub's valid ``sha256=...`` HMAC of ``body``.

    Uses ``hmac.compare_digest`` for a constant-time comparison. A missing/malformed header or an
    empty configured secret yields ``False`` (fail closed).
    """
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
