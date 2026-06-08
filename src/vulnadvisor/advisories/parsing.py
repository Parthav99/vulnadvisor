"""Defensive parsing helpers for external advisory/risk API payloads.

Everything here must tolerate malformed, partial, or unexpected JSON without raising: bad input
degrades to a safe default (``None``/empty), never a crash.
"""

import json
from typing import Any

__all__ = ["safe_float", "safe_json", "safe_str"]


def safe_json(raw: str | bytes) -> Any:
    """Parse JSON, returning ``None`` instead of raising on malformed input."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def safe_str(value: Any) -> str | None:
    """Return ``value`` if it is a non-empty string, else ``None``."""
    return value if isinstance(value, str) and value else None


def safe_float(value: Any) -> float | None:
    """Coerce ``value`` to ``float`` when possible, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None
