"""HTTP transport abstraction so advisory clients are testable without live network.

Clients depend on the :class:`Transport` protocol; production uses :class:`UrllibTransport`
(stdlib only), tests inject a fake that serves recorded fixtures and counts calls. Any network
or HTTP failure surfaces as :class:`TransportError`, which clients catch to enter degraded mode.
"""

import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Protocol

__all__ = ["Transport", "TransportError", "UrllibTransport"]


class TransportError(Exception):
    """Raised when an HTTP request fails (network error, timeout, or non-2xx status)."""


class Transport(Protocol):
    """Minimal HTTP transport: perform a request and return the raw response body bytes."""

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        """Perform an HTTP request, returning the response body or raising ``TransportError``."""
        ...


class UrllibTransport:
    """A :class:`Transport` backed by the standard library ``urllib``."""

    def __init__(self, timeout: float = 20.0) -> None:
        """Create a transport whose requests time out after ``timeout`` seconds."""
        self._timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        """Perform the request via ``urllib``, mapping any failure to ``TransportError``."""
        request = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                data: bytes = response.read()
                return data
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise TransportError(f"{method} {url} failed: {exc}") from exc
