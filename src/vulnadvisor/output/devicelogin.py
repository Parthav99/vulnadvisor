"""Stdlib-only client for the platform's device-flow login (Task 14.1).

``vulnadvisor login`` uses these two calls: mint a device grant, then poll the token endpoint
until the user approves the code in the dashboard. Mirrors ``output/upload.py``'s posture:
``urllib`` only (no new wheel dependency), typed :class:`LoginError` with context, and defensive
parsing of every server response (CLAUDE.md — never trust external JSON's shape).
"""

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["DeviceCode", "DeviceToken", "LoginError", "poll_device_token", "request_device_code"]

_CODE_ENDPOINT = "/v1/device/code"
_TOKEN_ENDPOINT = "/v1/device/token"  # noqa: S105 - URL path, not a credential
_MAX_ERROR_BODY = 500

# Pending-state error codes the poll loop keeps waiting on (RFC 8628 token errors).
_PENDING_ERRORS = frozenset({"authorization_pending", "slow_down"})


class LoginError(RuntimeError):
    """Raised when the device login cannot be completed (network, denial, expiry, bad data)."""


@dataclass(frozen=True)
class DeviceCode:
    """A minted device grant: what to show the user and how to poll."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class DeviceToken:
    """The approved login: the org-scoped API key (shown to no one) and its org."""

    access_token: str
    org_slug: str


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> tuple[int, Any]:
    """POST JSON and return ``(status, parsed_body)``; 4xx bodies are returned, not raised."""
    request = urllib.request.Request(  # noqa: S310 - scheme is the user's configured API URL
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, _parse_body(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, _parse_body(body)
        except LoginError:
            detail = body.decode("utf-8", "replace")[:_MAX_ERROR_BODY].strip()
            hint = f": {detail}" if detail else ""
            raise LoginError(f"server returned HTTP {exc.code}{hint}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LoginError(f"could not reach {url}: {exc}") from exc


def _parse_body(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise LoginError("server returned a non-JSON response") from exc


def _require_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise LoginError(f"server response is missing '{field}'")
    return value


def _coerce_positive_int(value: Any, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return default


def request_device_code(
    api_url: str, *, client_name: str | None = None, timeout: float = 30.0
) -> DeviceCode:
    """Mint a device grant at ``{api_url}/v1/device/code``."""
    if not api_url:
        raise LoginError("no API URL: pass --api-url or set the API_URL environment variable")
    status, data = _post_json(
        api_url.rstrip("/") + _CODE_ENDPOINT, {"client_name": client_name}, timeout
    )
    if status == 429:
        raise LoginError("too many login attempts; wait a minute and retry")
    if status not in (200, 201) or not isinstance(data, dict):
        raise LoginError(f"could not start a device login (HTTP {status})")
    return DeviceCode(
        device_code=_require_str(data, "device_code"),
        user_code=_require_str(data, "user_code"),
        verification_uri=_require_str(data, "verification_uri"),
        verification_uri_complete=_require_str(data, "verification_uri_complete"),
        expires_in=_coerce_positive_int(data.get("expires_in"), 900),
        interval=_coerce_positive_int(data.get("interval"), 5),
    )


def poll_device_token(
    api_url: str,
    device_code: str,
    *,
    interval: int,
    expires_in: int,
    timeout: float = 30.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> DeviceToken:
    """Poll ``{api_url}/v1/device/token`` until approved, expired, or denied.

    ``sleep``/``clock`` are injectable so tests run without real waiting. Pending responses keep
    polling at ``interval`` seconds until the grant's ``expires_in`` horizon passes.
    """
    url = api_url.rstrip("/") + _TOKEN_ENDPOINT
    deadline = clock() + expires_in
    while True:
        status, data = _post_json(url, {"device_code": device_code}, timeout)
        body = data if isinstance(data, dict) else {}

        if status == 200:
            return DeviceToken(
                access_token=_require_str(body, "access_token"),
                org_slug=_require_str(body, "org_slug"),
            )

        error = body.get("error")
        if status == 400 and error in _PENDING_ERRORS:
            if clock() + interval > deadline:
                raise LoginError("login timed out before the code was approved; run login again")
            sleep(interval)
            continue
        if status == 400 and error == "expired_token":  # noqa: S105 - RFC 8628 error code
            raise LoginError("the device code expired before approval; run login again")
        if status == 400 and error == "invalid_grant":
            raise LoginError("the device code was rejected (already used or unknown)")
        raise LoginError(f"unexpected response while polling for approval (HTTP {status})")
