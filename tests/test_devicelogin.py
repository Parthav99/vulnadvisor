"""Unit tests for the stdlib device-flow login client (``output/devicelogin.py``)."""

import io
import json
import urllib.error
from typing import Any

import pytest

from vulnadvisor.output import devicelogin as login_mod
from vulnadvisor.output.devicelogin import (
    DeviceToken,
    LoginError,
    poll_device_token,
    request_device_code,
)

_API = "https://api.example.com"

_CODE_BODY = {
    "device_code": "dev-secret",
    "user_code": "XK7M-2PQ9",
    "verification_uri": "https://dash.example.com/activate",
    "verification_uri_complete": "https://dash.example.com/activate?code=XK7M-2PQ9",
    "expires_in": 900,
    "interval": 5,
}


class _FakeResponse:
    def __init__(self, body: dict[str, Any], status: int = 200) -> None:
        self._body = json.dumps(body).encode()
        self.status = status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_: Any) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def _http_error(status: int, body: dict[str, Any]) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.example.com/v1/device/token",
        status,
        "Bad Request",
        {},  # type: ignore[arg-type]
        io.BytesIO(json.dumps(body).encode()),
    )


def test_request_device_code_parses_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float = 0) -> _FakeResponse:
        captured["url"] = request.full_url
        captured["payload"] = json.loads(request.data)
        return _FakeResponse(_CODE_BODY, status=201)

    monkeypatch.setattr(login_mod.urllib.request, "urlopen", fake_urlopen)
    code = request_device_code(_API, client_name="alice@laptop")

    assert captured["url"] == "https://api.example.com/v1/device/code"
    assert captured["payload"] == {"client_name": "alice@laptop"}
    assert code.device_code == "dev-secret"
    assert code.user_code == "XK7M-2PQ9"
    assert code.expires_in == 900 and code.interval == 5


def test_request_device_code_requires_api_url() -> None:
    with pytest.raises(LoginError, match="API URL"):
        request_device_code("")


def test_request_device_code_missing_field(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {k: v for k, v in _CODE_BODY.items() if k != "user_code"}
    monkeypatch.setattr(
        login_mod.urllib.request,
        "urlopen",
        lambda request, timeout=0: _FakeResponse(body, status=201),
    )
    with pytest.raises(LoginError, match="user_code"):
        request_device_code(_API)


def test_request_device_code_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(request: Any, timeout: float = 0) -> _FakeResponse:
        raise _http_error(429, {"detail": "too many device-code requests"})

    monkeypatch.setattr(login_mod.urllib.request, "urlopen", boom)
    with pytest.raises(LoginError, match="too many"):
        request_device_code(_API)


def test_request_device_code_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(request: Any, timeout: float = 0) -> _FakeResponse:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(login_mod.urllib.request, "urlopen", boom)
    with pytest.raises(LoginError, match="could not reach"):
        request_device_code(_API)


def test_poll_waits_through_pending_then_returns_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [
        _http_error(400, {"error": "authorization_pending"}),
        _http_error(400, {"error": "authorization_pending"}),
        _FakeResponse({"access_token": "va_k.s3cret", "token_type": "bearer", "org_slug": "acme"}),
    ]
    sleeps: list[float] = []

    def fake_urlopen(request: Any, timeout: float = 0) -> _FakeResponse:
        item = responses.pop(0)
        if isinstance(item, urllib.error.HTTPError):
            raise item
        return item

    monkeypatch.setattr(login_mod.urllib.request, "urlopen", fake_urlopen)
    token = poll_device_token(
        _API, "dev-secret", interval=5, expires_in=900, sleep=sleeps.append, clock=lambda: 0.0
    )

    assert token == DeviceToken(access_token="va_k.s3cret", org_slug="acme")
    assert sleeps == [5, 5]  # one wait per pending answer


@pytest.mark.parametrize(
    ("error", "match"),
    [("expired_token", "expired"), ("invalid_grant", "rejected")],
)
def test_poll_terminal_errors(monkeypatch: pytest.MonkeyPatch, error: str, match: str) -> None:
    def boom(request: Any, timeout: float = 0) -> _FakeResponse:
        raise _http_error(400, {"error": error})

    monkeypatch.setattr(login_mod.urllib.request, "urlopen", boom)
    with pytest.raises(LoginError, match=match):
        poll_device_token(_API, "dev-secret", interval=5, expires_in=900, sleep=lambda _: None)


def test_poll_times_out_at_the_expiry_horizon(monkeypatch: pytest.MonkeyPatch) -> None:
    def always_pending(request: Any, timeout: float = 0) -> _FakeResponse:
        raise _http_error(400, {"error": "authorization_pending"})

    ticks = iter([0.0, 10.0, 20.0, 31.0])  # deadline at 30 with expires_in=30

    monkeypatch.setattr(login_mod.urllib.request, "urlopen", always_pending)
    with pytest.raises(LoginError, match="timed out"):
        poll_device_token(
            _API,
            "dev-secret",
            interval=5,
            expires_in=30,
            sleep=lambda _: None,
            clock=lambda: next(ticks),
        )


def test_poll_unexpected_status_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(request: Any, timeout: float = 0) -> _FakeResponse:
        raise _http_error(500, {"detail": "boom"})

    monkeypatch.setattr(login_mod.urllib.request, "urlopen", boom)
    with pytest.raises(LoginError, match="HTTP 500"):
        poll_device_token(_API, "dev-secret", interval=5, expires_in=900, sleep=lambda _: None)
