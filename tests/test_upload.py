"""Unit tests for the stdlib-only report uploader (``output/upload.py``)."""

import io
import json
import urllib.error
from typing import Any

import pytest

from vulnadvisor.output import upload as upload_mod
from vulnadvisor.output.upload import UploadError, UploadResult, upload_report

_REPORT = {"schema_version": "1.0", "findings": []}
_ARGS = {"api_url": "https://api.example.com", "api_key": "va_x.secret", "repo": "web"}


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_: Any) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def test_upload_success_parses_result(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float = 0) -> _FakeResponse:
        captured["url"] = request.full_url
        captured["auth"] = request.headers.get("Authorization")
        captured["payload"] = json.loads(request.data)
        return _FakeResponse(
            json.dumps(
                {
                    "scan_id": "scan-123",
                    "summary": {"total": 0},
                    "diff_summary": {"introduced": 2, "fixed": 1, "unchanged": 3},
                }
            ).encode()
        )

    monkeypatch.setattr(upload_mod.urllib.request, "urlopen", fake_urlopen)
    result = upload_report(_REPORT, **_ARGS)

    assert result == UploadResult(scan_id="scan-123", introduced=2, fixed=1, unchanged=3)
    assert captured["url"] == "https://api.example.com/v1/scans"
    assert captured["auth"] == "Bearer va_x.secret"
    assert captured["payload"]["repo"] == "web"
    assert captured["payload"]["report"] == _REPORT


def test_upload_http_error_includes_status(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(request: Any, timeout: float = 0) -> _FakeResponse:
        raise urllib.error.HTTPError(
            "https://api.example.com/v1/scans", 422, "Unprocessable", {}, io.BytesIO(b"bad schema")
        )

    monkeypatch.setattr(upload_mod.urllib.request, "urlopen", boom)
    with pytest.raises(UploadError, match="HTTP 422"):
        upload_report(_REPORT, **_ARGS)


def test_upload_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(request: Any, timeout: float = 0) -> _FakeResponse:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(upload_mod.urllib.request, "urlopen", boom)
    with pytest.raises(UploadError, match="could not reach"):
        upload_report(_REPORT, **_ARGS)


def test_upload_non_json_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        upload_mod.urllib.request, "urlopen", lambda request, timeout=0: _FakeResponse(b"<html>")
    )
    with pytest.raises(UploadError, match="non-JSON"):
        upload_report(_REPORT, **_ARGS)


def test_upload_missing_credentials() -> None:
    with pytest.raises(UploadError, match="API URL"):
        upload_report(_REPORT, api_url="", api_key="k", repo="web")
    with pytest.raises(UploadError, match="API key"):
        upload_report(_REPORT, api_url="https://x", api_key="", repo="web")
