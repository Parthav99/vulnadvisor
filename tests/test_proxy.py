# File: tests/test_proxy.py
"""The platform-proxy suggest client (Task D): contract, defensive parsing, and the no-op latch."""

import json

import pytest

from vulnadvisor.advisories.transport import TransportError
from vulnadvisor.llm.client import LLMError
from vulnadvisor.llm.proxy import COMPLETE_PATH, PlatformSuggestClient


class _FakeTransport:
    """Serves scripted responses (bytes) or raises (a ``TransportError``); records every call."""

    def __init__(self, *responses: bytes | Exception) -> None:
        self.calls: list[dict[str, object]] = []
        self._responses = list(responses)

    def request(self, method, url, *, body=None, headers=None):  # type: ignore[no-untyped-def]
        self.calls.append(
            {"method": method, "url": url, "body": body, "headers": dict(headers or {})}
        )
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(text: str = "PATCH") -> bytes:
    return json.dumps({"available": True, "text": text, "remaining_today": 49}).encode()


def _client(transport: _FakeTransport, *, model: str | None = None) -> PlatformSuggestClient:
    return PlatformSuggestClient(
        api_url="https://platform.example/", api_key="va_secret", transport=transport, model=model
    )


def test_complete_returns_text_and_sends_the_expected_request() -> None:
    transport = _FakeTransport(_ok("THE PATCH"))
    client = _client(transport)

    assert client.complete(system="be safe", user="fix it") == "THE PATCH"

    (call,) = transport.calls
    assert call["method"] == "POST"
    # The trailing slash on the base URL is normalized away.
    assert call["url"] == "https://platform.example" + COMPLETE_PATH
    headers = call["headers"]
    assert headers["authorization"] == "Bearer va_secret"
    assert headers["content-type"] == "application/json"
    sent = json.loads(call["body"])
    assert sent == {"system": "be safe", "user": "fix it"}  # no model key when unset


def test_complete_includes_model_when_set() -> None:
    transport = _FakeTransport(_ok())
    client = _client(transport, model="deepseek/deepseek-r1:free")
    client.complete(system="s", user="u")
    assert json.loads(transport.calls[0]["body"])["model"] == "deepseek/deepseek-r1:free"
    assert client.model == "deepseek/deepseek-r1:free"


def test_model_property_defaults_to_proxy_sentinel() -> None:
    assert _client(_FakeTransport()).model == "platform-proxy"


def test_unavailable_response_latches_to_a_single_call() -> None:
    transport = _FakeTransport(json.dumps({"available": False}).encode())
    client = _client(transport)

    with pytest.raises(LLMError, match="no model key available"):
        client.complete(system="s", user="u")
    # Latched: a second call short-circuits without touching the transport again.
    with pytest.raises(LLMError, match="no model key available"):
        client.complete(system="s", user="u")
    assert len(transport.calls) == 1


def test_spent_cap_429_latches() -> None:
    transport = _FakeTransport(
        TransportError("POST url failed: HTTP Error 429: Too Many Requests"),
        _ok(),  # would succeed, but the latch should prevent a second call
    )
    client = _client(transport)

    with pytest.raises(LLMError):
        client.complete(system="s", user="u")
    with pytest.raises(LLMError):
        client.complete(system="s", user="u")
    assert len(transport.calls) == 1  # latched on the 429


def test_transient_error_does_not_latch() -> None:
    transport = _FakeTransport(
        TransportError("POST url failed: HTTP Error 502: Bad Gateway"),
        _ok("RECOVERED"),
    )
    client = _client(transport)

    with pytest.raises(LLMError):
        client.complete(system="s", user="u")
    # A non-cap failure is per-attempt; the next call retries the platform.
    assert client.complete(system="s", user="u") == "RECOVERED"
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",  # a non-object
        json.dumps({"available": True}).encode(),  # missing text
        json.dumps({"available": True, "text": "   "}).encode(),  # blank text
        json.dumps({"available": True, "text": 5}).encode(),  # non-string text
    ],
)
def test_malformed_response_raises_llm_error(raw: bytes) -> None:
    with pytest.raises(LLMError):
        _client(_FakeTransport(raw)).complete(system="s", user="u")
