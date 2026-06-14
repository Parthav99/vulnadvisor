# File: src/vulnadvisor/llm/proxy.py
"""Platform-proxy LLM client for ``vulnadvisor suggest`` in CI (Task D).

In a CI workflow the suggest loop has no model-key secret. Instead it authenticates with the org's
``VULNADVISOR_API_KEY`` (the same key ``scan --upload`` uses) and the platform runs the model call
server-side — the org's BYO copilot key, or the platform's configured fallback key. This client
speaks that ``POST /v1/llm/complete`` contract over the project's :class:`Transport`, so the wheel
stays dependency-free and the call is trivially mockable.

It satisfies the :class:`LLMClient` Protocol, so the existing validated-fix loop uses it unchanged.
When the platform reports no key is available (``available: false``) — or returns a spent-cap 429 —
``complete`` raises :class:`LLMError` *and latches* "unavailable", so the rest of the sweep
short-circuits instead of hammering the endpoint once per finding. ``suggest`` then simply posts
nothing and exits 0: the graceful no-op the build relies on.
"""

import json
from collections.abc import Mapping

from vulnadvisor.advisories.transport import Transport, TransportError
from vulnadvisor.llm.client import LLMError

COMPLETE_PATH = "/v1/llm/complete"

# Sentinel model id; the platform picks the real model (org key default or fallback model).
_PROXY_MODEL = "platform-proxy"


class PlatformSuggestClient:
    """An :class:`LLMClient` that runs each model call on the VulnAdvisor platform.

    Stateful by design: once the platform reports no key is available the client latches and every
    subsequent :meth:`complete` short-circuits to a :class:`LLMError`, so a key-less org costs at
    most one round-trip across the whole sweep.
    """

    def __init__(
        self,
        *,
        api_url: str,
        api_key: str,
        transport: Transport,
        model: str | None = None,
    ) -> None:
        """Bind the proxy to a platform base URL + org API key over ``transport``."""
        self._url = api_url.rstrip("/") + COMPLETE_PATH
        self._api_key = api_key
        self._transport = transport
        self._model = model
        self._unavailable = False

    @property
    def model(self) -> str:
        """A stable identifier (the platform decides the real model); used only for cache-keying."""
        return self._model or _PROXY_MODEL

    def complete(self, *, system: str, user: str) -> str:
        """Run one model call via the platform, or raise :class:`LLMError`.

        Latches "unavailable" on an ``available: false`` body or a spent-cap response so the
        suggest sweep stops calling after the first such answer.
        """
        if self._unavailable:
            raise LLMError("platform suggest proxy reported no model key available")
        payload: dict[str, object] = {"system": system, "user": user}
        if self._model is not None:
            payload["model"] = self._model
        body = json.dumps(payload).encode("utf-8")
        headers: Mapping[str, str] = {
            "content-type": "application/json",
            "authorization": f"Bearer {self._api_key}",
        }
        try:
            raw = self._transport.request("POST", self._url, body=body, headers=headers)
        except TransportError as exc:
            # A spent daily cap (429) is terminal for this run; latch so we stop retrying. Other
            # HTTP/network failures (e.g. a transient 502 model error) are surfaced per attempt.
            if " 429" in str(exc):
                self._unavailable = True
            raise LLMError(f"platform suggest proxy request failed: {exc}") from exc
        return self._parse(raw)

    def _parse(self, raw: bytes) -> str:
        """Defensively read the completion text from a ``/v1/llm/complete`` response."""
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise LLMError("platform suggest proxy returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise LLMError("platform suggest proxy returned a non-object response")
        if not payload.get("available"):
            self._unavailable = True
            raise LLMError("platform suggest proxy reported no model key available")
        text = payload.get("text")
        if not isinstance(text, str) or not text.strip():
            raise LLMError("platform suggest proxy returned no completion text")
        return text
