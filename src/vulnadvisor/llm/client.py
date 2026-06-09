"""A dependency-free Anthropic Messages client over the project's :class:`Transport`.

We deliberately avoid the official SDK: the call is one documented POST to ``/v1/messages``, so a
thin client over the existing ``Transport`` keeps the dependency surface minimal and the layer
trivially mockable in tests. The API key comes from ``ANTHROPIC_API_KEY`` only (never hardcoded);
the model from ``ANTHROPIC_MODEL`` or a fast default. Any network/parse failure raises
:class:`LLMError`, which the explainer catches to fall back to the deterministic template.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from vulnadvisor.advisories.transport import Transport, TransportError, UrllibTransport

__all__ = [
    "DEFAULT_MODEL",
    "AnthropicClient",
    "LLMClient",
    "LLMError",
    "build_anthropic_client",
]

_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"
# Haiku is fast and inexpensive — appropriate for an explanation layer that never decides priority.
DEFAULT_MODEL = "claude-haiku-4-5-20251001"


class LLMError(Exception):
    """Raised when the language model call fails (transport, HTTP, or malformed response)."""


class LLMClient(Protocol):
    """Minimal chat-completion surface: a system + user prompt yields raw model text."""

    @property
    def model(self) -> str:
        """The model identifier (used for cache-keying)."""
        ...

    def complete(self, *, system: str, user: str) -> str:
        """Return the model's raw text response, or raise :class:`LLMError`."""
        ...


@dataclass(frozen=True)
class AnthropicClient:
    """An :class:`LLMClient` backed by the Anthropic Messages API over a :class:`Transport`."""

    transport: Transport
    api_key: str
    model: str = DEFAULT_MODEL
    max_tokens: int = 700

    def complete(self, *, system: str, user: str) -> str:
        """POST the prompt to the Messages API and return the first text block."""
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
        ).encode("utf-8")
        headers: Mapping[str, str] = {
            "content-type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": _API_VERSION,
        }
        try:
            raw = self.transport.request("POST", _API_URL, body=body, headers=headers)
        except TransportError as exc:
            raise LLMError(f"Anthropic request failed: {exc}") from exc
        return _extract_text(raw)


def _extract_text(raw: bytes) -> str:
    """Pull the first text block out of a Messages API response, defensively."""
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise LLMError("Anthropic response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise LLMError("Anthropic response was not an object")
    content = payload.get("content")
    if isinstance(content, list):
        for block in content:
            if (
                isinstance(block, dict)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
                and block["text"].strip()
            ):
                return str(block["text"])
    raise LLMError("Anthropic response contained no text content")


def build_anthropic_client(transport: Transport | None = None) -> AnthropicClient | None:
    """Build an :class:`AnthropicClient` from the environment, or ``None`` if no key is set.

    Reads ``ANTHROPIC_API_KEY`` (required) and ``ANTHROPIC_MODEL`` (optional). Returning ``None``
    when the key is absent lets the explainer run in deterministic template-only mode with no error.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    model = os.environ.get("ANTHROPIC_MODEL") or DEFAULT_MODEL
    return AnthropicClient(transport or UrllibTransport(), api_key, model=model)
