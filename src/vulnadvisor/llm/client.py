# File: src/vulnadvisor/llm/client.py
"""Dependency-free chat clients for the LLM layer, over the project's :class:`Transport`.

We deliberately avoid every vendor SDK: each call is one documented POST, so thin clients over the
existing ``Transport`` keep the dependency surface minimal (the published wheel stays at 3 runtime
deps) and the layer trivially mockable in tests.

Two clients sit behind the :class:`LLMClient` Protocol:

* :class:`AnthropicClient` — the Anthropic Messages API (``api.anthropic.com``), used by the
  explanation layer and as the Anthropic ``fix`` path.
* :class:`OpenAICompatibleClient` — the OpenAI-style ``/chat/completions`` shape, which serves both
  **OpenAI** (``api.openai.com``) and **OpenRouter** (``openrouter.ai``). A free OpenRouter key is
  therefore enough to run ``vulnadvisor fix`` (Task 17.3).

Provider selection is by **key prefix** (``sk-or-`` → OpenRouter, ``sk-ant-`` → Anthropic,
``sk-``/``sk-proj-`` → OpenAI), with env-var precedence ``OPENROUTER_API_KEY`` →
``OPENAI_API_KEY`` → ``ANTHROPIC_API_KEY`` (first present wins). Keys come from the environment
only (never hardcoded). Any network/parse failure raises :class:`LLMError`, the same fallback
contract both clients have always offered.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from vulnadvisor.advisories.transport import Transport, TransportError, UrllibTransport

__all__ = [
    "DEFAULT_FIX_MODEL",
    "DEFAULT_MODEL",
    "AnthropicClient",
    "FixClientConfig",
    "LLMClient",
    "LLMError",
    "OpenAICompatibleClient",
    "Provider",
    "build_anthropic_client",
    "build_fix_client_from_env",
    "provider_for_key",
    "resolve_fix_client_config",
]

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
_OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
_API_VERSION = "2023-06-01"

# Haiku is fast and inexpensive — appropriate for an explanation layer that never decides priority.
DEFAULT_MODEL = "claude-haiku-4-5-20251001"


class Provider(str, Enum):
    """A supported model provider. The value is the canonical lowercase id used on the CLI."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"


# Default fix model per provider. Anthropic keeps the historical default (so the existing path is
# byte-for-byte unchanged); OpenRouter's routing meta-model works on every account incl. free tiers.
DEFAULT_FIX_MODEL: dict[Provider, str] = {
    Provider.ANTHROPIC: DEFAULT_MODEL,
    Provider.OPENAI: "gpt-5.2",
    Provider.OPENROUTER: "openrouter/auto",
}

# Key env vars in precedence order (first present wins). Each carries the provider it implies, used
# only as a fallback when the key itself has no recognized vendor prefix.
_KEY_ENV_VARS: tuple[tuple[str, Provider], ...] = (
    ("OPENROUTER_API_KEY", Provider.OPENROUTER),
    ("OPENAI_API_KEY", Provider.OPENAI),
    ("ANTHROPIC_API_KEY", Provider.ANTHROPIC),
)


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


# --- provider detection -------------------------------------------------------------------------


def provider_for_key(api_key: str, default: Provider = Provider.OPENAI) -> Provider:
    """Which provider a key belongs to, by its vendor prefix.

    ``sk-or-`` → OpenRouter, ``sk-ant-`` → Anthropic, ``sk-``/``sk-proj-`` → OpenAI. The more
    specific prefixes are checked first (they also start with ``sk-``). A key with no recognized
    prefix falls back to ``default`` (the env var the key came from, else OpenAI). Mirrors the
    dashboard's ``providerForKey`` (15.1b).
    """
    if api_key.startswith("sk-or-"):
        return Provider.OPENROUTER
    if api_key.startswith("sk-ant-"):
        return Provider.ANTHROPIC
    if api_key.startswith("sk-"):  # includes sk-proj-
        return Provider.OPENAI
    return default


# --- clients ------------------------------------------------------------------------------------


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
            raw = self.transport.request("POST", _ANTHROPIC_API_URL, body=body, headers=headers)
        except TransportError as exc:
            raise LLMError(f"Anthropic request failed: {exc}") from exc
        return _extract_anthropic_text(raw)


@dataclass(frozen=True)
class OpenAICompatibleClient:
    """An :class:`LLMClient` for the OpenAI ``/chat/completions`` shape (OpenAI or OpenRouter).

    ``base_url`` selects the endpoint, so the *same* client serves both providers — the only
    difference is the host and the model id. Auth is a standard ``Authorization: Bearer`` header.
    """

    transport: Transport
    api_key: str
    base_url: str
    model: str
    max_tokens: int = 700

    def complete(self, *, system: str, user: str) -> str:
        """POST the prompt to ``/chat/completions`` and return the first choice's text."""
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
        ).encode("utf-8")
        headers: Mapping[str, str] = {
            "content-type": "application/json",
            "authorization": f"Bearer {self.api_key}",
        }
        try:
            raw = self.transport.request("POST", self.base_url, body=body, headers=headers)
        except TransportError as exc:
            raise LLMError(f"model request failed: {exc}") from exc
        return _extract_openai_text(raw)


def _extract_anthropic_text(raw: bytes) -> str:
    """Pull the first text block out of a Messages API response, defensively."""
    payload = _load_object(raw)
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


def _extract_openai_text(raw: bytes) -> str:
    """Pull the first choice's message text out of a chat-completions response, defensively."""
    payload = _load_object(raw)
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                text = _content_text(message.get("content"))
                if text is not None:
                    return text
    raise LLMError("model response contained no message content")


def _content_text(content: object) -> str | None:
    """Coerce an OpenAI-style ``message.content`` (a string, or a list of parts) to text."""
    if isinstance(content, str):
        return content if content.strip() else None
    if isinstance(content, list):
        parts = [
            part["text"]
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        joined = "".join(parts)
        return joined if joined.strip() else None
    return None


def _load_object(raw: bytes) -> dict[str, object]:
    """Parse ``raw`` as a JSON object or raise :class:`LLMError` (the shared malformed contract)."""
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise LLMError("model response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise LLMError("model response was not an object")
    return payload


# --- builders -----------------------------------------------------------------------------------


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


@dataclass(frozen=True)
class FixClientConfig:
    """The resolved provider, key, and model for a ``fix`` client (pure, testable)."""

    provider: Provider
    api_key: str
    model: str


def resolve_fix_client_config(
    env: Mapping[str, str],
    *,
    provider_override: Provider | None = None,
    model_override: str | None = None,
) -> FixClientConfig | None:
    """Resolve the provider/key/model for ``vulnadvisor fix`` from ``env``, or ``None`` if no key.

    Key precedence: ``OPENROUTER_API_KEY`` → ``OPENAI_API_KEY`` → ``ANTHROPIC_API_KEY`` (first
    present wins). Provider: ``provider_override`` if given, else detected from the key prefix
    (falling back to the env var's implied provider). Model: ``model_override`` →
    ``VULNADVISOR_MODEL`` → ``ANTHROPIC_MODEL`` (Anthropic only, existing path) → provider default.
    """
    api_key: str | None = None
    source_provider = Provider.OPENAI
    for var, prov in _KEY_ENV_VARS:
        value = env.get(var)
        if value:
            api_key = value
            source_provider = prov
            break
    if not api_key:
        return None
    provider = provider_override or provider_for_key(api_key, default=source_provider)
    return FixClientConfig(
        provider=provider,
        api_key=api_key,
        model=_resolve_fix_model(env, provider, model_override),
    )


def _resolve_fix_model(
    env: Mapping[str, str], provider: Provider, model_override: str | None
) -> str:
    """Pick the model id: explicit flag → ``VULNADVISOR_MODEL`` → Anthropic legacy → default."""
    if model_override:
        return model_override
    generic = env.get("VULNADVISOR_MODEL")
    if generic:
        return generic
    if provider is Provider.ANTHROPIC:
        legacy = env.get("ANTHROPIC_MODEL")
        if legacy:
            return legacy
    return DEFAULT_FIX_MODEL[provider]


def build_fix_client_from_env(
    transport: Transport | None = None,
    *,
    provider_override: Provider | None = None,
    model_override: str | None = None,
    env: Mapping[str, str] | None = None,
) -> LLMClient | None:
    """Build the provider-flexible ``fix`` client from the environment, or ``None`` if no key set.

    Detects the provider from the key prefix (OpenRouter / OpenAI / Anthropic) and routes to the
    matching client over the same :class:`Transport`. The single network call still goes to the
    user's own chosen endpoint — the "code never leaves the machine otherwise" audit holds.
    """
    config = resolve_fix_client_config(
        env if env is not None else os.environ,
        provider_override=provider_override,
        model_override=model_override,
    )
    if config is None:
        return None
    transport = transport or UrllibTransport()
    if config.provider is Provider.ANTHROPIC:
        return AnthropicClient(transport, config.api_key, model=config.model)
    base_url = _OPENROUTER_API_URL if config.provider is Provider.OPENROUTER else _OPENAI_API_URL
    return OpenAICompatibleClient(
        transport=transport,
        api_key=config.api_key,
        base_url=base_url,
        model=config.model,
    )
