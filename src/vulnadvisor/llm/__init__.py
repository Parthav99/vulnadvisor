"""LLM: optional Anthropic plain-English explanation layer (never affects priority)."""

from vulnadvisor.llm.client import (
    DEFAULT_MODEL,
    AnthropicClient,
    LLMClient,
    LLMError,
    build_anthropic_client,
)
from vulnadvisor.llm.explainer import Explainer, finding_hash
from vulnadvisor.llm.prompt import build_messages, templated_explanation

__all__ = [
    "DEFAULT_MODEL",
    "AnthropicClient",
    "Explainer",
    "LLMClient",
    "LLMError",
    "build_anthropic_client",
    "build_messages",
    "finding_hash",
    "templated_explanation",
]
