"""LLM: optional Anthropic layers — plain-English explanations and validated fixes.

Neither layer can affect priority: explanations are narrative only, and ``fix`` proposes a patch
that a deterministic loop must *prove* before it is ever surfaced (Task 17.1).
"""

from vulnadvisor.llm.client import (
    DEFAULT_MODEL,
    AnthropicClient,
    LLMClient,
    LLMError,
    build_anthropic_client,
)
from vulnadvisor.llm.explainer import Explainer, finding_hash
from vulnadvisor.llm.fix import (
    extract_code_context,
    generate_fix,
    parse_fix_suggestion,
    resolve_sast_finding,
    sast_finding_id,
)
from vulnadvisor.llm.fix_validate import apply_patch_to_tree, build_validator, validate_fix
from vulnadvisor.llm.prompt import build_messages, templated_explanation

__all__ = [
    "DEFAULT_MODEL",
    "AnthropicClient",
    "Explainer",
    "LLMClient",
    "LLMError",
    "apply_patch_to_tree",
    "build_anthropic_client",
    "build_messages",
    "build_validator",
    "extract_code_context",
    "finding_hash",
    "generate_fix",
    "parse_fix_suggestion",
    "resolve_sast_finding",
    "sast_finding_id",
    "templated_explanation",
    "validate_fix",
]
