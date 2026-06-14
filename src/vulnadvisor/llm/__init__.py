"""LLM: optional, provider-flexible layers — plain-English explanations and validated fixes.

Neither layer can affect priority: explanations are narrative only, and ``fix`` proposes a patch
that a deterministic loop must *prove* before it is ever surfaced (Task 17.1). The ``fix`` loop is
provider-flexible (OpenRouter / OpenAI / Anthropic — Task 17.3); a free OpenRouter key is enough.
"""

from vulnadvisor.llm.client import (
    DEFAULT_MODEL,
    AnthropicClient,
    FixClientConfig,
    LLMClient,
    LLMError,
    OpenAICompatibleClient,
    Provider,
    build_anthropic_client,
    build_fix_client_from_env,
    provider_for_key,
    resolve_fix_client_config,
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
    "FixClientConfig",
    "LLMClient",
    "LLMError",
    "OpenAICompatibleClient",
    "Provider",
    "apply_patch_to_tree",
    "build_anthropic_client",
    "build_fix_client_from_env",
    "build_messages",
    "build_validator",
    "extract_code_context",
    "finding_hash",
    "generate_fix",
    "parse_fix_suggestion",
    "provider_for_key",
    "resolve_fix_client_config",
    "resolve_sast_finding",
    "sast_finding_id",
    "templated_explanation",
    "validate_fix",
]
