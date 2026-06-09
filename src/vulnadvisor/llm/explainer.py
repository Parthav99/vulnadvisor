"""Orchestrate explanation: cache -> LLM (strict-validated) -> deterministic template fallback.

The explainer is the only thing that talks to the model, and it can never affect priority: it
returns narrative text alongside the already-scored finding. Every failure mode — no client, no
key, transport error, non-JSON, schema-invalid, empty — resolves to the template, so Card A always
renders. Successful LLM results are cached by a content hash of the finding so repeat runs are free
and deterministic.
"""

import hashlib
import json

from vulnadvisor.llm.client import LLMClient, LLMError
from vulnadvisor.llm.prompt import build_messages, templated_explanation
from vulnadvisor.model.explanation import Explanation, ExplanationSource
from vulnadvisor.model.score import ScoredFinding
from vulnadvisor.store.cache import SqliteCache

__all__ = ["Explainer", "finding_hash"]

_MAX_STORY_CHARS = 700
_MAX_RATIONALE_CHARS = 240
_CACHE_PREFIX = "llm-explanation:v1"


def finding_hash(finding: ScoredFinding, model: str) -> str:
    """Return a stable content hash of the inputs that determine the explanation.

    Includes the model id so switching models re-generates rather than serving a stale story.
    """
    advisory = finding.matched.advisory
    dependency = finding.matched.dependency
    score = finding.score
    reachability = finding.reachability
    signature = {
        "model": model,
        "package": dependency.raw_name or dependency.name,
        "version": dependency.version,
        "advisory": advisory.id,
        "summary": advisory.summary or advisory.details or "",
        "verdict": score.verdict,
        "band": score.band.value,
        "value": round(score.value, 2),
        "epss": score.epss_probability,
        "kev": score.in_kev,
        "tier": reachability.tier.value if reachability is not None else None,
        "path": reachability.call_paths[0].render()
        if reachability is not None and reachability.call_paths
        else None,
    }
    blob = json.dumps(signature, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class Explainer:
    """Produce an :class:`Explanation` for a finding, with caching and a safe fallback."""

    def __init__(self, client: LLMClient | None = None, cache: SqliteCache | None = None) -> None:
        """Configure the optional LLM ``client`` (template-only when ``None``) and ``cache``."""
        self._client = client
        self._cache = cache

    def explain(self, finding: ScoredFinding) -> Explanation:
        """Return the explanation for ``finding`` (cache, then model, then template)."""
        if self._client is None:
            return templated_explanation(finding)

        key = f"{_CACHE_PREFIX}:{finding_hash(finding, self._client.model)}"
        if self._cache is not None:
            cached = self._cache.get(key)
            parsed = _from_cache(cached) if cached is not None else None
            if parsed is not None:
                return parsed

        system, user = build_messages(finding)
        try:
            raw = self._client.complete(system=system, user=user)
        except LLMError:
            return templated_explanation(finding)

        explanation = _parse_response(raw)
        if explanation is None:
            return templated_explanation(finding)
        if self._cache is not None:
            self._cache.set(key, explanation.model_dump_json(), ttl=-1)
        return explanation


def _from_cache(value: str) -> Explanation | None:
    """Deserialize a cached explanation, tolerating corruption (treat as a miss)."""
    try:
        return Explanation.model_validate_json(value)
    except ValueError:
        return None


def _parse_response(raw: str) -> Explanation | None:
    """Strictly validate the model's text into an :class:`Explanation`, else ``None``."""
    obj = _extract_json_object(raw)
    if obj is None:
        return None
    story = obj.get("attack_story")
    rationale = obj.get("verdict_rationale")
    if not isinstance(story, str) or not isinstance(rationale, str):
        return None
    story, rationale = story.strip(), rationale.strip()
    if not story or not rationale:
        return None
    return Explanation(
        attack_story=_clip(story, _MAX_STORY_CHARS),
        verdict_rationale=_clip(rationale, _MAX_RATIONALE_CHARS),
        source=ExplanationSource.LLM,
    )


def _extract_json_object(text: str) -> dict[str, object] | None:
    """Parse a JSON object from model text, tolerating code fences or surrounding prose."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Drop a leading ```json / ``` fence and any trailing fence.
        cleaned = cleaned.split("```", 2)[1] if cleaned.count("```") >= 2 else cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    for candidate in (cleaned, _braced_span(cleaned)):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _braced_span(text: str) -> str | None:
    """Return the substring from the first ``{`` to the last ``}``, if both are present."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start : end + 1]


def _clip(value: str, limit: int) -> str:
    """Truncate ``value`` to ``limit`` characters with an ellipsis if needed."""
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."
