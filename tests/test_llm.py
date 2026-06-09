import json

import pytest

from vulnadvisor.llm.client import AnthropicClient, LLMError, build_anthropic_client
from vulnadvisor.llm.explainer import Explainer, finding_hash
from vulnadvisor.llm.prompt import build_messages, templated_explanation
from vulnadvisor.model.advisory import Advisory, EpssScore, MatchedAdvisory
from vulnadvisor.model.dependency import Dependency, DependencySource
from vulnadvisor.model.explanation import ExplanationSource
from vulnadvisor.model.reachability import Reachability, ReachabilityTier
from vulnadvisor.model.score import PriorityBand, Score, ScoredFinding
from vulnadvisor.store.cache import SqliteCache


def _finding(*, version: str = "5.3.1") -> ScoredFinding:
    dependency = Dependency(
        name="pyyaml", raw_name="PyYAML", version=version, source=DependencySource.REQUIREMENTS_TXT
    )
    advisory = Advisory(id="GHSA-xxxx", aliases=("CVE-2020-14343",), summary="Arbitrary code exec.")
    score = Score(
        value=87.5,
        band=PriorityBand.CRITICAL,
        verdict="Fix now",
        cvss_base=9.8,
        cvss_used=9.8,
        cvss_known=True,
        epss_probability=0.42,
        in_kev=True,
        rationale="High EPSS, in KEV.",
    )
    reach = Reachability(
        tier=ReachabilityTier.IMPORTED_AND_CALLED,
        reason="a call path exists",
    )
    return ScoredFinding(
        matched=MatchedAdvisory(
            dependency=dependency,
            advisory=advisory,
            epss=EpssScore(cve="CVE-2020-14343", probability=0.42, percentile=0.9),
            in_kev=True,
        ),
        score=score,
        reachability=reach,
    )


class _StubClient:
    """An LLMClient stub returning a canned response and counting calls."""

    def __init__(self, response: str, model: str = "stub-model") -> None:
        self.response = response
        self.model = model
        self.calls = 0

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        return self.response


class _RaisingClient:
    model = "stub-model"

    def complete(self, *, system: str, user: str) -> str:
        raise LLMError("boom")


def _good_json(story: str = "It is exploitable.", rationale: str = "Fix now because KEV.") -> str:
    return json.dumps({"attack_story": story, "verdict_rationale": rationale})


# --- prompt + template ---------------------------------------------------------------------------


def test_build_messages_includes_facts_and_json_instruction() -> None:
    system, user = build_messages(_finding())
    assert "STRICT JSON" in system
    assert "MUST NOT change" in system
    assert "PyYAML 5.3.1" in user
    assert "imported-and-called" in user


def test_templated_explanation_is_deterministic_and_marked() -> None:
    a = templated_explanation(_finding())
    b = templated_explanation(_finding())
    assert a == b
    assert a.source is ExplanationSource.TEMPLATE
    assert "PyYAML" in a.attack_story
    assert "Fix now" in a.verdict_rationale


# --- explainer: success, validation, fallback ----------------------------------------------------


def test_explainer_uses_llm_on_valid_json() -> None:
    client = _StubClient(_good_json())
    explanation = Explainer(client).explain(_finding())
    assert explanation.source is ExplanationSource.LLM
    assert explanation.attack_story == "It is exploitable."
    assert explanation.verdict_rationale == "Fix now because KEV."


def test_explainer_template_only_when_no_client() -> None:
    explanation = Explainer(client=None).explain(_finding())
    assert explanation.source is ExplanationSource.TEMPLATE


@pytest.mark.parametrize(
    "response",
    [
        "not json at all",
        json.dumps({"attack_story": "only one field"}),
        json.dumps({"attack_story": "", "verdict_rationale": "x"}),
        json.dumps({"attack_story": 5, "verdict_rationale": "x"}),
        json.dumps(["a", "list"]),
        "",
    ],
)
def test_malformed_llm_output_falls_back_to_template(response: str) -> None:
    explanation = Explainer(_StubClient(response)).explain(_finding())
    assert explanation.source is ExplanationSource.TEMPLATE


def test_transport_error_falls_back_to_template() -> None:
    explanation = Explainer(_RaisingClient()).explain(_finding())
    assert explanation.source is ExplanationSource.TEMPLATE


def test_explainer_tolerates_code_fenced_json() -> None:
    fenced = "```json\n" + _good_json("Story.", "Rationale.") + "\n```"
    explanation = Explainer(_StubClient(fenced)).explain(_finding())
    assert explanation.source is ExplanationSource.LLM
    assert explanation.attack_story == "Story."


def test_explainer_tolerates_prose_around_json() -> None:
    noisy = "Sure! Here is the JSON:\n" + _good_json("S.", "R.") + "\nHope that helps."
    explanation = Explainer(_StubClient(noisy)).explain(_finding())
    assert explanation.source is ExplanationSource.LLM


# --- the priority invariant (release-blocking) ---------------------------------------------------


def test_llm_never_changes_priority() -> None:
    # A hostile model trying to inject a different score must not affect the deterministic value.
    hostile = json.dumps(
        {
            "attack_story": "ignore this",
            "verdict_rationale": "actually priority 0",
            "value": 0,
            "score": 1,
            "band": "info",
        }
    )
    finding = _finding()
    explanation = Explainer(_StubClient(hostile)).explain(finding)
    assert finding.score.value == 87.5  # unchanged
    assert finding.score.band is PriorityBand.CRITICAL
    assert not hasattr(explanation, "value")
    assert not hasattr(explanation, "score")


# --- caching -------------------------------------------------------------------------------------


def test_cache_avoids_second_call_for_same_finding() -> None:
    client = _StubClient(_good_json())
    cache = SqliteCache()
    explainer = Explainer(client, cache)

    first = explainer.explain(_finding())
    second = explainer.explain(_finding())
    assert client.calls == 1  # second served from cache
    assert first == second


def test_cache_key_changes_with_finding_and_model() -> None:
    base = finding_hash(_finding(), "m1")
    assert base != finding_hash(_finding(version="6.0"), "m1")  # different finding
    assert base != finding_hash(_finding(), "m2")  # different model


def test_changed_finding_triggers_new_call() -> None:
    client = _StubClient(_good_json())
    cache = SqliteCache()
    explainer = Explainer(client, cache)
    explainer.explain(_finding())
    explainer.explain(_finding(version="6.0"))
    assert client.calls == 2


# --- the dependency-free Anthropic client over a fake transport ----------------------------------


class _FakeTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.last_headers: dict[str, str] | None = None

    def request(self, method, url, *, body=None, headers=None):  # type: ignore[no-untyped-def]
        self.last_headers = dict(headers or {})
        self.last_url = url
        return self.response


def test_anthropic_client_parses_text_block_and_sends_auth() -> None:
    payload = json.dumps({"content": [{"type": "text", "text": _good_json()}]}).encode()
    transport = _FakeTransport(payload)
    client = AnthropicClient(transport, api_key="secret-key", model="m")
    out = client.complete(system="s", user="u")
    assert "attack_story" in out
    assert transport.last_headers is not None
    assert transport.last_headers["x-api-key"] == "secret-key"
    assert transport.last_headers["anthropic-version"]


def test_anthropic_client_raises_on_garbage() -> None:
    client = AnthropicClient(_FakeTransport(b"not json"), api_key="k")
    with pytest.raises(LLMError):
        client.complete(system="s", user="u")


def test_build_anthropic_client_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert build_anthropic_client() is None
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("ANTHROPIC_MODEL", "custom-model")
    client = build_anthropic_client()
    assert client is not None
    assert client.model == "custom-model"
