import json

import pytest

from vulnadvisor.llm.client import (
    DEFAULT_FIX_MODEL,
    AnthropicClient,
    LLMError,
    OpenAICompatibleClient,
    Provider,
    build_anthropic_client,
    build_fix_client_from_env,
    provider_for_key,
    resolve_fix_client_config,
)
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


# --- Task 17.3: provider-flexible fix client (OpenRouter / OpenAI / Anthropic) -------------------


class _RecordingTransport:
    """A Transport that records every outbound URL and replays a canned chat-completions body."""

    def __init__(self, response: bytes) -> None:
        self.response = response
        self.urls: list[str] = []
        self.headers: list[dict[str, str]] = []

    def request(self, method, url, *, body=None, headers=None):  # type: ignore[no-untyped-def]
        self.urls.append(url)
        self.headers.append(dict(headers or {}))
        return self.response


@pytest.mark.parametrize(
    "key,expected",
    [
        ("sk-or-v1-abc", Provider.OPENROUTER),
        ("sk-ant-api03-xyz", Provider.ANTHROPIC),
        ("sk-proj-123", Provider.OPENAI),
        ("sk-classic", Provider.OPENAI),
        ("nopfx", Provider.OPENAI),  # unrecognized -> default
    ],
)
def test_provider_for_key_by_prefix(key: str, expected: Provider) -> None:
    assert provider_for_key(key) is expected


def test_provider_for_key_unrecognized_uses_supplied_default() -> None:
    assert provider_for_key("weirdkey", default=Provider.OPENROUTER) is Provider.OPENROUTER


def test_resolve_config_key_precedence_openrouter_first() -> None:
    env = {
        "OPENROUTER_API_KEY": "sk-or-1",
        "OPENAI_API_KEY": "sk-proj-2",
        "ANTHROPIC_API_KEY": "sk-ant-3",
    }
    config = resolve_fix_client_config(env)
    assert config is not None
    assert config.provider is Provider.OPENROUTER
    assert config.api_key == "sk-or-1"
    assert config.model == DEFAULT_FIX_MODEL[Provider.OPENROUTER]


def test_resolve_config_falls_through_to_anthropic() -> None:
    config = resolve_fix_client_config({"ANTHROPIC_API_KEY": "sk-ant-3"})
    assert config is not None
    assert config.provider is Provider.ANTHROPIC
    assert config.model == DEFAULT_FIX_MODEL[Provider.ANTHROPIC]


def test_resolve_config_openai_default_model() -> None:
    config = resolve_fix_client_config({"OPENAI_API_KEY": "sk-proj-2"})
    assert config is not None
    assert config.provider is Provider.OPENAI
    assert config.model == DEFAULT_FIX_MODEL[Provider.OPENAI]


def test_resolve_config_no_key_returns_none() -> None:
    assert resolve_fix_client_config({}) is None


def test_resolve_config_provider_override_wins_over_prefix() -> None:
    # An Anthropic-looking key forced onto OpenRouter (e.g. a proxy) honours the override.
    config = resolve_fix_client_config(
        {"ANTHROPIC_API_KEY": "sk-ant-3"}, provider_override=Provider.OPENROUTER
    )
    assert config is not None
    assert config.provider is Provider.OPENROUTER
    assert config.model == DEFAULT_FIX_MODEL[Provider.OPENROUTER]


def test_resolve_config_model_override_wins() -> None:
    config = resolve_fix_client_config(
        {"OPENROUTER_API_KEY": "sk-or-1"}, model_override="meta-llama/llama-3:free"
    )
    assert config is not None
    assert config.model == "meta-llama/llama-3:free"


def test_resolve_config_vulnadvisor_model_env_override() -> None:
    config = resolve_fix_client_config(
        {"OPENROUTER_API_KEY": "sk-or-1", "VULNADVISOR_MODEL": "anthropic/claude-3:beta"}
    )
    assert config is not None
    assert config.model == "anthropic/claude-3:beta"


def test_resolve_config_explicit_model_beats_vulnadvisor_env() -> None:
    config = resolve_fix_client_config(
        {"OPENAI_API_KEY": "sk-proj-2", "VULNADVISOR_MODEL": "env-model"},
        model_override="flag-model",
    )
    assert config is not None
    assert config.model == "flag-model"


def test_resolve_config_anthropic_legacy_model_env_preserved() -> None:
    # The existing ANTHROPIC_MODEL path still works for an Anthropic key (no VULNADVISOR_MODEL).
    config = resolve_fix_client_config(
        {"ANTHROPIC_API_KEY": "sk-ant-3", "ANTHROPIC_MODEL": "claude-legacy"}
    )
    assert config is not None
    assert config.model == "claude-legacy"


def test_build_fix_client_openrouter_is_openai_compatible() -> None:
    client = build_fix_client_from_env(env={"OPENROUTER_API_KEY": "sk-or-1"})
    assert isinstance(client, OpenAICompatibleClient)
    assert client.base_url == "https://openrouter.ai/api/v1/chat/completions"
    assert client.model == "openrouter/auto"


def test_build_fix_client_openai_endpoint() -> None:
    client = build_fix_client_from_env(env={"OPENAI_API_KEY": "sk-proj-2"})
    assert isinstance(client, OpenAICompatibleClient)
    assert client.base_url == "https://api.openai.com/v1/chat/completions"


def test_build_fix_client_anthropic_uses_messages_client() -> None:
    client = build_fix_client_from_env(env={"ANTHROPIC_API_KEY": "sk-ant-3"})
    assert isinstance(client, AnthropicClient)


def test_build_fix_client_no_key_is_none() -> None:
    assert build_fix_client_from_env(env={}) is None


def test_openai_client_parses_choice_and_sends_bearer_auth() -> None:
    payload = json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": _good_json()}}]}
    ).encode()
    transport = _RecordingTransport(payload)
    client = OpenAICompatibleClient(
        transport=transport,
        api_key="sk-or-secret",
        base_url="https://openrouter.ai/api/v1/chat/completions",
        model="openrouter/auto",
    )
    out = client.complete(system="s", user="u")
    assert "attack_story" in out
    assert transport.headers[0]["authorization"] == "Bearer sk-or-secret"
    assert transport.urls == ["https://openrouter.ai/api/v1/chat/completions"]


def test_openai_client_accepts_list_content_parts() -> None:
    payload = json.dumps(
        {"choices": [{"message": {"content": [{"type": "text", "text": "hello"}]}}]}
    ).encode()
    client = OpenAICompatibleClient(
        transport=_RecordingTransport(payload),
        api_key="sk-or-1",
        base_url="https://openrouter.ai/api/v1/chat/completions",
        model="m",
    )
    assert client.complete(system="s", user="u") == "hello"


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        json.dumps({"choices": []}).encode(),  # empty choices
        json.dumps({"choices": [{}]}).encode(),  # no message
        json.dumps({"choices": [{"message": {}}]}).encode(),  # no content
        json.dumps({"choices": [{"message": {"content": ""}}]}).encode(),  # blank content
        json.dumps({"choices": [{"message": {"content": 5}}]}).encode(),  # non-string content
        json.dumps(["a", "list"]).encode(),  # not an object
    ],
)
def test_openai_client_malformed_raises_llm_error(body: bytes) -> None:
    client = OpenAICompatibleClient(
        transport=_RecordingTransport(body),
        api_key="sk-or-1",
        base_url="https://openrouter.ai/api/v1/chat/completions",
        model="m",
    )
    with pytest.raises(LLMError):
        client.complete(system="s", user="u")


def test_openrouter_network_audit_never_contacts_anthropic() -> None:
    """A built OpenRouter client's only outbound host is openrouter.ai — never api.anthropic.com."""
    payload = json.dumps({"choices": [{"message": {"content": _good_json()}}]}).encode()
    transport = _RecordingTransport(payload)
    client = build_fix_client_from_env(transport=transport, env={"OPENROUTER_API_KEY": "sk-or-1"})
    assert client is not None
    client.complete(system="s", user="u")
    assert transport.urls, "expected the model to be called"
    assert all("openrouter.ai" in url for url in transport.urls)
    assert all("api.anthropic.com" not in url for url in transport.urls)
