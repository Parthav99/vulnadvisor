import json
from collections.abc import Callable, Mapping
from pathlib import Path

from vulnadvisor.callgraph import build_import_graph
from vulnadvisor.callgraph.call_paths import PackageReflection
from vulnadvisor.callgraph.type_resolver import (
    NullResolver,
    Probe,
    PyrightResolver,
    literals_from_type_string,
    parse_pyright_reveals,
)
from vulnadvisor.model import Dependency, DependencySource, ReachabilityTier
from vulnadvisor.reachability import compute_reachability, refine_reachability

PROJECTS = Path(__file__).resolve().parent.parent / "fixtures" / "projects"
YAML_IMPORTS = ("yaml",)
YAML_VULN = frozenset({"load"})


def _pyyaml() -> Dependency:
    return Dependency(
        name="pyyaml",
        raw_name="PyYAML",
        version="5.3.1",
        source=DependencySource.REQUIREMENTS_TXT,
    )


def _pyright_with_types(type_by_project: dict[str, str]) -> PyrightResolver:
    """A PyrightResolver whose subprocess seam is replaced by canned revealed types per project."""

    def runner(project_dir: Path, probes: tuple[Probe, ...]) -> Mapping[Probe, str]:
        type_str = type_by_project.get(project_dir.name)
        if type_str is None:
            return {}
        return {probe: type_str for probe in probes}

    return PyrightResolver(runner=runner)


def _tier(project: str, resolver: object | None) -> ReachabilityTier:
    path = PROJECTS / project
    graph = build_import_graph(path)
    base = compute_reachability(_pyyaml(), graph)
    refined = refine_reachability(_pyyaml(), base, graph, path, YAML_VULN, resolver=resolver)  # type: ignore[arg-type]
    return refined.tier


# --- pure parsing --------------------------------------------------------------------------------


def test_literals_single() -> None:
    assert literals_from_type_string('Literal["safe_load"]') == frozenset({"safe_load"})


def test_literals_union() -> None:
    assert literals_from_type_string("Literal['a', 'b']") == frozenset({"a", "b"})


def test_non_literal_types_are_unknown() -> None:
    assert literals_from_type_string("str") is None
    assert literals_from_type_string("Unknown") is None
    assert literals_from_type_string("Literal[1, 2]") is None  # int literals are not attr names
    assert literals_from_type_string("Literal[]") is None


def test_parse_pyright_reveals_matches_on_line() -> None:
    probe = Probe(file="app.py", lineno=12, expr="name")
    payload = {
        "generalDiagnostics": [
            {
                "severity": "information",
                "message": 'Type of "name" is "Literal[\'safe_load\']"',
                "range": {"start": {"line": 11, "character": 4}},  # 0-based -> probe line 12
            },
            {"severity": "error", "message": "boom", "range": {"start": {"line": 99}}},
        ]
    }
    out = parse_pyright_reveals(json.dumps(payload), {12: probe})
    assert out == {probe: "Literal['safe_load']"}


def test_parse_pyright_reveals_is_defensive() -> None:
    probe = Probe(file="app.py", lineno=1, expr="name")
    assert parse_pyright_reveals("not json", {1: probe}) == {}
    assert parse_pyright_reveals(json.dumps({"generalDiagnostics": "nope"}), {1: probe}) == {}
    # An information diagnostic on a line we did not probe is ignored.
    other = {
        "severity": "information",
        "message": 'Type of "x" is "str"',
        "range": {"start": {"line": 5}},
    }
    payload = {"generalDiagnostics": [other]}
    assert parse_pyright_reveals(json.dumps(payload), {1: probe}) == {}


# --- resolver availability / fallback ------------------------------------------------------------


def test_null_resolver_resolves_nothing() -> None:
    resolver = NullResolver()
    assert resolver.available is False
    reflection = PackageReflection(file="app.py", lineno=1, col=0, alias="yaml", name_arg="name")
    assert resolver.resolve_attrs(Path("."), reflection) is None


def test_pyright_unavailable_when_executable_absent() -> None:
    resolver = PyrightResolver(command=("pyright-does-not-exist-xyz",))
    assert resolver.available is False
    reflection = PackageReflection(file="app.py", lineno=1, col=0, alias="yaml", name_arg="name")
    assert resolver.resolve_attrs(Path("."), reflection) is None


def test_injected_runner_makes_resolver_available() -> None:
    resolver = _pyright_with_types({"reach_dynamic_resolved_safe": 'Literal["safe_load"]'})
    assert resolver.available is True


# --- the precision gate: false positives drop vs M6, with no new false negatives -----------------


def test_resolved_safe_drops_false_positive_with_types() -> None:
    # Without a resolver (M6): conservative DYNAMIC_UNKNOWN.
    assert _tier("reach_dynamic_resolved_safe", None) is ReachabilityTier.DYNAMIC_UNKNOWN
    # With type info proving getattr -> yaml.safe_load (not the vulnerable load): IMPORTED.
    resolver = _pyright_with_types({"reach_dynamic_resolved_safe": 'Literal["safe_load"]'})
    assert _tier("reach_dynamic_resolved_safe", resolver) is ReachabilityTier.IMPORTED


def test_resolved_vuln_upgrades_to_called_with_types() -> None:
    resolver = _pyright_with_types({"reach_dynamic_resolved_vuln": 'Literal["load"]'})
    tier = _tier("reach_dynamic_resolved_vuln", resolver)
    assert tier is ReachabilityTier.IMPORTED_AND_CALLED


def test_resolved_vuln_stays_dynamic_without_types() -> None:
    # Soundness: absent type info, a reflective access to the vulnerable symbol is never "safe".
    assert _tier("reach_dynamic_resolved_vuln", None) is ReachabilityTier.DYNAMIC_UNKNOWN


def test_unresolvable_dispatch_stays_dynamic_even_with_resolver() -> None:
    # getattr(yaml, func_name) where func_name is an unannotated parameter: the resolver returns no
    # type info, so we must NOT downgrade — still DYNAMIC_UNKNOWN (no false negative).
    resolver = _pyright_with_types({})  # available, but yields no types for this project
    assert _tier("reach_dynamic_dispatch", resolver) is ReachabilityTier.DYNAMIC_UNKNOWN


def test_concrete_call_path_unaffected_by_resolver() -> None:
    resolver = _pyright_with_types({"reach_called": 'Literal["load"]'})
    assert _tier("reach_called", resolver) is ReachabilityTier.IMPORTED_AND_CALLED
    assert _tier("reach_called", None) is ReachabilityTier.IMPORTED_AND_CALLED


def test_resolver_does_not_disturb_plain_imported() -> None:
    resolver = _pyright_with_types({"reach_imported_only": 'Literal["safe_load"]'})
    assert _tier("reach_imported_only", resolver) is ReachabilityTier.IMPORTED


# --- end-to-end through the pipeline -------------------------------------------------------------


def test_pipeline_applies_type_resolution(fake_matcher: Callable[..., object]) -> None:
    from vulnadvisor.cli.pipeline import scan_project

    resolver = _pyright_with_types({"reach_dynamic_resolved_safe": 'Literal["safe_load"]'})
    report = scan_project(
        PROJECTS / "reach_dynamic_resolved_safe",
        fake_matcher(),  # type: ignore[arg-type]
        symbol_names_for=lambda _advisory: YAML_VULN,
        resolver=resolver,  # type: ignore[arg-type]
    )
    assert report.findings
    assert report.findings[0].reachability is not None
    assert report.findings[0].reachability.tier is ReachabilityTier.IMPORTED
