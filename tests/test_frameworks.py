import ast
from collections.abc import Callable
from pathlib import Path

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.callgraph import (
    DjangoPlugin,
    FastAPIPlugin,
    build_import_graph,
    collect_entry_points,
    entry_point_names,
    find_vulnerable_call_paths,
)
from vulnadvisor.callgraph.frameworks.base import FrameworkPlugin
from vulnadvisor.cli.pipeline import ScanReport, scan_project
from vulnadvisor.model import Dependency, DependencySource, ReachabilityTier
from vulnadvisor.model.reachability import Reachability
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


def _parse(rel: str) -> ast.Module:
    return ast.parse((PROJECTS / rel).read_text(encoding="utf-8"))


# --- plugin detection (unit) ---------------------------------------------------------------------


def test_fastapi_plugin_detects_route_handler() -> None:
    eps = FastAPIPlugin().entry_points(_parse("fastapi_app/app.py"), "app.py")
    assert {ep.name for ep in eps} == {"read_config"}
    assert eps[0].framework == "fastapi"


def test_fastapi_plugin_ignores_plain_functions() -> None:
    tree = ast.parse("def helper():\n    return 1\n")
    assert FastAPIPlugin().entry_points(tree, "x.py") == []


def test_django_plugin_detects_urlconf_view() -> None:
    eps = DjangoPlugin().entry_points(_parse("django_app/urls.py"), "urls.py")
    assert {ep.name for ep in eps} == {"parse_config"}
    assert eps[0].framework == "django"


def test_django_plugin_detects_signal_receiver() -> None:
    tree = ast.parse(
        "from django.dispatch import receiver\n\n\n"
        "@receiver(post_save)\ndef on_save(sender, **kw):\n    pass\n"
    )
    assert {ep.name for ep in DjangoPlugin().entry_points(tree, "signals.py")} == {"on_save"}


def test_django_plugin_detects_class_based_view() -> None:
    tree = ast.parse(
        "from django.urls import path\nfrom . import views\n\n"
        "urlpatterns = [path('x/', views.ConfigView.as_view())]\n"
    )
    assert {ep.name for ep in DjangoPlugin().entry_points(tree, "urls.py")} == {"ConfigView"}


# --- collection + plugin isolation ---------------------------------------------------------------


def _names(project: str, plugins: list[FrameworkPlugin]) -> frozenset[str]:
    return entry_point_names(collect_entry_points(PROJECTS / project, plugins))


def test_collect_with_all_plugins() -> None:
    assert _names("fastapi_app", [FastAPIPlugin(), DjangoPlugin()]) == frozenset({"read_config"})
    assert _names("django_app", [FastAPIPlugin(), DjangoPlugin()]) == frozenset({"parse_config"})


def test_plugins_are_isolated() -> None:
    # Disabling a plugin removes only its findings; the other is unaffected.
    assert _names("fastapi_app", [FastAPIPlugin()]) == frozenset({"read_config"})
    assert _names("fastapi_app", [DjangoPlugin()]) == frozenset()
    assert _names("django_app", [DjangoPlugin()]) == frozenset({"parse_config"})
    assert _names("django_app", [FastAPIPlugin()]) == frozenset()


# --- call-path rooting at the framework entry ----------------------------------------------------


def test_fastapi_path_rooted_at_handler() -> None:
    rooted = find_vulnerable_call_paths(
        PROJECTS / "fastapi_app",
        import_names=YAML_IMPORTS,
        vulnerable_names=YAML_VULN,
        entry_points={"read_config"},
    )
    assert rooted.paths
    assert rooted.paths[0].steps[0].qualname == "read_config"

    # Without the entry point the handler is not a root; the path falls back below the handler.
    bare = find_vulnerable_call_paths(
        PROJECTS / "fastapi_app", import_names=YAML_IMPORTS, vulnerable_names=YAML_VULN
    )
    assert bare.paths
    assert bare.paths[0].steps[0].qualname != "read_config"


def test_django_path_rooted_at_view() -> None:
    rooted = find_vulnerable_call_paths(
        PROJECTS / "django_app",
        import_names=YAML_IMPORTS,
        vulnerable_names=YAML_VULN,
        entry_points={"parse_config"},
    )
    assert rooted.paths
    assert rooted.paths[0].steps[0].qualname == "parse_config"
    assert "yaml.load" in rooted.paths[0].render()


# --- end-to-end: framework-routed reachable vuln is detected -------------------------------------


def _refined_tier(project: str, plugins: list[FrameworkPlugin]) -> ReachabilityTier:
    path = PROJECTS / project
    graph = build_import_graph(path)
    base = compute_reachability(_pyyaml(), graph)
    entry_points = entry_point_names(collect_entry_points(path, plugins))
    refined = refine_reachability(
        _pyyaml(), base, graph, path, YAML_VULN, entry_points=entry_points
    )
    return refined.tier


def test_fastapi_route_vuln_is_reachable() -> None:
    assert _refined_tier("fastapi_app", [FastAPIPlugin()]) is ReachabilityTier.IMPORTED_AND_CALLED


def test_django_view_vuln_is_reachable() -> None:
    assert _refined_tier("django_app", [DjangoPlugin()]) is ReachabilityTier.IMPORTED_AND_CALLED


def _pyyaml_reach(report: ScanReport) -> Reachability:
    for finding in report.findings:
        if finding.matched.dependency.name == "pyyaml":
            assert finding.reachability is not None
            return finding.reachability
    raise AssertionError("no pyyaml finding in report")


def test_pipeline_roots_path_at_handler(fake_matcher: Callable[..., AdvisoryMatcher]) -> None:
    report = scan_project(
        PROJECTS / "fastapi_app",
        fake_matcher(),
        symbol_names_for=lambda _advisory: YAML_VULN,
    )
    reach = _pyyaml_reach(report)
    assert reach.tier is ReachabilityTier.IMPORTED_AND_CALLED
    assert reach.call_paths[0].steps[0].qualname == "read_config"


def test_pipeline_without_frameworks_does_not_root_at_handler(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    report = scan_project(
        PROJECTS / "fastapi_app",
        fake_matcher(),
        symbol_names_for=lambda _advisory: YAML_VULN,
        frameworks=[],  # framework awareness disabled
    )
    reach = _pyyaml_reach(report)
    # Still detected (the fallback never drops a real call), but not rooted at the handler.
    assert reach.tier is ReachabilityTier.IMPORTED_AND_CALLED
    assert reach.call_paths[0].steps[0].qualname != "read_config"
