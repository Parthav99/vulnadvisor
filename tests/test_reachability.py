from collections.abc import Callable
from pathlib import Path

import pytest

from vulnadvisor.advisories import AdvisoryMatcher
from vulnadvisor.callgraph import build_import_graph
from vulnadvisor.cli.pipeline import scan_project
from vulnadvisor.engine.scoring import apply_reachability, compute_score, score_match
from vulnadvisor.model import (
    Advisory,
    Dependency,
    DependencySource,
    EpssScore,
    MatchedAdvisory,
    PriorityBand,
    Reachability,
    ReachabilityTier,
)
from vulnadvisor.reachability import compute_reachability

PROJECTS = Path(__file__).resolve().parent.parent / "fixtures" / "projects"


def _pyyaml() -> Dependency:
    return Dependency(
        name="pyyaml",
        raw_name="PyYAML",
        version="6.0",
        source=DependencySource.REQUIREMENTS_TXT,
    )


# --- security-critical tiering gate (Fixtures A / B / C) ---------------------------------------


def test_fixture_a_imported() -> None:
    graph = build_import_graph(PROJECTS / "reach_imported")
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.IMPORTED
    assert reach.evidence  # shows the import site as evidence
    assert reach.evidence[0].file == "app.py"


def test_fixture_b_not_imported() -> None:
    graph = build_import_graph(PROJECTS / "reach_not_imported")
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.NOT_IMPORTED
    assert "no path" in reach.reason.lower()


def test_fixture_c_dynamic_unknown() -> None:
    graph = build_import_graph(PROJECTS / "reach_dynamic")
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN
    assert reach.dynamic_evidence  # the importlib site is recorded


def test_zero_false_negatives_across_fixture_suite() -> None:
    # Release-blocking invariant: a reachable/uncertain package is NEVER marked confidently safe.
    for project in ("reach_imported", "reach_dynamic"):
        graph = build_import_graph(PROJECTS / project)
        reach = compute_reachability(_pyyaml(), graph)
        assert reach.tier is not ReachabilityTier.NOT_IMPORTED, project


# --- escalation safeguards --------------------------------------------------------------------


def test_no_source_files_escalates_to_dynamic_unknown(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("PyYAML==6.0\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


def test_parse_error_blocks_not_imported(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


def test_low_confidence_mapping_blocks_not_imported(tmp_path: Path) -> None:
    # An unknown distribution resolves to a LOW-confidence best-guess import name; if we do not
    # find it, we must not claim NOT_IMPORTED (the real import name might differ).
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    unknown = Dependency(
        name="totally-unknown-xyz",
        raw_name="totally-unknown-xyz",
        version="1.0",
        source=DependencySource.REQUIREMENTS_TXT,
    )
    reach = compute_reachability(unknown, graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


# --- first-party dynamic-import resolution (Task 10.3, security-critical) ----------------------
#
# A plugin loader that provably targets only the project's own modules cannot import an unused
# third-party distribution, so it must not block NOT_IMPORTED. Anything not provably first-party
# (bare variable, exec, or a constant third-party target) must STILL escalate — soundness first.


def _app_with_loader(tmp_path: Path, loader_body: str) -> Path:
    """Write a first-party package ``app`` whose loader.py has ``loader_body``; PyYAML unused."""
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "loader.py").write_text("import importlib\n\n\n" + loader_body, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "loader_body",
    [
        # f-string prefixed by the current module name -> within the first-party package
        'def load(name):\n    return importlib.import_module(f"{__name__}.{name}")\n',
        # constant first-party prefix via concatenation
        'def load(name):\n    return importlib.import_module("app." + name)\n',
        # leading-dot relative target resolved against the package
        'def load(name):\n    return importlib.import_module("." + name, __package__)\n',
        # __import__ of a constant first-party dotted module
        'def load():\n    return __import__("app.plugins")\n',
    ],
)
def test_first_party_only_loader_allows_not_imported(tmp_path: Path, loader_body: str) -> None:
    graph = build_import_graph(_app_with_loader(tmp_path, loader_body))
    assert graph.dynamic_sites  # the loader IS detected as a dynamic site
    assert not graph.unproven_dynamic_sites()  # ...but it is proven first-party-only
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.NOT_IMPORTED


@pytest.mark.parametrize(
    "loader_body",
    [
        # opaque bare-variable target: could be any module at runtime
        "def load(name):\n    return importlib.import_module(name)\n",
        # bare-variable __import__
        "def load(name):\n    return __import__(name)\n",
        # exec runs arbitrary code -> could import anything
        "def run(code):\n    exec(code)\n",
        # constant THIRD-PARTY target: provably reaches a non-first-party distribution
        'def load():\n    return importlib.import_module("requests")\n',
        # f-string with a non-dotted constant prefix: leading segment is not fully determined
        'def load(x):\n    return importlib.import_module(f"app{x}")\n',
    ],
)
def test_unproven_loader_still_blocks_not_imported(tmp_path: Path, loader_body: str) -> None:
    graph = build_import_graph(_app_with_loader(tmp_path, loader_body))
    assert graph.unproven_dynamic_sites()  # not provably first-party -> stays conservative
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


@pytest.mark.parametrize("rel", ["docs/conf.py", "setup.py", "docs/source/extra.py"])
def test_non_runtime_eval_does_not_block_not_imported(tmp_path: Path, rel: str) -> None:
    # A Sphinx conf.py / setup.py eval runs only at build/docs time, never in the deployed app,
    # so it cannot make a runtime dependency vulnerability reachable.
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("exec(open('x').read())\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    assert graph.dynamic_sites and not graph.dynamic_sites[0].runtime
    assert not graph.unproven_dynamic_sites()
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.NOT_IMPORTED


def test_runtime_eval_still_blocks_not_imported(tmp_path: Path) -> None:
    # The same eval in genuine runtime code (not docs/setup) must still escalate.
    (tmp_path / "app.py").write_text("exec(open('x').read())\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    assert graph.unproven_dynamic_sites()
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


def test_non_runtime_static_import_still_counts(tmp_path: Path) -> None:
    # Relaxing dynamic-site caution must NOT hide a real static import in a non-runtime file.
    (tmp_path / "setup.py").write_text("import yaml\n", encoding="utf-8")
    graph = build_import_graph(tmp_path)
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.IMPORTED


# --- bounded loader / framework-import detection (Task 10.3, false-negative vectors) -----------


@pytest.mark.parametrize(
    "body",
    [
        # bare import_module (from importlib import import_module) — previously a detection gap
        "from importlib import import_module\n\n\ndef load(n):\n    return import_module(n)\n",
        # custom file loader wrapping imp.load_source — searx's pattern
        "from imp import load_source\n\n\ndef load(f, d):\n    return load_source(f, d)\n",
        # importlib.util spec-based file loader
        "import importlib.util as u\n\n\ndef load(p):\n"
        "    return u.spec_from_file_location('m', p)\n",
        # pkgutil plugin discovery
        "import pkgutil\n\n\ndef discover(path):\n    return list(pkgutil.walk_packages(path))\n",
    ],
)
def test_bounded_loaders_are_detected_and_block(tmp_path: Path, body: str) -> None:
    (tmp_path / "app.py").write_text(body, encoding="utf-8")
    graph = build_import_graph(tmp_path)
    assert graph.unproven_dynamic_sites()  # the loader is detected and forces caution
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


def test_installed_apps_literal_counts_as_imported(tmp_path: Path) -> None:
    # Django imports every INSTALLED_APPS entry by string at startup, so a package listed there is
    # used even with no first-party `import` — it must not be deprioritized to NOT_IMPORTED.
    (tmp_path / "settings.py").write_text(
        'INSTALLED_APPS = [\n    "django.contrib.admin",\n    "yaml",\n]\n', encoding="utf-8"
    )
    graph = build_import_graph(tmp_path)
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.IMPORTED


def test_split_settings_apps_list_counts_as_imported(tmp_path: Path) -> None:
    # The common split-settings pattern: a THIRD_PARTY_APPS list later spread into INSTALLED_APPS.
    (tmp_path / "settings.py").write_text(
        'THIRD_PARTY_APPS = ("yaml",)\nINSTALLED_APPS = THIRD_PARTY_APPS\n', encoding="utf-8"
    )
    graph = build_import_graph(tmp_path)
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.IMPORTED


def test_one_opaque_site_escalates_despite_first_party_loaders(tmp_path: Path) -> None:
    # Soundness: a single unproven site anywhere keeps the whole project conservative.
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "good.py").write_text(
        "import importlib\n\n\ndef load(n):\n"
        '    return importlib.import_module(f"{__name__}.{n}")\n',
        encoding="utf-8",
    )
    (pkg / "bad.py").write_text(
        "import importlib\n\n\ndef load(n):\n    return importlib.import_module(n)\n",
        encoding="utf-8",
    )
    graph = build_import_graph(tmp_path)
    assert len(graph.unproven_dynamic_sites()) == 1
    reach = compute_reachability(_pyyaml(), graph)
    assert reach.tier is ReachabilityTier.DYNAMIC_UNKNOWN


# --- engine wiring ----------------------------------------------------------------------------


def _matched() -> MatchedAdvisory:
    return MatchedAdvisory(
        dependency=_pyyaml(),
        advisory=Advisory(id="GHSA-x", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        epss=EpssScore(cve="CVE-0000-0001", probability=0.9, percentile=0.99),
        in_kev=True,
    )


def _reach(tier: ReachabilityTier) -> Reachability:
    return Reachability(tier=tier, reason="test")


def test_not_imported_is_deprioritized() -> None:
    base = compute_score(cvss_base=9.8, epss_probability=0.9, in_kev=True)
    adjusted = apply_reachability(base, _reach(ReachabilityTier.NOT_IMPORTED))
    assert adjusted.value < base.value
    assert adjusted.band is PriorityBand.INFO
    assert adjusted.verdict == "No path from your code"


def test_dynamic_unknown_keeps_full_priority() -> None:
    base = compute_score(cvss_base=9.8, epss_probability=0.9, in_kev=True)
    adjusted = apply_reachability(base, _reach(ReachabilityTier.DYNAMIC_UNKNOWN))
    assert adjusted.value == base.value  # never silently downgraded
    assert "DYNAMIC-UNKNOWN" in adjusted.rationale


def test_imported_keeps_full_priority() -> None:
    base = compute_score(cvss_base=9.8, epss_probability=0.9, in_kev=True)
    adjusted = apply_reachability(base, _reach(ReachabilityTier.IMPORTED))
    assert adjusted.value == base.value
    assert "IMPORTED" in adjusted.rationale


def test_score_match_threads_reachability() -> None:
    finding = score_match(_matched(), _reach(ReachabilityTier.NOT_IMPORTED))
    assert finding.reachability is not None
    assert finding.reachability.tier is ReachabilityTier.NOT_IMPORTED
    assert finding.score.verdict == "No path from your code"


# --- end-to-end pipeline ----------------------------------------------------------------------


def test_pipeline_imported_stays_high(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    report = scan_project(PROJECTS / "reach_imported", fake_matcher())
    assert report.findings
    finding = report.findings[0]
    assert finding.reachability is not None
    assert finding.reachability.tier is ReachabilityTier.IMPORTED
    assert finding.score.band is PriorityBand.CRITICAL  # KEV + high EPSS, kept high


def test_pipeline_not_imported_is_deprioritized(
    fake_matcher: Callable[..., AdvisoryMatcher],
) -> None:
    report = scan_project(PROJECTS / "reach_not_imported", fake_matcher())
    assert report.findings
    finding = report.findings[0]
    assert finding.reachability is not None
    assert finding.reachability.tier is ReachabilityTier.NOT_IMPORTED
    assert finding.score.band is PriorityBand.INFO
    assert finding.score.verdict == "No path from your code"


@pytest.mark.parametrize("project", ["reach_imported", "reach_dynamic"])
def test_pipeline_never_marks_reachable_as_safe(
    project: str, fake_matcher: Callable[..., AdvisoryMatcher]
) -> None:
    report = scan_project(PROJECTS / project, fake_matcher())
    for finding in report.findings:
        assert finding.reachability is not None
        assert finding.reachability.tier is not ReachabilityTier.NOT_IMPORTED
