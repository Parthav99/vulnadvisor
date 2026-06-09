"""Task 10.4: IMPORTED-AND-CALLED fires when a public API reaches an internal vulnerable symbol.

Real advisories patch an internal symbol (PyYAML ``make_python_instance``, requests
``resolve_redirects``, PyJWT ``_verify_signature``) that user code never calls directly -- it calls
a public API (``yaml.load``, ``requests.get``, ``jwt.decode``). These tests prove the scan now shows
the full call path for those cases, and -- the soundness gate -- that it never reports a *safe* call
or an *unrelated* advisory.
"""

from pathlib import Path

import pytest

from vulnadvisor.callgraph.import_graph import build_import_graph
from vulnadvisor.callgraph.public_api import public_apis_reaching, safe_args_for
from vulnadvisor.model import Dependency, DependencySource, Reachability, ReachabilityTier
from vulnadvisor.reachability import compute_reachability
from vulnadvisor.reachability.tiering import refine_reachability

# (distribution, raw name, vulnerable internal symbols) for three real advisories.
_PYYAML = ("pyyaml", "PyYAML", ("make_python_instance", "construct_python_object_apply"))
_REQUESTS = ("requests", "requests", ("resolve_redirects", "rebuild_auth"))
_PYJWT = ("pyjwt", "PyJWT", ("_verify_signature",))


def _refine(tmp_path: Path, code: str, pkg: tuple[str, str, tuple[str, ...]]) -> Reachability:
    """Build a one-file project with ``code`` and refine reachability for ``pkg``'s advisory."""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    graph = build_import_graph(tmp_path)
    name, raw, symbols = pkg
    dep = Dependency(
        name=name, raw_name=raw, version="0.0.0", source=DependencySource.REQUIREMENTS_TXT
    )
    base = compute_reachability(dep, graph)
    return refine_reachability(dep, base, graph, tmp_path, symbols)


# --- the marquee demo: a public API call reaches the internal vulnerable symbol -----------------


@pytest.mark.parametrize(
    ("pkg", "code", "endpoint"),
    [
        (
            _PYYAML,
            "import yaml\n\n\ndef parse_config(p):\n    return yaml.load(open(p).read())\n",
            "yaml.load",
        ),
        (
            _REQUESTS,
            "import requests\n\n\ndef fetch(url):\n    return requests.get(url)\n",
            "requests.get",
        ),
        (
            _PYJWT,
            "import jwt\n\n\ndef verify(token, key):\n    return jwt.decode(token, key)\n",
            "jwt.decode",
        ),
    ],
)
def test_public_api_reaches_vuln_shows_call_path(
    tmp_path: Path, pkg: tuple[str, str, tuple[str, ...]], code: str, endpoint: str
) -> None:
    reach = _refine(tmp_path, code, pkg)
    assert reach.tier is ReachabilityTier.IMPORTED_AND_CALLED
    assert reach.call_paths, "a concrete call path must be shown"
    path = reach.call_paths[0]
    assert path.steps[-1].qualname == endpoint  # the path ends at the public API call
    assert path.steps[-1].line == 5


def test_from_import_form_also_resolves(tmp_path: Path) -> None:
    code = "from yaml import load\n\n\ndef parse(p):\n    return load(p)\n"
    reach = _refine(tmp_path, code, _PYYAML)
    assert reach.tier is ReachabilityTier.IMPORTED_AND_CALLED
    assert reach.call_paths[0].steps[-1].qualname == "load"


# --- soundness gate: never report a safe call or an unrelated advisory --------------------------


@pytest.mark.parametrize(
    "code",
    [
        # a different, safe public API
        "import yaml\n\n\ndef parse(p):\n    return yaml.safe_load(p)\n",
        # the vulnerable API, but with a provably-safe Loader argument
        "import yaml\n\n\ndef parse(p):\n    return yaml.load(p, Loader=yaml.SafeLoader)\n",
        "import yaml\n\n\ndef parse(p):\n    return yaml.load(p, Loader=yaml.CSafeLoader)\n",
    ],
)
def test_safe_usage_is_not_called(tmp_path: Path, code: str) -> None:
    reach = _refine(tmp_path, code, _PYYAML)
    assert reach.tier is ReachabilityTier.IMPORTED
    assert not reach.call_paths


def test_unrelated_advisory_does_not_flag_public_api(tmp_path: Path) -> None:
    # An advisory whose vulnerable symbol is NOT one a rule covers must not make us flag yaml.load.
    pkg = ("pyyaml", "PyYAML", ("scan_to_next_token",))  # a scanner DoS, not the constructor
    code = "import yaml\n\n\ndef parse(p):\n    return yaml.load(p)\n"
    reach = _refine(tmp_path, code, pkg)
    assert reach.tier is ReachabilityTier.IMPORTED
    assert not reach.call_paths


# --- the curated map itself ---------------------------------------------------------------------


def test_public_apis_reaching_requires_symbol_intersection() -> None:
    assert "load" in public_apis_reaching("PyYAML", frozenset({"make_python_instance"}))
    assert public_apis_reaching("PyYAML", frozenset({"unrelated_symbol"})) == frozenset()
    assert public_apis_reaching("not-a-known-package", frozenset({"x"})) == frozenset()


def test_safe_args_only_for_contributing_rules() -> None:
    guarded = safe_args_for("PyYAML", frozenset({"make_python_instance"}))
    assert "SafeLoader" in guarded["load"]
    assert safe_args_for("requests", frozenset({"resolve_redirects"}))["get"] == frozenset()
