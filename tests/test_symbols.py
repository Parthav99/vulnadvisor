from pathlib import Path

import pytest

from vulnadvisor.advisories import TransportError
from vulnadvisor.model import (
    Advisory,
    AdvisoryReference,
    ExtractionStatus,
    SymbolKind,
)
from vulnadvisor.symbols import (
    SymbolExtractor,
    extract_symbols_from_patch,
    fix_commit_urls,
)

PATCHES = Path(__file__).resolve().parent.parent / "fixtures" / "patches"

# Five hand-verified real-world advisory fixes -> the symbol the patch changed.
EXPECTED = {
    "pyyaml_cve_2020_14343.patch": (
        "lib3/yaml/constructor.py",
        "FullConstructor.find_python_name",
        SymbolKind.METHOD,
    ),
    "jinja2_cve_2019_10906.patch": (
        "src/jinja2/sandbox.py",
        "SandboxedEnvironment.is_safe_attribute",
        SymbolKind.METHOD,
    ),
    "requests_cve_2018_18074.patch": (
        "requests/sessions.py",
        "SessionRedirectMixin.resolve_redirects",
        SymbolKind.METHOD,
    ),
    "flask_cve_2023_30861.patch": (
        "src/flask/json/__init__.py",
        "dumps",
        SymbolKind.FUNCTION,
    ),
    "urllib3_cve_2021_33503.patch": (
        "src/urllib3/util/url.py",
        "parse_url",
        SymbolKind.FUNCTION,
    ),
}


@pytest.mark.parametrize("patch_name", sorted(EXPECTED))
def test_extracted_symbols_match_known_fix(patch_name: str) -> None:
    text = (PATCHES / patch_name).read_text(encoding="utf-8")
    file, qualname, kind = EXPECTED[patch_name]
    symbols = extract_symbols_from_patch(text)
    found = {(s.file, s.qualname, s.kind) for s in symbols}
    assert (file, qualname, kind) in found, found


def test_empty_or_malformed_patch_yields_nothing() -> None:
    assert extract_symbols_from_patch("") == []
    assert extract_symbols_from_patch("not a diff at all\njust text\n") == []


def test_non_python_files_ignored() -> None:
    patch = (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,1 @@ def looks_like_code():\n"
        "-old\n"
        "+new\n"
    )
    assert extract_symbols_from_patch(patch) == []


def test_removed_function_is_recorded() -> None:
    patch = (
        "--- a/mod.py\n"
        "+++ b/mod.py\n"
        "@@ -10,5 +10,2 @@\n"
        "-def insecure_eval(expr):\n"
        "-    return eval(expr)\n"
        " keep = 1\n"
    )
    symbols = extract_symbols_from_patch(patch)
    assert any(s.qualname == "insecure_eval" and s.kind is SymbolKind.FUNCTION for s in symbols)


# --- fix-commit URL discovery -----------------------------------------------------------------


def test_fix_commit_urls_from_references() -> None:
    advisory = Advisory(
        id="GHSA-x",
        references=(
            AdvisoryReference(type="ADVISORY", url="https://github.com/o/r/security/advisories/1"),
            AdvisoryReference(type="FIX", url="https://github.com/o/r/commit/abc123"),
            AdvisoryReference(type="WEB", url="https://example.com/blog"),
        ),
    )
    assert fix_commit_urls(advisory) == ["https://github.com/o/r/commit/abc123"]


# --- extractor (fetch + extract), with graceful degradation -----------------------------------


class PatchTransport:
    def __init__(self, payload: bytes = b"", *, fail: bool = False) -> None:
        self.payload = payload
        self.fail = fail
        self.calls: list[str] = []

    def request(self, method, url, *, body=None, headers=None):
        self.calls.append(url)
        if self.fail:
            raise TransportError("down")
        return self.payload


def _advisory_with_commit() -> Advisory:
    return Advisory(
        id="GHSA-pyyaml",
        references=(
            AdvisoryReference(type="FIX", url="https://github.com/yaml/pyyaml/commit/abc123"),
        ),
    )


def test_extractor_extracts_symbols() -> None:
    payload = (PATCHES / "pyyaml_cve_2020_14343.patch").read_bytes()
    transport = PatchTransport(payload)
    result = SymbolExtractor(transport).extract(_advisory_with_commit())

    assert result.status is ExtractionStatus.EXTRACTED
    assert result.confidence > 0
    assert result.provenance == ("https://github.com/yaml/pyyaml/commit/abc123",)
    assert transport.calls == ["https://github.com/yaml/pyyaml/commit/abc123.patch"]
    assert any(s.qualname == "FullConstructor.find_python_name" for s in result.symbols)


def test_extractor_no_fix_link() -> None:
    result = SymbolExtractor(PatchTransport()).extract(Advisory(id="GHSA-none"))
    assert result.status is ExtractionStatus.NO_FIX_LINK
    assert result.symbols == ()
    assert result.confidence == 0.0


def test_extractor_fetch_failure_is_handled() -> None:
    result = SymbolExtractor(PatchTransport(fail=True)).extract(_advisory_with_commit())
    assert result.status is ExtractionStatus.FETCH_FAILED
    assert result.symbols == ()


def test_extractor_no_symbols_when_patch_unusable() -> None:
    result = SymbolExtractor(PatchTransport(b"garbage, not a diff")).extract(
        _advisory_with_commit()
    )
    assert result.status is ExtractionStatus.NO_SYMBOLS
    assert result.provenance == ("https://github.com/yaml/pyyaml/commit/abc123",)
