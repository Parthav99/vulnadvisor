"""Extract candidate vulnerable symbols from an advisory's fix commit.

The vulnerable symbol is the function/method/class that *contained* the bug — i.e. the code the
fix changed. We find an advisory's fix-commit URL(s) (from its references), fetch the unified
diff (``<commit>.patch``), and map each changed hunk to its enclosing function/class/method.

The diff parser (:func:`extract_symbols_from_patch`) is pure and tested against recorded patches.
Extraction degrades honestly: no fix link, a failed fetch, or a diff with no Python symbols each
produce a typed status rather than a crash or a false symbol.
"""

import re
from collections.abc import Sequence

from vulnadvisor.advisories.transport import Transport, TransportError
from vulnadvisor.model.advisory import Advisory
from vulnadvisor.model.symbols import (
    ExtractionStatus,
    SymbolExtraction,
    SymbolKind,
    VulnerableSymbol,
)

__all__ = [
    "SymbolExtractor",
    "extract_symbols_from_patch",
    "fix_commit_urls",
]

_DEF_RE = re.compile(r"^(?P<indent>\s*)(?P<kw>async\s+def|def|class)\s+(?P<name>[A-Za-z_]\w*)")
_HEADING_RE = re.compile(r"(?P<kw>async\s+def|def|class)\s+(?P<name>[A-Za-z_]\w*)")
_HUNK_RE = re.compile(r"^@@ .* @@(?P<heading>.*)$")

# One enclosing-scope frame: (indentation, is_class, name).
_Frame = tuple[int, bool, str]


def _clean_path(raw: str) -> str:
    """Strip the ``a/``/``b/`` prefix and any trailing tab metadata from a diff path."""
    path = raw.strip().split("\t", 1)[0]
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path


def _kind(is_class: bool, enclosing_has_class: bool) -> SymbolKind:
    """Classify a symbol given whether it is a class and whether a class encloses it."""
    if is_class:
        return SymbolKind.CLASS
    return SymbolKind.METHOD if enclosing_has_class else SymbolKind.FUNCTION


def extract_symbols_from_patch(
    patch_text: str, *, default_file: str | None = None
) -> list[VulnerableSymbol]:
    """Extract candidate vulnerable symbols from a unified diff.

    For each changed line we record its enclosing function/method/class; a removed ``def``/
    ``class`` line is recorded directly (the deleted symbol). Non-Python files are ignored.
    """
    symbols: list[VulnerableSymbol] = []
    seen: set[tuple[str | None, str, SymbolKind]] = set()
    current_file = default_file
    in_python = bool(current_file and current_file.endswith(".py"))
    stack: list[_Frame] = []

    def _record(name: str, qualname: str, is_class: bool, enclosing_has_class: bool) -> None:
        kind = _kind(is_class, enclosing_has_class)
        key = (current_file, qualname, kind)
        if key in seen:
            return
        seen.add(key)
        symbols.append(VulnerableSymbol(name=name, qualname=qualname, kind=kind, file=current_file))

    for line in patch_text.splitlines():
        if line.startswith("+++ "):
            current_file = _clean_path(line[4:])
            in_python = current_file.endswith(".py")
            stack = []
            continue
        if line.startswith(("--- ", "diff --git", "index ", "new file", "deleted file")):
            continue
        hunk = _HUNK_RE.match(line)
        if hunk is not None:
            stack = []
            heading = _HEADING_RE.search(hunk.group("heading"))
            if heading is not None:
                stack.append((-1, heading.group("kw") == "class", heading.group("name")))
            continue
        if not in_python or not line:
            continue
        prefix = line[0]
        if prefix not in (" ", "+", "-"):
            continue
        content = line[1:]

        definition = _DEF_RE.match(content)
        if definition is not None:
            indent = len(definition.group("indent"))
            is_class = definition.group("kw") == "class"
            name = definition.group("name")
            if prefix in (" ", "+"):
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                stack.append((indent, is_class, name))
            else:  # a removed definition: the deleted symbol itself
                enclosing_has_class = any(frame[1] for frame in stack)
                qualname = ".".join([frame[2] for frame in stack] + [name])
                _record(name, qualname, is_class, enclosing_has_class)
            continue

        if prefix in ("+", "-") and stack:
            top = stack[-1]
            enclosing_has_class = any(frame[1] for frame in stack[:-1])
            qualname = ".".join(frame[2] for frame in stack)
            _record(top[2], qualname, top[1], enclosing_has_class)

    return symbols


def fix_commit_urls(advisory: Advisory) -> list[str]:
    """Return the advisory's fix-commit URLs (references pointing at a specific commit)."""
    urls: list[str] = []
    for reference in advisory.references:
        if "/commit/" in reference.url and reference.url not in urls:
            urls.append(reference.url)
    return urls


def _patch_url(commit_url: str) -> str:
    """Map a commit URL to its unified-diff URL (``.patch``)."""
    return commit_url.rstrip("/") + ".patch"


def _confidence(symbols: Sequence[VulnerableSymbol]) -> float:
    """Heuristic 0..1 confidence: lower for sprawling diffs (many files / many symbols)."""
    files = {symbol.file for symbol in symbols}
    base = 0.85
    if len(files) > 3:
        base -= 0.25
    if len(symbols) > 8:
        base -= 0.15
    return round(max(0.3, min(0.9, base)), 2)


class SymbolExtractor:
    """Fetch an advisory's fix commit(s) and extract candidate vulnerable symbols."""

    def __init__(self, transport: Transport) -> None:
        """Bind the extractor to an HTTP transport used to fetch patches."""
        self._transport = transport

    def extract(self, advisory: Advisory) -> SymbolExtraction:
        """Produce a :class:`SymbolExtraction` for ``advisory`` (degrading, never crashing)."""
        urls = fix_commit_urls(advisory)
        if not urls:
            return SymbolExtraction(advisory_id=advisory.id, status=ExtractionStatus.NO_FIX_LINK)

        symbols: list[VulnerableSymbol] = []
        used: list[str] = []
        seen: set[tuple[str | None, str, SymbolKind]] = set()
        for url in urls:
            try:
                data = self._transport.request("GET", _patch_url(url))
            except TransportError:
                continue
            used.append(url)
            for symbol in extract_symbols_from_patch(data.decode("utf-8", errors="replace")):
                key = (symbol.file, symbol.qualname, symbol.kind)
                if key not in seen:
                    seen.add(key)
                    symbols.append(symbol)

        if not used:
            return SymbolExtraction(advisory_id=advisory.id, status=ExtractionStatus.FETCH_FAILED)
        if not symbols:
            return SymbolExtraction(
                advisory_id=advisory.id,
                provenance=tuple(used),
                status=ExtractionStatus.NO_SYMBOLS,
            )
        return SymbolExtraction(
            advisory_id=advisory.id,
            symbols=tuple(symbols),
            confidence=_confidence(symbols),
            provenance=tuple(used),
            status=ExtractionStatus.EXTRACTED,
        )
