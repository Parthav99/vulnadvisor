"""The external-tool adapter protocol and its tool-neutral data shapes (fusion-design §3).

Everything here is pure and tool-agnostic: the :class:`ExternalToolAdapter` protocol declares the
three stages a concrete adapter (e.g. :class:`~vulnadvisor.sast.external.semgrep.SemgrepAdapter`)
implements, :class:`ExternalRawFinding` is the intermediate every tool's results are first parsed
into, and the CWE helpers turn an external rule's CWE tag into one of our known sink labels.

Two design rules from ``docs/fusion-design.md`` are enforced by the *types* here:

* **Defensive, total parsing.** :class:`ExternalRawFinding` is built only from already-validated,
  safe-defaulted values (see :func:`raw_from_mapping`); a record we cannot place keeps a sentinel
  location and is *kept*, never discarded (the overlay escalates it in Task 21.3).
* **No silent loss.** Parsing returns a :class:`ParseResult` carrying both the records and a tuple
  of degraded reasons (same spirit as SCA ``degraded_sources``) — malformed input degrades to a
  logged reason, never an exception that aborts the scan.
"""

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from vulnadvisor.sast.model import SastFinding
from vulnadvisor.sast.rules import RULES

__all__ = [
    "ExternalRawFinding",
    "ExternalScanResult",
    "ExternalToolAdapter",
    "ParseResult",
    "cwe_kind_title",
    "extract_cwe",
    "raw_from_mapping",
]

# Sentinel location for a record whose file/line we could not resolve. The record is *kept* (the
# overlay escalates it to DYNAMIC-UNKNOWN in 21.3, per fusion-design §4) — never dropped for lacking
# a location.
UNKNOWN_FILE = "<unknown>"


class ExternalRawFinding(BaseModel):
    r"""A third-party scanner's finding, normalized to a tool-neutral shape but not yet tiered.

    This is the boundary record between an external tool's JSON and our :class:`SastFinding`. Every
    field has a safe default so construction never fails on malformed input;
    :func:`raw_from_mapping` is the defensive constructor used by adapters.

    Attributes:
        tool: Stable provenance id of the scanner that produced it (e.g. ``"semgrep-oss"``).
        check_id: The tool's own rule id (kept for provenance / traceability).
        file: Project-relative path of the hit, or :data:`UNKNOWN_FILE` if unresolvable.
        line: 1-based line, or ``0`` when the tool gave no usable location.
        col: 0-based column offset (our convention), clamped to ``>= 0``.
        cwe: The extracted ``CWE-\\d+`` token, or ``None`` when the tool reported none.
        severity: The tool's own severity string (metadata only — it never drives our priority).
        message: The tool's human-readable message.
    """

    model_config = ConfigDict(frozen=True)

    tool: str
    check_id: str
    file: str = UNKNOWN_FILE
    line: int = 0
    col: int = 0
    cwe: str | None = None
    severity: str = ""
    message: str = ""

    @property
    def located(self) -> bool:
        """Whether the tool gave a usable file/line we can try to overlay (21.3)."""
        return self.file != UNKNOWN_FILE and self.line > 0


class ParseResult(BaseModel):
    """The pure output of an adapter's ``parse`` stage: kept records plus degraded reasons.

    ``parse`` is total — malformed input never raises; it returns whatever records were salvageable
    and appends a human-readable reason to :attr:`degraded` (surfaced like SCA degraded sources).
    """

    model_config = ConfigDict(frozen=True)

    records: tuple[ExternalRawFinding, ...] = ()
    degraded: tuple[str, ...] = ()


class ExternalScanResult(BaseModel):
    """The end-to-end output of running an adapter over a target: normalized findings + provenance.

    Attributes:
        tool: The adapter's stable provenance id.
        ran: ``True`` if the tool was available and executed; ``False`` for a clean tool-absent
            skip.
        findings: The normalized (pre-overlay) :class:`SastFinding`s, tier ``DYNAMIC_UNKNOWN``.
        degraded: Reasons the run was partial or skipped (tool absent, malformed JSON, run error).
    """

    model_config = ConfigDict(frozen=True)

    tool: str
    ran: bool
    findings: tuple[SastFinding, ...] = ()
    degraded: tuple[str, ...] = ()


@runtime_checkable
class ExternalToolAdapter(Protocol):
    """A third-party scanner bridged to our finding model in three stages (fusion-design §3).

    ``available`` and ``run`` are impure (PATH probe / subprocess); ``parse`` and ``normalize`` are
    pure and total so they can be unit-tested with no tool installed. ``scan`` orchestrates the
    three and is the single entry point the pipeline (Task 21.4) calls.
    """

    name: str

    def available(self) -> bool:
        """Whether the tool is installed / on PATH (impure)."""
        ...

    def run(self, target: Path) -> str:
        """Run the tool over ``target`` and return its raw JSON text (impure, isolated)."""
        ...

    def parse(self, raw: str) -> ParseResult:
        """Defensively parse raw tool output into tool-neutral records (pure, total)."""
        ...

    def normalize(self, records: Sequence[ExternalRawFinding]) -> tuple[SastFinding, ...]:
        """Turn tool-neutral records into our (pre-overlay) findings (pure)."""
        ...

    def scan(self, target: Path) -> ExternalScanResult:
        """Run → parse → normalize; tool-absent or any failure is a clean degraded result."""
        ...


# --- CWE helpers ----------------------------------------------------------------------------------

# A CWE token looks like ``CWE-89``; tools embed it in noisier strings (``"CWE-89: SQL Injection"``)
# or as a list. We extract only the canonical token and ignore the prose.
_CWE_TOKEN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def extract_cwe(value: object) -> str | None:
    r"""Extract the first canonical ``CWE-\d+`` token from a tool's CWE metadata, defensively.

    Accepts a string (``"CWE-89: ..."``), a list/tuple of such strings, or anything else
    (→ ``None``). Never raises; an unrecognized or absent value yields ``None`` (the overlay then
    escalates the finding to ``DYNAMIC_UNKNOWN`` rather than guessing a class).
    """
    if isinstance(value, str):
        match = _CWE_TOKEN.search(value)
        return f"CWE-{match.group(1)}" if match else None
    if isinstance(value, (list, tuple)):
        for item in value:
            found = extract_cwe(item)
            if found is not None:
                return found
    return None


# Our own rule pack already names every CWE we natively detect; reuse those (kind, title) labels for
# an external finding tagged with the same CWE so the merged list reads consistently. First rule per
# CWE wins (the rules differ only by callee within a CWE, sharing kind/title).
_CWE_KIND_TITLE: dict[str, tuple[str, str]] = {}
for _rule in RULES:
    _CWE_KIND_TITLE.setdefault(_rule.cwe, (_rule.kind, _rule.title))


def cwe_kind_title(cwe: str | None, *, fallback_title: str) -> tuple[str, str]:
    """Map a CWE to our ``(kind, title)`` label, falling back to a generic external label.

    A CWE we natively detect reuses our own rule's labels; an unknown or missing CWE becomes a
    generic ``external-finding`` kind titled by the tool's own message (so the finding is still
    legible), and will be scored in the default-severity bucket and tiered ``DYNAMIC_UNKNOWN``.
    """
    if cwe is not None and cwe in _CWE_KIND_TITLE:
        return _CWE_KIND_TITLE[cwe]
    title = fallback_title.strip() or (cwe or "External finding")
    return "external-finding", title


def raw_from_mapping(record: Mapping[str, object], *, tool: str) -> ExternalRawFinding:
    """Build an :class:`ExternalRawFinding` from a raw mapping with safe defaults for every field.

    This is the defensive heart of parsing: it never raises, and a missing/odd field degrades to the
    field's safe default rather than dropping the record. Adapters are responsible for mapping their
    tool's JSON keys to the neutral keys this reads (``check_id``/``file``/``line``/``col``/``cwe``/
    ``severity``/``message``) before calling it.
    """
    return ExternalRawFinding(
        tool=tool,
        check_id=_as_str(record.get("check_id")) or "<unknown-rule>",
        file=_as_str(record.get("file")) or UNKNOWN_FILE,
        line=_as_nonneg_int(record.get("line")),
        col=_as_nonneg_int(record.get("col")),
        cwe=extract_cwe(record.get("cwe")),
        severity=_as_str(record.get("severity")),
        message=_as_str(record.get("message")),
    )


def _as_str(value: object) -> str:
    """Coerce to a stripped string; non-strings (incl. ``None``) become ``""``."""
    return value.strip() if isinstance(value, str) else ""


def _as_nonneg_int(value: object) -> int:
    """Coerce to a non-negative int; non-coercible values become ``0`` (no-location sentinel)."""
    if isinstance(value, bool):  # bool is an int subclass; never a line number
        return 0
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, str):
        try:
            return max(int(value.strip()), 0)
        except ValueError:
            return 0
    return 0
