"""The Semgrep OSS adapter — the first external scanner fused into our findings (Task 21.2).

Semgrep is invoked **as a subprocess only**, never imported (``docs/fusion-design.md`` §7: the
subprocess boundary is also the license boundary, and keeps the published core wheel at three
runtime deps). The single impure stage is :meth:`SemgrepAdapter.run`; the pure :meth:`parse` and
:meth:`normalize` are fully unit-testable against recorded JSON with **no Semgrep installed**.

This task delivers ingestion only: a normalized finding carries the soundness floor
(``DYNAMIC_UNKNOWN``) and ``flow is None`` — the reachability overlay that assigns each finding one
of our real tiers (and may attach a source→sink path) is Task 21.3. Nothing Semgrep reports is ever
dropped: an unparseable record is degraded to a logged reason, never an exception.
"""

import json
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from vulnadvisor.sast.external.base import (
    ExternalRawFinding,
    ExternalScanResult,
    ParseResult,
    cwe_kind_title,
    raw_from_mapping,
)
from vulnadvisor.sast.model import SastFinding, SastTier

__all__ = ["SemgrepAdapter"]

#: Stable provenance id for Semgrep-found records (used in dedup/provenance, Task 21.3/21.4).
SEMGREP_TOOL = "semgrep-oss"

#: Default ruleset. ``docs/fusion-design.md`` §12 resolves the default to a pinned/offline ruleset
#: for reproducibility and the local-only guarantee; ``--config auto`` is opt-in (wired in 21.4).
DEFAULT_CONFIG = "p/python"

#: How long to let Semgrep run before giving up (defensive; a runaway scan degrades, never hangs).
DEFAULT_TIMEOUT_S = 300


class SemgrepAdapter:
    """Run Semgrep OSS over a target and normalize its JSON into our :class:`SastFinding`s.

    The subprocess and PATH probe are injected (``runner`` / ``which``) so the whole adapter is
    exercisable in tests without Semgrep present; the production defaults shell out to the local
    ``semgrep`` binary with a fixed argv, no shell, telemetry disabled, and a defensive timeout.
    """

    name = SEMGREP_TOOL

    def __init__(
        self,
        *,
        config: str = DEFAULT_CONFIG,
        runner: Callable[[Path], str] | None = None,
        which: Callable[[str], str | None] | None = None,
        timeout: int = DEFAULT_TIMEOUT_S,
    ) -> None:
        """Build an adapter.

        Args:
            config: The Semgrep ruleset (``--config``).
            runner: Override for the subprocess stage; receives the target and returns raw JSON.
            which: Override for the PATH probe (defaults to :func:`shutil.which`).
            timeout: Per-run subprocess timeout in seconds.
        """
        self._config = config
        self._runner = runner or self._default_runner
        self._which = which or shutil.which
        self._timeout = timeout

    # --- stage 1: availability + run (impure) -----------------------------------------------

    def available(self) -> bool:
        """Whether the ``semgrep`` binary is on PATH."""
        return self._which("semgrep") is not None

    def run(self, target: Path) -> str:
        """Run Semgrep over ``target`` and return its raw stdout JSON (delegates to the runner)."""
        return self._runner(target)

    def _default_runner(self, target: Path) -> str:
        """Production runner: ``semgrep --config <ruleset> --json`` over ``target``, no shell.

        Telemetry and version checks are disabled (privacy posture: Semgrep runs offline against
        local rules). Any subprocess failure is surfaced as empty output for the caller to degrade
        — this method never raises into a scan.
        """
        argv = [
            "semgrep",
            "--config",
            self._config,
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            str(target),
        ]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, local tool only
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return completed.stdout

    # --- stage 2: parse (pure, total) -------------------------------------------------------

    def parse(self, raw: str) -> ParseResult:
        """Defensively parse Semgrep ``--json`` output into tool-neutral records.

        Never raises: malformed JSON, a non-object root, a missing/odd ``results`` array, or an
        individual result that is not an object each degrade to a logged reason while keeping every
        record we *can* read. Semgrep's own ``errors`` array (rules that failed to run) is surfaced
        as a degraded reason so a partial Semgrep run never looks like "no findings".
        """
        try:
            data: object = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return ParseResult(degraded=(f"{SEMGREP_TOOL}: malformed JSON output (ignored)",))
        if not isinstance(data, Mapping):
            return ParseResult(degraded=(f"{SEMGREP_TOOL}: unexpected JSON root (ignored)",))

        records: list[ExternalRawFinding] = []
        degraded: list[str] = []

        results = data.get("results")
        if not isinstance(results, list):
            degraded.append(f"{SEMGREP_TOOL}: no 'results' array in output")
            results = []

        skipped = 0
        for result in results:
            record = _record_from_result(result)
            if record is None:
                skipped += 1
                continue
            records.append(record)
        if skipped:
            degraded.append(f"{SEMGREP_TOOL}: skipped {skipped} malformed result(s)")

        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            degraded.append(f"{SEMGREP_TOOL}: {len(errors)} tool error(s) during scan")

        return ParseResult(records=tuple(records), degraded=tuple(degraded))

    # --- stage 3: normalize (pure) ----------------------------------------------------------

    def normalize(self, records: Sequence[ExternalRawFinding]) -> tuple[SastFinding, ...]:
        """Turn neutral records into pre-overlay findings (tier ``DYNAMIC_UNKNOWN``, ``flow=None``).

        We never trust Semgrep's severity to set a tier (fusion-design §10); every normalized
        finding sits at the soundness floor until the Task 21.3 overlay either raises it (when our
        taint engine corroborates a flow) or confirms the escalation. The CWE picks our matching
        rule's label when we know that CWE, else a generic external label.
        """
        findings: list[SastFinding] = []
        for record in records:
            kind, title = cwe_kind_title(record.cwe, fallback_title=record.message)
            findings.append(
                SastFinding(
                    cwe=record.cwe or "",
                    kind=kind,
                    title=title,
                    file=record.file,
                    line=record.line,
                    col=record.col,
                    callee=record.check_id,
                    tier=SastTier.DYNAMIC_UNKNOWN,
                    reason=_normalize_reason(record),
                    source_kind=None,
                    flow=None,
                )
            )
        return tuple(findings)

    # --- orchestration ----------------------------------------------------------------------

    def scan(self, target: Path) -> ExternalScanResult:
        """Run → parse → normalize. Tool-absent or any failure is a clean degraded result.

        When Semgrep is not installed this is a no-op with a one-line "install the ``[semgrep]``
        extra" reason — never a crash and never a silent skip that reads as "no external findings".
        """
        if not self.available():
            return ExternalScanResult(
                tool=self.name,
                ran=False,
                degraded=(
                    f"{SEMGREP_TOOL} not installed; "
                    "`pip install vulnadvisor[semgrep]` to fuse its findings",
                ),
            )
        raw = self.run(target)
        parsed = self.parse(raw)
        findings = self.normalize(parsed.records)
        return ExternalScanResult(
            tool=self.name,
            ran=True,
            findings=findings,
            degraded=parsed.degraded,
        )


def _record_from_result(result: object) -> ExternalRawFinding | None:
    """Map one Semgrep ``results[]`` object to a neutral record, or ``None`` if it is not an object.

    Reads Semgrep's shape defensively: ``path``, ``start.{line,col}``, and ``extra.{message,
    severity,metadata.cwe}`` — any missing piece degrades to the neutral field's safe default
    rather than dropping the record. Semgrep columns are 1-based; we store the 0-based offset.
    """
    if not isinstance(result, Mapping):
        return None
    start = result.get("start")
    start_map: Mapping[str, object] = start if isinstance(start, Mapping) else {}
    extra = result.get("extra")
    extra_map: Mapping[str, object] = extra if isinstance(extra, Mapping) else {}
    metadata = extra_map.get("metadata")
    metadata_map: Mapping[str, object] = metadata if isinstance(metadata, Mapping) else {}

    col = start_map.get("col")
    zero_based_col = (
        (col - 1) if isinstance(col, int) and not isinstance(col, bool) and col > 0 else 0
    )

    neutral: dict[str, object] = {
        "check_id": result.get("check_id"),
        "file": result.get("path"),
        "line": start_map.get("line"),
        "col": zero_based_col,
        "cwe": metadata_map.get("cwe"),
        "severity": extra_map.get("severity"),
        "message": extra_map.get("message"),
    }
    return raw_from_mapping(neutral, tool=SEMGREP_TOOL)


def _normalize_reason(record: ExternalRawFinding) -> str:
    """Honest, pre-overlay reason string for a normalized Semgrep finding."""
    located = "" if record.located else " (location unresolved)"
    sev = f", severity {record.severity}" if record.severity else ""
    return (
        f"Located by Semgrep OSS (rule {record.check_id}{sev}){located}; "
        "VulnAdvisor reachability overlay pending (Task 21.3)."
    )
