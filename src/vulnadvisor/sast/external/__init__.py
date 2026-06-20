"""External-scanner adapters (multi-tool fusion, M21).

Per ``docs/fusion-design.md`` §3, an adapter bridges a third-party scanner to a list of our own
:class:`~vulnadvisor.sast.model.SastFinding`s through three stages — **run → parse → normalize** —
with the impure ``run`` isolated so ``parse``/``normalize`` are unit-testable with no tool present.
Task 21.2 ships the first adapter (Semgrep OSS); the reachability overlay that assigns each imported
finding one of our tiers is Task 21.3. Until then, a normalized external finding carries the
soundness floor (``DYNAMIC_UNKNOWN``) — never silently ``SANITIZED``, never dropped.
"""

from vulnadvisor.sast.external.base import (
    ExternalRawFinding,
    ExternalScanResult,
    ExternalToolAdapter,
    ParseResult,
    cwe_kind_title,
    extract_cwe,
)
from vulnadvisor.sast.external.semgrep import SemgrepAdapter

__all__ = [
    "ExternalRawFinding",
    "ExternalScanResult",
    "ExternalToolAdapter",
    "ParseResult",
    "SemgrepAdapter",
    "cwe_kind_title",
    "extract_cwe",
]
