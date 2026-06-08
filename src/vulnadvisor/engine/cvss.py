"""Compute a CVSS v3.x base score from its vector string.

OSV gives us the CVSS *vector* but not the numeric base score, so we derive it here using the
official CVSS v3.1 specification (https://www.first.org/cvss/v3.1/specification-document). Only
CVSS v3.0/3.1 vectors are supported; anything else (v2, v4, malformed) returns ``None`` so the
scoring engine can fall back rather than trust a wrong number.
"""

import math

__all__ = ["cvss_base_score"]

# Metric weights from the CVSS v3.1 specification.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.00}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= ``value`` (spec integer arithmetic)."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (math.floor(scaled / 10_000) + 1) / 10


def _parse_metrics(vector: str) -> tuple[str | None, dict[str, str]]:
    """Split a CVSS vector into its version and an upper-cased metric map."""
    version: str | None = None
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        key, sep, raw = part.partition(":")
        if not sep:
            continue
        key = key.strip().upper()
        value = raw.strip().upper()
        if key == "CVSS":
            version = value
        else:
            metrics[key] = value
    return version, metrics


def cvss_base_score(vector: str | None) -> float | None:
    """Return the CVSS v3.x base score for ``vector``, or ``None`` if it cannot be computed."""
    if not vector:
        return None
    version, metrics = _parse_metrics(vector)
    if version is None or not version.startswith("3"):
        return None

    scope = metrics.get("S")
    if scope not in ("U", "C"):
        return None
    pr_table = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = pr_table[metrics["PR"]]
        conf = _IMPACT[metrics["C"]]
        integ = _IMPACT[metrics["I"]]
        avail = _IMPACT[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope == "C" else 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    base = min(1.08 * combined if scope == "C" else combined, 10.0)
    return _roundup(base)
