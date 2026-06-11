"""Pure helpers for the org analytics endpoints (Task 13.3).

``parse_window`` is shared with the repo trend endpoint (Task 11.4). ``resolution_episodes``
derives "first-seen -> fixed" durations from a repo+ref scan timeline — the platform stores no
explicit finding lifecycle, so resolution is reconstructed from consecutive scan diffs: a
finding's episode starts at the first scan that contains it and ends at the first later scan
that does not.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException, status

# A finding's identity across scans (the same diff identity used since Task 11.3).
FindingKey = tuple[str, str]


def parse_window(window: str) -> int:
    """Parse a ``30d``/``90d``-style window into days; 400 on malformed/out-of-range input."""
    text = window.strip().lower().removesuffix("d")
    try:
        days = int(text)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "window must look like '90d'") from exc
    if not 1 <= days <= 365:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "window must be between 1 and 365 days")
    return days


@dataclass(frozen=True)
class ResolutionEpisode:
    """One resolved finding: its band (at first sight) and days from first-seen to fixed."""

    band: str
    days: float


def resolution_episodes(
    timeline: Sequence[tuple[datetime, Mapping[FindingKey, str]]],
) -> list[ResolutionEpisode]:
    """Derive resolved episodes from one repo+ref scan timeline (ascending by scan time).

    Each timeline entry is ``(scan_time, {finding_key: band})``. A finding still present in the
    final scan is unresolved and produces no episode; a finding that disappears and later
    reappears produces one episode per contiguous run of presence.
    """
    episodes: list[ResolutionEpisode] = []
    active: dict[FindingKey, tuple[datetime, str]] = {}
    for seen_at, findings in timeline:
        for key, (first_seen, band) in list(active.items()):
            if key not in findings:
                days = (seen_at - first_seen).total_seconds() / 86400.0
                episodes.append(ResolutionEpisode(band=band, days=days))
                del active[key]
        for key, band in findings.items():
            if key not in active:
                active[key] = (seen_at, band)
    return episodes
