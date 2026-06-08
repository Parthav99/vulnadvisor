"""Model for the resolved minimal safe-fix recommendation for a finding."""

from pydantic import BaseModel, ConfigDict


class SafeFix(BaseModel):
    """The nearest non-vulnerable upgrade for a vulnerable dependency.

    Attributes:
        current_version: The currently resolved version, if known.
        fixed_version: The recommended minimal safe version (smallest fixed version greater than
            the current one), or ``None`` when no fix is available.
        has_fix: Whether a concrete fixed version was found.
        is_major_jump: Whether the fix crosses a major version boundary (potentially breaking).
        available_fixes: All fixed versions advertised by the advisory, ascending.
        note: Plain-text guidance (e.g. "Minimal safe upgrade: 2.10.1." or a no-fix message).
    """

    model_config = ConfigDict(frozen=True)

    current_version: str | None
    fixed_version: str | None
    has_fix: bool
    is_major_jump: bool
    available_fixes: tuple[str, ...]
    note: str
