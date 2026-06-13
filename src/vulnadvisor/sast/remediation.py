"""Remediation *direction* for first-party (SAST) findings — Card C content (Task 16.4).

v1 emits the direction to fix, keyed by CWE (the rule's stable severity class), not the validated,
machine-proven patch — that is M17 (``vulnadvisor fix``). This is pure data: a CWE -> one-sentence
remediation direction, with a conservative fallback so an unknown CWE still yields a useful, never-
empty hint. The wording never claims a fix has been applied (``has_fix`` is always ``False`` here).
"""

__all__ = ["DEFAULT_DIRECTION", "remediation_direction"]

# Keyed by CWE so the secret kinds (which vary: aws-access-key, hardcoded-credential, ...) all map
# through their shared CWE-798 entry rather than needing a per-kind row.
_DIRECTIONS: dict[str, str] = {
    "CWE-89": (
        "Use a parameterized query: pass user input as bound parameters, never string-formatted "
        "into the SQL text."
    ),
    "CWE-78": (
        "Avoid shell=True; pass the command as an argument list, or shlex.quote() every "
        "interpolated value."
    ),
    "CWE-94": (
        "Do not eval/exec untrusted input; use a safe parser (e.g. ast.literal_eval) or an "
        "explicit dispatch table."
    ),
    "CWE-95": (
        "Do not eval/exec untrusted input; use a safe parser (e.g. ast.literal_eval) or an "
        "explicit dispatch table."
    ),
    "CWE-502": (
        "Deserialize safely: use yaml.safe_load / Loader=SafeLoader, and never unpickle data from "
        "an untrusted source."
    ),
    "CWE-22": (
        "Confine the path: resolve it and assert it stays within an allowed base directory, or use "
        "werkzeug.secure_filename for filenames."
    ),
    "CWE-918": (
        "Validate the URL against an allowlist of schemes and hosts before issuing the request; "
        "reject internal/metadata addresses."
    ),
    "CWE-798": (
        "Remove the secret from source: load it from an environment variable or a secrets manager, "
        "and rotate the exposed credential."
    ),
}

DEFAULT_DIRECTION = (
    "Treat external input as untrusted: validate or sanitize it before it reaches this sink."
)


def remediation_direction(cwe: str) -> str:
    """Return the one-sentence remediation direction for a CWE (never empty)."""
    return _DIRECTIONS.get(cwe, DEFAULT_DIRECTION)
