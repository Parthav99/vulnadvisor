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
    "CWE-1336": (
        "Never render user input as a template; pass it as template *context* (variables), or "
        "autoescape and use a fixed, trusted template."
    ),
    "CWE-611": (
        "Parse XML with defusedxml (or disable entity resolution / DTD loading on the parser); "
        "never resolve external entities from untrusted XML."
    ),
    "CWE-601": (
        "Validate the redirect target against an allowlist of paths/hosts, or only allow relative "
        "URLs; never redirect to an unvalidated user-supplied URL."
    ),
    "CWE-90": (
        "Escape the LDAP filter with ldap.filter.escape_filter_chars() before interpolating user "
        "input into the search filter."
    ),
    "CWE-643": (
        "Use a parameterized XPath (variables via the parser), or strictly validate/escape the "
        "user input before building the expression."
    ),
    "CWE-1333": (
        "Do not compile attacker-controlled regex patterns; use a fixed pattern, or bound input "
        "size and use a non-backtracking engine (e.g. re2)."
    ),
    "CWE-327": (
        "Use a strong hash (SHA-256+); pass usedforsecurity=False only for non-security checksums, "
        "and avoid broken ciphers (DES/RC4)."
    ),
    "CWE-328": (
        "Use a strong hash (SHA-256+); pass usedforsecurity=False only for non-security checksums."
    ),
    "CWE-330": (
        "Generate security-sensitive values with the secrets module (or os.urandom), never the "
        "random module's predictable PRNG."
    ),
    "CWE-295": (
        "Never disable TLS verification (verify=False); keep verification on and supply the proper "
        "CA bundle if a custom certificate is needed."
    ),
}

DEFAULT_DIRECTION = (
    "Treat external input as untrusted: validate or sanitize it before it reaches this sink."
)


def remediation_direction(cwe: str) -> str:
    """Return the one-sentence remediation direction for a CWE (never empty)."""
    return _DIRECTIONS.get(cwe, DEFAULT_DIRECTION)
