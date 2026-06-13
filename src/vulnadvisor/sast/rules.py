"""The SAST rule pack: sinks, guards, sanitizers, and secret patterns as pure data.

Per ``docs/sast-design.md`` §3, rules are *data matched by a pure function* — adding a CWE or a sink
is a data edit plus a test, never a new code branch. :mod:`vulnadvisor.sast.sinks` is the single
matcher over this table. Callees are matched on the *import-resolved* call target, so aliased
imports (``import yaml as y``) and ``from`` imports (``from os import system``) match the same rule;
the matcher does the resolution, this module only declares the rules.
"""

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "RULES",
    "SECRET_ASSIGN_NAMES",
    "SECRET_MIN_VALUE_LEN",
    "SECRET_PATTERNS",
    "SECRET_PLACEHOLDERS",
    "CalleeKind",
    "Guard",
    "SecretPattern",
    "SinkRule",
]


class CalleeKind(str, Enum):
    """How a sink rule's callee is matched against the import-resolved call target.

    * ``MODULE`` — module-qualified: ``import os; os.system(...)`` or ``from os import system;
      system(...)`` both resolve to the fully-qualified ``"os.system"``.
    * ``BUILTIN`` — a builtin name used bare and not shadowed by an import (``eval``/``exec``/
      ``open``).
    * ``METHOD`` — a method name on a receiver that cannot be resolved to a module
      (``cursor.execute(...)``); a deliberate heuristic, classified conservatively.
    """

    MODULE = "module"
    BUILTIN = "builtin"
    METHOD = "method"


@dataclass(frozen=True)
class Guard:
    """A keyword that must be present and truthy for the call to be a sink (e.g. ``shell=True``).

    A literal ``False`` clears the guard (the safe form); a non-literal value cannot be disproven,
    so it keeps the call a sink (sound: never miss a real shell call hidden behind a variable).
    """

    keyword: str
    require_value: bool = True


@dataclass(frozen=True)
class SinkRule:
    """One dangerous call pattern for a CWE, matched purely against a resolved call target.

    Attributes:
        cwe: CWE identifier (``"CWE-78"``).
        kind: Stable machine id (``"command-injection"``).
        title: Human-readable title.
        callee_kind: How ``callees`` are matched (see :class:`CalleeKind`).
        callees: The fully-qualified callees (``MODULE``), builtin names (``BUILTIN``), or method
            names (``METHOD``) this rule fires on.
        tainted_positions: Positional argument indices that carry the dangerous value.
        tainted_keywords: Keyword argument names that carry the dangerous value.
        guard: A keyword that must be set for the call to be dangerous, or ``None``.
        safe_args: Identifier names whose presence in the call proves a safe path (e.g.
            ``SafeLoader`` for ``yaml.load(..., Loader=SafeLoader)``).
        sanitizers: Callee names (fully-qualified or bare) that clear this CWE when they wrap the
            dangerous argument (e.g. ``shlex.quote`` for command injection).
    """

    cwe: str
    kind: str
    title: str
    callee_kind: CalleeKind
    callees: frozenset[str]
    tainted_positions: tuple[int, ...] = (0,)
    tainted_keywords: frozenset[str] = frozenset()
    guard: Guard | None = None
    safe_args: frozenset[str] = frozenset()
    sanitizers: frozenset[str] = frozenset()


# Sanitizer names shared across the command-injection rules.
_SHELL_QUOTE = frozenset({"shlex.quote", "quote", "pipes.quote", "shlex.join"})

# Safe YAML loader class names (a call referencing any of these is not a CWE-502 sink).
_SAFE_YAML_LOADERS = frozenset(
    {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader", "FullLoader", "CFullLoader"}
)

RULES: tuple[SinkRule, ...] = (
    # --- CWE-78: OS command injection -------------------------------------------------------
    SinkRule(
        cwe="CWE-78",
        kind="command-injection",
        title="OS command injection",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset({"os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4"}),
        tainted_positions=(0,),
        sanitizers=_SHELL_QUOTE,
    ),
    SinkRule(
        cwe="CWE-78",
        kind="command-injection",
        title="OS command injection via a shell subprocess",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {
                "subprocess.run",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.Popen",
            }
        ),
        tainted_positions=(0,),
        guard=Guard(keyword="shell", require_value=True),
        sanitizers=_SHELL_QUOTE,
    ),
    SinkRule(
        cwe="CWE-78",
        kind="command-injection",
        title="OS command injection via a shell subprocess",
        callee_kind=CalleeKind.MODULE,
        # These always run via the shell, so no shell=True guard is needed.
        callees=frozenset({"subprocess.getoutput", "subprocess.getstatusoutput"}),
        tainted_positions=(0,),
        sanitizers=_SHELL_QUOTE,
    ),
    # --- CWE-89: SQL injection --------------------------------------------------------------
    SinkRule(
        cwe="CWE-89",
        kind="sql-injection",
        title="SQL injection via a non-parameterized query",
        callee_kind=CalleeKind.METHOD,
        callees=frozenset({"execute", "executemany", "executescript"}),
        tainted_positions=(0,),
    ),
    # --- CWE-94/95: code injection ----------------------------------------------------------
    SinkRule(
        cwe="CWE-94",
        kind="code-injection",
        title="Code injection via eval/exec",
        callee_kind=CalleeKind.BUILTIN,
        callees=frozenset({"eval", "exec", "compile"}),
        tainted_positions=(0,),
    ),
    # --- CWE-502: unsafe deserialization ----------------------------------------------------
    SinkRule(
        cwe="CWE-502",
        kind="unsafe-deserialization",
        title="Unsafe deserialization",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {
                "pickle.load",
                "pickle.loads",
                "cPickle.load",
                "cPickle.loads",
                "marshal.load",
                "marshal.loads",
                "dill.load",
                "dill.loads",
                "shelve.open",
                "jsonpickle.decode",
            }
        ),
        tainted_positions=(0,),
    ),
    SinkRule(
        cwe="CWE-502",
        kind="unsafe-deserialization",
        title="Unsafe YAML deserialization",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"}
        ),
        tainted_positions=(0,),
        safe_args=_SAFE_YAML_LOADERS,
    ),
    # --- CWE-22: path traversal -------------------------------------------------------------
    SinkRule(
        cwe="CWE-22",
        kind="path-traversal",
        title="Path traversal via a non-literal file path",
        callee_kind=CalleeKind.BUILTIN,
        callees=frozenset({"open"}),
        tainted_positions=(0,),
        sanitizers=frozenset({"secure_filename", "werkzeug.utils.secure_filename"}),
    ),
    SinkRule(
        cwe="CWE-22",
        kind="path-traversal",
        title="Path traversal via a non-literal file path",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset({"os.open", "io.open"}),
        tainted_positions=(0,),
        sanitizers=frozenset({"secure_filename", "werkzeug.utils.secure_filename"}),
    ),
    # --- CWE-918: SSRF ----------------------------------------------------------------------
    SinkRule(
        cwe="CWE-918",
        kind="ssrf",
        title="Server-side request forgery (SSRF)",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.patch",
                "requests.delete",
                "requests.head",
                "requests.options",
                "requests.request",
                "httpx.get",
                "httpx.post",
                "httpx.put",
                "httpx.patch",
                "httpx.delete",
                "httpx.head",
                "httpx.options",
                "httpx.request",
                "httpx.stream",
                "urllib.request.urlopen",
                "urllib.request.urlretrieve",
            }
        ),
        tainted_positions=(0,),
        tainted_keywords=frozenset({"url"}),
    ),
)


# --- CWE-798: hardcoded secrets (literal patterns, not a taint flow) ------------------------


@dataclass(frozen=True)
class SecretPattern:
    """A regex over string literals that, when matched, is a hardcoded secret (CWE-798)."""

    kind: str
    title: str
    regex: str


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws-access-key-id", "Hardcoded AWS access key id", r"\bAKIA[0-9A-Z]{16}\b"),
    SecretPattern(
        "private-key",
        "Hardcoded private key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    ),
    SecretPattern("github-token", "Hardcoded GitHub token", r"\bghp_[A-Za-z0-9]{36}\b"),
    SecretPattern("slack-token", "Hardcoded Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)

# An assignment to one of these names with a literal string value is treated as a hardcoded secret.
SECRET_ASSIGN_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secret_key",
        "token",
        "auth_token",
        "access_token",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
    }
)

# Obvious placeholders/sentinels that are not real secrets (kept lowercase for case-insensitive
# comparison). A value equal to its own variable name is also skipped by the matcher.
SECRET_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "change_me",
        "password",
        "passwd",
        "secret",
        "token",
        "none",
        "null",
        "xxx",
        "todo",
        "example",
        "test",
        "placeholder",
        "redacted",
        "your_password",
        "your_password_here",
        "your_secret_here",
        "${password}",
    }
)

# Below this length a literal value assigned to a secret-named variable is treated as a placeholder.
SECRET_MIN_VALUE_LEN = 8
