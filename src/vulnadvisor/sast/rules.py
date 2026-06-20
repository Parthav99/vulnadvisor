"""The SAST rule pack: sinks, guards, sanitizers, and secret patterns as pure data.

Per ``docs/sast-design.md`` §3, rules are *data matched by a pure function* — adding a CWE or a sink
is a data edit plus a test, never a new code branch. :mod:`vulnadvisor.sast.sinks` is the single
matcher over this table. Callees are matched on the *import-resolved* call target, so aliased
imports (``import yaml as y``) and ``from`` imports (``from os import system``) match the same rule;
the matcher does the resolution, this module only declares the rules.
"""

import hashlib
import json
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
    "rule_pack_hash",
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
        intrinsic: When ``True`` the *call pattern itself* is the vulnerability (a weak algorithm,
            an insecure RNG, disabled TLS verification) — the danger is independent of argument
            taint, so a match is reported ``CONFIRMED_FLOW`` regardless of whether the argument is a
            literal, and the taint engine never tries to escalate or downgrade it (it is decided in
            the intra-procedural pass, exactly like a hardcoded secret). Honors ``guard`` (e.g.
            ``verify=False``) and ``safe_keyword_values`` (e.g. ``usedforsecurity=False``).
        safe_keyword_values: ``(keyword, value)`` pairs that mark the call safe. ``value`` is the
            literal the keyword must equal (``("usedforsecurity", False)`` for ``hashlib.md5``); a
            ``None`` value means the keyword's *presence* alone is safe (``("filter", None)`` for
            ``tarfile.extractall(..., filter="data")`` on Python 3.12+).
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
    intrinsic: bool = False
    safe_keyword_values: tuple[tuple[str, bool | None], ...] = ()


# Sanitizer names shared across the command-injection rules.
_SHELL_QUOTE = frozenset({"shlex.quote", "quote", "pipes.quote", "shlex.join"})

# Safe YAML loader class names (a call referencing any of these is not a CWE-502 sink).
_SAFE_YAML_LOADERS = frozenset(
    {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader", "FullLoader", "CFullLoader"}
)

# HTTP client request callables shared by the SSRF (CWE-918) and disabled-TLS (CWE-295) rules: the
# tainted URL is the SSRF danger; ``verify=False`` on the very same call is the TLS danger. A single
# call can therefore be both findings (the matcher returns every matching rule).
_HTTP_CLIENT_CALLS = frozenset(
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
    }
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
        callees=_HTTP_CLIENT_CALLS
        | frozenset({"urllib.request.urlopen", "urllib.request.urlretrieve"}),
        tainted_positions=(0,),
        tainted_keywords=frozenset({"url"}),
    ),
    # --- CWE-1336: server-side template injection (SSTI) ------------------------------------
    SinkRule(
        cwe="CWE-1336",
        kind="ssti",
        title="Server-side template injection",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {
                "flask.render_template_string",
                "jinja2.Template",
                "jinja2.environment.Template",
                "django.template.Template",
                "mako.template.Template",
            }
        ),
        tainted_positions=(0,),
    ),
    SinkRule(
        # ``Environment(...).from_string(user_input)`` — the renderer compiles attacker text.
        cwe="CWE-1336",
        kind="ssti",
        title="Server-side template injection",
        callee_kind=CalleeKind.METHOD,
        callees=frozenset({"from_string"}),
        tainted_positions=(0,),
    ),
    # --- CWE-611: XML external entity (XXE) ------------------------------------------------
    SinkRule(
        cwe="CWE-611",
        kind="xxe",
        title="XML external entity (XXE) injection",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {
                "lxml.etree.parse",
                "lxml.etree.fromstring",
                "lxml.etree.XML",
                "xml.etree.ElementTree.parse",
                "xml.etree.ElementTree.fromstring",
                "xml.etree.ElementTree.XML",
                "xml.etree.ElementTree.iterparse",
                "xml.dom.minidom.parse",
                "xml.dom.minidom.parseString",
                "xml.dom.pulldom.parse",
                "xml.dom.pulldom.parseString",
                "xml.sax.parse",
                "xml.sax.parseString",
            }
        ),
        tainted_positions=(0,),
        # ``defusedxml`` is the safe replacement; its functions live in a different module, so a
        # call to one simply never matches these callees (the safe path is "not a finding").
    ),
    # --- CWE-601: open redirect ------------------------------------------------------------
    SinkRule(
        cwe="CWE-601",
        kind="open-redirect",
        title="Open redirect",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {
                "flask.redirect",
                "werkzeug.utils.redirect",
                "django.shortcuts.redirect",
                "django.http.HttpResponseRedirect",
                "django.http.HttpResponsePermanentRedirect",
            }
        ),
        tainted_positions=(0,),
    ),
    # --- CWE-90: LDAP injection ------------------------------------------------------------
    SinkRule(
        cwe="CWE-90",
        kind="ldap-injection",
        title="LDAP injection via a non-escaped filter",
        callee_kind=CalleeKind.METHOD,
        callees=frozenset({"search", "search_s", "search_st", "search_ext", "search_ext_s"}),
        # python-ldap: ``conn.search_s(base, scope, filterstr)`` -> filter at index 2; ldap3:
        # ``conn.search(search_base, search_filter)`` -> filter at index 1. The filter is never at
        # index 0 (always the base DN), so a regex ``pattern.search(text)`` does not match.
        tainted_positions=(1, 2),
        tainted_keywords=frozenset({"filterstr", "search_filter"}),
        sanitizers=frozenset({"escape_filter_chars", "ldap.filter.escape_filter_chars"}),
    ),
    # --- CWE-643: XPath injection ----------------------------------------------------------
    SinkRule(
        cwe="CWE-643",
        kind="xpath-injection",
        title="XPath injection via a non-parameterized expression",
        callee_kind=CalleeKind.METHOD,
        callees=frozenset({"xpath"}),
        tainted_positions=(0,),
    ),
    SinkRule(
        cwe="CWE-643",
        kind="xpath-injection",
        title="XPath injection via a non-parameterized expression",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset({"lxml.etree.XPath", "lxml.etree.ETXPath"}),
        tainted_positions=(0,),
    ),
    # --- CWE-1333: regular-expression denial of service (ReDoS) ----------------------------
    SinkRule(
        cwe="CWE-1333",
        kind="redos",
        title="Regular-expression denial of service (ReDoS)",
        callee_kind=CalleeKind.MODULE,
        # The *pattern* (position 0 of every re.* entry point) being attacker-controlled lets a
        # caller craft a catastrophically backtracking expression. A literal pattern is SANITIZED.
        callees=frozenset(
            {
                "re.compile",
                "re.match",
                "re.fullmatch",
                "re.search",
                "re.sub",
                "re.subn",
                "re.split",
                "re.findall",
                "re.finditer",
            }
        ),
        tainted_positions=(0,),
    ),
    # --- CWE-22: archive extraction path traversal (tarbomb / zip-slip) --------------------
    SinkRule(
        # Intrinsic: ``extractall`` on any untrusted archive can write outside the target dir via
        # ``../`` members. Python 3.12+'s ``filter=`` argument is the safe form.
        cwe="CWE-22",
        kind="archive-path-traversal",
        title="Archive extraction path traversal (tarbomb / zip-slip)",
        callee_kind=CalleeKind.METHOD,
        callees=frozenset({"extractall"}),
        intrinsic=True,
        safe_keyword_values=(("filter", None),),
    ),
    # --- CWE-327/328: weak cryptographic hash ----------------------------------------------
    SinkRule(
        # Intrinsic: MD5/SHA-1 are broken for security regardless of the input. ``usedforsecurity=
        # False`` (Python 3.9+) declares a non-security use and is the safe form.
        cwe="CWE-327",
        kind="weak-hash",
        title="Weak cryptographic hash (MD5/SHA-1)",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset({"hashlib.md5", "hashlib.sha1"}),
        intrinsic=True,
        safe_keyword_values=(("usedforsecurity", False),),
    ),
    # --- CWE-330: insecure randomness for security-sensitive values ------------------------
    SinkRule(
        # Intrinsic: the ``random`` module is a non-cryptographic PRNG; using it for tokens,
        # passwords, or salts is predictable. ``secrets`` / ``os.urandom`` are the safe forms (a
        # different module, so they never match).
        cwe="CWE-330",
        kind="insecure-randomness",
        title="Insecure randomness in a security-sensitive context",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset(
            {
                "random.random",
                "random.randint",
                "random.randrange",
                "random.randbytes",
                "random.choice",
                "random.choices",
                "random.sample",
                "random.shuffle",
                "random.uniform",
                "random.getrandbits",
            }
        ),
        intrinsic=True,
    ),
    # --- CWE-295: disabled TLS certificate verification ------------------------------------
    SinkRule(
        # Intrinsic + guarded: a finding only when ``verify`` is explicitly falsy (the default,
        # ``verify=True``, and an absent keyword are the safe forms). Shares callees with SSRF.
        cwe="CWE-295",
        kind="disabled-tls-verification",
        title="Disabled TLS certificate verification",
        callee_kind=CalleeKind.MODULE,
        callees=_HTTP_CLIENT_CALLS,
        guard=Guard(keyword="verify", require_value=False),
        intrinsic=True,
    ),
    SinkRule(
        cwe="CWE-295",
        kind="disabled-tls-verification",
        title="Disabled TLS certificate verification",
        callee_kind=CalleeKind.MODULE,
        callees=frozenset({"ssl._create_unverified_context"}),
        intrinsic=True,
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


def _canonical_rule_pack() -> str:
    """Serialize the whole rule pack to a deterministic, order-stable JSON string.

    Every set is sorted and every enum reduced to its value so the output depends only on the
    *content* of the rules, never on Python's set-iteration order or object identity. This is the
    input to :func:`rule_pack_hash`: two interpreters, or two runs, produce byte-identical text iff
    the rules are semantically identical. ``RULES`` is a tuple, so its order is itself meaningful
    and is preserved (a reordering is a real change and *should* bust the cache).
    """
    rules_payload = [
        {
            "cwe": rule.cwe,
            "kind": rule.kind,
            "title": rule.title,
            "callee_kind": rule.callee_kind.value,
            "callees": sorted(rule.callees),
            "tainted_positions": list(rule.tainted_positions),
            "tainted_keywords": sorted(rule.tainted_keywords),
            "guard": None if rule.guard is None else [rule.guard.keyword, rule.guard.require_value],
            "safe_args": sorted(rule.safe_args),
            "sanitizers": sorted(rule.sanitizers),
            "intrinsic": rule.intrinsic,
            "safe_keyword_values": [[kw, val] for kw, val in rule.safe_keyword_values],
        }
        for rule in RULES
    ]
    secrets_payload = {
        "patterns": [[p.kind, p.title, p.regex] for p in SECRET_PATTERNS],
        "assign_names": sorted(SECRET_ASSIGN_NAMES),
        "placeholders": sorted(SECRET_PLACEHOLDERS),
        "min_value_len": SECRET_MIN_VALUE_LEN,
    }
    return json.dumps(
        {"rules": rules_payload, "secrets": secrets_payload},
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )


def rule_pack_hash() -> str:
    """Return the SHA-256 fingerprint of the current rule pack (sinks + secret patterns).

    Any edit to a sink rule, sanitizer, guard, secret pattern, or the rule *order* changes this
    digest. The per-file facts cache (``store/file_facts.py``) folds it into every key, so a rule
    change re-analyzes every file rather than serving facts computed under the old rules — the
    correctness obligation in ``docs/incremental-design.md`` that a stale cache never hides a find.
    """
    return hashlib.sha256(_canonical_rule_pack().encode("utf-8")).hexdigest()
