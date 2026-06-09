# File: src/vulnadvisor/callgraph/public_api.py
"""Curated public-API -> internal-vulnerable-symbol map for marquee advisories.

Many advisories patch an *internal* symbol (e.g. PyYAML's ``make_python_instance``) that user code
never calls directly; it is reached through a well-known *public* API (``yaml.load``). Demand-driven
call-path search (Task 6.1) matches only the exact vulnerable symbol, so it never fires on these --
which is why the live benchmark found 0 IMPORTED-AND-CALLED across real advisories.

This module supplies, for a few high-value packages, the public APIs that *provably* reach a known
vulnerable internal symbol in the affected versions. Soundness is preserved two ways:

* A rule contributes its public APIs **only when the advisory's own vulnerable symbols intersect**
  the rule's internal symbols. An unrelated advisory on the same package (say a DoS deep in the C
  parser) never makes us flag the public API -- so no false IMPORTED-AND-CALLED.
* ``safe_args`` names, when referenced in the call, prove the call took a provably-safe path
  (``yaml.load(x, Loader=SafeLoader)``), so it is not reported.

Every entry is hand-verified against the cited advisory; we never list an API that does not reach
the vulnerable code in the affected versions.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from vulnadvisor.deps.parsers import canonicalize_name

__all__ = ["PublicApiRule", "public_apis_reaching", "safe_args_for"]


@dataclass(frozen=True)
class PublicApiRule:
    """Public APIs that reach a set of internal vulnerable symbols, with a cited advisory.

    Attributes:
        internal_symbols: The patched internal symbols this rule covers; the rule fires only when an
            advisory's own vulnerable symbols intersect this set.
        public_apis: Public API names that provably reach those internal symbols in the affected
            versions (matched as ``pkg.api(...)`` or a ``from pkg import api`` call).
        safe_args: Identifier names whose presence in a call proves it took a safe path (e.g. a safe
            ``Loader``). A call referencing any of these is not reported.
        advisory: The advisory the rule is hand-verified against (for traceability).
    """

    internal_symbols: frozenset[str]
    public_apis: frozenset[str]
    safe_args: frozenset[str] = frozenset()
    advisory: str = ""


# Keyed by the PEP 503 canonical distribution name. Internal-symbol names are the real functions the
# fix patches; public APIs are the documented entry points that reach them in the affected versions.
_RULES: Mapping[str, tuple[PublicApiRule, ...]] = {
    # PyYAML: yaml.load (and friends) deserialize arbitrary Python objects via the constructor's
    # make_python_instance / construct_python_* helpers unless a safe Loader is supplied.
    "pyyaml": (
        PublicApiRule(
            internal_symbols=frozenset(
                {
                    "make_python_instance",
                    "construct_python_object",
                    "construct_python_object_apply",
                    "construct_python_object_new",
                    "construct_python_name",
                    "construct_python_module",
                    "find_python_name",
                    "find_python_module",
                }
            ),
            public_apis=frozenset({"load", "load_all", "unsafe_load", "unsafe_load_all"}),
            safe_args=frozenset(
                {
                    "SafeLoader",
                    "CSafeLoader",
                    "BaseLoader",
                    "CBaseLoader",
                    "FullLoader",
                    "CFullLoader",
                }
            ),
            advisory="CVE-2020-14343",
        ),
    ),
    # requests: any get/post/... follows redirects through resolve_redirects -> rebuild_auth, which
    # leaked the Authorization header to a different host (CVE-2018-18074).
    "requests": (
        PublicApiRule(
            internal_symbols=frozenset({"resolve_redirects", "rebuild_auth", "rebuild_proxies"}),
            public_apis=frozenset(
                {"get", "post", "put", "patch", "delete", "head", "options", "request"}
            ),
            advisory="CVE-2018-18074",
        ),
    ),
    # PyJWT: jwt.decode runs signature verification (_verify_signature), vulnerable to algorithm
    # confusion when the caller accepts asymmetric algorithms with a public key (CVE-2022-29217).
    "pyjwt": (
        PublicApiRule(
            internal_symbols=frozenset(
                {"_verify_signature", "decode_complete", "_validate_claims"}
            ),
            public_apis=frozenset({"decode"}),
            advisory="CVE-2022-29217",
        ),
    ),
}


def _rules_for(package: str, vulnerable_names: frozenset[str]) -> tuple[PublicApiRule, ...]:
    """Return the rules whose internal symbols intersect the advisory's vulnerable symbols."""
    rules = _RULES.get(canonicalize_name(package), ())
    return tuple(rule for rule in rules if rule.internal_symbols & vulnerable_names)


def public_apis_reaching(package: str, vulnerable_names: frozenset[str]) -> frozenset[str]:
    """Public API names that provably reach a vulnerable internal symbol of ``package``.

    Empty unless ``vulnerable_names`` (the advisory's own symbols) intersect a curated rule -- so an
    unrelated advisory never contributes a public API.
    """
    out: set[str] = set()
    for rule in _rules_for(package, vulnerable_names):
        out |= rule.public_apis
    return frozenset(out)


def safe_args_for(package: str, vulnerable_names: frozenset[str]) -> dict[str, frozenset[str]]:
    """Map each contributed public API to the identifier names that prove a *safe* call."""
    out: dict[str, frozenset[str]] = {}
    for rule in _rules_for(package, vulnerable_names):
        for api in rule.public_apis:
            out[api] = out.get(api, frozenset()) | rule.safe_args
    return out
