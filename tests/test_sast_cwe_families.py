"""Task 20.4 — the new CWE families (breadth).

Each family gets a positive (a proven or intrinsic finding), a negative/sanitized case, and an
adversarial aliasing case (``import x as y`` / ``from x import f``). The soundness invariant holds
verbatim: every genuinely-dangerous case escalates (``CONFIRMED_FLOW`` for a proven taint flow or an
intrinsic weakness), and the safe form is never a finding (or is ``SANITIZED``), never silently
dropped. Taint-based families (SSTI/XXE/open-redirect/LDAP/XPath/ReDoS) are proven from a real entry
point via :func:`analyze_source`; intrinsic families (weak-crypto/insecure-random/TLS/tarbomb) are
decided in the intra-procedural pass via :func:`find_sinks_in_source`.
"""

from vulnadvisor.sast import SastTier, analyze_source, find_sinks_in_source
from vulnadvisor.sast.model import SastFinding, SinkHit


def _hits(source: str) -> tuple[SinkHit, ...]:
    return find_sinks_in_source(source, "m.py")


def _hit(source: str, kind: str) -> SinkHit:
    matches = [h for h in _hits(source) if h.kind == kind]
    assert len(matches) == 1, [(h.kind, h.tier, h.callee) for h in _hits(source)]
    return matches[0]


def _kinds(source: str) -> set[str]:
    return {h.kind for h in _hits(source)}


def _findings(source: str) -> tuple[SastFinding, ...]:
    return analyze_source(source, "m.py")


def _flow(source: str, kind: str) -> SastFinding:
    matches = [f for f in _findings(source) if f.kind == kind]
    assert len(matches) == 1, [(f.kind, f.tier, f.callee) for f in _findings(source)]
    return matches[0]


_FASTAPI = "from fastapi import FastAPI\napp = FastAPI()\n"


# --- CWE-1336: server-side template injection ----------------------------------------------


def test_ssti_confirmed_from_entry_point() -> None:
    f = _flow(
        _FASTAPI
        + "from jinja2 import Template\n"
        + "@app.get('/r')\n"
        + "def r(tpl):\n"
        + "    return Template(tpl).render()\n",
        "ssti",
    )
    assert f.cwe == "CWE-1336"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_ssti_literal_template_is_sanitized() -> None:
    hit = _hit("from jinja2 import Template\nTemplate('<p>{{ x }}</p>')\n", "ssti")
    assert hit.tier is SastTier.SANITIZED


def test_ssti_flask_render_template_string_from_import() -> None:
    f = _flow(
        "from flask import Flask, request, render_template_string\n"
        "app = Flask(__name__)\n"
        "@app.route('/r')\n"
        "def r():\n"
        "    return render_template_string(request.args.get('n'))\n",
        "ssti",
    )
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_ssti_environment_from_string_method() -> None:
    hit = _hit("def f(env, t):\n    return env.from_string(t)\n", "ssti")
    assert hit.tier is SastTier.POSSIBLE_FLOW


# --- CWE-611: XML external entity (XXE) ----------------------------------------------------


def test_xxe_confirmed_lxml_from_import() -> None:
    f = _flow(
        _FASTAPI
        + "from lxml import etree\n"
        + "@app.get('/r')\n"
        + "def r(payload):\n"
        + "    etree.fromstring(payload)\n",
        "xxe",
    )
    assert f.cwe == "CWE-611"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_xxe_literal_is_sanitized() -> None:
    hit = _hit(
        "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n",
        "xxe",
    )
    assert hit.tier is SastTier.SANITIZED


def test_xxe_aliased_elementtree() -> None:
    hit = _hit(
        "import xml.etree.ElementTree as ET\ndef f(x):\n    ET.parse(x)\n",
        "xxe",
    )
    assert hit.tier is SastTier.POSSIBLE_FLOW


# --- CWE-601: open redirect ----------------------------------------------------------------


def test_open_redirect_confirmed() -> None:
    f = _flow(
        "from flask import Flask, request, redirect\n"
        "app = Flask(__name__)\n"
        "@app.route('/r')\n"
        "def r():\n"
        "    return redirect(request.args.get('next'))\n",
        "open-redirect",
    )
    assert f.cwe == "CWE-601"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_open_redirect_literal_is_sanitized() -> None:
    hit = _hit("from flask import redirect\nredirect('/home')\n", "open-redirect")
    assert hit.tier is SastTier.SANITIZED


def test_open_redirect_django_aliased() -> None:
    hit = _hit(
        "from django.shortcuts import redirect as r\ndef v(target):\n    return r(target)\n",
        "open-redirect",
    )
    assert hit.tier is SastTier.POSSIBLE_FLOW


# --- CWE-90: LDAP injection ----------------------------------------------------------------


def test_ldap_injection_confirmed() -> None:
    f = _flow(
        _FASTAPI
        + "@app.get('/r')\n"
        + "def r(uid, conn):\n"
        + "    conn.search_s('dc=x', 2, '(uid=' + uid + ')')\n",
        "ldap-injection",
    )
    assert f.cwe == "CWE-90"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_ldap_injection_escaped_is_sanitized() -> None:
    hit = _hit(
        "from ldap.filter import escape_filter_chars\n"
        "def f(conn, uid):\n"
        "    conn.search_s('dc=x', 2, escape_filter_chars(uid))\n",
        "ldap-injection",
    )
    assert hit.tier is SastTier.SANITIZED


def test_ldap_filter_at_index_one_for_ldap3() -> None:
    # ldap3: conn.search(search_base, search_filter) -> the filter is the 2nd positional arg.
    hit = _hit("def f(conn, flt):\n    conn.search('dc=x', flt)\n", "ldap-injection")
    assert hit.tier is SastTier.POSSIBLE_FLOW


def test_regex_search_is_not_ldap() -> None:
    # A compiled-regex ``pattern.search(text)`` puts text at index 0 (never the LDAP filter slot).
    assert "ldap-injection" not in _kinds("def f(pattern, text):\n    pattern.search(text)\n")


# --- CWE-643: XPath injection --------------------------------------------------------------


def test_xpath_injection_confirmed() -> None:
    f = _flow(
        _FASTAPI
        + "@app.get('/r')\n"
        + "def r(q, tree):\n"
        + "    tree.xpath('//user[name=\"' + q + '\"]')\n",
        "xpath-injection",
    )
    assert f.cwe == "CWE-643"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_xpath_literal_is_sanitized() -> None:
    hit = _hit("def f(tree):\n    tree.xpath('//user')\n", "xpath-injection")
    assert hit.tier is SastTier.SANITIZED


def test_xpath_lxml_etxpath_module() -> None:
    hit = _hit("from lxml import etree\ndef f(expr):\n    etree.XPath(expr)\n", "xpath-injection")
    assert hit.tier is SastTier.POSSIBLE_FLOW


# --- CWE-1333: regular-expression denial of service ----------------------------------------


def test_redos_confirmed_from_entry_point() -> None:
    f = _flow(
        _FASTAPI + "import re\n@app.get('/r')\ndef r(pat):\n    re.compile(pat)\n",
        "redos",
    )
    assert f.cwe == "CWE-1333"
    assert f.tier is SastTier.CONFIRMED_FLOW


def test_redos_literal_pattern_is_sanitized() -> None:
    hit = _hit("import re\nre.compile(r'\\d+')\n", "redos")
    assert hit.tier is SastTier.SANITIZED


def test_redos_aliased_import() -> None:
    hit = _hit("import re as regex\ndef f(p):\n    regex.match(p, 'x')\n", "redos")
    assert hit.tier is SastTier.POSSIBLE_FLOW


# --- CWE-22: archive extraction path traversal (intrinsic) ---------------------------------


def test_tarbomb_extractall_is_confirmed() -> None:
    hit = _hit(
        "import tarfile\ndef f(p):\n    tarfile.open(p).extractall('/tmp')\n",
        "archive-path-traversal",
    )
    assert hit.cwe == "CWE-22"
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_tarbomb_with_filter_is_sanitized() -> None:
    hit = _hit(
        "import zipfile\ndef f(p):\n    zipfile.ZipFile(p).extractall('/tmp', filter='data')\n",
        "archive-path-traversal",
    )
    assert hit.tier is SastTier.SANITIZED


def test_tarbomb_intrinsic_even_with_literal() -> None:
    # Intrinsic: extractall is dangerous regardless of argument literalness (no SANITIZED on a
    # literal path, unlike a taint-based sink).
    hit = _hit("def f(arch):\n    arch.extractall()\n", "archive-path-traversal")
    assert hit.tier is SastTier.CONFIRMED_FLOW


# --- CWE-327/328: weak cryptographic hash (intrinsic) --------------------------------------


def test_weak_hash_md5_is_confirmed() -> None:
    hit = _hit("import hashlib\ndef f(x):\n    return hashlib.md5(x).hexdigest()\n", "weak-hash")
    assert hit.cwe == "CWE-327"
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_weak_hash_usedforsecurity_false_is_sanitized() -> None:
    hit = _hit(
        "import hashlib\ndef f(x):\n    return hashlib.md5(x, usedforsecurity=False).hexdigest()\n",
        "weak-hash",
    )
    assert hit.tier is SastTier.SANITIZED


def test_weak_hash_usedforsecurity_true_stays_confirmed() -> None:
    # usedforsecurity=True explicitly opts md5 into security use -> still a finding (soundness).
    hit = _hit(
        "import hashlib\ndef f(x):\n    return hashlib.md5(x, usedforsecurity=True).hexdigest()\n",
        "weak-hash",
    )
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_weak_hash_aliased_from_import() -> None:
    hit = _hit("from hashlib import sha1\ndef f(x):\n    return sha1(x)\n", "weak-hash")
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_sha256_is_not_a_weak_hash() -> None:
    assert "weak-hash" not in _kinds("import hashlib\nhashlib.sha256(b'x')\n")


# --- CWE-330: insecure randomness (intrinsic) ----------------------------------------------


def test_insecure_random_is_confirmed() -> None:
    hit = _hit(
        "import random\ndef tok():\n    return random.getrandbits(128)\n",
        "insecure-randomness",
    )
    assert hit.cwe == "CWE-330"
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_insecure_random_aliased() -> None:
    hit = _hit(
        "import random as rng\ndef f():\n    return rng.choice('abc')\n",
        "insecure-randomness",
    )
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_secrets_module_is_not_insecure_random() -> None:
    assert "insecure-randomness" not in _kinds("import secrets\nsecrets.token_hex(16)\n")


# --- CWE-295: disabled TLS verification (intrinsic + guarded) ------------------------------


def test_tls_verify_false_is_confirmed() -> None:
    hit = _hit(
        "import requests\ndef f(u):\n    requests.get(u, verify=False)\n",
        "disabled-tls-verification",
    )
    assert hit.cwe == "CWE-295"
    assert hit.tier is SastTier.CONFIRMED_FLOW


def test_tls_verify_default_is_safe() -> None:
    assert "disabled-tls-verification" not in _kinds("import requests\nrequests.get('https://x')\n")


def test_tls_verify_true_is_safe() -> None:
    assert "disabled-tls-verification" not in _kinds(
        "import requests\nrequests.get('https://x', verify=True)\n"
    )


def test_tls_and_ssrf_both_fire_on_one_call() -> None:
    # A single call is both SSRF (the tainted URL) and disabled-TLS (verify=False): the matcher
    # returns every matching rule, so neither finding is lost.
    kinds = _kinds("import requests\ndef f(u):\n    requests.get(u, verify=False)\n")
    assert {"ssrf", "disabled-tls-verification"} <= kinds


def test_tls_unverified_ssl_context() -> None:
    hit = _hit("import ssl\nctx = ssl._create_unverified_context()\n", "disabled-tls-verification")
    assert hit.tier is SastTier.CONFIRMED_FLOW
