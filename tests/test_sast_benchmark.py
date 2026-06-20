"""Tests for the SAST benchmark (vs Bandit) — pure metrics, the seeded corpus, and the report.

The release-blocking assertion is :func:`test_corpus_misses_zero_seeded_vulns`: VulnAdvisor must
surface every seeded, entry-point-reachable vulnerability. The pure-metric tests pin the recall /
top-tier-precision math independent of the engine, and the corpus tests prove the real engine plus
(when installed) Bandit produce the numbers the report publishes.
"""

import json
from pathlib import Path

import pytest
from benchmarks.sast_corpus import (
    CORPUS,
    SastCase,
    _parse_semgrep_results,
    bandit_available,
    run_sast_corpus,
    semgrep_available,
)
from benchmarks.sast_metrics import (
    EXPECT_POSSIBLE,
    EXPECT_SAFE,
    EXPECT_VULN,
    TOOL_BANDIT,
    TOOL_SEMGREP,
    TOOL_VULNADVISOR,
    Detection,
    Seed,
    build_sast_report,
    compute_cwe_recall,
    compute_tool_metrics,
    parse_seeds,
)
from benchmarks.sast_report import render_sast_markdown

# --- seed parsing --------------------------------------------------------------------------------


def test_parse_seeds_extracts_marker_with_line_cwe_and_expectation() -> None:
    source = (
        '"""m."""\n'
        "import os\n"
        "os.system(x)  # seed: CWE-78 vuln\n"
        'yaml.safe_load(x)  # seed: CWE-502 safe note="safe_load"\n'
        "os.system(y)  # seed: CWE-78 possible\n"
        "plain = 1  # not a seed\n"
    )
    seeds = parse_seeds("c", "c/app.py", source)
    assert [(s.line, s.cwe, s.expect, s.note) for s in seeds] == [
        (3, "CWE-78", EXPECT_VULN, ""),
        (4, "CWE-502", EXPECT_SAFE, "safe_load"),
        (5, "CWE-78", EXPECT_POSSIBLE, ""),
    ]
    assert all(s.case == "c" and s.file == "c/app.py" for s in seeds)


def test_parse_seeds_ignores_malformed_markers() -> None:
    source = "x()  # seed: CWE vuln\ny()  # seed: CWE-1 banana\nz()  # seedish CWE-78 vuln\n"
    assert parse_seeds("c", "f", source) == ()


def test_seed_is_real_for_vuln_and_possible_only() -> None:
    real = Seed("c", "f", 1, "CWE-78", EXPECT_VULN)
    poss = Seed("c", "f", 2, "CWE-78", EXPECT_POSSIBLE)
    safe = Seed("c", "f", 3, "CWE-78", EXPECT_SAFE)
    assert real.is_real and poss.is_real and not safe.is_real


# --- detection predicates ------------------------------------------------------------------------


def test_vulnadvisor_sanitized_is_not_an_alarm_others_are() -> None:
    san = Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "sanitized")
    conf = Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "confirmed-flow")
    poss = Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "possible-flow")
    assert not san.is_alarm
    assert conf.is_alarm and poss.is_alarm
    assert conf.is_top and not poss.is_top and not san.is_top


def test_bandit_every_result_is_an_alarm_high_is_top() -> None:
    high = Detection(TOOL_BANDIT, "f", 1, "CWE-78", "HIGH")
    med = Detection(TOOL_BANDIT, "f", 1, "CWE-78", "MEDIUM")
    assert high.is_alarm and med.is_alarm
    assert high.is_top and not med.is_top


def test_semgrep_every_result_is_an_alarm_error_is_top() -> None:
    err = Detection(TOOL_SEMGREP, "f", 1, "CWE-78", "ERROR")
    warn = Detection(TOOL_SEMGREP, "f", 1, "CWE-78", "WARNING")
    assert err.is_alarm and warn.is_alarm
    # Semgrep's top tier is ERROR, not Bandit's "HIGH" — each tool keeps its own predicate.
    assert err.is_top and not warn.is_top
    assert not Detection(TOOL_SEMGREP, "f", 1, "CWE-78", "HIGH").is_top


# --- pure metric math (engine-independent) -------------------------------------------------------

_SEEDS = (
    Seed("c", "f", 1, "CWE-78", EXPECT_VULN),
    Seed("c", "f", 2, "CWE-78", EXPECT_VULN),
    Seed("c", "f", 3, "CWE-78", EXPECT_SAFE),
    Seed("c", "f", 4, "CWE-78", EXPECT_POSSIBLE),
)


def test_metrics_perfect_tool_full_recall_full_precision() -> None:
    detections = [
        Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "confirmed-flow"),
        Detection(TOOL_VULNADVISOR, "f", 2, "CWE-78", "confirmed-flow"),
        Detection(TOOL_VULNADVISOR, "f", 3, "CWE-78", "sanitized"),
        Detection(TOOL_VULNADVISOR, "f", 4, "CWE-78", "possible-flow"),
    ]
    m = compute_tool_metrics(TOOL_VULNADVISOR, _SEEDS, detections)
    assert m.vuln_total == 2 and m.caught_vuln == 2 and m.missed_vuln == 0
    assert m.recall_pct == 100.0
    assert m.top_on_real == 2 and m.top_on_safe == 0
    assert m.top_precision_pct == 100.0
    assert m.alarms_on_safe == 0  # sanitized is not an alarm
    assert m.unmatched_findings == 0


def test_metrics_noisy_tool_false_top_alarm_and_a_miss() -> None:
    detections = [
        Detection(TOOL_BANDIT, "f", 1, "CWE-78", "HIGH"),  # caught vuln, top, real
        # line 2 vuln missed entirely
        Detection(TOOL_BANDIT, "f", 3, "CWE-78", "HIGH"),  # HIGH on a SAFE seed -> false top alarm
        Detection(TOOL_BANDIT, "f", 4, "CWE-78", "HIGH"),  # HIGH on a possible (real) seed
        Detection(TOOL_BANDIT, "f", 9, "CWE-78", "LOW"),  # off-target (no seed)
    ]
    m = compute_tool_metrics(TOOL_BANDIT, _SEEDS, detections)
    assert m.caught_vuln == 1 and m.missed_vuln == 1 and m.recall_pct == 50.0
    assert m.top_on_real == 2  # line 1 (vuln) + line 4 (possible)
    assert m.top_on_safe == 1  # line 3
    assert round(m.top_precision_pct) == 67
    assert m.alarms_on_safe == 1
    assert m.unmatched_findings == 1


def test_metrics_deduplicate_repeated_location() -> None:
    detections = [
        Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "confirmed-flow"),
        Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "confirmed-flow"),
    ]
    m = compute_tool_metrics(TOOL_VULNADVISOR, _SEEDS, detections)
    assert m.caught_vuln == 1 and m.top_on_real == 1


def test_empty_top_tier_is_full_precision() -> None:
    m = compute_tool_metrics(TOOL_VULNADVISOR, _SEEDS, [])
    assert m.top_total == 0 and m.top_precision_pct == 100.0
    assert m.caught_vuln == 0 and m.missed_vuln == 2


def test_compute_cwe_recall_groups_by_cwe() -> None:
    seeds = (
        Seed("c", "f", 1, "CWE-78", EXPECT_VULN),
        Seed("c", "f", 2, "CWE-89", EXPECT_VULN),
        Seed("c", "f", 3, "CWE-89", EXPECT_SAFE),  # safe excluded from recall denominator
    )
    detections = [Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "confirmed-flow")]
    rows = compute_cwe_recall([TOOL_VULNADVISOR], seeds, detections)
    by_cwe = {r.cwe: r for r in rows}
    assert by_cwe["CWE-78"].vuln_total == 1 and by_cwe["CWE-78"].caught_for(TOOL_VULNADVISOR) == 1
    assert by_cwe["CWE-89"].vuln_total == 1 and by_cwe["CWE-89"].caught_for(TOOL_VULNADVISOR) == 0


# --- corpus integrity ----------------------------------------------------------------------------


def test_corpus_case_names_are_unique() -> None:
    names = [case.name for case in CORPUS]
    assert len(names) == len(set(names))


def test_corpus_covers_all_cwe_classes() -> None:
    cwes = {
        s.cwe
        for case in CORPUS
        for rel, src in case.files.items()
        for s in parse_seeds(case.name, f"{case.name}/{rel}", src)
    }
    # The seven founding classes (M16) plus the Task 20.4 families (M20) — 16 in all.
    assert cwes == {
        "CWE-78",
        "CWE-89",
        "CWE-94",
        "CWE-502",
        "CWE-22",
        "CWE-918",
        "CWE-798",
        "CWE-1336",
        "CWE-611",
        "CWE-601",
        "CWE-90",
        "CWE-643",
        "CWE-1333",
        "CWE-327",
        "CWE-330",
        "CWE-295",
    }


def test_corpus_has_recall_depth_cases() -> None:
    """Task 20.5: container / cross-module / attribute recall cases are present and multi-file."""
    names = {case.name for case in CORPUS}
    assert {"container_taint", "cross_module_taint", "attribute_taint"} <= names
    cross = next(c for c in CORPUS if c.name == "cross_module_taint")
    assert set(cross.files) == {"app.py", "helpers.py"}  # the source and the sink live apart


def test_corpus_has_safe_and_possible_decoys() -> None:
    expects = [
        s.expect
        for case in CORPUS
        for rel, src in case.files.items()
        for s in parse_seeds(case.name, f"{case.name}/{rel}", src)
    ]
    assert EXPECT_SAFE in expects and EXPECT_POSSIBLE in expects and EXPECT_VULN in expects


# --- end-to-end (the validation gate) ------------------------------------------------------------


def test_corpus_misses_zero_seeded_vulns() -> None:
    """Release-blocking: VulnAdvisor surfaces every seeded entry-point-reachable vulnerability."""
    report = run_sast_corpus()
    assert report.missed_seeded_vulns == 0
    va = report.for_tool(TOOL_VULNADVISOR)
    assert va is not None
    assert va.recall_pct == 100.0
    # Soundness story: no CONFIRMED-FLOW lands on sanitized code.
    assert va.top_on_safe == 0
    assert va.top_precision_pct == 100.0


def test_corpus_is_deterministic() -> None:
    a = run_sast_corpus()
    b = run_sast_corpus()
    assert a.metrics == b.metrics
    assert a.cwe_recall == b.cwe_recall
    assert render_sast_markdown(a) == render_sast_markdown(b)


@pytest.mark.skipif(not bandit_available(), reason="bandit not installed")
def test_bandit_is_run_and_is_noisier_at_the_top_tier() -> None:
    report = run_sast_corpus()
    assert report.bandit_available
    va = report.for_tool(TOOL_VULNADVISOR)
    bandit = report.for_tool(TOOL_BANDIT)
    assert va is not None and bandit is not None
    # The whole pitch: Bandit raises top-tier alarms on safe code; VulnAdvisor does not.
    assert bandit.top_on_safe > va.top_on_safe
    assert va.top_precision_pct >= bandit.top_precision_pct


def test_render_contains_headline_tables_and_gate() -> None:
    md = render_sast_markdown(run_sast_corpus())
    assert "SAST Benchmark vs Bandit" in md
    assert "## Head to head" in md
    assert "## Recall by CWE" in md
    assert "## Performance" in md
    assert "Soundness gate: **PASS**" in md
    assert md.isascii()  # portable / Windows-safe, matching the SCA report convention


def test_render_without_bandit_omits_comparison() -> None:
    seeds = (Seed("c", "f", 1, "CWE-78", EXPECT_VULN),)
    detections = [Detection(TOOL_VULNADVISOR, "f", 1, "CWE-78", "confirmed-flow")]
    report = build_sast_report(seeds, detections, bandit_available=False)
    md = render_sast_markdown(report)
    assert "not available" in md
    assert report.for_tool(TOOL_BANDIT) is None
    assert report.for_tool(TOOL_SEMGREP) is None


# --- Semgrep OSS comparator (forward-references M21) ---------------------------------------------


_SEMGREP_CASE = SastCase("cmd_injection", {"app.py": "import os\nos.system(x)\n"})


def test_parse_semgrep_results_normalizes_path_line_severity_and_cwe(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import os\nos.system(x)\n", encoding="utf-8")
    payload = json.dumps(
        {
            "results": [
                {
                    "path": (tmp_path / "app.py").as_posix(),
                    "start": {"line": 2, "col": 1},
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
                    },
                }
            ]
        }
    )
    dets = _parse_semgrep_results(payload, _SEMGREP_CASE, tmp_path)
    assert len(dets) == 1
    det = dets[0]
    assert det.tool == TOOL_SEMGREP
    assert det.file == "cmd_injection/app.py"
    assert det.line == 2 and det.cwe == "CWE-78" and det.label == "ERROR"
    assert det.is_alarm and det.is_top


def test_parse_semgrep_results_handles_multiple_and_unknown_cwe(tmp_path: Path) -> None:
    payload = (
        '{"results": ['
        '{"path": "a.py", "start": {"line": 1}, "extra": {"severity": "WARNING", '
        '"metadata": {"cwe": "CWE-89: SQLi"}}}, '
        '{"path": "b.py", "start": {"line": 5}, "extra": {"severity": "INFO", "metadata": {}}}]}'
    )
    dets = _parse_semgrep_results(payload, _SEMGREP_CASE, tmp_path)
    assert [(d.line, d.cwe, d.label) for d in dets] == [(1, "CWE-89", "WARNING"), (5, "", "INFO")]


def test_parse_semgrep_results_is_defensive(tmp_path: Path) -> None:
    # Malformed JSON, wrong shape, and entries missing required fields all degrade to no detection.
    assert _parse_semgrep_results("not json", _SEMGREP_CASE, tmp_path) == []
    assert _parse_semgrep_results("[1, 2, 3]", _SEMGREP_CASE, tmp_path) == []
    assert _parse_semgrep_results('{"results": "nope"}', _SEMGREP_CASE, tmp_path) == []
    partial = '{"results": [{"start": {"line": 2}}, {"path": "x.py"}, "junk"]}'
    assert _parse_semgrep_results(partial, _SEMGREP_CASE, tmp_path) == []


def test_run_sast_corpus_can_skip_semgrep() -> None:
    # Skipping is honored regardless of install state; the gate still passes without the comparator.
    report = run_sast_corpus(run_semgrep=False)
    assert report.semgrep_available is False
    assert report.for_tool(TOOL_SEMGREP) is None
    assert report.missed_seeded_vulns == 0


@pytest.mark.skipif(not semgrep_available(), reason="semgrep not installed")
def test_semgrep_is_run_when_available() -> None:
    report = run_sast_corpus()
    assert report.semgrep_available
    assert report.for_tool(TOOL_SEMGREP) is not None
