from __future__ import annotations

import json
from pathlib import Path

import pytest

from perflens.application.analyze import analyze_folded
from perflens.application.diagnose import load_analysis
from perflens.classification.engine import build_diagnosis_bundle
from perflens.classification.rules import load_builtin_rules, load_rule_file
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.reporting.markdown import render_markdown_report


def _allocation_analysis(tmp_path: Path):  # type: ignore[no-untyped-def]
    profile = tmp_path / "allocation.folded"
    profile.write_text("main;worker;malloc 60\nmain;worker;compute 40\n")
    return analyze_folded(profile)


def test_generic_rule_produces_candidate_with_explicit_missing_evidence(
    fixture_root: Path, tmp_path: Path
) -> None:
    diagnosis = build_diagnosis_bundle(_allocation_analysis(tmp_path))
    candidate = diagnosis.classifications[0]
    actual = {
        "category": candidate.category,
        "conclusion_status": candidate.conclusion_status,
        "confidence": candidate.confidence,
        "evidence_level": candidate.evidence_level,
        "forbidden_conclusions": list(candidate.forbidden_conclusions),
        "missing_evidence": list(candidate.missing_evidence),
        "rule_id": candidate.rule_id,
        "symbol": candidate.symbol,
    }
    expected = json.loads(
        (fixture_root / "golden" / "diagnosis.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected
    assert candidate.supporting_evidence[0].level == "L2"
    assert diagnosis.status == "partial"


def test_no_call_graph_caps_evidence_at_l1(tmp_path: Path) -> None:
    profile = tmp_path / "single.folded"
    profile.write_text("malloc 10\n")
    diagnosis = build_diagnosis_bundle(analyze_folded(profile))
    assert diagnosis.classifications[0].evidence_level == "L1"
    assert any("no call graph" in item for item in diagnosis.limitations)


def test_builtin_rules_are_generic_and_candidate_only() -> None:
    rules = load_builtin_rules()
    assert rules
    forbidden_terms = {"mysql", "postgres", "grpc", "redis", "rangeveckv"}
    for rule in rules:
        serialized = rule.document.model_dump_json().lower()
        assert not any(term in serialized for term in forbidden_terms)
        assert "confirmed" not in rule.document.classification.category


def test_invalid_rule_file_is_rejected_with_standard_error(fixture_root: Path) -> None:
    with pytest.raises(PerfLensError) as captured:
        load_rule_file(fixture_root / "rules" / "invalid.yaml")
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_markdown_report_has_required_sections_and_guardrails(tmp_path: Path) -> None:
    analysis = _allocation_analysis(tmp_path)
    diagnosis = build_diagnosis_bundle(analysis)
    report = render_markdown_report(
        analysis,
        diagnosis,
        problem_statement="Latency regression",
        target_metric="requests/second",
    )
    for heading in (
        "Problem Definition",
        "Data Quality",
        "Key Observations",
        "Top Hotspots",
        "Candidate Root Causes",
        "Recommendations",
        "Final Conclusion",
    ):
        assert heading in report
    assert "Status: Candidate" in report
    assert "Confirmed: none" in report
    assert "Allocation count and size distribution are unavailable." in report


def test_analysis_loader_enforces_bounded_reads_and_valid_limits(tmp_path: Path) -> None:
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(_allocation_analysis(tmp_path).model_dump_json())

    with pytest.raises(PerfLensError) as captured:
        load_analysis(analysis_path, max_input_bytes=32)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(PerfLensError) as captured:
        load_analysis(analysis_path, max_input_bytes=0)
    assert captured.value.code is ErrorCode.INVALID_INPUT
