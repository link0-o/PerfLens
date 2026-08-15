from __future__ import annotations

import json
from pathlib import Path

from perflens.application.analyze import analyze_perf_script
from perflens.application.verify_analysis import verify_analysis_artifact


def test_perf_script_analysis_matches_golden_summary(fixture_root: Path) -> None:
    artifact = analyze_perf_script(fixture_root / "perf_script" / "normal.perf-script")
    actual = {
        "status": artifact.status,
        "source_type": artifact.metadata.source_type,
        "sample_count": artifact.metadata.sample_count,
        "total_weight": artifact.metadata.total_weight,
        "event": artifact.metadata.event,
        "weight_unit": artifact.metadata.weight_unit,
        "has_call_graph": artifact.metadata.has_call_graph,
        "has_source_lines": artifact.metadata.has_source_lines,
        "hotspots": [
            [item.symbol, item.dso, item.self_weight, item.inclusive_weight, item.thread_count]
            for item in artifact.hotspots
        ],
        "call_paths": [[frame.symbol for frame in item.frames] for item in artifact.call_paths],
    }
    expected = json.loads(
        (fixture_root / "golden" / "perf-script.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected


def test_python_perf_map_analysis_matches_golden_summary(fixture_root: Path) -> None:
    artifact = analyze_perf_script(fixture_root / "perf_script" / "python-perf-map.perf-script")
    verification = verify_analysis_artifact(artifact, verify_source=True)
    actual = {
        "status": artifact.status,
        "sample_count": artifact.metadata.sample_count,
        "total_weight": artifact.metadata.total_weight,
        "weight_unit": artifact.metadata.weight_unit,
        "warning_count": artifact.metadata.parse_statistics.warning_count,
        "has_source_lines": artifact.metadata.has_source_lines,
        "source_line_frame_count": artifact.evidence_quality.source_line_frame_count,
        "source_line_self_weight": artifact.evidence_quality.source_line_self_weight,
        "hotspots": [
            [
                item.symbol,
                item.dso,
                item.self_weight,
                item.inclusive_weight,
                list(item.source_locations),
            ]
            for item in artifact.hotspots
        ],
        "call_paths": [
            {
                "frames": [frame.symbol for frame in item.frames],
                "weight": item.weight,
                "record_count": item.record_count,
            }
            for item in artifact.call_paths
        ],
    }
    expected = json.loads(
        (fixture_root / "golden" / "python-perf-map.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected
    assert verification.status == "verified"


def test_cross_language_analysis_matches_golden_summary(fixture_root: Path) -> None:
    artifact = analyze_perf_script(fixture_root / "perf_script" / "cross-language.perf-script")
    actual = {
        "status": artifact.status,
        "quality_status": artifact.evidence_quality.quality_status,
        "sample_count": artifact.metadata.sample_count,
        "total_weight": artifact.metadata.total_weight,
        "weight_unit": artifact.metadata.weight_unit,
        "frame_lines": artifact.metadata.parse_statistics.frame_lines,
        "source_annotations": (artifact.metadata.parse_statistics.source_annotation_lines),
        "inline_frame_count": artifact.evidence_quality.inline_frame_count,
        "normalization_merge_count": (artifact.evidence_quality.normalization_merge_count),
        "hotspots": [
            {
                "symbol": item.symbol,
                "dso": item.dso,
                "self_weight": item.self_weight,
                "symbol_variants": list(item.symbol_variants),
                "normalization_merged": item.normalization_merged,
                "source_locations": list(item.source_locations),
            }
            for item in artifact.hotspots
        ],
        "call_paths": [[frame.symbol for frame in item.frames] for item in artifact.call_paths],
    }
    expected = json.loads(
        (fixture_root / "golden" / "cross-language.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected
