from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from perflens.application.analyze import analyze_folded


def test_normal_profile_matches_golden(fixture_root: Path) -> None:
    artifact = analyze_folded(fixture_root / "folded" / "normal.folded")
    actual = artifact.model_dump(mode="json", exclude_none=True)
    normalized = _stable_projection(actual)
    expected = json.loads((fixture_root / "golden" / "normal.analysis.json").read_text())
    assert normalized == expected


def test_repeated_analysis_is_semantically_deterministic(fixture_root: Path) -> None:
    path = fixture_root / "folded" / "normal.folded"
    first = analyze_folded(path)
    second = analyze_folded(path)
    assert first == second


def _stable_projection(payload: dict[str, Any]) -> dict[str, Any]:
    projected = dict(payload)
    for key in (
        "analysis_id",
        "analysis_fingerprint",
        "content_sha256",
        "perflens_version",
        "limits",
        "evidence_quality",
    ):
        projected.pop(key)
    metadata = dict(projected["metadata"])
    for key in (
        "profile_id",
        "input_path",
        "input_sha256",
        "input_bytes",
        "created_at",
        "schema_version",
        "conversion",
    ):
        metadata.pop(key)
    parse_statistics = dict(metadata["parse_statistics"])
    for key in (
        "frame_lines",
        "duplicate_frame_lines",
        "address_annotation_lines",
        "source_annotation_lines",
        "unicode_replacement_count",
    ):
        parse_statistics.pop(key)
    metadata["parse_statistics"] = parse_statistics
    projected["metadata"] = metadata
    for hotspot in projected["hotspots"]:
        for key in (
            "symbol_variants",
            "symbol_variant_count",
            "symbol_variants_truncated",
            "normalization_merged",
        ):
            hotspot.pop(key)
    for call_path in projected["call_paths"]:
        for frame in call_path["frames"]:
            frame.pop("symbol_variant_count")
            frame.pop("symbol_variants_truncated")
            frame.pop("normalization_merged")
    return projected
