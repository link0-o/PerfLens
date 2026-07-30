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
    for key in ("analysis_id", "analysis_fingerprint", "perflens_version", "limits"):
        projected.pop(key)
    metadata = dict(projected["metadata"])
    for key in ("profile_id", "input_path", "input_sha256", "created_at", "schema_version"):
        metadata.pop(key)
    projected["metadata"] = metadata
    return projected
