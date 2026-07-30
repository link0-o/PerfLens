from __future__ import annotations

import json
from pathlib import Path

from perflens.application.analyze import analyze_perf_script


def test_perf_script_analysis_matches_golden_summary(fixture_root: Path) -> None:
    artifact = analyze_perf_script(fixture_root / "perf_script" / "normal.perf-script")
    actual = {
        "status": artifact.status,
        "source_type": artifact.metadata.source_type,
        "sample_count": artifact.metadata.sample_count,
        "total_weight": artifact.metadata.total_weight,
        "event": artifact.metadata.event,
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
