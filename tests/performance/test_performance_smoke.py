from __future__ import annotations

import resource
from pathlib import Path
from time import perf_counter

import pytest

from perflens.application.analyze import analyze_folded


@pytest.mark.performance
def test_small_corpus_has_no_order_of_magnitude_regression(tmp_path: Path) -> None:
    profile = tmp_path / "small.folded"
    profile.write_text("main;worker;leaf 1\n" * 1_000)
    started = perf_counter()
    artifact = analyze_folded(profile)
    elapsed = perf_counter() - started
    peak_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    assert artifact.metadata.sample_count == 1_000
    assert elapsed < 10
    assert peak_rss_kib < 1_000_000
