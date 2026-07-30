from __future__ import annotations

import pytest

from perflens.observability.timing import measure_stage


def test_measure_stage_records_success_and_failure() -> None:
    timings: dict[str, float] = {}
    with measure_stage("success", timings):
        pass
    with pytest.raises(RuntimeError), measure_stage("failure", timings):
        raise RuntimeError("expected")
    assert timings["success"] >= 0
    assert timings["failure"] >= 0
