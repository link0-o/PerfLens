from __future__ import annotations

import json

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.error_presentation import (
    ERROR_EXIT_CODES,
    error_artifact,
    error_json,
    render_error_chinese,
)


@pytest.mark.parametrize("code", list(ErrorCode))
def test_every_error_code_has_stable_machine_and_chinese_presentations(
    code: ErrorCode,
) -> None:
    error = PerfLensError(
        code,
        "test_stage",
        "bounded technical detail",
        recoverable=True,
        suggested_actions=("Inspect the exact test input.",),
    )

    artifact = error_artifact(error)
    machine = json.loads(error_json(error))
    human = render_error_chinese(error, executable="perflens")

    assert artifact.schema_version == "1.0"
    assert artifact.error.error_id.startswith("err-")
    assert machine["error"]["error_id"] == artifact.error.error_id
    assert machine["error"]["code"] == code.value
    assert human.startswith("PerfLens 操作失败\n错误: ")
    assert f"错误代码: {code.value}" in human
    assert "技术信息: bounded technical detail" in human
    assert "Inspect the exact test input." in human
    assert "perflens --json-errors <子命令>" in human
    assert ERROR_EXIT_CODES[code] in {2, 3, 4, 5, 6, 70}
