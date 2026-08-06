from __future__ import annotations

import json
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.privileged_helper.protocol import (
    HelperCollectPidRequest,
    HelperHealthRequest,
    HelperResponse,
    helper_request_schema,
    helper_response_schema,
    parse_helper_request_frame,
)

_NOW_MILLISECONDS = 4_102_444_700_000


def test_checked_in_privileged_helper_schema_matches_python_model() -> None:
    root = Path(__file__).resolve().parents[2]
    checked_in = json.loads(
        (root / "schemas/privileged-helper-request.schema.json").read_text(encoding="utf-8")
    )
    assert checked_in == helper_request_schema()
    checked_in_response = json.loads(
        (root / "schemas/privileged-helper-response.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert checked_in_response == helper_response_schema()


def test_privileged_helper_valid_golden_frames() -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures/privileged_helper/valid"
    parsed = {
        path.name: parse_helper_request_frame(
            path.read_bytes(), now_unix_milliseconds=_NOW_MILLISECONDS
        )
        for path in sorted(root.glob("*.jsonl"))
    }
    assert isinstance(parsed["health.jsonl"], HelperHealthRequest)
    assert isinstance(parsed["record.jsonl"], HelperCollectPidRequest)
    assert isinstance(parsed["stat.jsonl"], HelperCollectPidRequest)


@pytest.mark.parametrize(
    "fixture",
    sorted(
        (Path(__file__).resolve().parents[1] / "fixtures/privileged_helper/invalid").glob(
            "*.jsonl"
        )
    ),
    ids=lambda path: path.name,
)
def test_privileged_helper_invalid_golden_frames_are_rejected(fixture: Path) -> None:
    with pytest.raises(PerfLensError):
        parse_helper_request_frame(
            fixture.read_bytes(), now_unix_milliseconds=_NOW_MILLISECONDS
        )


def test_privileged_helper_rejects_missing_newline_and_trailing_frame() -> None:
    valid = (
        b'{"schema_version":"1.0","operation":"health",'
        b'"request_id":"request-0123456789abcdef"}'
    )
    with pytest.raises(PerfLensError):
        parse_helper_request_frame(valid, now_unix_milliseconds=_NOW_MILLISECONDS)
    with pytest.raises(PerfLensError):
        parse_helper_request_frame(valid + b"\n{}\n", now_unix_milliseconds=_NOW_MILLISECONDS)


def test_privileged_helper_response_requires_exactly_one_payload() -> None:
    with pytest.raises(ValueError):
        HelperResponse(
            request_id="request-0123456789abcdef",
            ok=True,
            result=None,
            error=None,
        )
