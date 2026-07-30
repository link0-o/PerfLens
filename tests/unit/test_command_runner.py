from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandRunner


def _runner() -> tuple[CommandRunner, Path]:
    executable = Path(sys.executable).resolve()
    return CommandRunner({executable}), executable


def test_runner_captures_stdout_and_bounded_stderr() -> None:
    runner, executable = _runner()
    output = io.BytesIO()
    result = runner.run_to_file(
        (
            str(executable),
            "-c",
            "import sys; sys.stdout.write('profile'); sys.stderr.write('warning')",
        ),
        output,
    )
    assert output.getvalue() == b"profile"
    assert result.stderr == "warning"
    assert not result.stderr_truncated


def test_runner_rejects_non_allowlisted_executable() -> None:
    runner, _ = _runner()
    with pytest.raises(PerfLensError) as captured:
        runner.run_to_file(("/bin/echo", "unsafe"), io.BytesIO())
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_runner_reports_nonzero_exit_with_bounded_diagnostics() -> None:
    runner, executable = _runner()
    with pytest.raises(PerfLensError) as captured:
        runner.run_to_file(
            (
                str(executable),
                "-c",
                "import sys; sys.stderr.write('x' * 1000); raise SystemExit(7)",
            ),
            io.BytesIO(),
            limits=CommandLimits(max_stderr_bytes=16),
        )
    assert captured.value.code is ErrorCode.EXTERNAL_TOOL_FAILED
    assert captured.value.details["exit_code"] == 7
    assert captured.value.details["stderr"] == "x" * 16
    assert captured.value.details["stderr_truncated"] is True


def test_runner_terminates_timeout_process_group() -> None:
    runner, executable = _runner()
    with pytest.raises(PerfLensError) as captured:
        runner.run_to_file(
            (str(executable), "-c", "import time; time.sleep(5)"),
            io.BytesIO(),
            limits=CommandLimits(timeout_seconds=0.05, terminate_grace_seconds=0.05),
        )
    assert captured.value.code is ErrorCode.EXTERNAL_TOOL_TIMEOUT


def test_runner_stops_stdout_flood() -> None:
    runner, executable = _runner()
    with pytest.raises(PerfLensError) as captured:
        runner.run_to_file(
            (str(executable), "-c", "import sys; sys.stdout.write('x' * 100000)"),
            io.BytesIO(),
            limits=CommandLimits(max_stdout_bytes=100),
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
