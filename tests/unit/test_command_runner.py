from __future__ import annotations

import io
import os
import sys
import time
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


def test_runner_drains_bounded_stderr_while_after_start_waits(tmp_path: Path) -> None:
    runner, executable = _runner()
    ready_path = tmp_path / "ready"
    output = io.BytesIO()

    def await_child_start(_process: object) -> None:
        deadline = time.monotonic() + 2
        while not ready_path.exists():
            if time.monotonic() >= deadline:
                raise AssertionError("child startup signal was blocked behind stderr")
            time.sleep(0.01)

    result = runner.run_to_file(
        (
            str(executable),
            "-c",
            "import pathlib, sys; "
            "sys.stderr.write('x' * 262144); sys.stderr.flush(); "
            f"pathlib.Path({str(ready_path)!r}).write_text('ready'); "
            "sys.stdout.write('profile')",
        ),
        output,
        limits=CommandLimits(timeout_seconds=3, max_stderr_bytes=32),
        after_start=await_child_start,
    )

    assert output.getvalue() == b"profile"
    assert result.stderr == "x" * 32
    assert result.stderr_bytes == 262144
    assert result.stderr_truncated is True


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


def test_runner_rejects_invalid_limits_and_non_executable_allowlist(tmp_path: Path) -> None:
    runner, executable = _runner()
    with pytest.raises(PerfLensError) as captured:
        runner.run_to_file(
            (str(executable), "-c", "pass"),
            io.BytesIO(),
            limits=CommandLimits(timeout_seconds=float("inf")),
        )
    assert captured.value.code is ErrorCode.INVALID_INPUT

    regular_file = tmp_path / "not-executable"
    regular_file.write_text("data")
    with pytest.raises(PerfLensError) as captured:
        CommandRunner({regular_file})
    assert captured.value.code is ErrorCode.INVALID_INPUT


def test_runner_wraps_output_write_failures() -> None:
    runner, executable = _runner()
    output = io.BytesIO()
    output.close()
    with pytest.raises(PerfLensError) as captured:
        runner.run_to_file(
            (str(executable), "-c", "print('profile')"),
            output,
        )
    assert captured.value.code is ErrorCode.OUTPUT_WRITE_FAILED


def test_runner_accepts_only_an_open_regular_stdin_file(tmp_path: Path) -> None:
    runner, executable = _runner()
    input_path = tmp_path / "context.tar"
    input_path.write_bytes(b"fixed-input")
    output = io.BytesIO()
    with input_path.open("rb") as input_stream:
        runner.run_to_file(
            (str(executable), "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"),
            output,
            stdin=input_stream,
        )
    assert output.getvalue() == b"fixed-input"

    read_descriptor, write_descriptor = os.pipe()
    try:
        with (
            os.fdopen(read_descriptor, "rb", closefd=False) as pipe_stream,
            pytest.raises(PerfLensError) as captured,
        ):
            runner.run_to_file(
                (str(executable), "-c", "pass"),
                io.BytesIO(),
                stdin=pipe_stream,
            )
        assert captured.value.code is ErrorCode.INVALID_INPUT
    finally:
        os.close(read_descriptor)
        os.close(write_descriptor)
