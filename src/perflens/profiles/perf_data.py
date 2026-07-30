"""Adapter from ``perf.data`` to the supported text parser via system perf."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import FrameTable, ParseDiagnostics, ResourceLimits, StackSample
from perflens.domain.ports import ProfileSource
from perflens.integrations.commands.runner import CommandLimits, CommandRunner
from perflens.profiles.perf_script import PERF_SCRIPT_FIELDS, PerfScriptStream


class PerfDataAdapter:
    """Convert perf's binary container using an allowlisted ``perf script`` command."""

    def __init__(self, perf_path: Path | None = None, *, timeout_seconds: float = 300.0) -> None:
        selected = perf_path or _find_perf()
        try:
            self._perf_path = selected.expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "perf executable cannot be resolved",
                details={"path": str(selected)},
            ) from exc
        self._timeout_seconds = timeout_seconds
        self._runner = CommandRunner({self._perf_path})

    def can_handle(self, source: ProfileSource) -> bool:
        return source.source_type == "perf_data" or source.path.name.endswith("perf.data")

    def open(self, source: ProfileSource, limits: ResourceLimits) -> PerfDataStream:
        if not self.can_handle(source):
            raise PerfLensError(
                ErrorCode.UNSUPPORTED_FORMAT,
                "input",
                f"PerfDataAdapter cannot handle source type {source.source_type!r}",
                details={"source_type": source.source_type},
            )
        return PerfDataStream(
            source.path,
            limits,
            perf_path=self._perf_path,
            runner=self._runner,
            timeout_seconds=self._timeout_seconds,
        )


class PerfDataStream:
    """Materialize bounded perf-script text in a private temporary directory."""

    __slots__ = (
        "_limits",
        "_path",
        "_perf_path",
        "_runner",
        "_script_stream",
        "_temporary_directory",
        "_timeout_seconds",
    )

    def __init__(
        self,
        path: Path,
        limits: ResourceLimits,
        *,
        perf_path: Path,
        runner: CommandRunner,
        timeout_seconds: float,
    ) -> None:
        self._path = path
        self._limits = limits
        self._perf_path = perf_path
        self._runner = runner
        self._timeout_seconds = timeout_seconds
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self._script_stream: PerfScriptStream | None = None

    @property
    def frame_table(self) -> FrameTable:
        if self._script_stream is None:
            raise RuntimeError("ProfileStream must be entered before accessing frames")
        return self._script_stream.frame_table

    def __enter__(self) -> Self:
        try:
            safe_input = self._path.expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "input",
                "perf.data input cannot be resolved",
                details={"path": str(self._path)},
            ) from exc
        if not safe_input.is_file():
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "input",
                "perf.data input is not a regular file",
                details={"path": str(safe_input)},
            )
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="perflens-perf-script-")
        text_path = Path(self._temporary_directory.name) / "profile.perf-script"
        try:
            with text_path.open("xb") as output:
                self._runner.run_to_file(
                    (
                        str(self._perf_path),
                        "script",
                        "--ns",
                        "-F",
                        PERF_SCRIPT_FIELDS,
                        "-i",
                        str(safe_input),
                    ),
                    output,
                    limits=CommandLimits(
                        timeout_seconds=self._timeout_seconds,
                        max_stdout_bytes=self._limits.max_input_bytes,
                    ),
                )
            self._script_stream = PerfScriptStream(text_path, self._limits)
            self._script_stream.__enter__()
            return self
        except BaseException:
            self._cleanup()
            raise

    def __iter__(self) -> Iterator[StackSample]:
        if self._script_stream is None:
            raise RuntimeError("ProfileStream must be entered before iteration")
        return iter(self._script_stream)

    def diagnostics(self) -> ParseDiagnostics:
        if self._script_stream is None:
            raise RuntimeError("ProfileStream must be entered before diagnostics")
        return self._script_stream.diagnostics()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._script_stream is not None:
            self._script_stream.__exit__(exc_type, exc_value, traceback)
        self._cleanup()

    def _cleanup(self) -> None:
        self._script_stream = None
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None


def _find_perf() -> Path:
    discovered = shutil.which("perf")
    if discovered is None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "external_tool",
            "System perf executable was not found",
            recoverable=True,
            suggested_actions=("Install Linux perf or pass an explicit --perf-path.",),
        )
    return Path(discovered)
