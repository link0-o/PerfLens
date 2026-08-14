"""Adapter from ``perf.data`` to the supported text parser via system perf."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import (
    FrameTable,
    ParseDiagnostics,
    ParseWarning,
    ResourceLimits,
    StackSample,
)
from perflens.domain.ports import ProfileSource
from perflens.integrations.commands.runner import CommandLimits, CommandRunner
from perflens.profiles.perf_script import (
    PERF_SCRIPT_FIELDS,
    PERF_SCRIPT_FIELDS_WITHOUT_CPU,
    PerfScriptStream,
)


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
        "_sample_cpu_missing",
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
        self._sample_cpu_missing = False
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
            try:
                self._run_perf_script(safe_input, text_path, PERF_SCRIPT_FIELDS, exclusive=True)
            except PerfLensError as exc:
                if not _is_missing_sample_cpu_error(exc):
                    raise
                self._sample_cpu_missing = True
                self._run_perf_script(
                    safe_input,
                    text_path,
                    PERF_SCRIPT_FIELDS_WITHOUT_CPU,
                    exclusive=False,
                )
            self._script_stream = PerfScriptStream(text_path, self._limits)
            self._script_stream.__enter__()
            if self._sample_cpu_missing:
                self._script_stream.diagnostics().add_warning(
                    ParseWarning(
                        code="MISSING_SAMPLE_CPU",
                        message=(
                            "perf.data has no sample CPU attribute; analysis continued without "
                            "per-sample CPU identity."
                        ),
                    )
                )
            return self
        except BaseException:
            self._cleanup()
            raise

    def _run_perf_script(
        self,
        safe_input: Path,
        text_path: Path,
        fields: str,
        *,
        exclusive: bool,
    ) -> None:
        mode = "xb" if exclusive else "wb"
        with text_path.open(mode) as output:
            self._runner.run_to_file(
                (
                    str(self._perf_path),
                    "script",
                    "--ns",
                    "-F",
                    fields,
                    "-i",
                    str(safe_input),
                ),
                output,
                limits=CommandLimits(
                    timeout_seconds=self._timeout_seconds,
                    max_stdout_bytes=self._limits.max_input_bytes,
                ),
            )

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


def _is_missing_sample_cpu_error(error: PerfLensError) -> bool:
    if error.code is not ErrorCode.EXTERNAL_TOOL_FAILED:
        return False
    stderr = error.details.get("stderr")
    return (
        isinstance(stderr, str)
        and "do not have CPU attribute set" in stderr
        and "Cannot print 'cpu' field" in stderr
    )
