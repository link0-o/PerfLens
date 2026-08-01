"""Streaming adapter for standard FlameGraph folded stacks."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import IO, Self

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import (
    FrameTable,
    ParseDiagnostics,
    ParseWarning,
    ResourceLimits,
    StackSample,
)
from perflens.domain.ports import ProfileSource


class FoldedStackAdapter:
    """Parse standard `root;leaf weight` records without format extensions."""

    def can_handle(self, source: ProfileSource) -> bool:
        return source.source_type == "folded" or source.path.suffix in {".folded", ".txt"}

    def open(self, source: ProfileSource, limits: ResourceLimits) -> FoldedStackStream:
        if not self.can_handle(source):
            raise PerfLensError(
                ErrorCode.UNSUPPORTED_FORMAT,
                "input",
                f"FoldedStackAdapter cannot handle source type {source.source_type!r}",
                details={"source_type": source.source_type},
            )
        return FoldedStackStream(source.path, limits)


class FoldedStackStream:
    """Single-use, closeable stream with bounded diagnostics."""

    __slots__ = (
        "_diagnostics",
        "_entered",
        "_file",
        "_frame_table",
        "_iterated",
        "_limits",
        "_path",
    )

    def __init__(self, path: Path, limits: ResourceLimits) -> None:
        self._path = path
        self._limits = limits
        self._file: IO[str] | None = None
        self._entered = False
        self._iterated = False
        self._frame_table = FrameTable()
        self._diagnostics = ParseDiagnostics(max_warnings=limits.max_warnings)

    @property
    def frame_table(self) -> FrameTable:
        return self._frame_table

    def __enter__(self) -> Self:
        if self._entered:
            raise RuntimeError("ProfileStream cannot be entered more than once")
        self._entered = True
        size = self._path.stat().st_size
        if size > self._limits.max_input_bytes:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "input",
                "Input file exceeds max_input_bytes",
                recoverable=True,
                details={"actual_bytes": size, "max_input_bytes": self._limits.max_input_bytes},
                suggested_actions=("Increase the explicit input limit if the file is trusted.",),
            )
        self._file = self._path.open(encoding="utf-8", errors="replace", newline=None)
        return self

    def __iter__(self) -> Iterator[StackSample]:
        if not self._entered or self._file is None:
            raise RuntimeError("ProfileStream must be entered before iteration")
        if self._iterated:
            raise RuntimeError("ProfileStream is single-pass")
        self._iterated = True
        return self._samples()

    def diagnostics(self) -> ParseDiagnostics:
        return self._diagnostics

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def _samples(self) -> Iterator[StackSample]:
        assert self._file is not None
        line_number = 0
        while True:
            raw_line = self._file.readline(self._limits.max_line_chars + 1)
            if raw_line == "":
                return
            line_number += 1
            self._diagnostics.bytes_read += len(raw_line.encode("utf-8", errors="replace"))
            self._check_input_bytes()
            if len(raw_line) > self._limits.max_line_chars:
                if not raw_line.endswith("\n"):
                    self._drain_overlong_line()
                self._malformed(
                    "LINE_TOO_LONG",
                    "Folded record exceeds max_line_chars",
                    line_number,
                    raw_line,
                )
                continue
            line = raw_line.strip()
            if not line:
                self._diagnostics.skipped_records += 1
                continue
            if (
                self._diagnostics.parsed_records + self._diagnostics.malformed_records
                >= self._limits.max_records
            ):
                raise PerfLensError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "parsing",
                    "Input exceeds max_records",
                    recoverable=True,
                    details={"max_records": self._limits.max_records},
                )
            parsed = self._parse_line(line, line_number)
            if parsed is not None:
                self._diagnostics.parsed_records += 1
                yield parsed

    def _drain_overlong_line(self) -> None:
        assert self._file is not None
        while True:
            chunk = self._file.readline(self._limits.max_line_chars + 1)
            if chunk == "":
                return
            self._diagnostics.bytes_read += len(chunk.encode("utf-8", errors="replace"))
            self._check_input_bytes()
            if chunk.endswith("\n"):
                return

    def _check_input_bytes(self) -> None:
        if self._diagnostics.bytes_read > self._limits.max_input_bytes:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "input",
                "Input grew beyond max_input_bytes while parsing",
                recoverable=True,
                details={
                    "actual_bytes": self._diagnostics.bytes_read,
                    "max_input_bytes": self._limits.max_input_bytes,
                },
            )

    def _parse_line(self, line: str, line_number: int) -> StackSample | None:
        try:
            stack_text, weight_text = line.rsplit(maxsplit=1)
        except ValueError:
            self._malformed(
                "MISSING_WEIGHT",
                "Folded record must end with a positive integer weight",
                line_number,
                line,
            )
            return None
        try:
            weight = int(weight_text)
        except ValueError:
            self._malformed(
                "INVALID_WEIGHT",
                "Folded record weight is not an integer",
                line_number,
                line,
            )
            return None
        if weight <= 0:
            self._malformed(
                "INVALID_WEIGHT",
                "Folded record weight must be positive",
                line_number,
                line,
            )
            return None
        symbols = stack_text.split(";")
        if not symbols or any(not symbol.strip() for symbol in symbols):
            self._malformed(
                "EMPTY_FRAME",
                "Folded record contains an empty frame",
                line_number,
                line,
            )
            return None
        if len(symbols) > self._limits.max_stack_depth:
            self._malformed(
                "STACK_TOO_DEEP",
                "Folded record exceeds max_stack_depth",
                line_number,
                line,
            )
            return None
        frame_ids = tuple(self._intern_frame(symbol.strip()) for symbol in symbols)
        return StackSample(frames=frame_ids, weight=weight)

    def _intern_frame(self, symbol: str) -> int:
        existing_count = len(self._frame_table)
        frame_id = self._frame_table.intern(
            symbol,
            is_unknown=symbol in {"[unknown]", "unknown", "0x0", "??"},
        )
        if (
            len(self._frame_table) > existing_count
            and len(self._frame_table) > self._limits.max_unique_frames
        ):
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "parsing",
                "Input exceeds max_unique_frames",
                recoverable=True,
                details={"max_unique_frames": self._limits.max_unique_frames},
            )
        return frame_id

    def _malformed(self, code: str, message: str, line_number: int, raw: str) -> None:
        self._diagnostics.malformed_records += 1
        self._diagnostics.skipped_records += 1
        preview = raw.replace("\n", "\\n")[:200]
        self._diagnostics.add_warning(
            ParseWarning(code=code, message=message, line_number=line_number, preview=preview)
        )
