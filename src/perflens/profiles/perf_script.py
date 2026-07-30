"""Streaming parser for explicitly-fielded ``perf script`` text output."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO, Self

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import (
    UNKNOWN,
    FrameTable,
    ParseDiagnostics,
    ParseWarning,
    ResourceLimits,
    StackSample,
)
from perflens.domain.ports import ProfileSource
from perflens.stacks.normalize import normalize_symbol

PERF_SCRIPT_FIELDS = "comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline"
PERF_WEIGHT_UNIT = "event_count"
PERF_WEIGHT_SOURCE = "perf_period"

_HEADER_SLASH = re.compile(
    r"^(?P<comm>.*?)\s+(?P<pid>\d+)/(?P<tid>\d+)\s+"
    r"\[(?P<cpu>\d+)\]\s+(?P<time>\d+(?:\.\d+)?):\s+"
    r"(?:(?P<period>\d+)\s+)?(?P<event>\S+):(?:\s+(?P<tail>.*))?$"
)
_HEADER_SPLIT = re.compile(
    r"^(?P<comm>.*?)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"\[(?P<cpu>\d+)\]\s+(?P<time>\d+(?:\.\d+)?):\s+"
    r"(?:(?P<period>\d+)\s+)?(?P<event>\S+):(?:\s+(?P<tail>.*))?$"
)
_HEADER_LEGACY = re.compile(
    r"^(?P<comm>.*?)\s+(?P<pid>\d+)\s+"
    r"\[(?P<cpu>\d+)\]\s+(?P<time>\d+(?:\.\d+)?):\s+"
    r"(?:(?P<period>\d+)\s+)?(?P<event>\S+):(?:\s+(?P<tail>.*))?$"
)
_FRAME = re.compile(r"^(?P<ip>(?:0x)?[0-9a-fA-F]+)\s+(?P<body>.+)$")
_FRAME_BODY = re.compile(r"^(?P<symbol>.*?)\s+\((?P<dso>[^()]*)\)(?:\s+(?P<source>.*))?$")
_SOURCE = re.compile(r"^(?P<file>.*):(?P<line>\d+)(?::(?P<column>\d+))?$")


@dataclass(frozen=True, slots=True)
class _Header:
    command: str
    process_id: int
    thread_id: int
    cpu: int
    timestamp: float
    event: str
    weight: int
    weight_source: str


@dataclass(slots=True)
class _PendingRecord:
    header: _Header
    line_number: int
    frames_leaf_to_root: list[int]


class PerfScriptAdapter:
    """Read text emitted with :data:`PERF_SCRIPT_FIELDS`."""

    def can_handle(self, source: ProfileSource) -> bool:
        return source.source_type == "perf_script" or source.path.suffix in {
            ".perf-script",
            ".script",
        }

    def open(self, source: ProfileSource, limits: ResourceLimits) -> PerfScriptStream:
        if not self.can_handle(source):
            raise PerfLensError(
                ErrorCode.UNSUPPORTED_FORMAT,
                "input",
                f"PerfScriptAdapter cannot handle source type {source.source_type!r}",
                details={"source_type": source.source_type},
            )
        return PerfScriptStream(source.path, limits)


class PerfScriptStream:
    """Single-pass parser that normalizes perf callchains to root-to-leaf order."""

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
        pending: _PendingRecord | None = None
        line_number = 0
        while True:
            raw_line = self._file.readline(self._limits.max_line_chars + 1)
            if raw_line == "":
                if pending is not None:
                    sample = self._finish_record(pending)
                    if sample is not None:
                        yield sample
                return
            line_number += 1
            self._diagnostics.bytes_read += len(raw_line.encode("utf-8", errors="replace"))
            if len(raw_line) > self._limits.max_line_chars:
                if not raw_line.endswith("\n"):
                    self._drain_overlong_line()
                self._malformed(
                    "LINE_TOO_LONG",
                    "perf script line exceeds max_line_chars",
                    line_number,
                    raw_line,
                )
                continue

            line = raw_line.rstrip("\r\n")
            if not line.strip():
                if pending is not None:
                    sample = self._finish_record(pending)
                    pending = None
                    if sample is not None:
                        yield sample
                else:
                    self._diagnostics.skipped_records += 1
                continue

            header = self._parse_header(line)
            if header is not None:
                if pending is not None:
                    sample = self._finish_record(pending)
                    if sample is not None:
                        yield sample
                self._check_record_limit()
                parsed_header, tail = header
                pending = _PendingRecord(parsed_header, line_number, [])
                if tail:
                    frame_id = self._parse_frame(tail, line_number)
                    if frame_id is not None:
                        pending.frames_leaf_to_root.append(frame_id)
                continue

            if pending is not None and raw_line[:1].isspace():
                frame_id = self._parse_frame(line.strip(), line_number)
                if frame_id is not None:
                    pending.frames_leaf_to_root.append(frame_id)
                continue

            self._malformed(
                "UNRECOGNIZED_LINE", "Line is not a perf script record", line_number, line
            )

    def _parse_header(self, line: str) -> tuple[_Header, str] | None:
        match = _HEADER_SLASH.match(line) or _HEADER_SPLIT.match(line) or _HEADER_LEGACY.match(line)
        if match is None:
            return None
        fields = match.groupdict()
        period_text = fields.get("period")
        weight = int(period_text) if period_text is not None else 1
        weight_source = PERF_WEIGHT_SOURCE if period_text is not None else "sample_count_fallback"
        process_id = int(fields["pid"])
        thread_text = fields.get("tid")
        header = _Header(
            command=fields["comm"].strip() or UNKNOWN,
            process_id=process_id,
            thread_id=int(thread_text) if thread_text is not None else process_id,
            cpu=int(fields["cpu"]),
            timestamp=float(fields["time"]),
            event=fields["event"],
            weight=weight,
            weight_source=weight_source,
        )
        return header, (fields.get("tail") or "").strip()

    def _parse_frame(self, text: str, line_number: int) -> int | None:
        match = _FRAME.match(text)
        if match is None:
            self._warning(
                "MALFORMED_FRAME", "Callchain frame has no hexadecimal IP", line_number, text
            )
            return None
        ip = match.group("ip").lower().removeprefix("0x")
        body = match.group("body").strip()
        body_match = _FRAME_BODY.match(body)
        if body_match is None:
            raw_symbol = body or UNKNOWN
            dso = UNKNOWN
            source = None
        else:
            raw_symbol = body_match.group("symbol").strip() or UNKNOWN
            dso = body_match.group("dso").strip() or UNKNOWN
            source = body_match.group("source")
        source_file, source_line = self._parse_source(source)
        symbol = normalize_symbol(raw_symbol)
        is_unknown = symbol in {"[unknown]", UNKNOWN, "0", "??"} or dso in {"[unknown]", UNKNOWN}
        is_kernel = dso in {"[kernel.kallsyms]", "[kernel]"} or "[k]" in raw_symbol
        before = len(self._frame_table)
        frame_id = self._frame_table.intern(
            symbol,
            dso=dso,
            raw_symbol=raw_symbol,
            ip=f"0x{ip}",
            source_file=source_file,
            source_line=source_line,
            is_kernel=is_kernel,
            is_unknown=is_unknown,
        )
        if (
            len(self._frame_table) > before
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

    @staticmethod
    def _parse_source(source: str | None) -> tuple[str | None, int | None]:
        if source is None or source in {"??", "??:0"}:
            return None, None
        match = _SOURCE.match(source)
        if match is None:
            return source, None
        line = int(match.group("line"))
        return match.group("file"), line if line > 0 else None

    def _finish_record(self, pending: _PendingRecord) -> StackSample | None:
        frames = pending.frames_leaf_to_root
        if len(frames) >= 2 and self._frame_table.resolve(frames[0]) == self._frame_table.resolve(
            frames[1]
        ):
            frames = frames[1:]
        if not frames:
            self._malformed(
                "MISSING_CALLCHAIN",
                "perf script record contains no parseable frame",
                pending.line_number,
                pending.header.command,
            )
            return None
        if len(frames) > self._limits.max_stack_depth:
            self._malformed(
                "STACK_TOO_DEEP",
                "perf script record exceeds max_stack_depth",
                pending.line_number,
                pending.header.command,
            )
            return None
        self._diagnostics.parsed_records += 1
        header = pending.header
        return StackSample(
            frames=tuple(reversed(frames)),
            weight=header.weight,
            event=header.event,
            weight_unit=PERF_WEIGHT_UNIT
            if header.weight_source == PERF_WEIGHT_SOURCE
            else "sample_count",
            weight_source=header.weight_source,
            process_id=header.process_id,
            thread_id=header.thread_id,
            thread_name=header.command,
            cpu=header.cpu,
            timestamp=header.timestamp,
        )

    def _check_record_limit(self) -> None:
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

    def _drain_overlong_line(self) -> None:
        assert self._file is not None
        while True:
            chunk = self._file.readline(self._limits.max_line_chars + 1)
            if chunk == "":
                return
            self._diagnostics.bytes_read += len(chunk.encode("utf-8", errors="replace"))
            if chunk.endswith("\n"):
                return

    def _warning(self, code: str, message: str, line_number: int, raw: str) -> None:
        self._diagnostics.add_warning(
            ParseWarning(
                code=code,
                message=message,
                line_number=line_number,
                preview=raw.replace("\n", "\\n")[:200],
            )
        )

    def _malformed(self, code: str, message: str, line_number: int, raw: str) -> None:
        self._diagnostics.malformed_records += 1
        self._diagnostics.skipped_records += 1
        self._warning(code, message, line_number, raw)
