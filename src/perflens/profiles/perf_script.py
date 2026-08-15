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
from perflens.profiles.events import perf_period_unit
from perflens.profiles.text import sanitize_surrogateescaped_text
from perflens.stacks.normalize import normalize_symbol

PERF_SCRIPT_FIELDS = "comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline"
PERF_SCRIPT_FIELDS_WITHOUT_CPU = "comm,pid,tid,time,event,period,ip,sym,dso,srcline"
PERF_WEIGHT_SOURCE = "perf_period"
PERF_SCRIPT_PARSER_VERSION = "perf-script-v4"

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
_HEADER_SLASH_WITHOUT_CPU = re.compile(
    r"^(?P<comm>.*?)\s+(?P<pid>\d+)/(?P<tid>\d+)\s+"
    r"(?P<time>\d+(?:\.\d+)?):\s+"
    r"(?:(?P<period>\d+)\s+)?(?P<event>\S+):(?:\s+(?P<tail>.*))?$"
)
_HEADER_SPLIT_WITHOUT_CPU = re.compile(
    r"^(?P<comm>.*?)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<time>\d+(?:\.\d+)?):\s+"
    r"(?:(?P<period>\d+)\s+)?(?P<event>\S+):(?:\s+(?P<tail>.*))?$"
)
_HEADER_LEGACY_WITHOUT_CPU = re.compile(
    r"^(?P<comm>.*?)\s+(?P<pid>\d+)\s+"
    r"(?P<time>\d+(?:\.\d+)?):\s+"
    r"(?:(?P<period>\d+)\s+)?(?P<event>\S+):(?:\s+(?P<tail>.*))?$"
)
_FRAME = re.compile(r"^(?P<ip>(?:0x)?[0-9a-fA-F]+)\s+(?P<body>.+)$")
_FRAME_ANNOTATION = re.compile(r"^(?P<label>.+)\[(?P<ip>[0-9a-fA-F]+)\]$")
_SOURCE_ANNOTATION = re.compile(r"^(?P<source>.+:\d+(?::\d+)?)(?P<inline>\s+\(inlined\))?$")
_PYTHON_PERF_MAP = re.compile(r"^perf-\d+\.map$")
_SOURCE = re.compile(r"^(?P<file>.*?):(?P<line>\d+)(?::(?P<column>\d+))?$")


@dataclass(frozen=True, slots=True)
class _Header:
    command: str
    process_id: int
    thread_id: int
    cpu: int | None
    timestamp: float
    event: str
    weight: int
    weight_source: str


@dataclass(slots=True)
class _PendingRecord:
    header: _Header
    line_number: int
    frames_leaf_to_root: list[int]
    header_frame_id: int | None = None


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
        self._file = self._path.open(encoding="utf-8", errors="surrogateescape", newline="")
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
            raw_line, byte_count, invalid_bytes = sanitize_surrogateescaped_text(raw_line)
            self._diagnostics.unicode_replacement_count += invalid_bytes
            self._diagnostics.bytes_read += byte_count
            self._check_input_bytes()
            if len(raw_line) > self._limits.max_line_chars:
                if not raw_line.endswith("\n"):
                    self._drain_overlong_line()
                if pending is not None and raw_line[:1].isspace():
                    self._warning(
                        "LINE_TOO_LONG",
                        "Overlong callchain line was retained as an unknown Frame",
                        line_number,
                        raw_line,
                    )
                    pending.frames_leaf_to_root.append(self._unknown_frame())
                    self._diagnostics.frame_lines += 1
                else:
                    if pending is not None:
                        sample = self._finish_record(pending)
                        pending = None
                        if sample is not None:
                            yield sample
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
                    if frame_id is None:
                        frame_id = self._unknown_frame()
                        self._diagnostics.frame_lines += 1
                    pending.frames_leaf_to_root.append(frame_id)
                    pending.header_frame_id = frame_id
                continue

            if pending is not None and raw_line[:1].isspace():
                frame_text = line.strip()
                if _FRAME.match(frame_text) is not None:
                    frame_id = self._parse_frame(frame_text, line_number)
                else:
                    if self._consume_frame_annotation(frame_text, pending):
                        continue
                    if (
                        _FRAME_ANNOTATION.fullmatch(frame_text) is not None
                        or _SOURCE_ANNOTATION.fullmatch(frame_text) is not None
                    ):
                        self._warning(
                            "UNMATCHED_FRAME_ANNOTATION",
                            "Callchain annotation does not match the preceding Frame",
                            line_number,
                            frame_text,
                        )
                        continue
                    frame_id = self._parse_frame(frame_text, line_number)
                if frame_id is None:
                    frame_id = self._unknown_frame()
                    self._diagnostics.frame_lines += 1
                pending.frames_leaf_to_root.append(frame_id)
                continue

            if pending is not None:
                sample = self._finish_record(pending)
                pending = None
                if sample is not None:
                    yield sample
            self._malformed(
                "UNRECOGNIZED_LINE", "Line is not a perf script record", line_number, line
            )

    def _parse_header(self, line: str) -> tuple[_Header, str] | None:
        match = (
            _HEADER_SLASH.match(line)
            or _HEADER_SPLIT.match(line)
            or _HEADER_LEGACY.match(line)
            or _HEADER_SLASH_WITHOUT_CPU.match(line)
            or _HEADER_SPLIT_WITHOUT_CPU.match(line)
            or _HEADER_LEGACY_WITHOUT_CPU.match(line)
        )
        if match is None:
            return None
        fields = match.groupdict()
        period_text = fields.get("period")
        weight = int(period_text) if period_text is not None else 1
        weight_source = PERF_WEIGHT_SOURCE if period_text is not None else "sample_count_fallback"
        process_id = int(fields["pid"])
        thread_text = fields.get("tid")
        cpu_text = fields.get("cpu")
        header = _Header(
            command=fields["comm"].strip() or UNKNOWN,
            process_id=process_id,
            thread_id=int(thread_text) if thread_text is not None else process_id,
            cpu=int(cpu_text) if cpu_text is not None else None,
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
        parsed_body = self._split_frame_body(body)
        if parsed_body is None:
            raw_symbol = body or UNKNOWN
            dso = UNKNOWN
            source = None
            is_inline = False
            self._warning(
                "UNPARSED_FRAME_BODY",
                "Callchain Frame body could not be split into symbol and DSO",
                line_number,
                body,
            )
        else:
            raw_symbol, dso, source, is_inline = parsed_body
        symbol_text, source = self._python_perf_map_source(raw_symbol, dso, source)
        source_file, source_line, source_column = self._parse_source(source)
        symbol = normalize_symbol(symbol_text)
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
            source_column=source_column,
            is_inline=is_inline,
            is_kernel=is_kernel,
            is_unknown=is_unknown,
        )
        self._diagnostics.frame_lines += 1
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

    def _consume_frame_annotation(
        self,
        text: str,
        pending: _PendingRecord,
    ) -> bool:
        """Consume address or source annotations without treating them as frames.

        With ``srcline`` enabled, perf emits an additional ``dso[offset]`` line after a
        frame that has no source line. CPython perf-map trampolines use the related
        ``[JIT] tid N[offset]`` spelling. It can also emit ``file:line`` with an optional
        ``(inlined)`` marker. Address annotations must repeat the immediately preceding
        frame address and label; source annotations enrich only that preceding frame.
        """
        if not pending.frames_leaf_to_root:
            return False
        match = _FRAME_ANNOTATION.fullmatch(text)
        previous = self._frame_table.resolve(pending.frames_leaf_to_root[-1])
        if match is not None:
            if previous.ip is None or self._normalized_ip(match.group("ip")) != self._normalized_ip(
                previous.ip
            ):
                return False
            label = match.group("label").strip()
            dso_label = Path(previous.dso).name if previous.dso != UNKNOWN else ""
            consumed = label == dso_label or label == f"[JIT] tid {pending.header.thread_id}"
            if consumed:
                self._diagnostics.address_annotation_lines += 1
            return consumed

        source_match = _SOURCE_ANNOTATION.fullmatch(text)
        if source_match is None or previous.source_file is not None:
            return False
        source_file, source_line, source_column = self._parse_source(
            source_match.group("source")
        )
        if source_file is None or source_line is None:
            return False
        before = len(self._frame_table)
        annotated_frame_id = self._frame_table.intern(
            previous.symbol,
            dso=previous.dso,
            raw_symbol=previous.raw_symbol,
            ip=previous.ip,
            source_file=source_file,
            source_line=source_line,
            source_column=source_column,
            is_inline=source_match.group("inline") is not None,
            is_kernel=previous.is_kernel,
            is_unknown=previous.is_unknown,
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
        pending.frames_leaf_to_root[-1] = annotated_frame_id
        self._diagnostics.source_annotation_lines += 1
        return True

    @staticmethod
    def _split_frame_body(body: str) -> tuple[str, str, str | None, bool] | None:
        """Split ``symbol (DSO) [source]`` while allowing balanced parentheses in paths."""
        search_from = 0
        while True:
            opening = body.find(" (", search_from)
            if opening < 0:
                return None
            opening += 1
            depth = 0
            closing: int | None = None
            for index in range(opening, len(body)):
                character = body[index]
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                    if depth == 0:
                        closing = index
                        break
            if closing is None:
                return None
            symbol = body[: opening - 1].strip()
            dso = body[opening + 1 : closing].strip()
            suffix = body[closing + 1 :].strip()
            source: str | None = None
            is_inline = False
            if suffix:
                source_match = _SOURCE_ANNOTATION.fullmatch(suffix)
                if source_match is None and suffix not in {"??", "??:0"}:
                    search_from = opening + 1
                    continue
                if source_match is not None:
                    source = source_match.group("source")
                    is_inline = source_match.group("inline") is not None
                else:
                    source = suffix
            return symbol or UNKNOWN, dso or UNKNOWN, source, is_inline

    @staticmethod
    def _python_perf_map_source(
        raw_symbol: str,
        dso: str,
        source: str | None,
    ) -> tuple[str, str | None]:
        """Split CPython's documented ``py::function:filename`` perf-map name."""
        if source is not None or not raw_symbol.startswith("py::"):
            return raw_symbol, source
        if _PYTHON_PERF_MAP.fullmatch(Path(dso).name) is None:
            return raw_symbol, source
        separator = raw_symbol.find(":", len("py::"))
        if separator < 0 or separator == len(raw_symbol) - 1:
            return raw_symbol, source
        return raw_symbol[:separator], raw_symbol[separator + 1 :]

    @staticmethod
    def _normalized_ip(value: str) -> str:
        normalized = value.lower().removeprefix("0x").lstrip("0")
        return normalized or "0"

    @staticmethod
    def _parse_source(
        source: str | None,
    ) -> tuple[str | None, int | None, int | None]:
        if source is None or source in {"??", "??:0"}:
            return None, None, None
        match = _SOURCE.match(source)
        if match is None:
            return source, None, None
        line = int(match.group("line"))
        column_text = match.group("column")
        column = int(column_text) if column_text is not None else None
        valid_line = line if line > 0 else None
        return (
            match.group("file"),
            valid_line,
            column if valid_line is not None and column is not None and column > 0 else None,
        )

    def _finish_record(self, pending: _PendingRecord) -> StackSample | None:
        frames = pending.frames_leaf_to_root
        if (
            pending.header_frame_id is not None
            and len(frames) >= 2
            and frames[0] == pending.header_frame_id
            and self._same_physical_frame(frames[0], frames[1])
        ):
            frames = frames[1:]
            self._diagnostics.duplicate_frame_lines += 1
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
            weight_unit=perf_period_unit(header.event)
            if header.weight_source == PERF_WEIGHT_SOURCE
            else "sample_count",
            weight_source=header.weight_source,
            process_id=header.process_id,
            thread_id=header.thread_id,
            thread_name=header.command,
            cpu=header.cpu,
            timestamp=header.timestamp,
        )

    def _same_physical_frame(self, left_id: int, right_id: int) -> bool:
        left = self._frame_table.resolve(left_id)
        right = self._frame_table.resolve(right_id)
        return (
            left.ip is not None
            and right.ip is not None
            and self._normalized_ip(left.ip) == self._normalized_ip(right.ip)
            and left.raw_symbol == right.raw_symbol
            and left.dso == right.dso
        )

    def _unknown_frame(self) -> int:
        """Preserve an unreadable callchain position without shifting Self to its parent."""
        before = len(self._frame_table)
        frame_id = self._frame_table.intern(
            UNKNOWN,
            dso=UNKNOWN,
            raw_symbol="[unparsed-frame]",
            is_unknown=True,
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
            _sanitized, byte_count, invalid_bytes = sanitize_surrogateescaped_text(chunk)
            self._diagnostics.unicode_replacement_count += invalid_bytes
            self._diagnostics.bytes_read += byte_count
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
