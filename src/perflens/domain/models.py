"""Memory-conscious records used on parsing and aggregation hot paths."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

UNKNOWN = "unknown"
UNKNOWN_DSO = UNKNOWN
FOLDED_EVENT = UNKNOWN
FOLDED_WEIGHT_UNIT = "sample_count"
FOLDED_WEIGHT_SOURCE = "folded_weight"


def _empty_warnings() -> list[ParseWarning]:
    return []


def _empty_thread_ids() -> set[int]:
    return set()


@dataclass(frozen=True, slots=True)
class FrameKey:
    symbol: str
    dso: str = UNKNOWN_DSO
    raw_symbol: str | None = None
    ip: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    is_kernel: bool = False
    is_unknown: bool = False


class FrameTable:
    """Intern repeated strings and expose frames through compact integer IDs."""

    __slots__ = ("_frames", "_ids")

    def __init__(self) -> None:
        self._frames: list[FrameKey] = []
        self._ids: dict[FrameKey, int] = {}

    def intern(
        self,
        symbol: str,
        *,
        dso: str = UNKNOWN_DSO,
        raw_symbol: str | None = None,
        ip: str | None = None,
        source_file: str | None = None,
        source_line: int | None = None,
        is_kernel: bool = False,
        is_unknown: bool = False,
    ) -> int:
        key = FrameKey(
            symbol=sys.intern(symbol),
            dso=sys.intern(dso),
            raw_symbol=sys.intern(raw_symbol) if raw_symbol is not None else None,
            ip=sys.intern(ip) if ip is not None else None,
            source_file=sys.intern(source_file) if source_file is not None else None,
            source_line=source_line,
            is_kernel=is_kernel,
            is_unknown=is_unknown,
        )
        existing = self._ids.get(key)
        if existing is not None:
            return existing
        frame_id = len(self._frames)
        self._frames.append(key)
        self._ids[key] = frame_id
        return frame_id

    def resolve(self, frame_id: int) -> FrameKey:
        return self._frames[frame_id]

    def __len__(self) -> int:
        return len(self._frames)


@dataclass(frozen=True, slots=True)
class StackSample:
    """A single logical weighted record. Frames always run root to leaf."""

    frames: tuple[int, ...]
    weight: int
    event: str = FOLDED_EVENT
    weight_unit: str = FOLDED_WEIGHT_UNIT
    weight_source: str = FOLDED_WEIGHT_SOURCE
    process_id: int | None = None
    thread_id: int | None = None
    thread_name: str = UNKNOWN
    cpu: int | None = None
    timestamp: float | None = None


@dataclass(frozen=True, slots=True)
class ParseWarning:
    code: str
    message: str
    line_number: int | None = None
    preview: str | None = None


@dataclass(slots=True)
class ParseDiagnostics:
    parsed_records: int = 0
    skipped_records: int = 0
    malformed_records: int = 0
    bytes_read: int = 0
    warnings: list[ParseWarning] = field(default_factory=_empty_warnings)
    warning_count: int = 0
    warnings_truncated: bool = False
    max_warnings: int = 100

    def add_warning(self, warning: ParseWarning) -> None:
        self.warning_count += 1
        if len(self.warnings) < self.max_warnings:
            self.warnings.append(warning)
        else:
            self.warnings_truncated = True


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_input_bytes: int = 1 << 30
    max_records: int = 10_000_000
    max_line_chars: int = 1 << 20
    max_stack_depth: int = 4_096
    max_unique_frames: int = 2_000_000
    max_unique_call_paths: int = 1_000_000
    max_warnings: int = 100
    max_hotspots_output: int = 10_000
    max_call_paths_output: int = 1_000
    max_output_bytes: int = 128 << 20


@dataclass(slots=True)
class HotspotAccumulator:
    self_weight: int = 0
    inclusive_weight: int = 0
    sample_count: int = 0
    stack_occurrence_count: int = 0
    thread_ids: set[int] = field(default_factory=_empty_thread_ids)


@dataclass(frozen=True, slots=True)
class HotspotResult:
    symbol: str
    dso: str
    self_weight: int
    inclusive_weight: int
    sample_count: int
    stack_occurrence_count: int
    thread_count: int


@dataclass(frozen=True, slots=True)
class CallPathResult:
    frame_ids: tuple[int, ...]
    weight: int
    record_count: int


@dataclass(frozen=True, slots=True)
class AggregationResult:
    total_weight: int
    record_count: int
    has_call_graph: bool
    event: str
    weight_unit: str
    weight_source: str
    hotspots: tuple[HotspotResult, ...]
    call_paths: tuple[CallPathResult, ...]
