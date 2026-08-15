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


def _empty_symbols() -> set[str]:
    return set()


def _empty_source_locations() -> set[str]:
    return set()


@dataclass(frozen=True, slots=True)
class FrameKey:
    symbol: str
    dso: str = UNKNOWN_DSO
    raw_symbol: str | None = None
    ip: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    source_column: int | None = None
    is_inline: bool = False
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
        source_column: int | None = None,
        is_inline: bool = False,
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
            source_column=source_column,
            is_inline=is_inline,
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
    frame_lines: int = 0
    duplicate_frame_lines: int = 0
    address_annotation_lines: int = 0
    source_annotation_lines: int = 0
    unicode_replacement_count: int = 0
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
class ProfileConversionProvenance:
    adapter: str
    parser_version: str
    normalization_version: str
    converter_path: str | None
    converter_sha256: str | None
    converter_version: str | None
    argv: tuple[str, ...]
    locale: str
    transcript_sha256: str
    transcript_bytes: int
    compatibility_fallbacks: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()


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

    def __post_init__(self) -> None:
        positive_limits = (
            self.max_input_bytes,
            self.max_records,
            self.max_line_chars,
            self.max_stack_depth,
            self.max_unique_frames,
            self.max_unique_call_paths,
            self.max_hotspots_output,
            self.max_call_paths_output,
            self.max_output_bytes,
        )
        if any(value < 1 for value in positive_limits) or self.max_warnings < 0:
            raise ValueError("ResourceLimits values must be positive except max_warnings")


@dataclass(slots=True)
class HotspotAccumulator:
    self_weight: int = 0
    inclusive_weight: int = 0
    sample_count: int = 0
    stack_occurrence_count: int = 0
    thread_ids: set[int] = field(default_factory=_empty_thread_ids)
    symbol_variants: set[str] = field(default_factory=_empty_symbols)
    symbol_variants_truncated: bool = False
    source_locations: set[str] = field(default_factory=_empty_source_locations)
    source_locations_truncated: bool = False


@dataclass(frozen=True, slots=True)
class HotspotResult:
    symbol: str
    dso: str
    self_weight: int
    inclusive_weight: int
    sample_count: int
    stack_occurrence_count: int
    thread_count: int
    symbol_variants: tuple[str, ...]
    symbol_variant_count: int
    symbol_variants_truncated: bool
    normalization_merged: bool
    source_locations: tuple[str, ...]
    source_locations_truncated: bool


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
    call_graph_weight: int
    unknown_self_weight: int
    source_line_frame_count: int
    source_line_self_weight: int
    inline_frame_count: int
    total_frame_count: int
    normalization_merge_count: int
    hotspots: tuple[HotspotResult, ...]
    call_paths: tuple[CallPathResult, ...]
