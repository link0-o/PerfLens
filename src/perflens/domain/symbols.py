"""Tool-independent symbol and source-location domain records."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

AddressKind = Literal["module_offset", "file_offset", "runtime_only", "unknown"]


@dataclass(frozen=True, slots=True)
class ModuleIdentity:
    build_id: str
    dso_path: Path
    debug_file_candidates: tuple[Path, ...]
    architecture: str


@dataclass(frozen=True, slots=True)
class ModuleLocation:
    module_offset: int | None
    runtime_ip: int | None = None
    file_offset: int | None = None
    mapping_start: int | None = None
    mapping_pgoff: int | None = None
    address_kind: AddressKind = "unknown"


@dataclass(frozen=True, slots=True)
class ResolvedFrame:
    symbol: str
    file: Path | None
    line: int | None
    column: int | None = None
    is_inline: bool = False


@dataclass(frozen=True, slots=True)
class ElfMetadata:
    schema_version: str
    path: Path
    build_id: str | None
    architecture: str
    elf_type: str
    is_pie: bool
    is_stripped: bool
    has_debug_info: bool
    debug_link: str | None
    debug_file_candidates: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class SourceContext:
    schema_version: str
    file: Path
    line: int
    start_line: int
    end_line: int
    lines: tuple[str, ...]


class SymbolResolver(Protocol):
    resolver_version: str

    def resolve(
        self,
        module: ModuleIdentity,
        location: ModuleLocation,
    ) -> tuple[ResolvedFrame, ...]: ...

    def close(self) -> None: ...
