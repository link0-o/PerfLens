"""Workspace-contained source path mapping and bounded context reads."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.symbols import SourceContext

SOURCE_CONTEXT_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class PathMapping:
    source_prefix: Path
    destination_prefix: Path


class SourceLocator:
    def __init__(self, workspace_root: Path, mappings: tuple[PathMapping, ...] = ()) -> None:
        self._workspace_root = workspace_root.expanduser().resolve(strict=True)
        if not self._workspace_root.is_dir():
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "source",
                "Workspace root is not a directory",
                details={"path": str(self._workspace_root)},
            )
        self._mappings = tuple(
            PathMapping(
                mapping.source_prefix.expanduser(),
                mapping.destination_prefix.expanduser().resolve(strict=False),
            )
            for mapping in mappings
        )

    def map_path(self, source_path: Path) -> Path:
        candidate = source_path.expanduser()
        for mapping in self._mappings:
            try:
                suffix = candidate.relative_to(mapping.source_prefix)
            except ValueError:
                continue
            candidate = mapping.destination_prefix / suffix
            break
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self._workspace_root)
        except (OSError, ValueError) as exc:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "source",
                "Source file is outside the allowed workspace",
                details={"path": str(candidate), "workspace_root": str(self._workspace_root)},
            ) from exc
        if not resolved.is_file():
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "source",
                "Source path is not a regular file",
                details={"path": str(resolved)},
            )
        return resolved

    def context(
        self,
        source_path: Path,
        line: int,
        *,
        before: int = 20,
        after: int = 20,
        max_line_chars: int = 16_384,
        max_input_bytes: int = 64 << 20,
    ) -> SourceContext:
        if (
            line < 1
            or before < 0
            or after < 0
            or before + after > 400
            or max_line_chars < 1
            or max_line_chars > 1 << 20
            or max_input_bytes < 1
            or max_input_bytes > 1 << 30
        ):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "source",
                "Invalid source context bounds",
                details={
                    "line": line,
                    "before": before,
                    "after": after,
                    "max_line_chars": max_line_chars,
                    "max_input_bytes": max_input_bytes,
                },
            )
        safe_path = self.map_path(source_path)
        try:
            size = safe_path.stat().st_size
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "source",
                "Source file size cannot be inspected",
                details={"path": str(safe_path)},
            ) from exc
        if size > max_input_bytes:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "source",
                "Source file exceeds max_input_bytes",
                recoverable=True,
                details={"actual_bytes": size, "max_input_bytes": max_input_bytes},
            )
        start = max(1, line - before)
        end = line + after
        selected: list[str] = []
        with safe_path.open(encoding="utf-8", errors="replace") as handle:
            number = 0
            while number < end:
                text = handle.readline(max_line_chars + 1)
                if text == "":
                    break
                number += 1
                if len(text) > max_line_chars and not text.endswith("\n"):
                    self._drain_line(handle, max_line_chars=max_line_chars)
                if number >= start:
                    selected.append(text.rstrip("\r\n")[:max_line_chars])
        actual_end = start + len(selected) - 1 if selected else start
        return SourceContext(
            schema_version=SOURCE_CONTEXT_SCHEMA_VERSION,
            file=safe_path,
            line=line,
            start_line=start,
            end_line=actual_end,
            lines=tuple(selected),
        )

    @staticmethod
    def _drain_line(handle: TextIO, *, max_line_chars: int) -> None:
        while True:
            chunk = handle.readline(max_line_chars + 1)
            if chunk == "" or chunk.endswith("\n"):
                return
