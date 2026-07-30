"""Ports implemented by profile adapters."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self

from perflens.domain.models import FrameTable, ParseDiagnostics, ResourceLimits, StackSample


class ProfileSource(Protocol):
    @property
    def path(self) -> Path: ...

    @property
    def source_type(self) -> str: ...


class ProfileStream(Protocol):
    @property
    def frame_table(self) -> FrameTable: ...

    def __enter__(self) -> Self: ...

    def __iter__(self) -> Iterator[StackSample]: ...

    def diagnostics(self) -> ParseDiagnostics: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


class ProfileAdapter(Protocol):
    def can_handle(self, source: ProfileSource) -> bool: ...

    def open(self, source: ProfileSource, limits: ResourceLimits) -> ProfileStream: ...
