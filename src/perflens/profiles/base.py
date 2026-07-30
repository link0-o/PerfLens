"""Concrete source record shared by adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FileProfileSource:
    path: Path
    source_type: str
