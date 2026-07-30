"""Stable domain errors without transport-layer dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


def _empty_details() -> dict[str, Any]:
    return {}


class ErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    PROFILE_PARSE_FAILED = "PROFILE_PARSE_FAILED"
    EXTERNAL_TOOL_FAILED = "EXTERNAL_TOOL_FAILED"
    EXTERNAL_TOOL_TIMEOUT = "EXTERNAL_TOOL_TIMEOUT"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    PATH_SAFETY_VIOLATION = "PATH_SAFETY_VIOLATION"
    OUTPUT_WRITE_FAILED = "OUTPUT_WRITE_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(slots=True)
class PerfLensError(Exception):
    code: ErrorCode
    stage: str
    message: str
    recoverable: bool = False
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=_empty_details)
    suggested_actions: tuple[str, ...] = ()

    def __str__(self) -> str:
        return self.message
