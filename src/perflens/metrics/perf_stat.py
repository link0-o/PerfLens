"""Bounded adapter for the stable delimited output requested from ``perf stat``."""

from __future__ import annotations

import csv
import math
from pathlib import Path
from typing import TextIO

from perflens.contracts.artifacts import PerfStatMetric
from perflens.domain.errors import ErrorCode, PerfLensError


class PerfStatMetricAdapter:
    """Parse semicolon-delimited perf-stat metrics without treating them as stacks."""

    def __init__(
        self,
        *,
        max_input_bytes: int = 16 << 20,
        max_line_chars: int = 64 << 10,
        max_metrics: int = 256,
        max_warnings: int = 32,
    ) -> None:
        if (
            max_input_bytes < 1
            or max_line_chars < 1
            or max_metrics < 1
            or max_warnings < 0
        ):
            raise ValueError("perf stat resource limits are invalid")
        self.max_input_bytes = max_input_bytes
        self.max_line_chars = max_line_chars
        self.max_metrics = max_metrics
        self.max_warnings = max_warnings

    def parse(self, path: Path) -> tuple[tuple[PerfStatMetric, ...], tuple[str, ...]]:
        try:
            safe_path = path.expanduser().resolve(strict=True)
            size = safe_path.stat().st_size
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "perf_stat",
                "perf stat output cannot be resolved",
                details={"path": str(path)},
            ) from exc
        if not safe_path.is_file():
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "perf_stat",
                "perf stat output is not a regular file",
                details={"path": str(safe_path)},
            )
        if size > self.max_input_bytes:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "perf_stat",
                "perf stat output exceeds its input limit",
                details={"actual_bytes": size, "max_input_bytes": self.max_input_bytes},
            )

        metrics: list[PerfStatMetric] = []
        warnings: list[str] = []
        with safe_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            line_number = 0
            while True:
                raw_line = handle.readline(self.max_line_chars + 1)
                if raw_line == "":
                    break
                line_number += 1
                if len(raw_line) > self.max_line_chars:
                    if not raw_line.endswith("\n"):
                        self._drain_line(handle)
                    self._warn(
                        warnings,
                        f"Line {line_number} exceeds the line limit and was skipped.",
                    )
                    continue
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if len(metrics) >= self.max_metrics:
                    raise PerfLensError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        "perf_stat",
                        "perf stat output exceeds max_metrics",
                        details={"max_metrics": self.max_metrics},
                    )
                fields = next(csv.reader([line], delimiter=";"))
                metric = self._parse_row(fields, line_number, warnings)
                if metric is not None:
                    metrics.append(metric)

        metrics = self._append_ipc(metrics)
        if not metrics:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "perf_stat",
                "perf stat output contained no supported metric rows",
                recoverable=True,
                details={"warnings": warnings},
            )
        return tuple(metrics), tuple(warnings)

    def _parse_row(
        self,
        fields: list[str],
        line_number: int,
        warnings: list[str],
    ) -> PerfStatMetric | None:
        if len(fields) < 3:
            self._warn(warnings, f"Line {line_number} has fewer than three fields and was skipped.")
            return None
        raw_value = fields[0].strip()
        unit = fields[1].strip()
        event = fields[2].strip()
        if not event:
            self._warn(warnings, f"Line {line_number} has no event name and was skipped.")
            return None
        lowered = raw_value.lower()
        if "not supported" in lowered:
            value = None
            status = "not_supported"
        elif "not counted" in lowered:
            value = None
            status = "not_counted"
        else:
            try:
                value = float(raw_value)
            except ValueError:
                self._warn(
                    warnings,
                    f"Line {line_number} has an invalid numeric value and was skipped.",
                )
                return None
            if not math.isfinite(value):
                self._warn(
                    warnings,
                    f"Line {line_number} has a non-finite numeric value and was skipped.",
                )
                return None
            status = "measured"
        run_time_ns = self._optional_int(fields, 3)
        running_percent = self._optional_float(fields, 4)
        return PerfStatMetric(
            event=event,
            value=value,
            unit=unit,
            run_time_ns=run_time_ns,
            running_percent=running_percent,
            status=status,
        )

    @staticmethod
    def _optional_int(fields: list[str], index: int) -> int | None:
        if index >= len(fields):
            return None
        try:
            value = int(float(fields[index].strip()))
        except (OverflowError, ValueError):
            return None
        return value if value >= 0 else None

    @staticmethod
    def _optional_float(fields: list[str], index: int) -> float | None:
        if index >= len(fields):
            return None
        try:
            value = float(fields[index].strip().rstrip("%"))
        except ValueError:
            return None
        return value if 0 <= value <= 100 else None

    @staticmethod
    def _append_ipc(metrics: list[PerfStatMetric]) -> list[PerfStatMetric]:
        values = {
            metric.event.split(":", maxsplit=1)[0]: metric.value
            for metric in metrics
            if metric.value is not None
        }
        cycles = values.get("cycles")
        instructions = values.get("instructions")
        if cycles is None or instructions is None or cycles <= 0:
            return metrics
        return [
            *metrics,
            PerfStatMetric(
                event="instructions-per-cycle",
                value=instructions / cycles,
                unit="instructions/cycle",
                derived=True,
                status="derived",
            ),
        ]

    def _warn(self, warnings: list[str], message: str) -> None:
        if len(warnings) < self.max_warnings:
            warnings.append(message)

    def _drain_line(self, handle: TextIO) -> None:
        while True:
            chunk = handle.readline(self.max_line_chars + 1)
            if chunk == "" or chunk.endswith("\n"):
                return
