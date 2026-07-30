"""Simple stage timing without a logging-framework dependency."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from time import perf_counter


@contextmanager
def measure_stage(name: str, timings: dict[str, float]) -> Generator[None]:
    started = perf_counter()
    try:
        yield
    finally:
        timings[name] = perf_counter() - started
