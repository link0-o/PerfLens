"""Stable event semantics shared by parsers and evidence verification."""

from __future__ import annotations

import re

_PMU_HARDWARE_EVENT = re.compile(
    r"^(?:cpu|cpu_core|cpu_atom)/"
    r"(?P<event>cycles|instructions|cache-references|cache-misses|branches|branch-misses)/$"
)
_PERF_EVENT_MODIFIER = re.compile(r"^[ukhGHpPSDWebR]+$")


def canonical_perf_event(event: str) -> str:
    """Normalize only equivalent spellings needed for fixed event provenance checks."""
    event_name = event
    if ":" in event:
        candidate, modifier = event.rsplit(":", 1)
        if _PERF_EVENT_MODIFIER.fullmatch(modifier) is not None:
            event_name = candidate
    if event_name == "cpu-cycles":
        return "cycles"
    match = _PMU_HARDWARE_EVENT.fullmatch(event_name)
    if match is not None:
        return match.group("event")
    return event_name


def perf_period_unit(event: str) -> str:
    """Return only units whose perf-event period semantics are unambiguous."""
    event_name = canonical_perf_event(event)
    if event_name in {"cpu-clock", "task-clock"}:
        return "nanoseconds"
    if event_name == "cycles":
        return "cycles"
    if event_name == "instructions":
        return "instructions"
    return "event_count"
