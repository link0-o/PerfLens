"""Allowlisted perf event sets shared without importing collection execution code."""

from __future__ import annotations

HARDWARE_STAT_EVENTS = (
    "cycles",
    "instructions",
    "cache-references",
    "cache-misses",
    "branches",
    "branch-misses",
)
SOFTWARE_STAT_EVENTS = (
    "task-clock",
    "context-switches",
    "cpu-migrations",
    "page-faults",
)
DEFAULT_STAT_EVENTS = (*HARDWARE_STAT_EVENTS, *SOFTWARE_STAT_EVENTS)
DEFAULT_RECORD_EVENT = "cycles"
SOFTWARE_RECORD_EVENT = "cpu-clock"
