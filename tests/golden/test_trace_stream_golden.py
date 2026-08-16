from __future__ import annotations

import json
import os
from pathlib import Path

from perflens.domain.trace import LockAction, LockEvent, TargetIdentity
from perflens.profiles.trace_stream import FixedTracePerfScriptAdapter


def _private_fixture(fixture_root: Path, tmp_path: Path, name: str) -> Path:
    destination = tmp_path / name
    destination.write_bytes((fixture_root / "trace_perf_script" / name).read_bytes())
    destination.chmod(0o600)
    return destination


def test_fixed_trace_stream_matches_privacy_safe_golden(
    fixture_root: Path,
    tmp_path: Path,
) -> None:
    target = TargetIdentity(pid=4242, uid=1000, start_time_ticks=123456)
    scheduler = FixedTracePerfScriptAdapter(
        mode="sched",
        target=target,
        observed_target_tids=(4242, 4243),
        expected_input_owner_uid=os.getuid(),
        expected_input_owner_gid=os.getgid(),
        expected_input_mode=0o600,
        lock_identity_key=bytes(32),
    ).parse(_private_fixture(fixture_root, tmp_path, "scheduler.perf-script"))
    lock = FixedTracePerfScriptAdapter(
        mode="lock",
        target=target,
        observed_target_tids=(4242, 4243),
        expected_input_owner_uid=os.getuid(),
        expected_input_owner_gid=os.getgid(),
        expected_input_mode=0o600,
        lock_identity_key=bytes(32),
    ).parse(_private_fixture(fixture_root, tmp_path, "lock.perf-script"))
    actual = {
        "scheduler": {
            "event_kinds": [event.kind.value for event in scheduler.events],
            "observed_target_tids": list(scheduler.observed_target_tids),
            "input_event_count": scheduler.statistics.input_event_count,
            "emitted_event_count": scheduler.statistics.emitted_event_count,
            "lost_event_count": scheduler.statistics.lost_event_count,
            "malformed_event_count": scheduler.statistics.malformed_event_count,
            "foreign_event_dropped_count": (
                scheduler.statistics.foreign_event_dropped_count
            ),
            "unsupported_event_count": scheduler.statistics.unsupported_event_count,
            "provisional_enrichment_event_count": (
                scheduler.statistics.provisional_enrichment_event_count
            ),
        },
        "lock": {
            "event_kinds": [event.kind.value for event in lock.events],
            "wait_outcomes": [
                event.wait_outcome.value
                for event in lock.events
                if isinstance(event, LockEvent)
                and event.action is LockAction.WAIT_ENDED
                and event.wait_outcome is not None
            ],
            "observed_target_tids": list(lock.observed_target_tids),
            "input_event_count": lock.statistics.input_event_count,
            "emitted_event_count": lock.statistics.emitted_event_count,
            "unsupported_event_count": lock.statistics.unsupported_event_count,
            "lock_phase_enrichment_event_count": (
                lock.statistics.lock_phase_enrichment_event_count
            ),
            "foreign_event_dropped_count": lock.statistics.foreign_event_dropped_count,
        },
    }
    expected = json.loads(
        (fixture_root / "golden" / "trace-stream.summary.json").read_text(encoding="utf-8")
    )

    assert actual == expected
