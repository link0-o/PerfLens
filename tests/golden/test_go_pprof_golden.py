from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal, TypedDict, cast

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import RuntimeSampledContentionEvent
from perflens.runtime_locks import go_pprof_adapter
from perflens.runtime_locks.go_pprof_converter import convert_go_pprof_raw

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "runtime_locks" / "go"


class _GoldenEvent(TypedDict):
    lock_kind: str
    observed_count: int
    cumulative_wait_ns: int


class _GoldenProfile(TypedDict):
    fixture: str
    profile_kind: Literal["mutex", "block"]
    runtime_version: str
    generator: str
    expected_event_count: int
    expected_events: list[_GoldenEvent]
    source_sha256: str


class _GoldenManifest(TypedDict):
    schema_version: str
    profiles: list[_GoldenProfile]


def _binding(runtime_version: str) -> RuntimeLockAdapterExecutionBinding:
    tools = (
        RuntimeLockAdapterToolBinding(
            name="go", version=runtime_version, binary_sha256="1" * 64
        ),
        RuntimeLockAdapterToolBinding(
            name="pprof", version=runtime_version, binary_sha256="2" * 64
        ),
    )
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    configuration = "3" * 64
    metadata = "4" * 64
    identity = derive_runtime_lock_adapter_execution_identity(
        "go_pprof",
        "go-pprof-adapter-v1",
        "pprof",
        runtime_version,
        "mutex_and_block",
        "cumulative",
        None,
        toolchain,
        configuration,
        metadata,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id="go_pprof",
        adapter_version="go-pprof-adapter-v1",
        backend_id="pprof",
        runtime_version=runtime_version,
        profile="mutex_and_block",
        measurement_semantics="cumulative",
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256=configuration,
        metadata_sha256=metadata,
        execution_identity_sha256=identity,
        limitations=(),
    )


def test_real_go_pprof_raw_goldens_remain_compatible_and_private() -> None:
    manifest = cast(
        _GoldenManifest,
        json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8")),
    )
    assert manifest["schema_version"] == "1.1"

    for profile in manifest["profiles"]:
        assert profile["generator"] == (
            f"go{profile['runtime_version']} linux/amd64 runtime/pprof "
            "+ matching pprof -raw"
        )
        assert len(profile["expected_events"]) == profile["expected_event_count"]
        source_path = FIXTURE_ROOT / profile["fixture"]
        source = source_path.read_bytes()
        assert hashlib.sha256(source).hexdigest() == profile["source_sha256"]
        with source_path.open("rb") as stream:
            evidence = convert_go_pprof_raw(
                stream,
                execution_binding=_binding(profile["runtime_version"]),
                profile_kind=profile["profile_kind"],
                target_pid=101,
                target_uid=1000,
                target_start_time_ticks=202,
                mutex_profile_fraction=(
                    1 if profile["profile_kind"] == "mutex" else None
                ),
                block_profile_rate_ns=(
                    1 if profile["profile_kind"] == "block" else None
                ),
            ).evidence

        assert len(evidence.events) == profile["expected_event_count"]
        samples = [
            event
            for event in evidence.events
            if isinstance(event, RuntimeSampledContentionEvent)
        ]
        assert len(samples) == len(evidence.events)
        assert [
            {
                "lock_kind": event.lock_kind,
                "observed_count": event.observed_count,
                "cumulative_wait_ns": event.cumulative_wait_ns,
            }
            for event in samples
        ] == profile["expected_events"]
        assert evidence.quality.status == "partial"
        assert all(event.estimated_count is None for event in samples)
        assert "/tmp/" not in evidence.model_dump_json()
        assert "/home/" not in evidence.model_dump_json()
        assert all(context.kind == "process_aggregate" for context in evidence.execution_contexts)


def test_available_go_versions_have_matching_mutex_and_block_goldens() -> None:
    manifest = cast(
        _GoldenManifest,
        json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8")),
    )
    kinds_by_version: dict[str, set[str]] = {}
    for profile in manifest["profiles"]:
        kinds = kinds_by_version.setdefault(profile["runtime_version"], set())
        assert profile["profile_kind"] not in kinds
        kinds.add(profile["profile_kind"])

    complete_versions = {
        version for version, kinds in kinds_by_version.items() if kinds == {"mutex", "block"}
    }
    assert complete_versions == go_pprof_adapter.REVIEWED_GO_PPROF_GOLDEN_VERSIONS
