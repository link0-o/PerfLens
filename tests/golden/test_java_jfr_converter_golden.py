from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

import pytest

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import RuntimeWaitEndEvent
from perflens.runtime_locks.java_jfr_converter import convert_java_jfr_json

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _binding(jdk: int) -> RuntimeLockAdapterExecutionBinding:
    version = f"{jdk}.0.1"
    tools = (
        RuntimeLockAdapterToolBinding(name="java", version=version, binary_sha256="1" * 64),
        RuntimeLockAdapterToolBinding(name="jfr", version=version, binary_sha256="2" * 64),
    )
    toolchain = derive_runtime_lock_toolchain_identity(tools)
    execution = derive_runtime_lock_adapter_execution_identity(
        "java_jfr",
        "java-jfr-adapter-v1",
        "jfr",
        version,
        "deep",
        "thresholded",
        1_000_000,
        toolchain,
        "3" * 64,
        "4" * 64,
        "5" * 64,
    )
    return RuntimeLockAdapterExecutionBinding(
        adapter_id="java_jfr",
        adapter_version="java-jfr-adapter-v1",
        backend_id="jfr",
        runtime_version=version,
        profile="deep",
        measurement_semantics="thresholded",
        duration_threshold_ns=1_000_000,
        tools=tools,
        toolchain_identity_sha256=toolchain,
        configuration_sha256="3" * 64,
        metadata_sha256="4" * 64,
        runtime_payload_identity_sha256="5" * 64,
        execution_identity_sha256=execution,
    )


@pytest.mark.parametrize("jdk", [21, 25])
def test_real_jfr_conversion_matches_reviewed_golden(jdk: int) -> None:
    raw = (FIXTURES / f"runtime_locks/jfr/jdk{jdk}-locks.json").read_bytes()
    receipt = convert_java_jfr_json(
        BytesIO(raw),
        execution_binding=_binding(jdk),
        target_pid=9000,
        target_uid=1000,
        target_start_time_ticks=77,
        created_at="2026-08-30T00:00:00+00:00",
    )
    evidence = receipt.evidence
    outcomes: list[dict[str, str]] = []
    for event in evidence.events:
        assert isinstance(event, RuntimeWaitEndEvent)
        outcomes.append({"lock_kind": event.lock_kind, "outcome": event.outcome})
    actual: dict[str, object] = {
        "content_sha256": evidence.content_sha256,
        "context_count": len(evidence.execution_contexts),
        "event_count": len(evidence.events),
        "evidence_id": evidence.runtime_lock_evidence_id,
        "kinds": sorted({event.lock_kind for event in evidence.events}),
        "outcomes": sorted(outcomes, key=lambda item: (item["lock_kind"], item["outcome"])),
        "quality": evidence.quality.status,
        "raw_bytes": receipt.raw_source_bytes,
        "raw_sha256": receipt.raw_source_sha256,
        "stack_count": len(evidence.stacks),
    }
    expected = json.loads(
        (FIXTURES / f"golden/java-jfr-jdk{jdk}.summary.json").read_text(encoding="utf-8")
    )
    assert actual == expected
