from __future__ import annotations

# pyright: reportPrivateUsage=false
import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from perflens.collection.planning import inspect_pid_identity
from perflens.collector_broker.client import (
    _SocketIdentity,
    _verify_trace_evidence_receipt,
)
from perflens.collector_broker.protocol import BrokerTraceEvidenceReference
from perflens.collector_broker.trace import (
    TraceCollectionCoordinator,
    _trace_helper_target_from_plan,
)
from perflens.contracts.artifacts import (
    CollectionPlanArtifact,
    ContainerCollectionTargetBinding,
)
from perflens.contracts.trace import TraceEvidenceArtifact
from perflens.domain.errors import PerfLensError
from perflens.trace_helper.client import TraceHelperClient
from perflens.trace_helper.policy import TracePolicy
from perflens.trace_helper.protocol import (
    TraceHelperCollectionResult,
    TraceHelperCollectPidRequest,
    TraceHelperDockerTarget,
    TraceHelperHealthResult,
    parse_trace_helper_request_frame,
)


class _FakeTraceHelper:
    def __init__(self, policy: TracePolicy, private_spool: Path, target_tid: int) -> None:
        self._policy = policy
        self._private_spool = private_spool
        self._target_tid = target_tid

    def health(self) -> TraceHelperHealthResult:
        return TraceHelperHealthResult(
            kind="health",
            helper_version="test-helper-v1",
            helper_pid=os.getpid(),
            helper_uid=os.geteuid(),
            ready=True,
            capture_backend="target_filtered_kernel_v1",
            capture_backend_status="available",
            supported_modes=self._policy.allowed_modes,
            policy_sha256=self._policy.policy_sha256,
            max_duration_milliseconds=10_000,
            max_output_bytes=67_108_864,
            max_concurrent_collections=1,
            target_filter_before_userspace=True,
        )

    def collect(
        self,
        request: TraceHelperCollectPidRequest,
        *,
        ready_callback: Callable[[], None] | None = None,
    ) -> TraceHelperCollectionResult:
        if ready_callback is not None:
            ready_callback()
        artifact_name = f"{request.plan_id}.trace.ndjson"
        raw_path = self._private_spool / artifact_name
        payload = (
            json.dumps(
                {
                    "schema_version": "1.0",
                    "sequence": 0,
                    "timestamp_ns": 1_500,
                    "cpu": 0,
                    "kind": "sched_wakeup",
                    "target_tid": self._target_tid,
                    "target_cpu": 0,
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        raw_path.write_bytes(payload)
        raw_path.chmod(0o640)
        return TraceHelperCollectionResult(
            kind="collection",
            plan_id=request.plan_id,
            mode=request.mode,
            target_pid=request.target.pid,
            target_start_time_ticks=request.target.start_time_ticks,
            artifact_name=artifact_name,
            output_bytes=len(payload),
            output_sha256=hashlib.sha256(payload).hexdigest(),
            output_format="target_filtered_trace_ndjson",
            capture_backend="target_filtered_kernel_v1",
            policy_sha256=request.expected_policy_sha256,
            observed_target_tids=(self._target_tid,),
            event_count=1,
            lost_event_count=0,
            truncated=False,
            started_at_monotonic_nanoseconds=1_000,
            # A real ring-buffer poll can finish just beyond the requested one-second window.
            # The public evidence limit is the independently enforced policy ceiling (10s), not
            # ceil(requested duration), so bounded teardown time must not invalidate the trace.
            finished_at_monotonic_nanoseconds=1_000_001_001,
        )


def _immutable_code(path: Path) -> Path:
    path.write_text("fixed test code\n", encoding="utf-8")
    path.chmod(0o400)
    return path


def _trace_plan() -> CollectionPlanArtifact:
    target_pid = os.getppid()
    target_uid, start_ticks = inspect_pid_identity(target_pid)
    return CollectionPlanArtifact(
        plan_id="plan-0123456789abcdefabcd",
        mode="sched",
        target_type="pid",
        target_pid=target_pid,
        target_uid=target_uid,
        target_start_time_ticks=start_ticks,
        backend="privileged_broker",
        duration_seconds=1,
        requested_event_source="hardware_required",
        max_output_bytes=1 << 20,
        expires_at=(datetime.now(tz=UTC) + timedelta(seconds=30)).isoformat(),
        policy_status="allowed",
        required_privilege="cap_perfmon",
    )


def test_trace_coordinator_preserves_complete_docker_target_binding() -> None:
    fixture = (
        Path(__file__).parents[1]
        / "fixtures/trace_helper/valid/docker-sched.jsonl"
    )
    request = parse_trace_helper_request_frame(
        fixture.read_bytes(),
        now_unix_milliseconds=4_102_444_700_000,
    )
    assert isinstance(request, TraceHelperCollectPidRequest)
    assert isinstance(request.target, TraceHelperDockerTarget)
    binding = ContainerCollectionTargetBinding.model_validate(
        request.target.container.model_dump()
    )
    plan = _trace_plan().model_copy(
        update={
            "target_pid": request.target.pid,
            "target_uid": request.target.uid,
            "target_start_time_ticks": request.target.start_time_ticks,
            "target_runtime": "docker",
            "container_target": binding,
        }
    )

    assert _trace_helper_target_from_plan(plan) == request.target


def _coordinator(tmp_path: Path, plan: CollectionPlanArtifact) -> TraceCollectionCoordinator:
    private_spool = tmp_path / "private"
    public_spool = tmp_path / "public"
    private_spool.mkdir(mode=0o750)
    public_spool.mkdir(mode=0o750)
    policy = TracePolicy(
        path=tmp_path / "trace.toml",
        policy_sha256="a" * 64,
        allowed_uid=plan.target_uid,
        allowed_modes=("sched", "off_cpu", "lock"),
        max_duration_seconds=10,
        max_output_bytes=64 << 20,
        helper_socket=tmp_path / "private.sock",
        private_spool=private_spool,
    )
    helper = _FakeTraceHelper(policy, private_spool, plan.target_pid)
    return TraceCollectionCoordinator(
        policy,
        helper_client=cast(TraceHelperClient, helper),
        public_spool=public_spool,
        public_artifact_mode=0o640,
        expected_helper_uid=os.geteuid(),
        producer_path=_immutable_code(tmp_path / "producer"),
        converter_path=_immutable_code(tmp_path / "converter"),
    )


def _socket_identity(public_spool: Path) -> _SocketIdentity:
    parent = public_spool.parent.stat()
    return _SocketIdentity(
        path=public_spool / "unused.sock",
        device=1,
        inode=1,
        ctime_ns=1,
        uid=os.geteuid(),
        gid=os.getegid(),
        mode=0o660,
        parent_device=parent.st_dev,
        parent_inode=parent.st_ino,
        parent_uid=parent.st_uid,
        parent_mode=0o750,
    )


def test_trace_coordinator_publishes_only_verified_public_evidence(tmp_path: Path) -> None:
    plan = _trace_plan()
    coordinator = _coordinator(tmp_path, plan)

    receipt = coordinator.collect(os.geteuid(), plan)

    assert receipt.mode == "sched"
    assert "/private/" not in receipt.model_dump_json()
    evidence = _verify_trace_evidence_receipt(
        receipt,
        plan,
        _socket_identity(Path(receipt.evidence_path).parent),
        os.geteuid(),
    )
    assert isinstance(evidence, TraceEvidenceArtifact)
    assert evidence.source.output_format == "target_filtered_trace_ndjson"
    assert evidence.source.capture.foreign_metadata_before_userspace is False
    assert evidence.target.observed_target_tids == (plan.target_pid,)
    assert evidence.limits.max_duration_seconds == 10


def test_trace_client_rejects_public_evidence_digest_tampering(tmp_path: Path) -> None:
    plan = _trace_plan()
    receipt = _coordinator(tmp_path, plan).collect(os.geteuid(), plan)
    tampered = BrokerTraceEvidenceReference.model_validate(
        {
            **receipt.model_dump(mode="json"),
            "evidence_file_sha256": "f" * 64,
        }
    )

    with pytest.raises(PerfLensError, match="identity, permissions, or digest"):
        _verify_trace_evidence_receipt(
            tampered,
            plan,
            _socket_identity(Path(receipt.evidence_path).parent),
            os.geteuid(),
        )


def test_trace_coordinator_rejects_arbitrary_perf_fields(tmp_path: Path) -> None:
    plan = _trace_plan().model_copy(update={"frequency_hz": 99})
    coordinator = _coordinator(tmp_path, plan)

    with pytest.raises(PerfLensError, match="fixed policy"):
        coordinator.collect(os.geteuid(), plan)
