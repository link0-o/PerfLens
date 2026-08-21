"""Private Trace Helper orchestration and public evidence publication."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import stat
import struct
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

from perflens import __version__
from perflens.application.build_trace_evidence import build_trace_evidence
from perflens.application.trace_evidence import (
    compute_trace_capture_fingerprint,
    compute_trace_conversion_fingerprint,
    verify_private_raw_snapshot,
)
from perflens.artifacts.filesystem import serialize_json, write_json_new_atomic
from perflens.collection.planning import assert_plan_current
from perflens.collector_broker.protocol import BrokerTraceEvidenceReference
from perflens.contracts.artifacts import CollectionPlanArtifact
from perflens.contracts.trace import (
    TraceCaptureManifest,
    TraceConversionManifest,
    TraceEventFormatIdentity,
    TraceEvidenceArtifact,
    TraceObservationWindow,
    TraceRawArtifactReference,
    TraceResourceLimits,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.trace import ResourceLimits, TargetIdentity
from perflens.profiles.kernel_trace_stream import (
    KERNEL_TRACE_STREAM_PARSER_VERSION,
    FixedKernelTraceNdjsonAdapter,
)
from perflens.trace_helper.client import TraceHelperClient
from perflens.trace_helper.policy import TraceMode, TracePolicy
from perflens.trace_helper.protocol import (
    TraceHelperCollectPidRequest,
    TraceHelperDockerTarget,
    TraceHelperHealthResult,
    TraceHelperTarget,
)

_MAX_PUBLIC_EVIDENCE_BYTES = 256 << 20
_NORMALIZATION_VERSION = "trace-normalizer-v1"


def _trace_helper_target_from_plan(
    plan: CollectionPlanArtifact,
) -> TraceHelperTarget | TraceHelperDockerTarget:
    if plan.target_runtime == "docker":
        if plan.container_target is None:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "trace_backend",
                "Docker trace plan lost its container identity binding",
            )
        return TraceHelperDockerTarget(
            pid=plan.target_pid,
            uid=plan.target_uid,
            start_time_ticks=plan.target_start_time_ticks,
            container=plan.container_target,
        )
    return TraceHelperTarget(
        pid=plan.target_pid,
        uid=plan.target_uid,
        start_time_ticks=plan.target_start_time_ticks,
    )


class TraceCollectionCoordinator:
    """Convert one typed Helper result into an immutable public Trace artifact."""

    def __init__(
        self,
        policy: TracePolicy,
        *,
        helper_client: TraceHelperClient,
        public_spool: Path,
        public_artifact_mode: int,
        expected_helper_uid: int,
        allow_rootful_container_targets: bool = False,
        producer_path: Path = Path("/usr/lib/perflens/perflens-trace-helper"),
        converter_path: Path | None = None,
    ) -> None:
        self._policy = policy
        self._helper = helper_client
        self._health = helper_client.health()
        if (
            self._health.capture_backend_status != "available"
            or not self._health.target_filter_before_userspace
            or set(self._health.supported_modes) != set(policy.allowed_modes)
            or self._health.policy_sha256 != policy.policy_sha256
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "trace_backend",
                "Trace Helper health does not match the immutable Trace policy",
            )
        self._public_spool = _trusted_public_spool(public_spool)
        if public_artifact_mode not in {0o440, 0o640}:
            raise ValueError("public Trace artifact mode must be 0440 or 0640")
        self._public_artifact_mode = public_artifact_mode
        self._expected_helper_uid = expected_helper_uid
        if type(allow_rootful_container_targets) is not bool:
            raise ValueError("rootful-container Trace policy must be boolean")
        self._allow_rootful_container_targets = allow_rootful_container_targets
        self._private_spool_gid = _trusted_private_spool(policy.private_spool, expected_helper_uid)
        self._producer_path = producer_path
        self._producer_sha256 = _trusted_code_sha256(
            producer_path,
            expected_owners={expected_helper_uid},
        )
        parser = converter_path or (
            Path(__file__).resolve().parents[1] / "profiles/kernel_trace_stream.py"
        )
        self._converter_path = parser
        self._converter_sha256 = _trusted_code_sha256(
            parser,
            expected_owners={0, os.geteuid()},
        )

    @property
    def health(self) -> TraceHelperHealthResult:
        return self._health

    def collect(
        self,
        peer_uid: int,
        plan: CollectionPlanArtifact,
        *,
        ready_callback: Callable[[], None] | None = None,
    ) -> BrokerTraceEvidenceReference:
        if plan.mode not in {"sched", "off_cpu", "lock"}:
            raise ValueError("Trace coordinator requires a Trace collection plan")
        mode = cast(TraceMode, plan.mode)
        self._authorize(peer_uid, plan)
        assert_plan_current(plan)
        trace_plan_id = _trace_plan_id(plan)
        helper_target = _trace_helper_target_from_plan(plan)
        request = TraceHelperCollectPidRequest(
            request_id=f"request-{hashlib.sha256(plan.plan_id.encode()).hexdigest()[:24]}",
            plan_id=trace_plan_id,
            caller_uid=peer_uid,
            target=helper_target,
            mode=mode,
            duration_milliseconds=max(1, math.ceil(plan.duration_seconds * 1000)),
            max_output_bytes=plan.max_output_bytes,
            expires_at_unix_milliseconds=math.floor(
                datetime.fromisoformat(plan.expires_at).timestamp() * 1000
            ),
            expected_policy_sha256=self._policy.policy_sha256,
            expected_capture_backend="target_filtered_kernel_v1",
            report_ready=ready_callback is not None,
        )
        result = self._helper.collect(request, ready_callback=ready_callback)
        assert_plan_current(plan)
        raw_path = self._policy.private_spool / result.artifact_name
        capture = self._capture_manifest(plan, result.mode)
        collection_digest = hashlib.sha256(
            json.dumps(
                result.model_dump(mode="json"),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        collection_id = f"collection-{collection_digest[:16]}"
        source = TraceRawArtifactReference(
            collection_id=collection_id,
            mode=result.mode,
            collection_artifact_sha256=collection_digest,
            output_sha256=result.output_sha256,
            output_bytes=result.output_bytes,
            output_format="target_filtered_trace_ndjson",
            capture=capture,
        )
        snapshot = verify_private_raw_snapshot(
            source,
            raw_path,
            max_input_bytes=self._policy.max_output_bytes,
            expected_owner_uid=self._expected_helper_uid,
            expected_owner_gid=self._private_spool_gid,
            expected_mode=0o640,
        )
        target = TargetIdentity(
            pid=plan.target_pid,
            uid=plan.target_uid,
            start_time_ticks=plan.target_start_time_ticks,
        )
        limits = _public_limits(
            plan,
            policy_max_duration_seconds=self._policy.max_duration_seconds,
        )
        adapter = FixedKernelTraceNdjsonAdapter(
            target=target,
            observed_target_tids=result.observed_target_tids,
            expected_input_owner_uid=self._expected_helper_uid,
            expected_input_owner_gid=self._private_spool_gid,
            expected_input_mode=0o640,
            expected_input_sha256=result.output_sha256,
            expected_input_bytes=result.output_bytes,
            mode=mode,
            lost_event_count=result.lost_event_count,
            truncated=result.truncated,
            limits=_domain_limits(limits),
        )
        parsed = adapter.parse(raw_path)
        conversion = self._conversion_manifest(mode)
        evidence = build_trace_evidence(
            source=source,
            verified_raw=snapshot,
            parsed=parsed,
            conversion=conversion,
            target=target,
            observation_window=TraceObservationWindow(
                start_timestamp_ns=result.started_at_monotonic_nanoseconds,
                end_timestamp_ns=result.finished_at_monotonic_nanoseconds,
                source="collector_monotonic_bounds",
            ),
            limits=limits,
            perflens_version=__version__,
            container_target=plan.container_target,
        )
        assert_plan_current(plan)
        return self._publish(plan, evidence)

    def _authorize(self, peer_uid: int, plan: CollectionPlanArtifact) -> None:
        target_allowed = plan.target_uid == peer_uid
        if plan.target_runtime == "docker" and plan.container_target is not None:
            container = plan.container_target
            if plan.target_uid == peer_uid:
                target_allowed = (
                    container.uid_mapping != "rootful_cross_uid"
                    and not container.rootful_risk_authorized
                )
            else:
                target_allowed = (
                    self._allow_rootful_container_targets
                    and plan.target_uid == 0
                    and container.uid_mapping == "rootful_cross_uid"
                    and container.rootful_risk_authorized
                )
        if (
            peer_uid != self._policy.allowed_uid
            or not target_allowed
            or plan.mode not in self._policy.allowed_modes
            or plan.duration_seconds > self._policy.max_duration_seconds
            or plan.max_output_bytes > self._policy.max_output_bytes
            or plan.frequency_hz is not None
            or plan.call_graph is not None
            or plan.requested_event_source != "hardware_required"
            or plan.fallback_allowed
            or plan.events
            or plan.fallback_events
            or plan.record_event is not None
            or plan.fallback_record_event is not None
        ):
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "trace_authorization",
                "Trace plan exceeds the independent fixed policy",
                recoverable=True,
            )

    def _capture_manifest(
        self,
        plan: CollectionPlanArtifact,
        mode: TraceMode,
    ) -> TraceCaptureManifest:
        format_digest = hashlib.sha256(
            f"target-filtered-kernel-v1:{mode}:{self._health.helper_version}".encode("ascii")
        ).hexdigest()
        pointer_size_bits = cast(Literal[32, 64], struct.calcsize("P") * 8)
        provisional = TraceCaptureManifest(
            mode=mode,
            backend_id="target_filtered_kernel_v1",
            backend_version=self._health.helper_version,
            producer_path=str(self._producer_path),
            producer_sha256=self._producer_sha256,
            kernel_release=platform.release(),
            architecture=platform.machine(),
            byte_order=sys.byteorder,
            pointer_size_bits=pointer_size_bits,
            target_scope="kernel_tgid_filtered",
            dynamic_thread_coverage="complete",
            switch_in_visibility="not_applicable" if mode == "lock" else "complete",
            external_wakeup_visibility=(
                "not_applicable" if mode == "lock" else "complete"
            ),
            foreign_metadata_before_userspace=False,
            event_formats=(
                TraceEventFormatIdentity(
                    event_name="perflens:typed_trace",
                    format_sha256=format_digest,
                ),
            ),
            capture_fingerprint="0" * 64,
        )
        return provisional.model_copy(
            update={"capture_fingerprint": compute_trace_capture_fingerprint(provisional)}
        )

    def _conversion_manifest(self, mode: TraceMode) -> TraceConversionManifest:
        recipe_ids: dict[
            TraceMode,
            Literal["sched-v1", "off-cpu-v1", "lock-v1"],
        ] = {"sched": "sched-v1", "off_cpu": "off-cpu-v1", "lock": "lock-v1"}
        recipe_id = recipe_ids[mode]
        provisional = TraceConversionManifest(
            adapter="kernel_trace_ndjson",
            recipe_id=recipe_id,
            converter_path=str(self._converter_path),
            converter_sha256=self._converter_sha256,
            converter_version=__version__,
            parser_version=KERNEL_TRACE_STREAM_PARSER_VERSION,
            normalization_version=_NORMALIZATION_VERSION,
            argv=(str(self._converter_path), "<private-input>"),
            locale="C",
            conversion_fingerprint="0" * 64,
        )
        return provisional.model_copy(
            update={
                "conversion_fingerprint": compute_trace_conversion_fingerprint(provisional)
            }
        )

    def _publish(
        self,
        plan: CollectionPlanArtifact,
        evidence: TraceEvidenceArtifact,
    ) -> BrokerTraceEvidenceReference:
        output = self._public_spool / f"{evidence.trace_evidence_id}.json"
        serialized = serialize_json(evidence)
        write_json_new_atomic(evidence, output, max_output_bytes=_MAX_PUBLIC_EVIDENCE_BYTES)
        try:
            os.chmod(output, self._public_artifact_mode)
            metadata = output.stat(follow_symlinks=False)
        except OSError as exc:
            output.unlink(missing_ok=True)
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                "trace_evidence",
                "Public Trace evidence permissions could not be applied",
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != self._public_artifact_mode
            or metadata.st_size != len(serialized)
        ):
            output.unlink(missing_ok=True)
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "trace_evidence",
                "Public Trace evidence identity is unsafe",
            )
        return BrokerTraceEvidenceReference(
            plan_id=plan.plan_id,
            target_pid=plan.target_pid,
            mode=cast(TraceMode, plan.mode),
            trace_evidence_id=evidence.trace_evidence_id,
            evidence_path=str(output),
            evidence_file_sha256=hashlib.sha256(serialized).hexdigest(),
            evidence_file_bytes=len(serialized),
            evidence_content_sha256=evidence.content_sha256,
        )


def _trace_plan_id(plan: CollectionPlanArtifact) -> str:
    digest = hashlib.sha256(
        f"{plan.plan_id}\0{plan.target_pid}\0{plan.target_start_time_ticks}".encode("ascii")
    ).hexdigest()
    return f"trace-plan-{digest[:20]}"


def _public_limits(
    plan: CollectionPlanArtifact,
    *,
    policy_max_duration_seconds: int,
) -> TraceResourceLimits:
    return TraceResourceLimits(
        # This field records the independently enforced policy ceiling, not the requested
        # measurement duration. Kernel polling and service scheduling can add a small amount of
        # bounded teardown time to the monotonic observation window without extending the typed
        # collection request. Using ceil(plan.duration_seconds) here incorrectly rejects such a
        # valid trace, especially for the one-second host acceptance probe.
        max_duration_seconds=policy_max_duration_seconds,
        max_input_bytes=plan.max_output_bytes,
        max_output_bytes=plan.max_output_bytes,
    )


def _domain_limits(limits: TraceResourceLimits) -> ResourceLimits:
    return ResourceLimits(
        max_events=limits.max_input_events,
        max_input_lines=limits.max_input_lines,
        max_line_chars=limits.max_line_bytes,
        max_stack_depth=limits.max_stack_depth,
        max_unique_tids=limits.max_unique_target_tids,
        max_unique_locks=limits.max_unique_locks,
        max_warnings=limits.max_warnings,
        max_output_bytes=limits.max_input_bytes,
    )


def _trusted_public_spool(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("public Trace spool cannot be resolved") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or metadata.st_mode & 0o022
    ):
        raise ValueError("public Trace spool identity is unsafe")
    return resolved


def _trusted_private_spool(path: Path, expected_uid: int) -> int:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("private Trace spool cannot be resolved") from exc
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o750
    ):
        raise ValueError("private Trace spool identity is unsafe")
    return metadata.st_gid


def _trusted_code_sha256(path: Path, *, expected_owners: set[int]) -> str:
    descriptor = -1
    try:
        resolved = path.resolve(strict=True)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in expected_owners
            or before.st_mode & 0o022
            or (before.st_uid == os.geteuid() and os.geteuid() != 0 and before.st_mode & 0o200)
        ):
            raise OSError("unsafe code identity")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1 << 20):
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = resolved.stat(follow_symlinks=False)
        if _file_identity(before) != _file_identity(after) or (
            _file_identity(after) != _file_identity(current)
        ):
            raise OSError("code identity changed")
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            "trace_backend",
            "Trace producer or converter identity is unsafe",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
