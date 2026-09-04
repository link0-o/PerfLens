"""Bind private in-container Runtime Lock conversion to verified Docker identity."""

from __future__ import annotations

from perflens.application.runtime_lock_evidence import (
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.docker import ContainerRunArtifact, ContainerTargetArtifact
from perflens.contracts.runtime_lock_sessions import RuntimeLockAdapterExecutionBinding
from perflens.contracts.runtime_locks import (
    RuntimeContainerTargetReference,
    RuntimeLockEvidenceArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def bind_runtime_lock_evidence_to_container(
    evidence: RuntimeLockEvidenceArtifact,
    *,
    execution_binding: RuntimeLockAdapterExecutionBinding,
    target: ContainerTargetArtifact,
    run: ContainerRunArtifact,
) -> RuntimeLockEvidenceArtifact:
    """Replace a cooperative container-local target claim with verified Docker evidence.

    The Adapter's source bytes and normalized records are preserved.  Container identity is
    taken only from the independently verified Target and Run Artifacts.
    """

    if (
        evidence.schema_version != "1.1"
        or evidence.target.target_kind != "host"
        or target.container_uid is None
        or evidence.target.target_pid != target.container_pid
        or evidence.target.target_uid != target.container_uid
        or evidence.target.target_start_time_ticks != target.host_start_time_ticks
        or run.container_pid != target.container_pid
        or run.host_pid != target.host_pid
        or run.host_start_time_ticks != target.host_start_time_ticks
        or run.target_identity_sha256 != target.identity_fingerprint
        or run.container_identity_sha256 != target.container_identity_sha256
        or not (
            evidence.source.adapter_id == execution_binding.adapter_id
            or (
                execution_binding.adapter_id == "native_pthread"
                and evidence.source.adapter_id == "native-pthread"
            )
        )
        or evidence.source.measurement_semantics != execution_binding.measurement_semantics
        or evidence.source.runtime_version != execution_binding.runtime_version
    ):
        raise _binding_error("Runtime Lock evidence differs from the verified Docker target")
    source_provisional = evidence.source.model_copy(
        update={
            "adapter_id": execution_binding.adapter_id,
            "adapter_version": execution_binding.adapter_version,
            "backend_id": (
                evidence.source.backend_id
                if execution_binding.adapter_id == "go_pprof"
                else execution_binding.backend_id
            ),
            "backend_version": execution_binding.runtime_version,
            "runtime_version": execution_binding.runtime_version,
            "adapter_execution_identity_sha256": (execution_binding.execution_identity_sha256),
            "configuration_sha256": execution_binding.configuration_sha256,
            "metadata_sha256": execution_binding.metadata_sha256,
            "conversion_fingerprint": "0" * 64,
        }
    )
    source = source_provisional.model_copy(
        update={
            "conversion_fingerprint": compute_runtime_source_conversion_fingerprint(
                source_provisional
            )
        }
    )
    reference = RuntimeContainerTargetReference(
        container_target_id=target.target_id,
        container_target_content_sha256=target.content_sha256,
        container_run_id=run.run_id,
        container_run_content_sha256=run.content_sha256,
        container_identity_sha256=target.container_identity_sha256,
        target_identity_sha256=target.identity_fingerprint,
        cgroup_identity_sha256=target.cgroup.identity_sha256,
    )
    target_identity = evidence.target.model_copy(
        update={"target_kind": "docker", "container_reference": reference}
    )
    provisional = evidence.model_copy(
        update={
            "target": target_identity,
            "source": source,
            "evidence_fingerprint": "0" * 64,
            "content_sha256": "0" * 64,
            "content_bytes": 1,
        }
    )
    fingerprinted = provisional.model_copy(
        update={"evidence_fingerprint": compute_runtime_lock_evidence_fingerprint(provisional)}
    )
    sized = _stable_size(fingerprinted)
    bound = sized.model_copy(
        update={"content_sha256": compute_runtime_lock_evidence_content_sha256(sized)}
    )
    return RuntimeLockEvidenceArtifact.model_validate(
        bound.model_dump(mode="json", exclude_none=True)
    )


def _stable_size(evidence: RuntimeLockEvidenceArtifact) -> RuntimeLockEvidenceArtifact:
    current = evidence
    for _ in range(8):
        size = len(serialize_json(current))
        if current.content_bytes == size:
            return current
        current = current.model_copy(update={"content_bytes": size})
    raise _binding_error("Runtime Lock Docker evidence size did not converge")


def _binding_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_docker_binding",
        message,
        recoverable=False,
    )
