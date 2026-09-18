"""Bind converted Native pthread evidence to its authorized probe execution."""

from __future__ import annotations

from perflens.application.runtime_lock_evidence import (
    compute_runtime_lock_evidence_content_sha256,
    compute_runtime_lock_evidence_fingerprint,
    compute_runtime_source_conversion_fingerprint,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.runtime_lock_sessions import RuntimeLockAdapterExecutionBinding
from perflens.contracts.runtime_locks import RuntimeLockEvidenceArtifact
from perflens.domain.errors import ErrorCode, PerfLensError


def bind_native_pthread_evidence_execution(
    evidence: RuntimeLockEvidenceArtifact,
    execution_binding: RuntimeLockAdapterExecutionBinding,
) -> RuntimeLockEvidenceArtifact:
    """Add the Preview-bound probe/configuration identity to Native evidence.

    The private converter deliberately understands only probe bytes. The host
    integration supplies the independently authorized, path-free execution
    binding after conversion and recomputes every affected public identity.
    """

    source = evidence.source
    if (
        evidence.schema_version != "1.1"
        or execution_binding.adapter_id != "native_pthread"
        or source.runtime != "c_cpp"
        or source.adapter_id != "native-pthread"
        or source.source_format != "native_interposer_ndjson_v1"
        or source.backend_id != "ld-preload"
        or source.target_scope != "bound_pid"
        or source.tool is not None
        or source.measurement_semantics != execution_binding.measurement_semantics
        or source.runtime_version != execution_binding.runtime_version
    ):
        raise _binding_error(
            "Native pthread evidence differs from its authorized execution binding"
        )
    source_provisional = source.model_copy(
        update={
            "adapter_id": execution_binding.adapter_id,
            "adapter_version": execution_binding.adapter_version,
            "backend_id": execution_binding.backend_id,
            "backend_version": execution_binding.runtime_version,
            "runtime_version": execution_binding.runtime_version,
            "adapter_execution_identity_sha256": (execution_binding.execution_identity_sha256),
            "configuration_sha256": execution_binding.configuration_sha256,
            "metadata_sha256": execution_binding.metadata_sha256,
            "conversion_fingerprint": "0" * 64,
        }
    )
    bound_source = source_provisional.model_copy(
        update={
            "conversion_fingerprint": compute_runtime_source_conversion_fingerprint(
                source_provisional
            )
        }
    )
    provisional = evidence.model_copy(
        update={
            "source": bound_source,
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
    raise _binding_error("Native pthread Evidence byte identity did not converge")


def _binding_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_native_binding",
        message,
        recoverable=False,
    )
