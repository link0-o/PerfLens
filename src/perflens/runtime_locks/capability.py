"""Read-only capability discovery for bounded Runtime Lock sessions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterCapabilityReference,
    RuntimeLockAdapterId,
    RuntimeLockCapabilityArtifact,
    derive_runtime_lock_capability_id,
)
from perflens.contracts.runtime_locks import (
    LockKind,
    RuntimeAdapterCapabilityArtifact,
    RuntimeFamily,
)
from perflens.runtime_locks.project_config import RuntimeLockProjectPolicy

_ADAPTER_RUNTIME: dict[RuntimeLockAdapterId, tuple[RuntimeFamily, str]] = {
    "cpython_threading": ("python", "CPython"),
    "generic_ndjson_import": ("custom", "Versioned NDJSON import"),
    "go_pprof": ("go", "Go runtime/pprof"),
    "java_jfr": ("java", "Java Flight Recorder"),
    "native_pthread": ("c_cpp", "glibc pthread"),
}
_ALL_LOCK_KINDS: tuple[LockKind, ...] = (
    "condition",
    "custom",
    "gil",
    "mutex",
    "park",
    "recursive_mutex",
    "runtime_internal",
    "rwlock_read",
    "rwlock_write",
    "semaphore",
)
_ALL_EVENT_KINDS = (
    "acquire",
    "park",
    "release",
    "sampled_contention",
    "unpark",
    "wait_begin",
    "wait_end",
)


@dataclass(frozen=True, slots=True)
class RuntimeLockCapabilityInspection:
    capability: RuntimeLockCapabilityArtifact
    adapter_capabilities: tuple[RuntimeAdapterCapabilityArtifact, ...]


def inspect_runtime_lock_capability(
    policy: RuntimeLockProjectPolicy,
    *,
    project_identity_sha256: str,
    created_at: datetime | None = None,
) -> RuntimeLockCapabilityInspection:
    """Report only implemented and policy-enabled backends; never execute a target."""

    now = created_at or datetime.now(tz=UTC)
    if now.tzinfo is None:
        raise ValueError("Runtime Lock capability time must include a timezone")
    created = now.isoformat()
    adapters = tuple(
        _adapter_capability(policy, adapter_id, created_at=created)
        for adapter_id in policy.allowed_adapters
    )
    references = tuple(
        RuntimeLockAdapterCapabilityReference(
            adapter_id=adapter_id,  # type: ignore[arg-type]
            capability_id=adapter.capability_id,
            capability_content_sha256=adapter.content_sha256,
            availability=adapter.availability,
            supported_semantics=adapter.measurement_semantics,
            limitations=adapter.limitations,
        )
        for adapter_id, adapter in zip(policy.allowed_adapters, adapters, strict=True)
    )
    available = [item for item in references if item.availability == "available"]
    status = "available" if available else ("disabled" if not policy.enabled else "unavailable")
    limitations = (
        (
            "Only controlled NDJSON import is implemented; active Runtime Lock launch, "
            "instrumentation, attach, and collection are unavailable in this milestone.",
        )
        if available
        else ("No policy-enabled Runtime Lock Adapter is currently available.",)
    )
    provisional = RuntimeLockCapabilityArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        capability_id=derive_runtime_lock_capability_id(
            project_identity_sha256,
            policy.sha256,
            created,
        ),
        created_at=created,
        project_identity_sha256=project_identity_sha256,
        project_policy_sha256=policy.sha256,
        status=status,
        adapters=references,
        limitations=limitations,
        next_steps=(
            "Preview one controlled-import Session before importing Runtime Lock evidence.",
        )
        if available
        else ("Install or enable one reviewed Runtime Lock Adapter.",),
        content_sha256="0" * 64,
    )
    capability = provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
    return RuntimeLockCapabilityInspection(
        capability=capability,
        adapter_capabilities=adapters,
    )


def _adapter_capability(
    policy: RuntimeLockProjectPolicy,
    adapter_id: RuntimeLockAdapterId,
    *,
    created_at: str,
) -> RuntimeAdapterCapabilityArtifact:
    adapter_policy = policy.adapter_policy(adapter_id)
    implemented = adapter_id == "generic_ndjson_import"
    enabled = policy.enabled and adapter_policy.enabled
    import_allowed = (
        enabled
        and adapter_policy.controlled_import_allowed
        and "controlled_import" in policy.target_scopes
    )
    availability = (
        "available"
        if implemented and import_allowed
        else ("disabled" if not enabled else "unavailable")
    )
    limitations: tuple[str, ...]
    if availability == "available":
        limitations = (
            "This Adapter is available only for controlled NDJSON import; it cannot launch, "
            "instrument, attach to, or actively collect from a workload.",
        )
    elif not enabled:
        limitations = ("This Runtime Lock Adapter is disabled by project policy.",)
    elif not implemented:
        limitations = ("This Runtime Lock Adapter is not implemented in the current milestone.",)
    else:
        limitations = ("Controlled import is disabled for this Runtime Lock Adapter.",)
    runtime, runtime_name = _ADAPTER_RUNTIME[adapter_id]
    material = "\0".join(
        (
            "perflens-runtime-adapter-capability-v1",
            policy.sha256,
            adapter_id,
            availability,
            created_at,
        )
    )
    capability_id = (
        "runtime-adapter-capability-" + hashlib.sha256(material.encode()).hexdigest()[:20]
    )
    provisional = RuntimeAdapterCapabilityArtifact(
        schema_version="1.1",
        capability_id=capability_id,
        created_at=created_at,
        runtime=runtime,
        runtime_name=runtime_name,
        adapter_id=adapter_id,
        adapter_version="runtime-lock-adapter-v1",
        backend_id=(
            "perflens_runtime_lock_ndjson_v1"
            if adapter_id == "generic_ndjson_import"
            else adapter_id
        ),
        availability=availability,
        supported_lock_kinds=_ALL_LOCK_KINDS if availability == "available" else (),
        supported_event_kinds=_ALL_EVENT_KINDS if availability == "available" else (),
        measurement_semantics=(
            adapter_policy.allowed_semantics if availability == "available" else ()
        ),
        fast_path_visibility="unknown",
        owner_visibility="partial" if availability == "available" else "unavailable",
        hold_time_visibility="partial" if availability == "available" else "unavailable",
        launch_instrumentation_required=False,
        attach_required=False,
        privileged_backend_required=False,
        limitations=limitations,
        next_steps=(
            "Authorize a controlled-import Session and supply one versioned NDJSON source."
            if availability == "available"
            else "Complete this Adapter milestone before active collection.",
        ),
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )
