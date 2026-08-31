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
from perflens.runtime_locks.cpython_adapter import CpythonAdapterBridge
from perflens.runtime_locks.java_jfr_adapter import (
    JavaJfrAdapterBridge,
    build_java_jfr_adapter_bridge,
)
from perflens.runtime_locks.java_jfr_capability import JavaJfrCapability
from perflens.runtime_locks.native_launcher import NativeLaunchCapability
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
_NATIVE_EVENT_KINDS = ("acquire", "release", "wait_begin", "wait_end")
_NATIVE_LOCK_KINDS: tuple[LockKind, ...] = (
    "condition",
    "mutex",
    "recursive_mutex",
    "rwlock_read",
    "rwlock_write",
)
NATIVE_PTHREAD_PROVENANCE_LIMITATION = (
    "Native pthread events are emitted cooperatively inside the target process and are not "
    "tamper-proof against an adversarial workload; hashes and deterministic replay prove byte "
    "consistency, not independent event provenance."
)
NATIVE_PTHREAD_ACTIVE_SCOPE_LIMITATION = (
    "Active Native pthread collection is implemented only for host_launched_workload; "
    "managed_temporary_container and docker_optimization collection remain unavailable until "
    "the separately reviewed Stage 7 integration. Controlled NDJSON import remains available "
    "through generic_ndjson_import."
)


@dataclass(frozen=True, slots=True)
class RuntimeLockCapabilityInspection:
    capability: RuntimeLockCapabilityArtifact
    adapter_capabilities: tuple[RuntimeAdapterCapabilityArtifact, ...]


def inspect_runtime_lock_capability(
    policy: RuntimeLockProjectPolicy,
    *,
    project_identity_sha256: str,
    native_pthread_capability: NativeLaunchCapability | None = None,
    java_jfr_capability: JavaJfrCapability | None = None,
    java_jfr_bridge: JavaJfrAdapterBridge | None = None,
    cpython_bridge: CpythonAdapterBridge | None = None,
    created_at: datetime | None = None,
) -> RuntimeLockCapabilityInspection:
    """Report only implemented and policy-enabled backends; never execute a target."""

    now = created_at or datetime.now(tz=UTC)
    if now.tzinfo is None:
        raise ValueError("Runtime Lock capability time must include a timezone")
    created = now.isoformat()
    adapters = tuple(
        _adapter_capability(
            policy,
            adapter_id,
            created_at=created,
            native_pthread_capability=native_pthread_capability,
            java_jfr_capability=java_jfr_capability,
            java_jfr_bridge=java_jfr_bridge,
            cpython_bridge=cpython_bridge,
        )
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
    available = tuple(item for item in references if item.availability == "available")
    partial = tuple(item for item in references if item.availability == "partial")
    status = (
        "available"
        if available
        else ("partial" if partial else ("disabled" if not policy.enabled else "unavailable"))
    )
    native_reference = next(
        (item for item in references if item.adapter_id == "native_pthread"),
        None,
    )
    java_reference = next(
        (item for item in references if item.adapter_id == "java_jfr"),
        None,
    )
    cpython_reference = next(
        (item for item in references if item.adapter_id == "cpython_threading"),
        None,
    )
    if native_reference is not None and native_reference.availability == "available":
        limitations = (
            "Native pthread launch instrumentation is available only for the safely discovered "
            "packaged probe and a policy-authorized host_launched_workload.",
            NATIVE_PTHREAD_ACTIVE_SCOPE_LIMITATION,
        )
    elif native_reference is not None and native_reference.availability == "partial":
        limitations = (
            "Native pthread launch instrumentation has partial coverage; its Adapter limitations "
            "must be retained in every result.",
            NATIVE_PTHREAD_ACTIVE_SCOPE_LIMITATION,
        )
    elif cpython_reference is not None and cpython_reference.availability in {
        "available",
        "partial",
    }:
        limitations = (
            "CPython startup instrumentation is limited to public threading constructors; "
            "GIL, internal, C-extension, and direct _thread locks remain outside coverage.",
            *cpython_reference.limitations,
        )
    elif java_reference is not None and java_reference.availability in {
        "available",
        "partial",
    }:
        limitations = (
            "Java JFR startup instrumentation is available only for one policy-authorized "
            "host executable-JAR workload; live attach is unavailable.",
            *java_reference.limitations,
        )
    elif any(item.adapter_id == "generic_ndjson_import" for item in available):
        limitations = (
            "Only controlled NDJSON import is available; active Runtime Lock launch and "
            "instrumentation require a safely discovered Adapter backend.",
        )
    else:
        limitations = ("No policy-enabled Runtime Lock Adapter is currently available.",)
    if native_reference is not None and native_reference.availability in {
        "available",
        "partial",
    }:
        next_steps = (
            "Preview one bounded Native pthread launch Session for an explicit workload.",
        )
    elif cpython_reference is not None and cpython_reference.availability in {
        "available",
        "partial",
    }:
        next_steps = ("Preview one bounded CPython threading launch Session.",)
    elif java_reference is not None and java_reference.availability in {
        "available",
        "partial",
    }:
        next_steps = ("Preview one bounded Java JFR launch Session for an explicit JAR.",)
    elif any(item.adapter_id == "generic_ndjson_import" for item in available):
        next_steps = (
            "Preview one controlled-import Session before importing Runtime Lock evidence.",
        )
    else:
        next_steps = ("Install or enable one reviewed Runtime Lock Adapter.",)
    provisional = RuntimeLockCapabilityArtifact(
        schema_version="1.1",
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
        next_steps=next_steps,
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
    native_pthread_capability: NativeLaunchCapability | None,
    java_jfr_capability: JavaJfrCapability | None,
    java_jfr_bridge: JavaJfrAdapterBridge | None,
    cpython_bridge: CpythonAdapterBridge | None,
) -> RuntimeAdapterCapabilityArtifact:
    if adapter_id == "native_pthread":
        return _native_adapter_capability(
            policy,
            created_at=created_at,
            native_pthread_capability=native_pthread_capability,
        )
    if adapter_id == "java_jfr":
        if java_jfr_bridge is not None:
            return java_jfr_bridge.capability
        return build_java_jfr_adapter_bridge(
            policy,
            java_jfr_capability,
            created_at=created_at,
        ).capability
    if adapter_id == "cpython_threading" and cpython_bridge is not None:
        return cpython_bridge.capability
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


def _native_adapter_capability(
    policy: RuntimeLockProjectPolicy,
    *,
    created_at: str,
    native_pthread_capability: NativeLaunchCapability | None,
) -> RuntimeAdapterCapabilityArtifact:
    adapter_id: RuntimeLockAdapterId = "native_pthread"
    adapter_policy = policy.adapter_policy(adapter_id)
    native = native_pthread_capability
    enabled = policy.enabled and adapter_policy.enabled
    policy_allows_launch = (
        enabled
        and adapter_policy.launch_instrumentation_allowed
        and native is not None
        and native.target_scope in policy.target_scopes
    )
    if not enabled:
        availability = "disabled"
        limitations = ("This Runtime Lock Adapter is disabled by project policy.",)
    elif native is None:
        availability = "unavailable"
        limitations = (
            "No safely discovered Native pthread launch capability was supplied; active "
            "instrumentation is unavailable.",
        )
    elif not adapter_policy.launch_instrumentation_allowed:
        availability = "unavailable"
        limitations = ("Native pthread launch instrumentation is disabled by project policy.",)
    elif native.target_scope not in policy.target_scopes:
        availability = "unavailable"
        limitations = (
            "The safely discovered Native pthread backend target scope is outside project policy.",
        )
    else:
        availability = native.availability
        limitations = tuple(
            dict.fromkeys(
                (
                    *native.limitations,
                    NATIVE_PTHREAD_PROVENANCE_LIMITATION,
                    NATIVE_PTHREAD_ACTIVE_SCOPE_LIMITATION,
                )
            )
        )
        if availability == "partial" and not limitations:
            limitations = (
                "The safely discovered Native pthread backend reports partial coverage.",
            )
        elif availability == "unavailable" and not limitations:
            limitations = ("The safely discovered Native pthread backend is unavailable.",)

    supported_semantics = (
        tuple(
            sorted(
                set(native.supported_semantics)
                & set(adapter_policy.allowed_semantics)
                & set(policy.allowed_semantics)
            )
        )
        if native is not None and policy_allows_launch and availability in {"available", "partial"}
        else ()
    )
    if availability in {"available", "partial"} and not supported_semantics:
        availability = "unavailable"
        limitations = (
            *limitations,
            "Native pthread backend and project policy have no common measurement semantics.",
        )
    supported_lock_kinds: tuple[LockKind, ...] = ()
    if native is not None and availability in {"available", "partial"}:
        visible_surfaces = set(native.supported_lock_surfaces)
        supported_lock_kinds = tuple(
            kind
            for kind in _NATIVE_LOCK_KINDS
            if kind in visible_surfaces
            or (kind == "recursive_mutex" and "mutex" in visible_surfaces)
        )
    material = "\0".join(
        (
            "perflens-runtime-adapter-capability-v1",
            policy.sha256,
            adapter_id,
            availability,
            native.launch_backend if native is not None else "undiscovered",
            native.probe_sha256
            if native is not None and native.probe_sha256 is not None
            else "no-probe",
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
        runtime="c_cpp",
        runtime_name="glibc pthread",
        runtime_version=(native.runtime_glibc_version if native is not None else None),
        adapter_id=adapter_id,
        adapter_version="native-pthread-adapter-v1",
        backend_id=(native.launch_backend if native is not None else "native_pthread"),
        availability=availability,
        supported_lock_kinds=supported_lock_kinds,
        supported_event_kinds=(
            _NATIVE_EVENT_KINDS if availability in {"available", "partial"} else ()
        ),
        measurement_semantics=supported_semantics,
        fast_path_visibility="partial" if availability in {"available", "partial"} else "none",
        owner_visibility="unavailable",
        hold_time_visibility=(
            "partial" if availability in {"available", "partial"} else "unavailable"
        ),
        launch_instrumentation_required=True,
        attach_required=False,
        privileged_backend_required=False,
        limitations=limitations,
        next_steps=(
            "Preview a bounded Native pthread launch Session for one explicit workload."
            if availability in {"available", "partial"}
            else "Install or enable the reviewed main-DEB Native pthread probe backend.",
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
