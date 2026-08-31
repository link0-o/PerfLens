"""Bridge trusted JDK discovery into public capability and launch contracts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import (
    MeasurementSemantics,
    RuntimeAdapterCapabilityArtifact,
    RuntimeToolIdentity,
)
from perflens.runtime_locks.java_jfr_capability import (
    JavaJfrCapability,
    JavaJfrDirectoryIdentity,
    JavaJfrNativeLibraryIdentity,
    JavaJfrPayloadFileIdentity,
    JavaJfrRunner,
    JavaJfrRuntimePayloadIdentity,
    JavaJfrToolIdentity,
    discover_java_jfr_installation,
)
from perflens.runtime_locks.java_jfr_launcher import (
    JavaJfrDirectoryPolicy,
    JavaJfrFilePolicy,
    JavaJfrLaunchPolicy,
    JavaJfrNativeLibraryPolicy,
    JavaJfrPayloadFilePolicy,
    JavaJfrRuntimePayloadPolicy,
)
from perflens.runtime_locks.java_jfr_profiles import DEFAULT_JAVA_JFR_PROFILE_ROOT
from perflens.runtime_locks.project_config import RuntimeLockProjectPolicy
from perflens.runtime_locks.supervisor import discover_runtime_supervisor_policy

JAVA_JFR_ADAPTER_VERSION = "java-jfr-adapter-v1"


@dataclass(frozen=True, slots=True)
class JavaJfrAdapterBridge:
    capability: RuntimeAdapterCapabilityArtifact
    execution_binding: RuntimeLockAdapterExecutionBinding | None
    launch_policy: JavaJfrLaunchPolicy | None


def discover_java_jfr_adapter_bridge(
    policy: RuntimeLockProjectPolicy,
    *,
    profile_root: Path = DEFAULT_JAVA_JFR_PROFILE_ROOT,
    trusted_owner_uids: tuple[int, ...] = (0,),
    runner: JavaJfrRunner | None = None,
    created_at: str | None = None,
) -> JavaJfrAdapterBridge:
    """Safely discover JDK/JFR and immediately intersect it with project policy."""

    discovered = discover_java_jfr_installation(
        profile_root=profile_root,
        trusted_owner_uids=trusted_owner_uids,
        runner=runner,
    )
    supervisor_available = discover_runtime_supervisor_policy().policy is not None
    return build_java_jfr_adapter_bridge(
        policy,
        discovered,
        created_at=created_at,
        active_supervisor_available=supervisor_available,
    )


def build_java_jfr_adapter_bridge(
    policy: RuntimeLockProjectPolicy,
    discovered: JavaJfrCapability | None,
    *,
    created_at: str | None = None,
    active_supervisor_available: bool = True,
) -> JavaJfrAdapterBridge:
    """Intersect JDK discovery with policy without exposing absolute tool paths publicly."""

    timestamp = created_at or datetime.now(tz=UTC).isoformat()
    adapter_policy = policy.adapter_policy("java_jfr")
    enabled = policy.enabled and adapter_policy.enabled
    host_launch_allowed = (
        enabled
        and adapter_policy.launch_instrumentation_allowed
        and "host_launched_workload" in policy.target_scopes
    )
    discovered_semantics: set[MeasurementSemantics] = set()
    if discovered is not None:
        discovered_semantics.update(discovered.measurement_semantics)
    common_semantics = (
        discovered_semantics & set(adapter_policy.allowed_semantics) & set(policy.allowed_semantics)
    )
    discovered_limitations = _public_limitations(discovered)
    limitations: tuple[str, ...]
    if not enabled:
        availability = "disabled"
        limitations = ("The Java JFR Adapter is disabled by project policy.",)
    elif not host_launch_allowed:
        availability = "unavailable"
        limitations = (
            "Startup-time Java JFR launch is outside the project policy target or launch scope.",
        )
    elif not active_supervisor_available:
        availability = "unavailable"
        limitations = (
            "The fixed root-owned Runtime Lock supervisor is unavailable; controlled JFR "
            "import remains available.",
        )
    elif discovered is None:
        availability = "unavailable"
        limitations = ("No safely discovered JDK/JFR installation was supplied.",)
    elif discovered.availability not in {"available", "partial"}:
        availability = "unavailable"
        limitations = (
            "Trusted JDK/JFR discovery reported unavailable; absolute local diagnostic paths "
            "are intentionally omitted from the public capability.",
        )
    elif common_semantics != {"thresholded"}:
        availability = "unavailable"
        limitations = (
            *discovered_limitations,
            "JDK/JFR discovery and project policy have no common thresholded semantics.",
        )
    else:
        availability = discovered.availability
        limitations = discovered_limitations

    binding: RuntimeLockAdapterExecutionBinding | None = None
    launch_policy: JavaJfrLaunchPolicy | None = None
    if availability in {"available", "partial"}:
        assert discovered is not None
        assert discovered.java_tool is not None
        assert discovered.jfr_tool is not None
        assert discovered.event_surface is not None
        assert discovered.jdk_major is not None
        assert discovered.java_version is not None
        assert discovered.runtime_payload is not None
        profile_name = adapter_policy.profile
        profile = next(
            (item for item in discovered.profiles if item.profile_id == profile_name),
            None,
        )
        if (
            profile is None
            or adapter_policy.duration_threshold_ns != profile.threshold_ns
            or discovered.java_tool.mode not in {0o555, 0o755}
            or discovered.jfr_tool.mode not in {0o555, 0o755}
            or profile.mode != 0o644
        ):
            availability = "unavailable"
            limitations = (
                *limitations,
                "The policy-selected fixed JFR profile, threshold, or packaged file mode is "
                "unavailable.",
            )
        else:
            if profile.profile_id == "deep":
                limitations = tuple(
                    dict.fromkeys(
                        (
                            *limitations,
                            "The Java JFR deep profile uses a 1 ms threshold and may add "
                            "material collection overhead; treat results as diagnostic unless "
                            "a matched overhead check passes.",
                        )
                    )
                )
            launch_policy = JavaJfrLaunchPolicy(
                java_tool=_file_policy(discovered.java_tool),
                jfr_tool=_file_policy(discovered.jfr_tool),
                jfc_profile=JavaJfrFilePolicy(
                    path=profile.path,
                    sha256=profile.sha256,
                    owner_uid=profile.owner_uid,
                    mode=profile.mode,
                ),
                jdk_major=discovered.jdk_major,
                profile=profile.profile_id,
                runtime_payload=_runtime_payload_policy(discovered.runtime_payload),
            )
            tools = (
                RuntimeLockAdapterToolBinding(
                    name="java",
                    version=discovered.java_version,
                    binary_sha256=discovered.java_tool.sha256,
                ),
                RuntimeLockAdapterToolBinding(
                    name="jfr",
                    version=discovered.java_version,
                    binary_sha256=discovered.jfr_tool.sha256,
                ),
            )
            toolchain_sha = derive_runtime_lock_toolchain_identity(tools)
            execution_sha = derive_runtime_lock_adapter_execution_identity(
                "java_jfr",
                JAVA_JFR_ADAPTER_VERSION,
                "jfr",
                discovered.java_version,
                profile.profile_id,
                "thresholded",
                profile.threshold_ns,
                toolchain_sha,
                profile.sha256,
                discovered.event_surface.canonical_metadata_sha256,
                discovered.runtime_payload.identity_sha256,
            )
            binding = RuntimeLockAdapterExecutionBinding(
                adapter_id="java_jfr",
                adapter_version=JAVA_JFR_ADAPTER_VERSION,
                backend_id="jfr",
                runtime_version=discovered.java_version,
                profile=profile.profile_id,
                measurement_semantics="thresholded",
                duration_threshold_ns=profile.threshold_ns,
                tools=tools,
                toolchain_identity_sha256=toolchain_sha,
                configuration_sha256=profile.sha256,
                metadata_sha256=discovered.event_surface.canonical_metadata_sha256,
                runtime_payload_identity_sha256=(discovered.runtime_payload.identity_sha256),
                execution_identity_sha256=execution_sha,
                limitations=limitations,
            )

    material = "\0".join(
        (
            "perflens-runtime-adapter-capability-v1",
            policy.sha256,
            "java_jfr",
            availability,
            binding.execution_identity_sha256 if binding is not None else "unavailable",
            timestamp,
        )
    )
    provisional = RuntimeAdapterCapabilityArtifact(
        schema_version="1.1",
        capability_id=(
            "runtime-adapter-capability-"
            + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
        ),
        created_at=timestamp,
        runtime="java",
        runtime_name="Java Flight Recorder",
        runtime_version=(discovered.java_version if discovered is not None else None),
        adapter_id="java_jfr",
        adapter_version=JAVA_JFR_ADAPTER_VERSION,
        backend_id="jfr",
        availability=availability,
        supported_lock_kinds=("condition", "mutex", "park") if binding is not None else (),
        supported_event_kinds=("wait_end",) if binding is not None else (),
        measurement_semantics=("thresholded",) if binding is not None else (),
        fast_path_visibility="none",
        owner_visibility="partial" if binding is not None else "unavailable",
        hold_time_visibility="unavailable",
        launch_instrumentation_required=True,
        attach_required=False,
        privileged_backend_required=False,
        tools=(
            tuple(
                RuntimeToolIdentity(
                    name=tool.name,
                    path=tool.name,
                    version=tool.version,
                    binary_sha256=tool.binary_sha256,
                    status="available",
                )
                for tool in binding.tools
            )
            if binding is not None
            else ()
        ),
        limitations=limitations,
        next_steps=(
            ("Preview one bounded startup-time Java JFR Session for an explicit executable JAR.")
            if binding is not None
            else "Install or enable one trusted JDK 17, 21, or 25 startup-time JFR backend.",
        ),
        content_sha256="0" * 64,
    )
    public = provisional.model_copy(
        update={"content_sha256": contract_content_sha256(provisional, exclude={"content_sha256"})}
    )
    return JavaJfrAdapterBridge(public, binding, launch_policy)


def _file_policy(identity: JavaJfrToolIdentity) -> JavaJfrFilePolicy:
    # JavaJfrToolIdentity is intentionally kept out of the public contract.
    return JavaJfrFilePolicy(
        path=identity.path,
        sha256=identity.sha256,
        owner_uid=identity.owner_uid,
        mode=identity.mode,
    )


def _runtime_directory_policy(
    identity: JavaJfrDirectoryIdentity,
) -> JavaJfrDirectoryPolicy:
    return JavaJfrDirectoryPolicy(
        path=identity.path,
        device=identity.device,
        inode=identity.inode,
        owner_uid=identity.owner_uid,
        mode=identity.mode,
        links=identity.links,
        size=identity.size,
        modified_ns=identity.modified_ns,
        changed_ns=identity.changed_ns,
    )


def _runtime_file_policy(
    identity: JavaJfrPayloadFileIdentity,
) -> JavaJfrPayloadFilePolicy:
    return JavaJfrPayloadFilePolicy(
        path=identity.path,
        sha256=identity.sha256,
        device=identity.device,
        inode=identity.inode,
        owner_uid=identity.owner_uid,
        mode=identity.mode,
        size=identity.size,
        modified_ns=identity.modified_ns,
        changed_ns=identity.changed_ns,
    )


def _runtime_payload_policy(
    identity: JavaJfrRuntimePayloadIdentity,
) -> JavaJfrRuntimePayloadPolicy:
    return JavaJfrRuntimePayloadPolicy(
        jdk_root=_runtime_directory_policy(identity.jdk_root),
        bin_directory=_runtime_directory_policy(identity.bin_directory),
        lib_directory=_runtime_directory_policy(identity.lib_directory),
        release_file=_runtime_file_policy(identity.release_file),
        modules_file=_runtime_file_policy(identity.modules_file),
        native_libraries=tuple(
            _runtime_native_library_policy(item) for item in identity.native_libraries
        ),
        native_library_bytes=identity.native_library_bytes,
        native_library_manifest_sha256=identity.native_library_manifest_sha256,
        identity_sha256=identity.identity_sha256,
    )


def _runtime_native_library_policy(
    identity: JavaJfrNativeLibraryIdentity,
) -> JavaJfrNativeLibraryPolicy:
    return JavaJfrNativeLibraryPolicy(
        relative_path=identity.relative_path,
        named_path=identity.named_path,
        resolved_path=identity.resolved_path,
        source_kind=identity.source_kind,
        link_target_sha256=identity.link_target_sha256,
        link_device=identity.link_device,
        link_inode=identity.link_inode,
        link_owner_uid=identity.link_owner_uid,
        link_mode=identity.link_mode,
        link_links=identity.link_links,
        link_size=identity.link_size,
        link_modified_ns=identity.link_modified_ns,
        link_changed_ns=identity.link_changed_ns,
        sha256=identity.sha256,
        device=identity.device,
        inode=identity.inode,
        owner_uid=identity.owner_uid,
        mode=identity.mode,
        links=identity.links,
        size=identity.size,
        modified_ns=identity.modified_ns,
        changed_ns=identity.changed_ns,
    )


def _public_limitations(discovered: JavaJfrCapability | None) -> tuple[str, ...]:
    if discovered is None:
        return ()
    replacements: dict[str, str] = {}
    if discovered.jdk_root is not None:
        replacements[str(discovered.jdk_root)] = discovered.jdk_root.name
    for identity in (discovered.java_tool, discovered.jfr_tool):
        if identity is not None:
            replacements[str(identity.path)] = identity.path.name
    for profile in discovered.profiles:
        replacements[str(profile.path)] = profile.path.name
    return tuple(_replace_paths(limitation, replacements) for limitation in discovered.limitations)


def _replace_paths(value: str, replacements: dict[str, str]) -> str:
    result = value
    for private, basename in sorted(replacements.items(), key=lambda item: -len(item[0])):
        result = result.replace(private, basename)
    return result
