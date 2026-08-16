"""Feature-profile lifecycle planning kept independent from privilege mode."""

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from perflens import __version__
from perflens.contracts.artifacts import CollectorProfileSwitchArtifact
from perflens.domain.errors import ErrorCode, PerfLensError

FeatureProfile = Literal["cpu_only", "full_diagnostics"]
ProfileSource = Literal["implicit_v0_2_compatibility", "managed"]
TraceBackendStatus = Literal["available", "unavailable"]

_MAX_PROFILE_BYTES = 64 << 10
_PROFILE_SCHEMA_VERSION = 1
_TRACE_BACKEND = "target_filtered_kernel_v1"
_TRACE_MODES = ("sched", "off_cpu", "lock")


@dataclass(frozen=True, slots=True)
class FeatureProfileSnapshot:
    """One verified host feature profile; absence means v0.2-compatible cpu_only."""

    feature_profile: FeatureProfile
    source: ProfileSource
    path: Path
    raw: bytes | None
    sha256: str | None


@dataclass(frozen=True, slots=True)
class TraceBackendCapability:
    """Host fact used by setup/switch planning, never a request to grant privilege."""

    status: TraceBackendStatus
    target_filter_before_userspace: bool
    supported_modes: tuple[Literal["sched", "off_cpu", "lock"], ...]
    reason: str

    def __post_init__(self) -> None:
        if self.status == "available":
            if (
                set(self.supported_modes) != set(_TRACE_MODES)
                or not self.target_filter_before_userspace
            ):
                raise ValueError("available Trace backend must provide all target-filtered modes")
        elif self.supported_modes or self.target_filter_before_userspace:
            raise ValueError("unavailable Trace backend cannot claim collection capability")


def unavailable_trace_backend_capability() -> TraceBackendCapability:
    """Return the current fail-closed fact until the packaged backend passes acceptance."""
    return TraceBackendCapability(
        status="unavailable",
        target_filter_before_userspace=False,
        supported_modes=(),
        reason=(
            "The packaged target-filtered kernel Trace backend has not passed authenticated "
            "external-waker, switch-in, dynamic-thread, loss, and privacy acceptance."
        ),
    )


def load_feature_profile(
    path: Path,
    *,
    require_root_owner: bool = True,
    invoking_uid: int | None = None,
    stage: str = "collector_profile",
) -> FeatureProfileSnapshot:
    """Load strict managed TOML; a missing file maps to cpu_only without writing it."""
    candidate = path.expanduser()
    if not os.path.lexists(candidate):
        return FeatureProfileSnapshot(
            feature_profile="cpu_only",
            source="implicit_v0_2_compatibility",
            path=candidate,
            raw=None,
            sha256=None,
        )
    if not candidate.is_absolute() or candidate.is_symlink():
        raise _unsafe_profile(stage, "Feature profile path is unsafe")
    descriptor = -1
    try:
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise _unsafe_profile(stage, "Feature profile cannot be opened safely") from exc
    expected_uid = os.geteuid() if invoking_uid is None else invoking_uid
    owners = {0} if require_root_owner else {0, expected_uid}
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in owners
        or metadata.st_mode & 0o022
        or metadata.st_size > _MAX_PROFILE_BYTES
    ):
        os.close(descriptor)
        raise _unsafe_profile(stage, "Feature profile ownership or permissions are unsafe")
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            raw = handle.read(_MAX_PROFILE_BYTES + 1)
        if len(raw) > _MAX_PROFILE_BYTES:
            raise _unsafe_profile(stage, "Feature profile exceeds its size limit")
        text = raw.decode("utf-8")
        payload = tomllib.loads(text)
    except PerfLensError:
        raise
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise _unsafe_profile(stage, "Feature profile is not bounded valid TOML") from exc
    if set(payload) != {"profile"} or not isinstance(payload["profile"], dict):
        raise _unsafe_profile(stage, "Feature profile requires exactly one [profile] table")
    values = cast(dict[str, object], payload["profile"])
    if set(values) != {"schema_version", "feature_profile"}:
        raise _unsafe_profile(stage, "Feature profile contains unknown or missing fields")
    if values["schema_version"] != _PROFILE_SCHEMA_VERSION:
        raise _unsafe_profile(stage, "Feature profile schema version is unsupported")
    selected = values["feature_profile"]
    if selected not in {"cpu_only", "full_diagnostics"}:
        raise _unsafe_profile(stage, "Feature profile name is unsupported")
    return FeatureProfileSnapshot(
        feature_profile=cast(FeatureProfile, selected),
        source="managed",
        path=resolved,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def render_feature_profile(profile: FeatureProfile) -> str:
    """Render the only accepted managed profile representation."""
    return (
        "# Managed by PerfLens.\n"
        "[profile]\n"
        f"schema_version = {_PROFILE_SCHEMA_VERSION}\n"
        f'feature_profile = "{profile}"\n'
    )


def plan_feature_profile_switch(
    target_profile: FeatureProfile,
    *,
    current: FeatureProfileSnapshot,
    privilege_mode: Literal["cap_perfmon", "paranoid3_helper"],
    profile_path: Path,
    trace_helper_service_path: Path,
    trace_socket_path: Path,
    trace_private_spool: Path,
    capability: TraceBackendCapability | None = None,
    dry_run: bool = False,
) -> CollectorProfileSwitchArtifact:
    """Produce a no-write plan and refuse a partial full_diagnostics topology."""
    observed = capability or unavailable_trace_backend_capability()
    warnings = [
        "Host sysctl, Collector privilege mode, authorized UIDs, and retained evidence are "
        "not changed by a feature-profile switch.",
    ]
    next_steps: list[str] = []
    profile_update_required = current.feature_profile != target_profile

    if target_profile == "full_diagnostics" and observed.status != "available":
        warnings.append(observed.reason)
        next_steps.extend(
            (
                "Keep cpu_only active; stat and record remain available within the deployed "
                "Collector boundary.",
                "Install a release whose packaged Trace backend passes the documented real-host "
                "acceptance before retrying full_diagnostics.",
            )
        )
        status: Literal["blocked", "dry_run", "unchanged", "switched"] = "blocked"
    elif current.feature_profile == target_profile:
        status = "unchanged"
        next_steps.append("No feature-profile change is required.")
    else:
        # This milestone deliberately has no mutation path. Reaching this branch would mean a
        # future backend capability was injected without the reviewed multi-service transaction.
        status = "blocked"
        warnings.append(
            "The Trace backend capability exists, but the transactional service topology is not "
            "available in this build."
        )
        next_steps.append(
            "Do not edit allowed_modes or the profile file manually; install a build with the "
            "reviewed switch transaction."
        )

    del dry_run  # The current milestone has no safe mutating transition to preview yet.
    return CollectorProfileSwitchArtifact(
        perflens_version=__version__,
        status=status,
        current_profile=current.feature_profile,
        target_profile=target_profile,
        profile_source=current.source,
        privilege_mode=privilege_mode,
        profile_path=str(profile_path),
        trace_helper_service_path=str(trace_helper_service_path),
        trace_socket_path=str(trace_socket_path),
        trace_private_spool=str(trace_private_spool),
        trace_backend=_TRACE_BACKEND,
        trace_backend_status=observed.status,
        target_filter_before_userspace=observed.target_filter_before_userspace,
        supported_trace_modes=observed.supported_modes,
        trace_risk_acknowledgement_required=target_profile == "full_diagnostics",
        profile_update_required=profile_update_required,
        planned_commands=(),
        warnings=tuple(warnings),
        next_steps=tuple(next_steps),
    )


def require_actionable_profile_switch(
    artifact: CollectorProfileSwitchArtifact,
) -> CollectorProfileSwitchArtifact:
    """Turn a blocked non-mutating plan into a stable administrator error."""
    if artifact.status != "blocked":
        return artifact
    raise PerfLensError(
        ErrorCode.UNSUPPORTED_FORMAT,
        "collector_profile_switch",
        "The requested Collector feature profile is not safely deployable on this build/host",
        recoverable=True,
        details={
            "current_profile": artifact.current_profile,
            "target_profile": artifact.target_profile,
            "trace_backend_status": artifact.trace_backend_status,
            "target_filter_before_userspace": artifact.target_filter_before_userspace,
        },
        suggested_actions=artifact.next_steps,
    )


def _unsafe_profile(stage: str, message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.PATH_SAFETY_VIOLATION, stage, message)
