"""Strict project policy for bounded Runtime Lock sessions."""

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, TypedDict, cast

from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterId,
    RuntimeLockSessionBudget,
    RuntimeLockTargetScope,
)
from perflens.contracts.runtime_locks import MeasurementSemantics
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_POLICY_BYTES = 256 << 10
_TOP_LEVEL_KEYS = {
    "schema_version",
    "enabled",
    "target_scopes",
    "allowed_adapters",
    "allowed_semantics",
    "import_roots",
    "preview_ttl_seconds",
    "max_workload_runs",
    "max_active_seconds",
    "hard_expiry_seconds",
    "max_artifact_bytes",
    "max_evidence_bytes",
    "max_collection_duration_seconds",
    "max_exact_duration_seconds",
    "max_exact_events",
    "max_adapter_concurrency",
    "adapters",
}
_ADAPTER_KEYS = {
    "native_pthread",
    "java_jfr",
    "cpython_threading",
    "go_pprof",
    "generic_ndjson_import",
}
_ADAPTER_POLICY_KEYS = {
    "enabled",
    "allowed_semantics",
    "duration_threshold_ns",
    "exact_enabled",
    "launch_instrumentation_allowed",
    "controlled_import_allowed",
}
_ADAPTER_ORDER = (
    "cpython_threading",
    "generic_ndjson_import",
    "go_pprof",
    "java_jfr",
    "native_pthread",
)
_SEMANTICS_ORDER = ("cumulative", "exact", "sampled", "thresholded")
_TARGET_SCOPE_ORDER = (
    "controlled_import",
    "docker_optimization",
    "host_launched_workload",
    "managed_temporary_container",
)


@dataclass(frozen=True, slots=True)
class RuntimeLockAdapterProjectPolicy:
    enabled: bool
    allowed_semantics: tuple[MeasurementSemantics, ...]
    duration_threshold_ns: int | None
    exact_enabled: bool
    launch_instrumentation_allowed: bool
    controlled_import_allowed: bool


@dataclass(frozen=True, slots=True)
class RuntimeLockProjectPolicy:
    schema_version: Literal["1.0"]
    path: Path
    device: int
    inode: int
    owner_uid: int
    size: int
    modified_ns: int
    sha256: str
    enabled: bool
    target_scopes: tuple[RuntimeLockTargetScope, ...]
    allowed_adapters: tuple[RuntimeLockAdapterId, ...]
    allowed_semantics: tuple[MeasurementSemantics, ...]
    import_roots: tuple[str, ...]
    preview_ttl_seconds: int
    budget: RuntimeLockSessionBudget
    adapters: tuple[tuple[RuntimeLockAdapterId, RuntimeLockAdapterProjectPolicy], ...]

    def adapter_policy(self, adapter_id: RuntimeLockAdapterId) -> RuntimeLockAdapterProjectPolicy:
        for candidate, policy in self.adapters:
            if candidate == adapter_id:
                return policy
        raise KeyError(adapter_id)


class _ValidatedPolicy(TypedDict):
    schema_version: Literal["1.0"]
    enabled: bool
    target_scopes: tuple[RuntimeLockTargetScope, ...]
    allowed_adapters: tuple[RuntimeLockAdapterId, ...]
    allowed_semantics: tuple[MeasurementSemantics, ...]
    import_roots: tuple[str, ...]
    preview_ttl_seconds: int
    budget: RuntimeLockSessionBudget
    adapters: tuple[tuple[RuntimeLockAdapterId, RuntimeLockAdapterProjectPolicy], ...]


def render_default_runtime_lock_project_policy(*, docker_enabled: bool = False) -> str:
    """Return an enabled-for-discovery policy that executes nothing during init."""

    scopes = (
        '["controlled_import", "docker_optimization", "host_launched_workload", '
        '"managed_temporary_container"]'
        if docker_enabled
        else '["controlled_import", "host_launched_workload"]'
    )
    return f"""# PerfLens v0.4.0 Runtime Lock discovery and bounded-session policy.
# Initialization only writes this policy. It does not instrument, attach, import, or collect.
# 初始化只写入本策略, 不执行插桩、附加、导入或采集。

schema_version = "1.0"
enabled = true
target_scopes = {scopes}
allowed_adapters = [
  "cpython_threading", "generic_ndjson_import", "go_pprof", "java_jfr", "native_pthread"
]
allowed_semantics = ["cumulative", "exact", "sampled", "thresholded"]
import_roots = ["perflens-runtime-locks"]
preview_ttl_seconds = 600
max_workload_runs = 6
max_active_seconds = 1200
hard_expiry_seconds = 3600
max_artifact_bytes = 67108864
max_evidence_bytes = 536870912
max_collection_duration_seconds = 30
max_exact_duration_seconds = 3
max_exact_events = 20000
max_adapter_concurrency = 1

[adapters.native_pthread]
enabled = true
allowed_semantics = ["exact", "thresholded"]
duration_threshold_ns = 1000
exact_enabled = true
launch_instrumentation_allowed = true
controlled_import_allowed = true

[adapters.java_jfr]
enabled = true
allowed_semantics = ["thresholded"]
duration_threshold_ns = 10000000
exact_enabled = false
launch_instrumentation_allowed = true
controlled_import_allowed = true

[adapters.cpython_threading]
enabled = true
allowed_semantics = ["exact", "thresholded"]
duration_threshold_ns = 10000
exact_enabled = true
launch_instrumentation_allowed = true
controlled_import_allowed = true

[adapters.go_pprof]
enabled = true
allowed_semantics = ["cumulative"]
duration_threshold_ns = 0
exact_enabled = false
launch_instrumentation_allowed = false
controlled_import_allowed = true

[adapters.generic_ndjson_import]
enabled = true
allowed_semantics = ["cumulative", "exact", "sampled", "thresholded"]
duration_threshold_ns = 0
exact_enabled = true
launch_instrumentation_allowed = false
controlled_import_allowed = true
"""


def load_runtime_lock_project_policy(
    path: Path,
    *,
    allowed_roots: tuple[Path, ...],
    invoking_uid: int | None = None,
) -> RuntimeLockProjectPolicy:
    """Load one same-UID, immutable-during-read Runtime Lock policy."""

    uid = os.geteuid() if invoking_uid is None else invoking_uid
    if not path.is_absolute() or path.is_symlink():
        raise _policy_error("Runtime Lock policy must be an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=True)
        roots = tuple(root.expanduser().resolve(strict=True) for root in allowed_roots)
    except OSError as exc:
        raise _policy_error("Runtime Lock policy path cannot be resolved safely") from exc
    if resolved != path or not any(resolved.is_relative_to(root) for root in roots):
        raise _policy_error("Runtime Lock policy is outside the configured project roots")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(resolved, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != uid
            or before.st_mode & 0o022
            or not 1 <= before.st_size <= _MAX_POLICY_BYTES
        ):
            raise _policy_error("Runtime Lock policy owner, mode, links, or size are unsafe")
        raw = bytearray()
        while chunk := os.read(descriptor, min(1 << 16, _MAX_POLICY_BYTES + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > _MAX_POLICY_BYTES:
                raise _policy_error("Runtime Lock policy exceeds its size limit")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise _policy_error("Runtime Lock policy changed while it was read")
    except OSError as exc:
        raise _policy_error("Runtime Lock policy cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        parsed = cast(dict[str, object], tomllib.loads(bytes(raw).decode("utf-8")))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise _policy_error("Runtime Lock policy must be valid UTF-8 TOML") from exc
    values = _validate_policy_values(parsed)
    return RuntimeLockProjectPolicy(
        path=resolved,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        sha256=hashlib.sha256(raw).hexdigest(),
        **values,
    )


def assert_runtime_lock_project_policy_current(
    policy: RuntimeLockProjectPolicy,
    *,
    allowed_roots: tuple[Path, ...],
) -> None:
    current = load_runtime_lock_project_policy(
        policy.path,
        allowed_roots=allowed_roots,
        invoking_uid=policy.owner_uid,
    )
    if current != policy:
        raise _policy_error(
            "Runtime Lock policy changed after MCP startup; restart the client to review it"
        )


def _validate_policy_values(parsed: dict[str, object]) -> _ValidatedPolicy:
    if parsed.get("schema_version") != "1.0":
        raise _policy_error("Runtime Lock project policy version is unsupported")
    if set(parsed) != _TOP_LEVEL_KEYS:
        raise _policy_error("Runtime Lock policy has missing or unknown top-level fields")
    enabled = _boolean(parsed["enabled"], "enabled")
    target_scopes = _enum_list(
        parsed["target_scopes"],
        "target scopes",
        _TARGET_SCOPE_ORDER,
    )
    allowed_adapters = _enum_list(
        parsed["allowed_adapters"],
        "allowed Adapters",
        _ADAPTER_ORDER,
    )
    allowed_semantics = _enum_list(
        parsed["allowed_semantics"],
        "allowed semantics",
        _SEMANTICS_ORDER,
    )
    import_roots = _relative_path_list(parsed["import_roots"], "import roots", 32)
    if enabled and (not target_scopes or not allowed_adapters or not allowed_semantics):
        raise _policy_error("enabled Runtime Lock policy requires non-empty scopes")
    if "controlled_import" in target_scopes and not import_roots:
        raise _policy_error("controlled Runtime Lock import requires an import root")
    max_active_seconds = _integer(parsed["max_active_seconds"], "active seconds", 1, 1200)
    hard_expiry_seconds = _integer(parsed["hard_expiry_seconds"], "hard expiry", 1, 3600)
    if hard_expiry_seconds < max_active_seconds:
        raise _policy_error("Runtime Lock hard expiry cannot be shorter than active time")
    max_artifact_bytes = _integer(parsed["max_artifact_bytes"], "Artifact bytes", 1, 64 << 20)
    max_evidence_bytes = _integer(
        parsed["max_evidence_bytes"], "Session evidence bytes", 1, 512 << 20
    )
    if max_artifact_bytes > max_evidence_bytes:
        raise _policy_error("Runtime Lock Artifact limit exceeds Session evidence budget")
    max_adapter_concurrency = _integer(
        parsed["max_adapter_concurrency"], "Adapter concurrency", 1, 1
    )
    assert max_adapter_concurrency == 1
    budget = RuntimeLockSessionBudget(
        max_workload_runs=_integer(parsed["max_workload_runs"], "workload runs", 1, 6),
        max_active_seconds=max_active_seconds,
        hard_expiry_seconds=hard_expiry_seconds,
        max_artifact_bytes=max_artifact_bytes,
        max_evidence_bytes=max_evidence_bytes,
        max_collection_duration_seconds=_integer(
            parsed["max_collection_duration_seconds"], "collection duration", 1, 30
        ),
        max_exact_duration_seconds=_integer(
            parsed["max_exact_duration_seconds"], "exact duration", 1, 3
        ),
        max_exact_events=_integer(parsed["max_exact_events"], "exact events", 1, 20_000),
        max_adapter_concurrency=1,
    )
    raw_adapters = parsed["adapters"]
    if not isinstance(raw_adapters, dict):
        raise _policy_error("Runtime Lock Adapter policy must be a table")
    adapter_values = cast(dict[str, object], raw_adapters)
    if set(adapter_values) != _ADAPTER_KEYS:
        raise _policy_error("Runtime Lock Adapter policy has missing or unknown tables")
    adapters: list[tuple[RuntimeLockAdapterId, RuntimeLockAdapterProjectPolicy]] = []
    for adapter_id in _ADAPTER_ORDER:
        raw_adapter = adapter_values[adapter_id]
        if not isinstance(raw_adapter, dict):
            raise _policy_error(f"Runtime Lock {adapter_id} policy must be a table")
        typed_adapter = cast(dict[str, object], raw_adapter)
        if set(typed_adapter) != _ADAPTER_POLICY_KEYS:
            raise _policy_error(f"Runtime Lock {adapter_id} policy has unknown fields")
        adapter = _validate_adapter_policy(typed_adapter)
        typed_id = adapter_id
        if typed_id in allowed_adapters and enabled and not adapter.enabled:
            raise _policy_error("allowed Runtime Lock Adapter cannot be disabled")
        if adapter.enabled and typed_id not in allowed_adapters:
            raise _policy_error("enabled Runtime Lock Adapter must be in allowed_adapters")
        if any(semantics not in allowed_semantics for semantics in adapter.allowed_semantics):
            raise _policy_error("Adapter semantics exceed the Runtime Lock policy scope")
        adapters.append((typed_id, adapter))
    return {
        "schema_version": "1.0",
        "enabled": enabled,
        "target_scopes": cast(tuple[RuntimeLockTargetScope, ...], target_scopes),
        "allowed_adapters": cast(tuple[RuntimeLockAdapterId, ...], allowed_adapters),
        "allowed_semantics": cast(tuple[MeasurementSemantics, ...], allowed_semantics),
        "import_roots": import_roots,
        "preview_ttl_seconds": _integer(parsed["preview_ttl_seconds"], "Preview TTL", 1, 600),
        "budget": budget,
        "adapters": tuple(adapters),
    }


def _validate_adapter_policy(values: dict[str, object]) -> RuntimeLockAdapterProjectPolicy:
    enabled = _boolean(values["enabled"], "Adapter enabled")
    semantics = _enum_list(
        values["allowed_semantics"],
        "Adapter semantics",
        _SEMANTICS_ORDER,
    )
    threshold = _integer(values["duration_threshold_ns"], "duration threshold", 0, 10**12)
    exact_enabled = _boolean(values["exact_enabled"], "exact enabled")
    launch = _boolean(values["launch_instrumentation_allowed"], "launch instrumentation")
    controlled_import = _boolean(values["controlled_import_allowed"], "controlled import")
    if enabled and not semantics:
        raise _policy_error("enabled Runtime Lock Adapter needs a semantics")
    if exact_enabled != ("exact" in semantics):
        raise _policy_error("Runtime Lock exact switch disagrees with Adapter semantics")
    if launch and "thresholded" in semantics and threshold == 0:
        raise _policy_error("thresholded Runtime Lock Adapter requires a non-zero threshold")
    if "thresholded" not in semantics and threshold != 0:
        raise _policy_error("non-thresholded Runtime Lock Adapter cannot set a threshold")
    if enabled and not (launch or controlled_import):
        raise _policy_error("enabled Runtime Lock Adapter has no bounded evidence entry point")
    return RuntimeLockAdapterProjectPolicy(
        enabled=enabled,
        allowed_semantics=cast(tuple[MeasurementSemantics, ...], semantics),
        duration_threshold_ns=threshold or None,
        exact_enabled=exact_enabled,
        launch_instrumentation_allowed=launch,
        controlled_import_allowed=controlled_import,
    )


def _enum_list(value: object, label: str, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _policy_error(f"Runtime Lock {label} must be a list")
    items = cast(list[object], value)
    if len(items) > len(allowed) or any(not isinstance(item, str) for item in items):
        raise _policy_error(f"Runtime Lock {label} are invalid or unbounded")
    typed = tuple(cast(str, item) for item in items)
    if any(item not in allowed for item in typed):
        raise _policy_error(f"Runtime Lock {label} contain an unsupported value")
    if len(typed) != len(set(typed)) or tuple(sorted(typed, key=allowed.index)) != typed:
        raise _policy_error(f"Runtime Lock {label} must be unique and canonical")
    return typed


def _relative_path_list(value: object, label: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _policy_error(f"Runtime Lock {label} must be a list")
    items = cast(list[object], value)
    if len(items) > maximum or any(not isinstance(item, str) for item in items):
        raise _policy_error(f"Runtime Lock {label} are invalid or unbounded")
    paths = tuple(_project_relative_path(cast(str, item), label) for item in items)
    if len(paths) != len(set(paths)):
        raise _policy_error(f"Runtime Lock {label} must be unique")
    return tuple(sorted(paths))


def _project_relative_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
        or str(path) != value
        or value in {".", ".."}
        or ".." in path.parts
    ):
        raise _policy_error(f"Runtime Lock {label} must be normalized project-relative paths")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise _policy_error(f"Runtime Lock {label} must be a boolean")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise _policy_error(f"Runtime Lock {label} is outside its fixed bound")
    return value


def _policy_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_lock_project_policy",
        message,
        recoverable=True,
    )
