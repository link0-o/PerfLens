"""Capability and execution bindings for startup-only CPython threading instrumentation."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.runtime_lock_sessions import (
    RuntimeLockAdapterExecutionBinding,
    RuntimeLockAdapterToolBinding,
    derive_runtime_lock_adapter_execution_identity,
    derive_runtime_lock_toolchain_identity,
)
from perflens.contracts.runtime_locks import RuntimeAdapterCapabilityArtifact, RuntimeToolIdentity
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.runtime_locks.project_config import RuntimeLockProjectPolicy
from perflens.runtime_locks.supervisor import discover_runtime_supervisor_policy

CPYTHON_THREADING_ADAPTER_VERSION = "cpython-threading-adapter-v1"
DEFAULT_CPYTHON_BOOTSTRAP_PATH = Path("/usr/lib/perflens/cpython-threading-bootstrap.py")


@dataclass(frozen=True, slots=True)
class CpythonFileIdentity:
    path: Path
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    links: int
    size: int


@dataclass(frozen=True, slots=True)
class CpythonDirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner_uid: int
    mode: int


@dataclass(frozen=True, slots=True)
class CpythonInstallation:
    availability: Literal["available", "partial", "unavailable"]
    runtime_version: str | None
    free_threaded: bool | None
    interpreter: CpythonFileIdentity | None
    runtime_home: CpythonDirectoryIdentity | None
    bootstrap: CpythonFileIdentity | None
    metadata_sha256: str | None
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CpythonRuntimeProbe:
    interpreter: CpythonFileIdentity
    runtime_home: Path
    runtime_version: str
    free_threaded: bool
    cache_tag: str
    soabi: str
    abiflags: str


@dataclass(frozen=True, slots=True)
class CpythonLaunchPolicy:
    interpreter: CpythonFileIdentity
    runtime_home: CpythonDirectoryIdentity
    bootstrap: CpythonFileIdentity
    runtime_version: str
    free_threaded: bool
    metadata_sha256: str


@dataclass(frozen=True, slots=True)
class CpythonAdapterBridge:
    capability: RuntimeAdapterCapabilityArtifact
    execution_bindings: tuple[RuntimeLockAdapterExecutionBinding, ...]
    launch_policy: CpythonLaunchPolicy | None

    def binding_for(
        self, semantics: Literal["exact", "thresholded"]
    ) -> RuntimeLockAdapterExecutionBinding | None:
        return next(
            (item for item in self.execution_bindings if item.measurement_semantics == semantics),
            None,
        )


def assert_cpython_launch_policy_current(policy: CpythonLaunchPolicy) -> None:
    """Reopen and verify the authorized interpreter and bootstrap identities.

    A Docker optimization Preview binds immutable file identities.  Comparing a
    launch request only with the cached bridge would miss an on-disk replacement
    between Preview and workload-lease issuance.
    """

    trusted_owner_uids = tuple(
        sorted(
            {
                policy.interpreter.owner_uid,
                policy.runtime_home.owner_uid,
                policy.bootstrap.owner_uid,
            }
        )
    )
    interpreter = _inspect_file(
        policy.interpreter.path,
        executable=True,
        maximum_size=512 << 20,
        trusted_owner_uids=trusted_owner_uids,
    )
    runtime_home = _inspect_runtime_home(
        policy.runtime_home.path,
        trusted_owner_uids=trusted_owner_uids,
    )
    bootstrap = _inspect_file(
        policy.bootstrap.path,
        executable=False,
        maximum_size=1 << 20,
        trusted_owner_uids=trusted_owner_uids,
    )
    if (
        interpreter != policy.interpreter
        or runtime_home != policy.runtime_home
        or bootstrap != policy.bootstrap
    ):
        raise _error("CPython runtime payload changed after capability inspection")


def inspect_cpython_installation(
    *,
    interpreter_path: Path | None = None,
    runtime_home_path: Path | None = None,
    bootstrap_path: Path = DEFAULT_CPYTHON_BOOTSTRAP_PATH,
    trusted_owner_uids: tuple[int, ...] = (0,),
    runtime_probe: CpythonRuntimeProbe | None = None,
) -> CpythonInstallation:
    """Inspect a pinned interpreter, using its own metadata when explicitly probed."""

    version = (
        runtime_probe.runtime_version
        if runtime_probe is not None
        else ".".join(map(str, sys.version_info[:3]))
    )
    free_threaded = (
        runtime_probe.free_threaded
        if runtime_probe is not None
        else bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    )
    supported = runtime_probe is not None or (
        sys.implementation.name == "cpython" and sys.version_info[:2] in {(3, 12), (3, 13)}
    )
    if not supported:
        return CpythonInstallation(
            availability="unavailable",
            runtime_version=version,
            free_threaded=free_threaded,
            interpreter=None,
            runtime_home=None,
            bootstrap=None,
            metadata_sha256=None,
            limitations=("Active CPython instrumentation requires CPython 3.12 or 3.13.",),
        )
    candidate = interpreter_path or Path(sys.executable)
    if interpreter_path is None:
        # ``sys.executable`` is commonly the distribution-managed
        # ``/usr/bin/python3`` symlink.  Treat it only as a discovery hint and
        # bind the inspected launch policy to the canonical regular file.  An
        # explicitly supplied path remains subject to the stricter no-symlink
        # contract so callers cannot silently change an authorized identity.
        try:
            candidate = candidate.resolve(strict=True)
        except OSError as exc:
            return CpythonInstallation(
                availability="unavailable",
                runtime_version=version,
                free_threaded=free_threaded,
                interpreter=None,
                runtime_home=None,
                bootstrap=None,
                metadata_sha256=None,
                limitations=(
                    "Active CPython threading instrumentation is unavailable: "
                    f"the running interpreter cannot be resolved ({type(exc).__name__}).",
                    "Controlled Runtime Lock import and analysis remain available.",
                ),
            )
    try:
        interpreter = _inspect_file(
            candidate,
            executable=True,
            maximum_size=512 << 20,
            trusted_owner_uids=trusted_owner_uids,
        )
        if runtime_probe is not None and interpreter != runtime_probe.interpreter:
            raise _error("CPython interpreter changed after its version probe")
        runtime_home = _inspect_runtime_home(
            runtime_home_path
            or (runtime_probe.runtime_home if runtime_probe is not None else Path(sys.base_prefix)),
            trusted_owner_uids=trusted_owner_uids,
        )
        bootstrap = _inspect_file(
            bootstrap_path,
            executable=False,
            maximum_size=1 << 20,
            trusted_owner_uids=trusted_owner_uids,
        )
    except PerfLensError as exc:
        return CpythonInstallation(
            availability="unavailable",
            runtime_version=version,
            free_threaded=free_threaded,
            interpreter=None,
            runtime_home=None,
            bootstrap=None,
            metadata_sha256=None,
            limitations=(
                f"Active CPython threading instrumentation is unavailable: {exc.message}",
                "Controlled Runtime Lock import and analysis remain available.",
            ),
        )
    metadata = hashlib.sha256(
        "\0".join(
            (
                "perflens-cpython-runtime-metadata-v1",
                version,
                (
                    runtime_probe.cache_tag
                    if runtime_probe is not None
                    else sys.implementation.cache_tag or ""
                ),
                str(int(free_threaded)),
                (
                    runtime_probe.soabi
                    if runtime_probe is not None
                    else sysconfig.get_config_var("SOABI") or ""
                ),
                (
                    runtime_probe.abiflags
                    if runtime_probe is not None
                    else sysconfig.get_config_var("ABIFLAGS") or ""
                ),
                str(runtime_home.device),
                str(runtime_home.inode),
                str(runtime_home.owner_uid),
                str(runtime_home.mode),
            )
        ).encode("utf-8")
    ).hexdigest()
    limitations = (
        "Only public threading.Lock, RLock, Condition, Semaphore, and BoundedSemaphore "
        "constructors used after startup bootstrap are visible.",
        "The GIL, CPython internal locks, C-extension locks, direct _thread objects, and "
        "custom atomic locks are not observed.",
        "Instrumentation is cooperative target-process evidence; hashes prove byte "
        "consistency, not adversarial provenance.",
    )
    if free_threaded:
        limitations = (
            *limitations,
            "This CPython build is free-threaded; traditional GIL conclusions are unavailable.",
        )
    else:
        limitations = (*limitations, "No source-observed GIL event surface is available.")
    return CpythonInstallation(
        availability="available",
        runtime_version=version,
        free_threaded=free_threaded,
        interpreter=interpreter,
        runtime_home=runtime_home,
        bootstrap=bootstrap,
        metadata_sha256=metadata,
        limitations=limitations,
    )


def build_cpython_adapter_bridge(
    policy: RuntimeLockProjectPolicy,
    installation: CpythonInstallation | None,
    *,
    created_at: str | None = None,
    supervisor_available: bool = True,
) -> CpythonAdapterBridge:
    timestamp = created_at or datetime.now(tz=UTC).isoformat()
    adapter_policy = policy.adapter_policy("cpython_threading")
    enabled = policy.enabled and adapter_policy.enabled
    launch_allowed = (
        enabled
        and adapter_policy.launch_instrumentation_allowed
        and "host_launched_workload" in policy.target_scopes
    )
    if not enabled:
        availability = "disabled"
        limitations = ("The CPython threading Adapter is disabled by project policy.",)
    elif not launch_allowed:
        availability = "unavailable"
        limitations = ("CPython startup instrumentation is outside project policy.",)
    elif not supervisor_available:
        availability = "unavailable"
        limitations = ("The fixed Runtime Lock supervisor is unavailable.",)
    elif installation is None or installation.availability == "unavailable":
        availability = "unavailable"
        limitations = (
            installation.limitations
            if installation is not None
            else ("No safely inspected CPython installation was supplied.",)
        )
    else:
        availability = installation.availability
        limitations = installation.limitations

    bindings: list[RuntimeLockAdapterExecutionBinding] = []
    launch_policy: CpythonLaunchPolicy | None = None
    if availability in {"available", "partial"}:
        assert installation is not None
        assert installation.interpreter is not None
        assert installation.runtime_home is not None
        assert installation.bootstrap is not None
        assert installation.runtime_version is not None
        assert installation.free_threaded is not None
        assert installation.metadata_sha256 is not None
        launch_policy = CpythonLaunchPolicy(
            interpreter=installation.interpreter,
            runtime_home=installation.runtime_home,
            bootstrap=installation.bootstrap,
            runtime_version=installation.runtime_version,
            free_threaded=installation.free_threaded,
            metadata_sha256=installation.metadata_sha256,
        )
        tool = RuntimeLockAdapterToolBinding(
            name="python",
            version=installation.runtime_version,
            binary_sha256=installation.interpreter.sha256,
        )
        tools = (tool,)
        toolchain_sha = derive_runtime_lock_toolchain_identity(tools)
        for semantics in ("exact", "thresholded"):
            if (
                semantics not in adapter_policy.allowed_semantics
                or semantics not in policy.allowed_semantics
            ):
                continue
            threshold = 10_000 if semantics == "thresholded" else None
            identity = derive_runtime_lock_adapter_execution_identity(
                "cpython_threading",
                CPYTHON_THREADING_ADAPTER_VERSION,
                "threading-bootstrap",
                installation.runtime_version,
                semantics,
                semantics,
                threshold,
                toolchain_sha,
                installation.bootstrap.sha256,
                installation.metadata_sha256,
                installation.bootstrap.sha256,
            )
            bindings.append(
                RuntimeLockAdapterExecutionBinding(
                    adapter_id="cpython_threading",
                    adapter_version=CPYTHON_THREADING_ADAPTER_VERSION,
                    backend_id="threading-bootstrap",
                    runtime_version=installation.runtime_version,
                    profile=semantics,
                    measurement_semantics=semantics,
                    duration_threshold_ns=threshold,
                    tools=tools,
                    toolchain_identity_sha256=toolchain_sha,
                    configuration_sha256=installation.bootstrap.sha256,
                    metadata_sha256=installation.metadata_sha256,
                    runtime_payload_identity_sha256=installation.bootstrap.sha256,
                    execution_identity_sha256=identity,
                    limitations=limitations,
                )
            )
    material = "\0".join(
        (
            "perflens-runtime-adapter-capability-v1",
            policy.sha256,
            "cpython_threading",
            availability,
            *(item.execution_identity_sha256 for item in bindings),
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
        runtime="python",
        runtime_name="CPython threading",
        runtime_version=(installation.runtime_version if installation is not None else None),
        adapter_id="cpython_threading",
        adapter_version=CPYTHON_THREADING_ADAPTER_VERSION,
        backend_id="threading-bootstrap",
        availability=availability,
        supported_lock_kinds=(
            ("condition", "mutex", "recursive_mutex", "semaphore") if bindings else ()
        ),
        supported_event_kinds=(
            ("acquire", "release", "wait_begin", "wait_end") if bindings else ()
        ),
        measurement_semantics=tuple(item.measurement_semantics for item in bindings),
        fast_path_visibility="partial" if bindings else "none",
        owner_visibility="unavailable",
        hold_time_visibility="unavailable",
        launch_instrumentation_required=True,
        attach_required=False,
        privileged_backend_required=False,
        tools=(
            (
                RuntimeToolIdentity(
                    name="python",
                    version=installation.runtime_version,
                    path="python",
                    binary_sha256=installation.interpreter.sha256,
                    status="available",
                ),
            )
            if installation is not None and installation.interpreter is not None
            else ()
        ),
        limitations=limitations,
        next_steps=(
            (
                "Preview one bounded startup-only CPython threading workload."
                if bindings
                else "Install the main DEB or select a supported CPython 3.12/3.13 runtime."
            ),
        ),
        content_sha256="0" * 64,
    )
    capability = provisional.model_copy(
        update={"content_sha256": contract_content_sha256(provisional, exclude={"content_sha256"})}
    )
    return CpythonAdapterBridge(
        capability=capability,
        execution_bindings=tuple(bindings),
        launch_policy=launch_policy,
    )


_CPYTHON_TARGET_PROBE = (
    "import json,sys,sysconfig;"
    "print(json.dumps({"
    "'implementation':sys.implementation.name,"
    "'executable':sys.executable,"
    "'version':[sys.version_info.major,sys.version_info.minor,sys.version_info.micro],"
    "'runtime_home':sys.base_prefix,"
    "'free_threaded':bool(sysconfig.get_config_var('Py_GIL_DISABLED')),"
    "'cache_tag':sys.implementation.cache_tag or '',"
    "'soabi':sysconfig.get_config_var('SOABI') or '',"
    "'abiflags':sysconfig.get_config_var('ABIFLAGS') or ''"
    "},separators=(',',':')))"
)
_CPYTHON_TARGET_PROBE_KEYS = frozenset(
    {
        "implementation",
        "executable",
        "version",
        "runtime_home",
        "free_threaded",
        "cache_tag",
        "soabi",
        "abiflags",
    }
)


def inspect_configured_cpython_installation(
    interpreter_path: Path,
    *,
    bootstrap_path: Path = DEFAULT_CPYTHON_BOOTSTRAP_PATH,
    trusted_owner_uids: tuple[int, ...] = (0,),
) -> CpythonInstallation:
    """Probe one explicitly configured, trusted target Python without importing MCP into it."""

    try:
        interpreter = _inspect_file(
            interpreter_path,
            executable=True,
            maximum_size=512 << 20,
            trusted_owner_uids=trusted_owner_uids,
        )
        probe = _probe_cpython_target(interpreter)
        installation = inspect_cpython_installation(
            interpreter_path=interpreter_path,
            runtime_home_path=probe.runtime_home,
            bootstrap_path=bootstrap_path,
            trusted_owner_uids=trusted_owner_uids,
            runtime_probe=probe,
        )
        return installation
    except (OSError, PerfLensError) as exc:
        reason = exc.message if isinstance(exc, PerfLensError) else type(exc).__name__
        return CpythonInstallation(
            availability="unavailable",
            runtime_version=None,
            free_threaded=None,
            interpreter=None,
            runtime_home=None,
            bootstrap=None,
            metadata_sha256=None,
            limitations=(
                f"Configured CPython target is unavailable: {reason}",
                "Controlled Runtime Lock import and analysis remain available.",
            ),
        )


def _probe_cpython_target(interpreter: CpythonFileIdentity) -> CpythonRuntimeProbe:
    """Run a fixed isolated stdlib identity query through the hashed executable FD."""

    descriptor = -1
    try:
        descriptor = os.open(
            interpreter.path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            before.st_dev != interpreter.device
            or before.st_ino != interpreter.inode
            or before.st_uid != interpreter.owner_uid
            or stat.S_IMODE(before.st_mode) != interpreter.mode
            or before.st_nlink != interpreter.links
            or before.st_size != interpreter.size
        ):
            raise _error("Configured CPython executable changed before its version probe")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != interpreter.sha256:
            raise _error("Configured CPython executable changed before its version probe")
        os.lseek(descriptor, 0, os.SEEK_SET)
        result = subprocess.run(  # noqa: S603 - executable is the hashed, open FD
            [str(interpreter.path), "-I", "-S", "-c", _CPYTHON_TARGET_PROBE],
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=3,
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise _error("Configured CPython executable changed during its version probe")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _error("Configured CPython interpreter identity probe failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if result.returncode != 0 or len(result.stdout) > 4096 or len(result.stderr) > 4096:
        raise _error("Configured CPython interpreter identity probe failed")
    try:
        raw_payload: object = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("Configured CPython interpreter returned invalid identity data") from exc
    if not isinstance(raw_payload, dict):
        raise _error("Configured CPython interpreter returned invalid identity fields")
    payload = cast(dict[str, object], raw_payload)
    if set(payload) != set(_CPYTHON_TARGET_PROBE_KEYS):
        raise _error("Configured CPython interpreter returned invalid identity fields")
    if payload["implementation"] != "cpython" or payload["executable"] != str(interpreter.path):
        raise _error("Configured CPython executable identity is inconsistent")
    raw_version = payload["version"]
    if not isinstance(raw_version, list):
        raise _error("Configured CPython version is outside the reviewed 3.12/3.13 matrix")
    version = cast(list[object], raw_version)
    if len(version) != 3:
        raise _error("Configured CPython version is outside the reviewed 3.12/3.13 matrix")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in version):
        raise _error("Configured CPython version is outside the reviewed 3.12/3.13 matrix")
    major, minor, micro = cast(tuple[int, int, int], tuple(version))
    if major != 3 or minor not in (12, 13) or not 0 <= micro <= 999:
        raise _error("Configured CPython version is outside the reviewed 3.12/3.13 matrix")
    free_threaded = payload["free_threaded"]
    if not isinstance(free_threaded, bool) or (free_threaded and minor != 13):
        raise _error("Configured CPython free-threaded identity is invalid")
    runtime_home = payload["runtime_home"]
    if (
        not isinstance(runtime_home, str)
        or not runtime_home.startswith("/")
        or "\x00" in runtime_home
        or len(runtime_home.encode("utf-8")) > 4096
    ):
        raise _error("Configured CPython Runtime Home is invalid")
    cache_tag = _bounded_probe_abi_text(payload["cache_tag"], 80)
    soabi = _bounded_probe_abi_text(payload["soabi"], 160)
    abiflags = _bounded_probe_abi_text(payload["abiflags"], 16)
    return CpythonRuntimeProbe(
        interpreter=interpreter,
        runtime_home=Path(runtime_home),
        runtime_version=f"{major}.{minor}.{micro}",
        free_threaded=free_threaded,
        cache_tag=cache_tag,
        soabi=soabi,
        abiflags=abiflags,
    )


def _bounded_probe_abi_text(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value.isprintable() or len(value) > maximum:
        raise _error("Configured CPython ABI identity is invalid")
    return value


def discover_cpython_adapter_bridge(
    policy: RuntimeLockProjectPolicy,
    *,
    interpreter_path: Path | None = None,
    bootstrap_path: Path = DEFAULT_CPYTHON_BOOTSTRAP_PATH,
    trusted_owner_uids: tuple[int, ...] = (0,),
    created_at: str | None = None,
) -> CpythonAdapterBridge:
    installation = (
        inspect_configured_cpython_installation(
            interpreter_path,
            bootstrap_path=bootstrap_path,
            trusted_owner_uids=trusted_owner_uids,
        )
        if interpreter_path is not None
        else inspect_cpython_installation(
            bootstrap_path=bootstrap_path,
            trusted_owner_uids=trusted_owner_uids,
        )
    )
    return build_cpython_adapter_bridge(
        policy,
        installation,
        created_at=created_at,
        supervisor_available=discover_runtime_supervisor_policy().policy is not None,
    )


def _inspect_file(
    path: Path,
    *,
    executable: bool,
    maximum_size: int,
    trusted_owner_uids: tuple[int, ...],
) -> CpythonFileIdentity:
    if not path.is_absolute() or path.is_symlink():
        raise _error("CPython runtime files must be absolute non-symlink paths")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _error("CPython runtime file cannot be resolved") from exc
    if resolved != path:
        raise _error("CPython runtime file resolution changed its identity")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        allowed_modes = {0o555, 0o755} if executable else {0o444, 0o644}
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in trusted_owner_uids
            or before.st_nlink < 1
            or mode not in allowed_modes
            or before.st_mode & 0o6000
            or not 1 <= before.st_size <= maximum_size
        ):
            raise _error("CPython runtime file owner, mode, links, or size is unsafe")
        _reject_file_capabilities(descriptor, "CPython runtime file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 64 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise _error("CPython runtime file changed while hashing")
        return CpythonFileIdentity(
            path=path,
            sha256=digest.hexdigest(),
            device=before.st_dev,
            inode=before.st_ino,
            owner_uid=before.st_uid,
            mode=mode,
            links=before.st_nlink,
            size=before.st_size,
        )
    finally:
        os.close(descriptor)


def _inspect_runtime_home(
    path: Path,
    *,
    trusted_owner_uids: tuple[int, ...],
) -> CpythonDirectoryIdentity:
    """Bind the CPython standard-library root without exposing it publicly.

    Descriptor-bound execution hides the interpreter's original pathname.
    CPython distributions whose compiled prefix is relocated (including uv's
    portable builds) therefore need an authenticated runtime home.  The
    supervisor receives only this already-open directory descriptor and
    constructs a fixed ``PYTHONHOME=/proc/self/fd/<n>`` value itself.
    """

    if not path.is_absolute():
        raise _error("CPython runtime home must be an absolute directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _error("CPython runtime home cannot be resolved") from exc
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(resolved, flags)
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in trusted_owner_uids
            or mode not in {0o555, 0o755}
        ):
            raise _error("CPython runtime home owner or mode is unsafe")
        try:
            after = resolved.stat(follow_symlinks=False)
        except OSError as exc:
            raise _error("CPython runtime home cannot be revalidated") from exc
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_uid != metadata.st_uid
            or stat.S_IMODE(after.st_mode) != mode
        ):
            raise _error("CPython runtime home changed while it was inspected")
        return CpythonDirectoryIdentity(
            path=resolved,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            mode=mode,
        )
    finally:
        os.close(descriptor)


def _reject_file_capabilities(descriptor: int, label: str) -> None:
    try:
        os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise _error(f"{label} capabilities cannot be checked safely") from exc
    raise _error(f"{label} with file capabilities is unsupported")


def _error(message: str) -> PerfLensError:
    return PerfLensError(ErrorCode.PATH_SAFETY_VIOLATION, "cpython_threading_capability", message)
