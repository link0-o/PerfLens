"""Read-only, identity-pinned Java Flight Recorder capability discovery."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from perflens.runtime_locks.java_jfr_profiles import (
    DEFAULT_JAVA_JFR_PROFILE_ROOT,
    JFR_EVENT_SURFACE,
    JavaJfrProfileIdentity,
    load_java_jfr_profiles,
)

JavaJfrAvailability = Literal["available", "partial", "unavailable"]
JavaJfrRunner = Callable[[Sequence[str], float, int], subprocess.CompletedProcess[str]]
_SUPPORTED_JDK_MAJORS = frozenset({17, 21, 25})
_MAX_TOOL_BYTES = 256 << 20
_MAX_RELEASE_BYTES = 1 << 20
_MAX_MODULES_BYTES = 512 << 20
_MAX_NATIVE_LIBRARY_BYTES = 256 << 20
_MAX_NATIVE_LIBRARY_TOTAL_BYTES = 512 << 20
_MAX_NATIVE_LIBRARY_FILES = 256
_MAX_NATIVE_LIBRARY_DIRECTORIES = 128
_MAX_NATIVE_LIBRARY_ENTRIES = 4096
_MAX_NATIVE_LIBRARY_DEPTH = 4
_MAX_NATIVE_RELATIVE_PATH_BYTES = 1024
_MAX_NATIVE_LINK_TARGET_BYTES = 4096
_MAX_OUTPUT_BYTES = 1 << 20
_VERSION = re.compile(r'^(?:openjdk|java) version "(?P<version>[0-9]+(?:\.[0-9]+){1,3})')
_BUILD = re.compile(
    r"Runtime Environment(?: [^\r\n()]{1,128})? "
    r"\(build (?P<build>[^\r\n()]{1,128})\)"
)
_JFR_VERSION = re.compile(r"^(?P<version>[0-9]+(?:\.[0-9]+){1,3})")
_NAME = re.compile(r'^@Name\("(?P<name>jdk\.[A-Za-z0-9]+)"\)$')
_CLASS = re.compile(r"^class [A-Za-z0-9]+ extends jdk\.jfr\.Event \{$")
_FIELD = re.compile(r"^(?P<type>[A-Za-z][A-Za-z0-9.]*) (?P<name>[A-Za-z][A-Za-z0-9]*);$")
_EXPECTED_FIELDS = {
    "jdk.DataLoss": (("long", "startTime"), ("long", "amount"), ("long", "total")),
    "jdk.JVMInformation": (
        ("long", "startTime"),
        ("String", "jvmName"),
        ("String", "jvmVersion"),
        ("String", "jvmArguments"),
        ("String", "jvmFlags"),
        ("String", "javaArguments"),
        ("long", "jvmStartTime"),
        ("long", "pid"),
    ),
    "jdk.JavaMonitorEnter": (
        ("long", "startTime"),
        ("long", "duration"),
        ("Thread", "eventThread"),
        ("StackTrace", "stackTrace"),
        ("Class", "monitorClass"),
        ("Thread", "previousOwner"),
        ("long", "address"),
    ),
    "jdk.JavaMonitorWait": (
        ("long", "startTime"),
        ("long", "duration"),
        ("Thread", "eventThread"),
        ("StackTrace", "stackTrace"),
        ("Class", "monitorClass"),
        ("Thread", "notifier"),
        ("long", "timeout"),
        ("boolean", "timedOut"),
        ("long", "address"),
    ),
    "jdk.ThreadPark": (
        ("long", "startTime"),
        ("long", "duration"),
        ("Thread", "eventThread"),
        ("StackTrace", "stackTrace"),
        ("Class", "parkedClass"),
        ("long", "timeout"),
        ("long", "until"),
        ("long", "address"),
    ),
}


@dataclass(frozen=True, slots=True)
class JavaJfrToolIdentity:
    path: Path
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class JavaJfrDirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner_uid: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class JavaJfrPayloadFileIdentity:
    path: Path
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class JavaJfrNativeLibraryIdentity:
    """Private identity for one native library reachable from the JDK ``lib`` tree."""

    relative_path: str
    named_path: Path
    resolved_path: Path
    source_kind: Literal["regular", "symlink"]
    link_target_sha256: str | None
    link_device: int | None
    link_inode: int | None
    link_owner_uid: int | None
    link_mode: int | None
    link_links: int | None
    link_size: int | None
    link_modified_ns: int | None
    link_changed_ns: int | None
    sha256: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class JavaJfrRuntimePayloadIdentity:
    """Private JDK runtime payload identity used by the startup launcher."""

    jdk_root: JavaJfrDirectoryIdentity
    bin_directory: JavaJfrDirectoryIdentity
    lib_directory: JavaJfrDirectoryIdentity
    release_file: JavaJfrPayloadFileIdentity
    modules_file: JavaJfrPayloadFileIdentity
    native_libraries: tuple[JavaJfrNativeLibraryIdentity, ...]
    native_library_bytes: int
    native_library_manifest_sha256: str
    identity_sha256: str


@dataclass(frozen=True, slots=True)
class JavaJfrEventSurface:
    events: tuple[str, ...]
    fields: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]
    raw_metadata_sha256: str
    canonical_metadata_sha256: str
    data_loss_disclosed: bool


@dataclass(frozen=True, slots=True)
class JavaJfrCapability:
    availability: JavaJfrAvailability
    jdk_root: Path | None
    jdk_major: int | None
    java_version: str | None
    java_build: str | None
    java_tool: JavaJfrToolIdentity | None
    jfr_tool: JavaJfrToolIdentity | None
    profiles: tuple[JavaJfrProfileIdentity, ...]
    event_surface: JavaJfrEventSurface | None
    measurement_semantics: tuple[Literal["thresholded"], ...]
    active_launch_supported: bool
    live_attach_supported: bool
    limitations: tuple[str, ...]
    runtime_payload: JavaJfrRuntimePayloadIdentity | None = None


def inspect_java_jfr_installation(
    jdk_root: Path | None,
    *,
    profile_root: Path = DEFAULT_JAVA_JFR_PROFILE_ROOT,
    trusted_owner_uids: tuple[int, ...] = (0,),
    runner: JavaJfrRunner | None = None,
) -> JavaJfrCapability:
    """Inspect one administrator-selected JDK without launching or attaching a target JVM."""

    if jdk_root is None:
        return _unavailable("No trusted packaged JDK root is configured; import remains available.")
    root_fd = -1
    bin_fd = -1
    lib_fd = -1
    release_fd = -1
    modules_fd = -1
    java_fd = -1
    jfr_fd = -1
    native_library_fds: tuple[tuple[JavaJfrNativeLibraryIdentity, int], ...] = ()
    try:
        if not jdk_root.is_absolute():
            raise ValueError("JDK root must be absolute and non-symlinked")
        root_fd, root_identity = _open_safe_directory(
            jdk_root, trusted_owner_uids, label="JDK root"
        )
        bin_path = jdk_root / "bin"
        bin_fd, bin_identity = _open_safe_directory(
            bin_path,
            trusted_owner_uids,
            label="JDK bin directory",
            parent_fd=root_fd,
            relative_name="bin",
        )
        lib_path = jdk_root / "lib"
        lib_fd, lib_identity = _open_safe_directory(
            lib_path,
            trusted_owner_uids,
            label="JDK lib directory",
            parent_fd=root_fd,
            relative_name="lib",
        )
        release, release_fd = _open_safe_payload_file(
            root_fd,
            "release",
            jdk_root / "release",
            trusted_owner_uids,
            max_bytes=_MAX_RELEASE_BYTES,
        )
        modules, modules_fd = _open_safe_payload_file(
            lib_fd,
            "modules",
            jdk_root / "lib/modules",
            trusted_owner_uids,
            max_bytes=_MAX_MODULES_BYTES,
        )
        native_library_fds = _open_native_library_manifest(
            lib_fd,
            lib_path,
            trusted_owner_uids,
        )
        native_libraries = tuple(identity for identity, _fd in native_library_fds)
        native_library_bytes = sum(item.size for item in native_libraries)
        native_library_manifest_sha256 = _derive_native_library_manifest_identity(native_libraries)
        java, java_fd = _open_safe_tool(bin_fd, "java", jdk_root / "bin/java", trusted_owner_uids)
        jfr, jfr_fd = _open_safe_tool(bin_fd, "jfr", jdk_root / "bin/jfr", trusted_owner_uids)
        profiles = tuple(
            profile
            for profile in load_java_jfr_profiles(
                profile_root, trusted_owner_uids=trusted_owner_uids
            )
            if profile.jdk_major in _SUPPORTED_JDK_MAJORS
        )
        identities = (
            (jdk_root, root_fd, root_identity, "JDK root"),
            (bin_path, bin_fd, bin_identity, "JDK bin directory"),
            (lib_path, lib_fd, lib_identity, "JDK lib directory"),
        )
        tools = ((java, java_fd), (jfr, jfr_fd))
        payload_files = ((release, release_fd), (modules, modules_fd))
        runtime_payload = JavaJfrRuntimePayloadIdentity(
            jdk_root=root_identity,
            bin_directory=bin_identity,
            lib_directory=lib_identity,
            release_file=release,
            modules_file=modules,
            native_libraries=native_libraries,
            native_library_bytes=native_library_bytes,
            native_library_manifest_sha256=native_library_manifest_sha256,
            identity_sha256=_derive_runtime_payload_identity(
                (root_identity, bin_identity, lib_identity),
                (release, modules),
                native_libraries,
            ),
        )

        def invoke_tool(identity: JavaJfrToolIdentity, fd: int, args: tuple[str, ...]) -> str:
            _revalidate_installation(
                identities,
                tools,
                payload_files,
                native_library_fds,
            )
            if runner is None:
                output = _invoke_fd(identity, fd, args)
            else:
                output = _invoke(runner, (str(identity.path), *args))
            _revalidate_installation(
                identities,
                tools,
                payload_files,
                native_library_fds,
            )
            return output

        java_output = invoke_tool(java, java_fd, ("-version",))
        jfr_output = invoke_tool(jfr, jfr_fd, ("version",))
        java_version, java_build = _parse_java_version(java_output)
        jfr_version = _parse_jfr_version(jfr_output)
        major = int(java_version.split(".", 1)[0])
        if major not in _SUPPORTED_JDK_MAJORS:
            raise ValueError("JDK major is outside the supported 17/21/25 matrix")
        jfr_format_version_only = False
        if jfr_version != java_version:
            # JDK 17 may report the JFR format version, not the JDK patch.
            # Its already-open release file must corroborate java's build.
            if major != 17 or jfr_version != "1.0":
                raise ValueError("java and jfr do not identify the same JDK build")
            release_version, release_build = _parse_release_jdk_identity(release_fd)
            if (release_version, release_build) != (java_version, java_build):
                raise ValueError("JDK release identity does not match the java runtime build")
            jfr_format_version_only = True
        selected_profiles = tuple(p for p in profiles if p.jdk_major == major)
        if {p.profile_id for p in selected_profiles} != {"balanced", "deep"}:
            raise ValueError("Both fixed JFR profiles are required for this JDK")
        metadata = invoke_tool(
            jfr,
            jfr_fd,
            ("metadata", "--events", ",".join(JFR_EVENT_SURFACE)),
        )
        surface = parse_java_jfr_metadata(metadata)
        _revalidate_installation(
            identities,
            tools,
            payload_files,
            native_library_fds,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return _unavailable(f"Trusted JDK/JFR capability check failed: {exc}", jdk_root=jdk_root)
    finally:
        for _identity, fd in native_library_fds:
            if fd >= 0:
                os.close(fd)
        for fd in (
            modules_fd,
            release_fd,
            jfr_fd,
            java_fd,
            lib_fd,
            bin_fd,
            root_fd,
        ):
            if fd >= 0:
                os.close(fd)
    return JavaJfrCapability(
        availability="available",
        jdk_root=jdk_root,
        jdk_major=major,
        java_version=java_version,
        java_build=java_build,
        java_tool=java,
        jfr_tool=jfr,
        profiles=selected_profiles,
        event_surface=surface,
        measurement_semantics=("thresholded",),
        active_launch_supported=True,
        live_attach_supported=False,
        limitations=(
            "JFR evidence is thresholded: an unrecorded event does not prove no waiting occurred.",
            "jdk.DataLoss is enabled and must be retained; data loss prevents "
            "complete-event claims.",
            "Only startup-time JFR is supported; live JVM attach is unavailable.",
            "Monitor addresses are sensitive and must be converted to Artifact-local opaque IDs.",
            "JFR events do not provide acquire/release pairs, so exact owner or hold-time "
            "claims are forbidden.",
            *(
                (
                    "This JDK 17 jfr CLI reports format version 1.0, not an independent "
                    "JDK patch version; its identity is bound to the trusted JDK root "
                    "and release file.",
                )
                if jfr_format_version_only
                else ()
            ),
        ),
        runtime_payload=runtime_payload,
    )


def discover_java_jfr_installation(
    *,
    profile_root: Path = DEFAULT_JAVA_JFR_PROFILE_ROOT,
    trusted_owner_uids: tuple[int, ...] = (0,),
    runner: JavaJfrRunner | None = None,
) -> JavaJfrCapability:
    """Discover the current PATH JDK, then apply the same strict identity checks.

    PATH is used only as a location hint.  The resolved JDK root and both tools
    still have to be trusted-owner, non-writable, non-capability files before
    any executable is invoked.
    """

    java_hint = shutil.which("java")
    if java_hint is None:
        return _unavailable("No java executable is available on PATH; import remains available.")
    try:
        java_path = Path(java_hint).resolve(strict=True)
    except OSError:
        return _unavailable("The PATH java executable cannot be resolved safely.")
    if java_path.name != "java" or java_path.parent.name != "bin":
        return _unavailable("The PATH java executable does not identify one fixed JDK root.")
    return inspect_java_jfr_installation(
        java_path.parent.parent,
        profile_root=profile_root,
        trusted_owner_uids=trusted_owner_uids,
        runner=runner,
    )


def parse_java_jfr_metadata(raw: str) -> JavaJfrEventSurface:
    """Strictly parse the bounded metadata projection used by the Adapter."""

    encoded = raw.encode("utf-8")
    if not encoded or len(encoded) > _MAX_OUTPUT_BYTES:
        raise ValueError("JFR metadata output is empty or exceeds its bound")
    lines = [line.strip() for line in raw.splitlines()]
    parsed: dict[str, list[tuple[str, str]]] = {}
    pending: str | None = None
    current: str | None = None
    for line in lines:
        match = _NAME.fullmatch(line)
        if match:
            pending = match.group("name")
            continue
        if _CLASS.fullmatch(line):
            if pending not in JFR_EVENT_SURFACE or pending in parsed:
                raise ValueError("JFR metadata contains an unexpected or duplicate event")
            current = pending
            parsed[current] = []
            pending = None
            continue
        if line == "}" and current is not None:
            current = None
            continue
        field = _FIELD.fullmatch(line)
        if field and current is not None:
            parsed[current].append((field.group("type"), field.group("name")))
    if tuple(sorted(parsed)) != JFR_EVENT_SURFACE:
        raise ValueError("JFR metadata is missing a required event")
    for event, expected in _EXPECTED_FIELDS.items():
        if tuple(parsed[event]) != expected:
            raise ValueError(f"JFR metadata field surface drifted for {event}")
    fields = tuple((event, tuple(parsed[event])) for event in JFR_EVENT_SURFACE)
    canonical = json.dumps(fields, ensure_ascii=True, separators=(",", ":"))
    return JavaJfrEventSurface(
        events=JFR_EVENT_SURFACE,
        fields=fields,
        raw_metadata_sha256=hashlib.sha256(encoded).hexdigest(),
        canonical_metadata_sha256=hashlib.sha256(canonical.encode()).hexdigest(),
        data_loss_disclosed=True,
    )


def _open_safe_directory(
    path: Path,
    trusted: tuple[int, ...],
    *,
    label: str,
    parent_fd: int | None = None,
    relative_name: str | None = None,
) -> tuple[int, JavaJfrDirectoryIdentity]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    target: str | os.PathLike[str]
    if parent_fd is None:
        target = path
    else:
        if relative_name is None or "/" in relative_name or relative_name in {"", ".", ".."}:
            raise ValueError(f"{label} relative name is unsafe")
        target = relative_name
    fd = os.open(target, flags, dir_fd=parent_fd)
    try:
        value = os.fstat(fd)
        mode = stat.S_IMODE(value.st_mode)
        if (
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid not in trusted
            or mode not in {0o555, 0o755}
        ):
            raise ValueError(f"{label} identity is unsafe")
        identity = JavaJfrDirectoryIdentity(
            path=path,
            device=value.st_dev,
            inode=value.st_ino,
            owner_uid=value.st_uid,
            mode=mode,
            links=value.st_nlink,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
        )
    except BaseException:
        os.close(fd)
        raise
    return fd, identity


def _open_safe_payload_file(
    parent_fd: int,
    name: Literal["release", "modules"],
    display_path: Path,
    trusted: tuple[int, ...],
    *,
    max_bytes: int,
) -> tuple[JavaJfrPayloadFileIdentity, int]:
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in trusted
            or mode not in {0o444, 0o644}
            or not 0 < before.st_size <= max_bytes
        ):
            raise ValueError("JDK runtime payload identity is unsafe")
        try:
            capability = os.getxattr(fd, "security.capability")
        except OSError as exc:
            if exc.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise
            capability = b""
        if capability:
            raise ValueError("JDK runtime payload files with capabilities are forbidden")
        with os.fdopen(os.dup(fd), "rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after):
            raise ValueError("JDK runtime payload changed while it was hashed")
        identity = JavaJfrPayloadFileIdentity(
            path=display_path,
            sha256=digest,
            device=before.st_dev,
            inode=before.st_ino,
            owner_uid=before.st_uid,
            mode=mode,
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
        )
    except BaseException:
        os.close(fd)
        raise
    return identity, fd


def _open_native_library_manifest(
    lib_fd: int,
    lib_path: Path,
    trusted: tuple[int, ...],
) -> tuple[tuple[JavaJfrNativeLibraryIdentity, int], ...]:
    """Hash a bounded, deterministic manifest of JDK native libraries.

    Directory symlinks are never followed.  A library symlink is allowed only
    when both the link and its resolved regular target have trusted ownership;
    the link text and target identity are then bound independently.  Absolute
    paths remain private and are not included in the manifest digest.
    """

    opened: list[tuple[JavaJfrNativeLibraryIdentity, int]] = []
    entry_count = 0
    directory_count = 0
    total_bytes = 0

    def visit(directory_fd: int, parts: tuple[str, ...], depth: int) -> None:
        nonlocal entry_count, directory_count, total_bytes
        if depth > _MAX_NATIVE_LIBRARY_DEPTH:
            raise ValueError("JDK native library tree exceeds its depth bound")
        directory_count += 1
        if directory_count > _MAX_NATIVE_LIBRARY_DIRECTORIES:
            raise ValueError("JDK native library tree exceeds its directory bound")
        with os.scandir(os.dup(directory_fd)) as entries:
            ordered = sorted(entries, key=lambda item: os.fsencode(item.name))
        for entry in ordered:
            entry_count += 1
            if entry_count > _MAX_NATIVE_LIBRARY_ENTRIES:
                raise ValueError("JDK native library tree exceeds its entry bound")
            name = entry.name
            if not name or name in {".", ".."} or "/" in name or b"\x00" in os.fsencode(name):
                raise ValueError("JDK native library path is unsafe")
            relative_parts = (*parts, name)
            relative_path = "/".join(relative_parts)
            try:
                encoded_relative = relative_path.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ValueError("JDK native library path is not valid UTF-8") from exc
            if len(encoded_relative) > _MAX_NATIVE_RELATIVE_PATH_BYTES:
                raise ValueError("JDK native library path exceeds its bound")
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    current = os.fstat(child_fd)
                    mode = stat.S_IMODE(current.st_mode)
                    if (
                        _stat_identity(metadata) != _stat_identity(current)
                        or current.st_uid not in trusted
                        or mode not in {0o555, 0o755}
                    ):
                        raise ValueError("JDK native library directory identity is unsafe")
                    visit(child_fd, relative_parts, depth + 1)
                finally:
                    os.close(child_fd)
                continue
            if not _is_native_library_name(name):
                continue
            named_path = lib_path.joinpath(*relative_parts)
            if stat.S_ISREG(metadata.st_mode):
                identity, fd = _open_safe_native_library(
                    directory_fd,
                    name,
                    relative_path,
                    named_path,
                    trusted,
                )
            elif stat.S_ISLNK(metadata.st_mode):
                identity, fd = _open_safe_native_library_symlink(
                    directory_fd,
                    name,
                    relative_path,
                    named_path,
                    metadata,
                    trusted,
                )
            else:
                raise ValueError("JDK native library is not a regular file or safe symlink")
            if len(opened) >= _MAX_NATIVE_LIBRARY_FILES:
                os.close(fd)
                raise ValueError("JDK native library manifest exceeds its file-count bound")
            total_bytes += identity.size
            if total_bytes > _MAX_NATIVE_LIBRARY_TOTAL_BYTES:
                os.close(fd)
                raise ValueError("JDK native library manifest exceeds its byte bound")
            opened.append((identity, fd))

    try:
        visit(lib_fd, (), 0)
        relative_paths = tuple(identity.relative_path for identity, _fd in opened)
        if relative_paths != tuple(sorted(relative_paths, key=os.fsencode)):
            raise ValueError("JDK native library manifest is not deterministic")
        required = {"libjli.so", "server/libjvm.so"}
        if not required.issubset(relative_paths):
            raise ValueError("JDK native library manifest is missing a required runtime library")
        return tuple(opened)
    except BaseException:
        for _identity, fd in opened:
            os.close(fd)
        raise


def _is_native_library_name(name: str) -> bool:
    return name.endswith(".so") or ".so." in name


def _open_safe_native_library(
    parent_fd: int,
    name: str,
    relative_path: str,
    named_path: Path,
    trusted: tuple[int, ...],
) -> tuple[JavaJfrNativeLibraryIdentity, int]:
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        identity = _native_library_identity(
            fd,
            relative_path=relative_path,
            named_path=named_path,
            resolved_path=named_path,
            source_kind="regular",
            link_target_sha256=None,
            link_metadata=None,
            trusted=trusted,
        )
    except BaseException:
        os.close(fd)
        raise
    return identity, fd


def _open_safe_native_library_symlink(
    parent_fd: int,
    name: str,
    relative_path: str,
    named_path: Path,
    link_metadata: os.stat_result,
    trusted: tuple[int, ...],
) -> tuple[JavaJfrNativeLibraryIdentity, int]:
    if link_metadata.st_uid not in trusted:
        raise ValueError("JDK native library symlink owner is unsafe")
    target = os.readlink(name, dir_fd=parent_fd)
    encoded_target = os.fsencode(target)
    if not encoded_target or len(encoded_target) > _MAX_NATIVE_LINK_TARGET_BYTES:
        raise ValueError("JDK native library symlink target exceeds its bound")
    try:
        resolved_path = named_path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("JDK native library symlink target cannot be resolved") from exc
    fd = os.open(resolved_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if (
            os.readlink(name, dir_fd=parent_fd) != target
            or named_path.resolve(strict=True) != resolved_path
            or _stat_identity(named_path.lstat()) != _stat_identity(link_metadata)
        ):
            raise ValueError("JDK native library symlink changed while it was inspected")
        identity = _native_library_identity(
            fd,
            relative_path=relative_path,
            named_path=named_path,
            resolved_path=resolved_path,
            source_kind="symlink",
            link_target_sha256=hashlib.sha256(encoded_target).hexdigest(),
            link_metadata=link_metadata,
            trusted=trusted,
        )
    except BaseException:
        os.close(fd)
        raise
    return identity, fd


def _native_library_identity(
    fd: int,
    *,
    relative_path: str,
    named_path: Path,
    resolved_path: Path,
    source_kind: Literal["regular", "symlink"],
    link_target_sha256: str | None,
    link_metadata: os.stat_result | None,
    trusted: tuple[int, ...],
) -> JavaJfrNativeLibraryIdentity:
    before = os.fstat(fd)
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink < 1
        or before.st_uid not in trusted
        or mode & 0o022
        or mode & 0o6000
        or not 0 < before.st_size <= _MAX_NATIVE_LIBRARY_BYTES
    ):
        raise ValueError("JDK native library identity is unsafe")
    try:
        capability = os.getxattr(fd, "security.capability")
    except OSError as exc:
        if exc.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise
        capability = b""
    if capability:
        raise ValueError("JDK native libraries with file capabilities are forbidden")
    with os.fdopen(os.dup(fd), "rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    after = os.fstat(fd)
    if _stat_identity(before) != _stat_identity(after):
        raise ValueError("JDK native library changed while it was hashed")
    return JavaJfrNativeLibraryIdentity(
        relative_path=relative_path,
        named_path=named_path,
        resolved_path=resolved_path,
        source_kind=source_kind,
        link_target_sha256=link_target_sha256,
        link_device=(link_metadata.st_dev if link_metadata is not None else None),
        link_inode=(link_metadata.st_ino if link_metadata is not None else None),
        link_owner_uid=(link_metadata.st_uid if link_metadata is not None else None),
        link_mode=(stat.S_IMODE(link_metadata.st_mode) if link_metadata is not None else None),
        link_links=(link_metadata.st_nlink if link_metadata is not None else None),
        link_size=(link_metadata.st_size if link_metadata is not None else None),
        link_modified_ns=(link_metadata.st_mtime_ns if link_metadata is not None else None),
        link_changed_ns=(link_metadata.st_ctime_ns if link_metadata is not None else None),
        sha256=digest,
        device=before.st_dev,
        inode=before.st_ino,
        owner_uid=before.st_uid,
        mode=mode,
        links=before.st_nlink,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        changed_ns=before.st_ctime_ns,
    )


def _open_safe_tool(
    bin_fd: int,
    name: Literal["java", "jfr"],
    display_path: Path,
    trusted: tuple[int, ...],
) -> tuple[JavaJfrToolIdentity, int]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=bin_fd)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in trusted
            or mode & 0o022
            or mode & 0o6000
            or not mode & 0o111
            or not 0 < before.st_size <= _MAX_TOOL_BYTES
        ):
            raise ValueError("JDK tool identity is unsafe")
        try:
            capability = os.getxattr(fd, "security.capability")
        except OSError as exc:
            if exc.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise
            capability = b""
        if capability:
            raise ValueError("JDK tools with file capabilities are forbidden")
        with os.fdopen(os.dup(fd), "rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after):
            raise ValueError("JDK tool changed while it was hashed")
        identity = JavaJfrToolIdentity(
            path=display_path,
            sha256=digest,
            device=before.st_dev,
            inode=before.st_ino,
            owner_uid=before.st_uid,
            mode=mode,
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
        )
    except BaseException:
        os.close(fd)
        raise
    return identity, fd


def _invoke(runner: JavaJfrRunner, argv: tuple[str, ...]) -> str:
    result = runner(argv, 10.0, _MAX_OUTPUT_BYTES)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise ValueError("JDK inspection command failed")
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("JDK inspection output exceeds its bound")
    return output.strip()


def _invoke_fd(identity: JavaJfrToolIdentity, fd: int, args: tuple[str, ...]) -> str:
    result = _run_bounded_fd(identity, fd, args, 10.0, _MAX_OUTPUT_BYTES)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise ValueError("JDK inspection command failed")
    if len(output.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ValueError("JDK inspection output exceeds its bound")
    return output.strip()


def _run_bounded_fd(
    identity: JavaJfrToolIdentity,
    fd: int,
    args: tuple[str, ...],
    timeout: float,
    max_bytes: int,
) -> subprocess.CompletedProcess[str]:
    # The executable is the already-opened, hashed descriptor.  argv[0] retains
    # the trusted JDK path so the standard launcher can locate its own runtime.
    executable = f"/proc/self/fd/{fd}"
    process = subprocess.Popen(  # noqa: S603
        [str(identity.path), *args],
        executable=executable,
        pass_fds=(fd,),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    assert process.stdout is not None
    stream_fd = process.stdout.fileno()
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(stream_fd, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired([str(identity.path), *args], timeout)
            ready = selector.select(remaining)
            if not ready:
                raise subprocess.TimeoutExpired([str(identity.path), *args], timeout)
            for key, _ in ready:
                chunk = os.read(key.fd, min(65536, max_bytes + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise ValueError("JDK inspection output exceeds its bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired([str(identity.path), *args], timeout)
        returncode = process.wait(timeout=remaining)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
    try:
        decoded = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("JDK inspection output is not valid UTF-8") from exc
    return subprocess.CompletedProcess([str(identity.path), *args], returncode, decoded, "")


def _parse_java_version(output: str) -> tuple[str, str]:
    first = output.splitlines()[0] if output.splitlines() else ""
    version = _VERSION.match(first)
    build = _BUILD.search(output)
    if version is None or build is None:
        raise ValueError("java version output is not recognized")
    java_version = version.group("version")
    java_build = build.group("build")
    if not java_build.startswith(f"{java_version}+"):
        raise ValueError("java version and runtime build do not match")
    return java_version, java_build


def _parse_release_jdk_identity(release_fd: int) -> tuple[str, str]:
    """Bind a JFR-format-only CLI to its trusted, already-open JDK release file."""

    raw = os.pread(release_fd, _MAX_RELEASE_BYTES + 1, 0)
    if len(raw) > _MAX_RELEASE_BYTES:
        raise ValueError("JDK release identity exceeds its bound")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("JDK release identity is not UTF-8") from exc
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if key not in {"JAVA_VERSION", "JAVA_RUNTIME_VERSION"}:
            continue
        if (
            separator != "="
            or key in values
            or len(value) < 3
            or value[0] != '"'
            or value[-1] != '"'
        ):
            raise ValueError("JDK release identity is malformed")
        values[key] = value[1:-1]
    if set(values) != {"JAVA_VERSION", "JAVA_RUNTIME_VERSION"}:
        raise ValueError("JDK release identity is incomplete")
    return values["JAVA_VERSION"], values["JAVA_RUNTIME_VERSION"]


def _parse_jfr_version(output: str) -> str:
    match = _JFR_VERSION.match(output)
    if match is None:
        raise ValueError("jfr version output is not recognized")
    return match.group("version")


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_stat_identity(expected: JavaJfrDirectoryIdentity) -> tuple[int, ...]:
    return (
        expected.device,
        expected.inode,
        expected.owner_uid,
        stat.S_IFDIR | expected.mode,
        expected.links,
        expected.size,
        expected.modified_ns,
        expected.changed_ns,
    )


def _payload_stat_identity(expected: JavaJfrPayloadFileIdentity) -> tuple[int, ...]:
    return (
        expected.device,
        expected.inode,
        expected.owner_uid,
        stat.S_IFREG | expected.mode,
        1,
        expected.size,
        expected.modified_ns,
        expected.changed_ns,
    )


def _revalidate_directory(
    path: Path, fd: int, expected: JavaJfrDirectoryIdentity, label: str
) -> None:
    identity = _directory_stat_identity(expected)
    if _stat_identity(os.fstat(fd)) != identity:
        raise ValueError(f"{label} descriptor changed during discovery")
    if _stat_identity(path.stat(follow_symlinks=False)) != identity:
        raise ValueError(f"{label} changed during discovery")


def _revalidate_tool(expected: JavaJfrToolIdentity, fd: int) -> None:
    identity = (
        expected.device,
        expected.inode,
        expected.owner_uid,
        stat.S_IFREG | expected.mode,
        1,
        expected.size,
        expected.modified_ns,
        expected.changed_ns,
    )
    if _stat_identity(os.fstat(fd)) != identity:
        raise ValueError("JDK tool descriptor changed during discovery")
    value = expected.path.stat(follow_symlinks=False)
    if _stat_identity(value) != identity:
        raise ValueError("JDK tool changed during discovery")


def _revalidate_payload_file(expected: JavaJfrPayloadFileIdentity, fd: int) -> None:
    identity = _payload_stat_identity(expected)
    if _stat_identity(os.fstat(fd)) != identity:
        raise ValueError("JDK runtime payload descriptor changed during discovery")
    if _stat_identity(expected.path.stat(follow_symlinks=False)) != identity:
        raise ValueError("JDK runtime payload changed during discovery")


def _derive_runtime_payload_identity(
    directories: tuple[JavaJfrDirectoryIdentity, ...],
    files: tuple[JavaJfrPayloadFileIdentity, ...],
    native_libraries: tuple[JavaJfrNativeLibraryIdentity, ...],
) -> str:
    material = ["perflens-java-jfr-runtime-payload-v2"]
    for directory in directories:
        material.extend(
            (
                directory.path.name,
                str(directory.device),
                str(directory.inode),
                str(directory.owner_uid),
                str(directory.mode),
            )
        )
    for payload in files:
        material.extend(
            (
                payload.path.name,
                payload.sha256,
                str(payload.size),
                str(payload.owner_uid),
                str(payload.mode),
            )
        )
    material.extend(
        (
            _derive_native_library_manifest_identity(native_libraries),
            str(len(native_libraries)),
            str(sum(item.size for item in native_libraries)),
        )
    )
    return hashlib.sha256("\0".join(material).encode("utf-8")).hexdigest()


def _derive_native_library_manifest_identity(
    native_libraries: tuple[JavaJfrNativeLibraryIdentity, ...],
) -> str:
    material = ["perflens-java-jfr-native-library-manifest-v1"]
    for library in native_libraries:
        material.extend(
            (
                library.relative_path,
                library.source_kind,
                library.link_target_sha256 or "",
                library.sha256,
                str(library.size),
                str(library.owner_uid),
                str(library.mode),
            )
        )
    return hashlib.sha256("\0".join(material).encode("utf-8")).hexdigest()


def _revalidate_installation(
    directories: tuple[tuple[Path, int, JavaJfrDirectoryIdentity, str], ...],
    tools: tuple[tuple[JavaJfrToolIdentity, int], ...],
    payload_files: tuple[tuple[JavaJfrPayloadFileIdentity, int], ...],
    native_libraries: tuple[tuple[JavaJfrNativeLibraryIdentity, int], ...],
) -> None:
    for path, fd, identity, label in directories:
        _revalidate_directory(path, fd, identity, label)
    for identity, fd in tools:
        _revalidate_tool(identity, fd)
    for identity, fd in payload_files:
        _revalidate_payload_file(identity, fd)
    for identity, fd in native_libraries:
        _revalidate_native_library(identity, fd)


def _revalidate_native_library(
    expected: JavaJfrNativeLibraryIdentity,
    fd: int,
) -> None:
    target_identity = (
        expected.device,
        expected.inode,
        expected.owner_uid,
        stat.S_IFREG | expected.mode,
        expected.links,
        expected.size,
        expected.modified_ns,
        expected.changed_ns,
    )
    if _stat_identity(os.fstat(fd)) != target_identity:
        raise ValueError("JDK native library descriptor changed during discovery")
    if _stat_identity(expected.resolved_path.stat(follow_symlinks=False)) != target_identity:
        raise ValueError("JDK native library target changed during discovery")
    if expected.source_kind == "regular":
        if expected.named_path != expected.resolved_path:
            raise ValueError("JDK native library regular-path identity is invalid")
        if _stat_identity(expected.named_path.stat(follow_symlinks=False)) != target_identity:
            raise ValueError("JDK native library changed during discovery")
        return
    if None in {
        expected.link_target_sha256,
        expected.link_device,
        expected.link_inode,
        expected.link_owner_uid,
        expected.link_mode,
        expected.link_links,
        expected.link_size,
        expected.link_modified_ns,
        expected.link_changed_ns,
    }:
        raise ValueError("JDK native library symlink identity is incomplete")
    assert expected.link_device is not None
    assert expected.link_inode is not None
    assert expected.link_owner_uid is not None
    assert expected.link_mode is not None
    assert expected.link_links is not None
    assert expected.link_size is not None
    assert expected.link_modified_ns is not None
    assert expected.link_changed_ns is not None
    link_value = expected.named_path.lstat()
    link_identity = (
        expected.link_device,
        expected.link_inode,
        expected.link_owner_uid,
        stat.S_IFLNK | expected.link_mode,
        expected.link_links,
        expected.link_size,
        expected.link_modified_ns,
        expected.link_changed_ns,
    )
    if _stat_identity(link_value) != link_identity:
        raise ValueError("JDK native library symlink changed during discovery")
    target = os.readlink(expected.named_path)
    if hashlib.sha256(os.fsencode(target)).hexdigest() != expected.link_target_sha256:
        raise ValueError("JDK native library symlink target changed during discovery")
    if expected.named_path.resolve(strict=True) != expected.resolved_path:
        raise ValueError("JDK native library symlink resolution changed during discovery")


def _unavailable(message: str, *, jdk_root: Path | None = None) -> JavaJfrCapability:
    return JavaJfrCapability(
        availability="unavailable",
        jdk_root=jdk_root,
        jdk_major=None,
        java_version=None,
        java_build=None,
        java_tool=None,
        jfr_tool=None,
        profiles=(),
        event_surface=None,
        measurement_semantics=(),
        active_launch_supported=False,
        live_attach_supported=False,
        limitations=(
            message,
            "Controlled JFR JSON import and deterministic analysis remain available.",
        ),
    )
