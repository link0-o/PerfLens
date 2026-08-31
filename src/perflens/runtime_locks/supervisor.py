"""Strict Python client for the unprivileged Runtime Lock supervisor.

The client is deliberately smaller than a general subprocess runner.  It
executes one package-pinned supervisor through an already-open descriptor,
passes only descriptors named by a typed request, and keeps a private
liveness pipe open until the supervisor has returned a complete receipt.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import time
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from pydantic import ConfigDict, Field, TypeAdapter, field_validator, model_validator

from perflens.contracts.artifacts import ContractModel
from perflens.domain.errors import ErrorCode, PerfLensError

RUNTIME_SUPERVISOR_PROTOCOL_VERSION = "1.0"
RUNTIME_SUPERVISOR_SCHEMA_VERSION = "1.0"
RUNTIME_SUPERVISOR_MAX_FRAME_BYTES = 64 << 10
DEFAULT_RUNTIME_SUPERVISOR_PATH = Path("/usr/lib/perflens/perflens-runtime-supervisor")

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_REQUEST_ID = re.compile(r"^[a-f0-9]{20}$")
_MAX_DESCRIPTOR = 1_048_575
_MAX_ARGUMENTS = 256
_MAX_ARGUMENT_BYTES = 64 << 10
_MAX_TIMEOUT_MILLISECONDS = 30_000
_SUPERVISOR_MAX_BYTES = 64 << 20


class _StrictSupervisorModel(ContractModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        strict=True,
    )


class RuntimeSupervisorFileIdentity(_StrictSupervisorModel):
    descriptor: int = Field(ge=3, le=_MAX_DESCRIPTOR)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    device: int = Field(ge=0)
    inode: int = Field(gt=0)
    owner_uid: int = Field(ge=0, le=(1 << 32) - 1)
    mode: int = Field(ge=0, le=0o7777)
    links: int = Field(ge=0)
    size: int = Field(gt=0)


class RuntimeSupervisorWritableFileIdentity(_StrictSupervisorModel):
    descriptor: int = Field(ge=3, le=_MAX_DESCRIPTOR)
    device: int = Field(ge=0)
    inode: int = Field(gt=0)
    owner_uid: int = Field(ge=0, le=(1 << 32) - 1)
    mode: Literal[0o600] = 0o600
    links: int = Field(ge=0)
    maximum_size: int = Field(gt=0, le=64 << 20)


class RuntimeSupervisorDirectoryIdentity(_StrictSupervisorModel):
    descriptor: int = Field(ge=3, le=_MAX_DESCRIPTOR)
    device: int = Field(ge=0)
    inode: int = Field(gt=0)
    owner_uid: int = Field(ge=0, le=(1 << 32) - 1)
    mode: int = Field(ge=0, le=0o7777)


class RuntimeSupervisorNativePthreadRequest(_StrictSupervisorModel):
    adapter: Literal["native_pthread"] = "native_pthread"
    probe: RuntimeSupervisorFileIdentity
    output: RuntimeSupervisorWritableFileIdentity
    semantics: Literal["exact", "thresholded"]
    threshold_ns: int | None = Field(default=None, ge=1, le=1_000_000_000)
    max_events: int = Field(ge=1, le=20_000)

    @model_validator(mode="after")
    def validate_semantics(self) -> RuntimeSupervisorNativePthreadRequest:
        if self.semantics == "exact" and self.threshold_ns is not None:
            raise ValueError("exact Native supervision cannot set a threshold")
        if self.semantics == "thresholded" and self.threshold_ns is None:
            raise ValueError("thresholded Native supervision requires a threshold")
        return self


class RuntimeSupervisorJavaJfrWorkloadRequest(_StrictSupervisorModel):
    adapter: Literal["java_jfr_workload"] = "java_jfr_workload"
    jar: RuntimeSupervisorFileIdentity
    profile: RuntimeSupervisorFileIdentity
    recording: RuntimeSupervisorWritableFileIdentity


class RuntimeSupervisorJavaJfrPrintRequest(_StrictSupervisorModel):
    adapter: Literal["java_jfr_print"] = "java_jfr_print"
    recording_directory: RuntimeSupervisorDirectoryIdentity
    recording_name: str = Field(pattern=r"^java-jfr-[a-f0-9]{20}\.jfr$")
    recording: RuntimeSupervisorFileIdentity
    output: RuntimeSupervisorWritableFileIdentity


class RuntimeSupervisorCpythonThreadingRequest(_StrictSupervisorModel):
    adapter: Literal["cpython_threading"] = "cpython_threading"
    bootstrap: RuntimeSupervisorFileIdentity
    script: RuntimeSupervisorFileIdentity
    script_label: str = Field(min_length=1, max_length=4096)
    output: RuntimeSupervisorWritableFileIdentity
    semantics: Literal["exact", "thresholded"]
    threshold_ns: int | None = Field(default=None, ge=1, le=1_000_000_000)
    max_events: int = Field(ge=1, le=20_000)

    @model_validator(mode="after")
    def validate_semantics(self) -> RuntimeSupervisorCpythonThreadingRequest:
        parts = self.script_label.split("/")
        if (
            self.script_label.startswith("/")
            or "\\" in self.script_label
            or any(not part or part in {".", ".."} for part in parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in self.script_label)
        ):
            raise ValueError("CPython script label must be one safe project-relative path")
        if self.semantics == "exact" and self.threshold_ns is not None:
            raise ValueError("exact CPython supervision cannot set a threshold")
        if self.semantics == "thresholded" and self.threshold_ns != 10_000:
            raise ValueError("thresholded CPython supervision requires the fixed 10 us threshold")
        return self


class RuntimeSupervisorGoPprofWorkloadRequest(_StrictSupervisorModel):
    adapter: Literal["go_pprof_workload"] = "go_pprof_workload"
    mutex_profile: RuntimeSupervisorWritableFileIdentity
    block_profile: RuntimeSupervisorWritableFileIdentity


class RuntimeSupervisorGoPprofRawRequest(_StrictSupervisorModel):
    adapter: Literal["go_pprof_raw"] = "go_pprof_raw"
    profile: RuntimeSupervisorFileIdentity
    output: RuntimeSupervisorWritableFileIdentity


RuntimeSupervisorAdapterRequest = Annotated[
    RuntimeSupervisorNativePthreadRequest
    | RuntimeSupervisorJavaJfrWorkloadRequest
    | RuntimeSupervisorJavaJfrPrintRequest
    | RuntimeSupervisorCpythonThreadingRequest
    | RuntimeSupervisorGoPprofWorkloadRequest
    | RuntimeSupervisorGoPprofRawRequest,
    Field(discriminator="adapter"),
]


class RuntimeSupervisorRequest(_StrictSupervisorModel):
    schema_version: Literal["1.0"] = RUNTIME_SUPERVISOR_SCHEMA_VERSION
    protocol_version: Literal["1.0"] = RUNTIME_SUPERVISOR_PROTOCOL_VERSION
    request_id: str = Field(pattern=r"^[a-f0-9]{20}$")
    expected_parent_pid: int = Field(gt=0, le=(1 << 31) - 1)
    expected_supervisor_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    executable: RuntimeSupervisorFileIdentity
    working_directory: RuntimeSupervisorDirectoryIdentity
    arguments: tuple[str, ...] = Field(max_length=_MAX_ARGUMENTS)
    timeout_milliseconds: int = Field(gt=0, le=_MAX_TIMEOUT_MILLISECONDS)
    request: RuntimeSupervisorAdapterRequest

    @field_validator("arguments", mode="before")
    @classmethod
    def normalize_protocol_arguments(cls, value: object) -> object:
        """Accept the JSON-array representation without weakening strict fields.

        The shared Rust protocol naturally represents argv as a JSON array,
        whereas the immutable Python contract stores it as a tuple.  Convert
        only an actual list at the protocol boundary; all element validation
        remains strict below.
        """

        if isinstance(value, list):
            items = cast(list[object], value)
            if all(isinstance(item, str) for item in items):
                return tuple(cast(list[str], items))
        return cast(object, value)

    @model_validator(mode="after")
    def validate_request(self) -> RuntimeSupervisorRequest:
        if self.expected_parent_pid != os.getpid():
            raise ValueError("Runtime supervisor request must bind the current parent PID")
        total = 0
        for argument in self.arguments:
            encoded = argument.encode("utf-8")
            if b"\x00" in encoded:
                raise ValueError("Runtime supervisor argument contains NUL")
            total += len(encoded)
        if total > _MAX_ARGUMENT_BYTES:
            raise ValueError("Runtime supervisor argument bytes exceed the fixed bound")
        descriptors = runtime_supervisor_request_descriptors(self)
        if len(descriptors) != len(set(descriptors)):
            raise ValueError("Runtime supervisor request descriptors must be unique")
        if (
            self.request.adapter == "native_pthread"
            and self.request.semantics == "exact"
            and self.timeout_milliseconds > 3_000
        ):
            raise ValueError("exact Native supervision exceeds three seconds")
        if (
            self.request.adapter == "cpython_threading"
            and self.request.semantics == "exact"
            and self.timeout_milliseconds > 3_000
        ):
            raise ValueError("exact CPython supervision exceeds three seconds")
        if self.request.adapter in {"java_jfr_print", "go_pprof_raw"} and self.arguments:
            raise ValueError("runtime profile conversion does not accept workload arguments")
        return self


RUNTIME_SUPERVISOR_REQUEST_ADAPTER: TypeAdapter[RuntimeSupervisorRequest] = TypeAdapter(
    RuntimeSupervisorRequest
)


class RuntimeSupervisorReceipt(_StrictSupervisorModel):
    schema_version: Literal["1.0"] = RUNTIME_SUPERVISOR_SCHEMA_VERSION
    protocol_version: Literal["1.0"] = RUNTIME_SUPERVISOR_PROTOCOL_VERSION
    request_id: str = Field(pattern=r"^[a-f0-9]{20}$")
    supervisor_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    supervisor_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    workload_pid: int = Field(gt=0, le=(1 << 31) - 1)
    workload_start_ticks: int = Field(gt=0)
    elapsed_monotonic_ns: int = Field(gt=0)
    accounted_active_seconds: int = Field(gt=0, le=32)
    exit_code: int | None = Field(default=None, ge=0, le=255)
    terminating_signal: int | None = Field(default=None, ge=1, le=64)
    termination_reason: Literal[
        "exited",
        "timeout",
        "parent_lost",
        "supervisor_signal",
        "setup_failed",
    ]
    term_sent: bool
    kill_sent: bool
    observed_group_descendants: int = Field(ge=0)
    residual_group_descendants: int = Field(ge=0)
    cleanup_complete: bool

    @model_validator(mode="after")
    def validate_receipt(self) -> RuntimeSupervisorReceipt:
        expected_accounting = (self.elapsed_monotonic_ns + 999_999_999) // 1_000_000_000
        if self.accounted_active_seconds != expected_accounting:
            raise ValueError("Runtime supervisor accounting differs from monotonic elapsed time")
        if self.cleanup_complete != (self.residual_group_descendants == 0):
            raise ValueError("Runtime supervisor cleanup status differs from residual descendants")
        if self.exit_code is not None and self.terminating_signal is not None:
            raise ValueError("Runtime supervisor receipt cannot report both exit and signal")
        return self


@dataclass(frozen=True, slots=True)
class RuntimeSupervisorPolicy:
    path: Path
    sha256: str
    owner_uid: int = 0
    mode: int = 0o755

    def __post_init__(self) -> None:
        if not self.path.is_absolute() or self.path.is_symlink():
            raise _supervisor_error("Runtime supervisor path must be absolute and non-symlinked")
        if _SHA256.fullmatch(self.sha256) is None:
            raise _supervisor_error("Runtime supervisor policy digest is invalid")
        if self.owner_uid < 0 or self.owner_uid > (1 << 32) - 1:
            raise _supervisor_error("Runtime supervisor policy owner is invalid")
        if self.mode not in {0o555, 0o755}:
            raise _supervisor_error("Runtime supervisor policy mode is unsupported")


@dataclass(frozen=True, slots=True)
class RuntimeSupervisorDiscovery:
    availability: Literal["available", "unavailable"]
    policy: RuntimeSupervisorPolicy | None
    limitations: tuple[str, ...]


class RuntimeSupervisorClient:
    """Execute one typed request through the fixed supervisor binary."""

    def __init__(self, policy: RuntimeSupervisorPolicy) -> None:
        self._policy = policy
        _inspect_supervisor(policy)

    @property
    def policy(self) -> RuntimeSupervisorPolicy:
        return self._policy

    def execute(self, request: RuntimeSupervisorRequest) -> RuntimeSupervisorReceipt:
        if request.expected_parent_pid != os.getpid():
            raise _supervisor_error("Runtime supervisor parent binding changed")
        if request.expected_supervisor_sha256 != self._policy.sha256:
            raise _supervisor_error("Runtime supervisor request differs from its pinned policy")
        payload = request.model_dump_json(exclude_none=False).encode("utf-8")
        if not payload or len(payload) > RUNTIME_SUPERVISOR_MAX_FRAME_BYTES:
            raise _supervisor_limit("Runtime supervisor request frame exceeds 64 KiB")

        supervisor_fd = request_read = request_write = -1
        receipt_read = receipt_write = liveness_read = liveness_write = -1
        process: subprocess.Popen[bytes] | None = None
        try:
            supervisor_fd = _open_supervisor(self._policy)
            request_read, request_write = os.pipe2(os.O_CLOEXEC)
            receipt_read, receipt_write = os.pipe2(os.O_CLOEXEC)
            liveness_read, liveness_write = os.pipe2(os.O_CLOEXEC)
            request_descriptors = runtime_supervisor_request_descriptors(request)
            pass_fds = tuple(
                sorted(
                    {
                        supervisor_fd,
                        request_read,
                        receipt_write,
                        liveness_read,
                        *request_descriptors,
                    }
                )
            )
            if len(pass_fds) != 4 + len(request_descriptors):
                raise _supervisor_error("Runtime supervisor descriptor allowlist overlaps")
            try:
                process = subprocess.Popen(  # noqa: S603 - pinned descriptor-bound supervisor
                    (  # noqa: S607 - argv0 is paired with pinned descriptor execution below
                        "perflens-runtime-supervisor",
                        "--request-fd",
                        str(request_read),
                        "--receipt-fd",
                        str(receipt_write),
                        "--liveness-fd",
                        str(liveness_read),
                    ),
                    executable=f"/proc/self/fd/{supervisor_fd}",
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    # The fixed supervisor emits only bounded, implementation-owned
                    # diagnostics.  Keep that stream private so protocol failures can
                    # be reported without exposing workload stderr (the supervisor
                    # redirects the workload's stderr to /dev/null independently).
                    stderr=subprocess.PIPE,
                    shell=False,
                    close_fds=True,
                    pass_fds=pass_fds,
                    start_new_session=True,
                    env={"LANG": "C", "LC_ALL": "C"},
                )
            except OSError as exc:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "runtime_supervisor",
                    "The fixed Runtime Lock supervisor could not be started",
                    recoverable=True,
                ) from exc
            for descriptor_name in ("request_read", "receipt_write", "liveness_read"):
                descriptor = locals()[descriptor_name]
                os.close(descriptor)
                if descriptor_name == "request_read":
                    request_read = -1
                elif descriptor_name == "receipt_write":
                    receipt_write = -1
                else:
                    liveness_read = -1
            _write_all(request_write, len(payload).to_bytes(4, "big") + payload)
            os.close(request_write)
            request_write = -1

            receipt_payload = _read_receipt_frame(
                receipt_read,
                process,
                timeout_seconds=request.timeout_milliseconds / 1_000 + 3.0,
            )
            exit_code = process.wait(timeout=1.0)
            try:
                receipt = RuntimeSupervisorReceipt.model_validate(
                    parse_runtime_supervisor_json_object(receipt_payload)
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
                raise _supervisor_error("Runtime supervisor returned a malformed receipt") from exc
            _assert_receipt(request, receipt, self._policy, exit_code)
            _inspect_supervisor(self._policy)
            return receipt
        finally:
            # Closing the liveness writer is the fail-closed signal if this
            # client exits through an exception while the supervisor is live.
            if liveness_write >= 0:
                with suppress(OSError):
                    os.close(liveness_write)
                liveness_write = -1
            for descriptor in (
                request_read,
                request_write,
                receipt_read,
                receipt_write,
                liveness_read,
                supervisor_fd,
            ):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            if process is not None and process.poll() is None:
                # The supervisor, not the MCP process, owns process-group
                # teardown.  Cancellation only closes liveness and waits for
                # its bounded cleanup; directly signalling it would recreate
                # the orphan race this boundary is designed to eliminate.
                with suppress(OSError, subprocess.TimeoutExpired):
                    process.wait(timeout=3.0)
            if process is not None and process.stderr is not None:
                with suppress(OSError):
                    process.stderr.close()


def discover_runtime_supervisor_policy(
    path: Path = DEFAULT_RUNTIME_SUPERVISOR_PATH,
    *,
    expected_owner_uid: int = 0,
) -> RuntimeSupervisorDiscovery:
    try:
        policy = _policy_from_path(path, expected_owner_uid)
        _inspect_supervisor(policy)
    except (OSError, PerfLensError) as exc:
        return RuntimeSupervisorDiscovery(
            availability="unavailable",
            policy=None,
            limitations=(
                "Active Runtime Lock launch requires the fixed root-owned main-DEB "
                f"supervisor: {exc}",
            ),
        )
    return RuntimeSupervisorDiscovery("available", policy, ())


def runtime_supervisor_file_identity(descriptor: int) -> RuntimeSupervisorFileIdentity:
    metadata = os.fstat(descriptor)
    return RuntimeSupervisorFileIdentity(
        descriptor=descriptor,
        sha256=_hash_fd(descriptor),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        links=metadata.st_nlink,
        size=metadata.st_size,
    )


def runtime_supervisor_writable_identity(
    descriptor: int,
    *,
    maximum_size: int,
) -> RuntimeSupervisorWritableFileIdentity:
    metadata = os.fstat(descriptor)
    descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    access_mode = descriptor_flags & os.O_ACCMODE
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != 0
        or access_mode not in {os.O_WRONLY, os.O_RDWR}
        or descriptor_flags & os.O_APPEND
    ):
        raise _supervisor_error(
            "Runtime supervisor writable file must be regular, empty, writable, non-append, "
            "and mode 0600"
        )
    return RuntimeSupervisorWritableFileIdentity(
        descriptor=descriptor,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        links=metadata.st_nlink,
        maximum_size=maximum_size,
    )


def runtime_supervisor_directory_identity(
    descriptor: int,
) -> RuntimeSupervisorDirectoryIdentity:
    metadata = os.fstat(descriptor)
    return RuntimeSupervisorDirectoryIdentity(
        descriptor=descriptor,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def runtime_supervisor_request_descriptors(request: RuntimeSupervisorRequest) -> tuple[int, ...]:
    descriptors = [request.executable.descriptor, request.working_directory.descriptor]
    adapter = request.request
    if adapter.adapter == "native_pthread":
        descriptors.extend((adapter.probe.descriptor, adapter.output.descriptor))
    elif adapter.adapter == "java_jfr_workload":
        descriptors.extend(
            (adapter.jar.descriptor, adapter.profile.descriptor, adapter.recording.descriptor)
        )
    elif adapter.adapter == "java_jfr_print":
        descriptors.extend(
            (
                adapter.recording_directory.descriptor,
                adapter.recording.descriptor,
                adapter.output.descriptor,
            )
        )
    elif adapter.adapter == "cpython_threading":
        descriptors.extend(
            (adapter.bootstrap.descriptor, adapter.script.descriptor, adapter.output.descriptor)
        )
    elif adapter.adapter == "go_pprof_workload":
        descriptors.extend((adapter.mutex_profile.descriptor, adapter.block_profile.descriptor))
    else:
        descriptors.extend((adapter.profile.descriptor, adapter.output.descriptor))
    return tuple(descriptors)


def runtime_supervisor_request_id() -> str:
    return os.urandom(10).hex()


def runtime_supervisor_request_schema() -> dict[str, Any]:
    """Return the strict wire schema shared by Python and Rust."""

    schema = RUNTIME_SUPERVISOR_REQUEST_ADAPTER.json_schema()
    schema.update(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://github.com/link0-o/PerfLens/schemas/runtime-supervisor-request.schema.json"
            ),
            "title": "PerfLens Runtime Supervisor Request",
            "required": [
                "schema_version",
                "protocol_version",
                "request_id",
                "expected_parent_pid",
                "expected_supervisor_sha256",
                "executable",
                "working_directory",
                "arguments",
                "timeout_milliseconds",
                "request",
            ],
        }
    )
    properties = cast(dict[str, Any], schema["properties"])
    cast(dict[str, Any], properties["arguments"])["items"] = {
        "type": "string",
        "maxLength": _MAX_ARGUMENT_BYTES,
    }
    definitions = cast(dict[str, dict[str, Any]], schema["$defs"])
    cast(dict[str, Any], definitions["RuntimeSupervisorFileIdentity"]["properties"])["size"][
        "maximum"
    ] = 512 << 20
    definitions["RuntimeSupervisorWritableFileIdentity"]["required"] = [
        "descriptor",
        "device",
        "inode",
        "owner_uid",
        "mode",
        "links",
        "maximum_size",
    ]
    for name in (
        "RuntimeSupervisorNativePthreadRequest",
        "RuntimeSupervisorJavaJfrWorkloadRequest",
        "RuntimeSupervisorJavaJfrPrintRequest",
        "RuntimeSupervisorCpythonThreadingRequest",
        "RuntimeSupervisorGoPprofWorkloadRequest",
        "RuntimeSupervisorGoPprofRawRequest",
    ):
        required = cast(list[str], definitions[name]["required"])
        definitions[name]["required"] = ["adapter", *required]
    native = definitions["RuntimeSupervisorNativePthreadRequest"]
    native["required"] = [*cast(list[str], native["required"]), "threshold_ns"]
    native["allOf"] = [
        {
            "if": {
                "properties": {"semantics": {"const": "exact"}},
                "required": ["semantics"],
            },
            "then": {"properties": {"threshold_ns": {"type": "null"}}},
            "else": {"properties": {"threshold_ns": {"type": "integer"}}},
        }
    ]
    cpython = definitions["RuntimeSupervisorCpythonThreadingRequest"]
    cpython["required"] = [*cast(list[str], cpython["required"]), "threshold_ns"]
    cpython["allOf"] = [
        {
            "if": {
                "properties": {"semantics": {"const": "exact"}},
                "required": ["semantics"],
            },
            "then": {"properties": {"threshold_ns": {"type": "null"}}},
            "else": {"properties": {"threshold_ns": {"const": 10_000}}},
        }
    ]
    schema["allOf"] = [
        {
            "if": {
                "properties": {
                    "request": {
                        "properties": {
                            "adapter": {"enum": ["go_pprof_raw", "java_jfr_print"]}
                        },
                        "required": ["adapter"],
                    }
                },
                "required": ["request"],
            },
            "then": {"properties": {"arguments": {"maxItems": 0}}},
        }
    ]
    return schema


def runtime_supervisor_receipt_schema() -> dict[str, Any]:
    """Return the strict wire receipt schema shared by Python and Rust."""

    schema = RuntimeSupervisorReceipt.model_json_schema()
    schema.update(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://github.com/link0-o/PerfLens/schemas/runtime-supervisor-receipt.schema.json"
            ),
            "title": "PerfLens Runtime Supervisor Receipt",
            "required": [
                "schema_version",
                "protocol_version",
                "request_id",
                "supervisor_version",
                "supervisor_sha256",
                "workload_pid",
                "workload_start_ticks",
                "elapsed_monotonic_ns",
                "accounted_active_seconds",
                "exit_code",
                "terminating_signal",
                "termination_reason",
                "term_sent",
                "kill_sent",
                "observed_group_descendants",
                "residual_group_descendants",
                "cleanup_complete",
            ],
        }
    )
    return schema


def parse_runtime_supervisor_json_object(payload: bytes) -> dict[str, object]:
    """Decode one strict protocol object and reject duplicate JSON fields."""

    decoded = payload.decode("utf-8", errors="strict")
    raw = cast(
        object,
        json.loads(decoded, object_pairs_hook=_supervisor_object_without_duplicate_keys),
    )
    if not isinstance(raw, dict):
        raise TypeError("Runtime supervisor protocol payload must be a JSON object")
    return cast(dict[str, object], raw)


def _supervisor_object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _policy_from_path(path: Path, owner_uid: int) -> RuntimeSupervisorPolicy:
    if not path.is_absolute() or path.is_symlink():
        raise _supervisor_error("Runtime supervisor path is not fixed and non-symlinked")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or mode not in {0o555, 0o755}
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= _SUPERVISOR_MAX_BYTES
            or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        ):
            raise _supervisor_error("Runtime supervisor package identity is unsafe")
        _reject_supervisor_file_capabilities(descriptor)
        digest = _hash_fd(descriptor)
        return RuntimeSupervisorPolicy(path, digest, owner_uid, mode)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _inspect_supervisor(policy: RuntimeSupervisorPolicy) -> None:
    descriptor = _open_supervisor(policy)
    os.close(descriptor)


def _open_supervisor(policy: RuntimeSupervisorPolicy) -> int:
    descriptor = -1
    try:
        descriptor = os.open(policy.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != policy.owner_uid
            or stat.S_IMODE(metadata.st_mode) != policy.mode
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= _SUPERVISOR_MAX_BYTES
            or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or _hash_fd(descriptor) != policy.sha256
        ):
            raise _supervisor_error("Runtime supervisor identity changed")
        _reject_supervisor_file_capabilities(descriptor)
        result = descriptor
        descriptor = -1
        return result
    except OSError as exc:
        raise _supervisor_error("Runtime supervisor cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _hash_fd(descriptor: int) -> str:
    metadata_before = os.fstat(descriptor)
    digest = hashlib.sha256()
    offset = 0
    while offset < metadata_before.st_size:
        chunk = os.pread(descriptor, min(1 << 20, metadata_before.st_size - offset), offset)
        if not chunk:
            raise _supervisor_error("Runtime supervisor input changed while hashing")
        digest.update(chunk)
        offset += len(chunk)
    metadata_after = os.fstat(descriptor)
    if (
        metadata_before.st_dev,
        metadata_before.st_ino,
        metadata_before.st_uid,
        metadata_before.st_mode,
        metadata_before.st_nlink,
        metadata_before.st_size,
        metadata_before.st_mtime_ns,
        metadata_before.st_ctime_ns,
    ) != (
        metadata_after.st_dev,
        metadata_after.st_ino,
        metadata_after.st_uid,
        metadata_after.st_mode,
        metadata_after.st_nlink,
        metadata_after.st_size,
        metadata_after.st_mtime_ns,
        metadata_after.st_ctime_ns,
    ):
        raise _supervisor_error("Runtime supervisor input changed while hashing")
    return digest.hexdigest()


def _reject_supervisor_file_capabilities(descriptor: int) -> None:
    try:
        os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise _supervisor_error(
            "Runtime supervisor file capabilities cannot be checked safely"
        ) from exc
    raise _supervisor_error("Runtime supervisor with file capabilities is forbidden")


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            count = os.write(descriptor, view)
        except OSError as exc:
            raise _supervisor_error("Runtime supervisor request pipe failed") from exc
        if count <= 0:
            raise _supervisor_error("Runtime supervisor request pipe closed early")
        view = view[count:]


def _read_receipt_frame(
    descriptor: int,
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    prefix = _read_exact_with_process(descriptor, 4, process, deadline)
    size = int.from_bytes(prefix, "big")
    if size <= 0 or size > RUNTIME_SUPERVISOR_MAX_FRAME_BYTES:
        raise _supervisor_error("Runtime supervisor receipt frame is malformed")
    payload = _read_exact_with_process(descriptor, size, process, deadline)
    _require_receipt_eof(descriptor, process, deadline)
    return payload


def _require_receipt_eof(
    descriptor: int,
    process: subprocess.Popen[bytes],
    deadline: float,
) -> None:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_TIMEOUT,
                "runtime_supervisor",
                "Runtime supervisor did not close its receipt frame",
                recoverable=True,
            )
        if not poller.poll(max(1, int(remaining * 1_000))):
            continue
        trailing = os.read(descriptor, 1)
        if trailing:
            raise _supervisor_error("Runtime supervisor receipt has trailing bytes")
        if process.poll() is None:
            # EOF is authoritative even if waitpid has not yet observed the
            # immediately following supervisor exit.
            return
        return


def _read_exact_with_process(
    descriptor: int,
    size: int,
    process: subprocess.Popen[bytes],
    deadline: float,
) -> bytes:
    output = bytearray()
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    while len(output) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_TIMEOUT,
                "runtime_supervisor",
                "Runtime supervisor receipt exceeded its fixed deadline",
                recoverable=True,
            )
        events = poller.poll(max(1, int(remaining * 1_000)))
        if not events:
            continue
        chunk = os.read(descriptor, size - len(output))
        if not chunk:
            exit_code = process.poll()
            details: dict[str, object] = {"supervisor_exit_code": exit_code}
            if process.stderr is not None:
                diagnostic = process.stderr.read(4097)
                if diagnostic:
                    details["supervisor_diagnostic"] = diagnostic[:4096].decode(
                        "utf-8", errors="replace"
                    )
                    details["supervisor_diagnostic_truncated"] = len(diagnostic) > 4096
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "runtime_supervisor",
                "Runtime supervisor exited without a complete receipt",
                recoverable=True,
                details=details,
            )
        output.extend(chunk)
    return bytes(output)


def _assert_receipt(
    request: RuntimeSupervisorRequest,
    receipt: RuntimeSupervisorReceipt,
    policy: RuntimeSupervisorPolicy,
    supervisor_exit_code: int,
) -> None:
    if (
        receipt.request_id != request.request_id
        or receipt.supervisor_sha256 != policy.sha256
        or supervisor_exit_code != 0
        or not receipt.cleanup_complete
        or receipt.residual_group_descendants != 0
    ):
        raise _supervisor_error("Runtime supervisor receipt differs from the authorized request")


def _supervisor_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "runtime_supervisor",
        message,
        recoverable=True,
    )


def _supervisor_limit(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        "runtime_supervisor",
        message,
        recoverable=True,
    )


def close_descriptors(descriptors: Iterable[int]) -> None:
    """Close an owned descriptor list, ignoring only already-closed entries."""

    for descriptor in descriptors:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
