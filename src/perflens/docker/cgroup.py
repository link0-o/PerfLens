"""Bounded, read-only cgroup-v2 resource context for a verified Docker target."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from perflens import __version__
from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import (
    CgroupIoDeviceSnapshot,
    ContainerResourceContextArtifact,
    ContainerResourceDelta,
    ContainerResourceSnapshot,
    PressureSnapshot,
    derive_container_resource_context_id,
)
from perflens.docker.identity import ResolvedContainerTarget
from perflens.domain.errors import ErrorCode, PerfLensError

_MAX_FILE_BYTES = 64 << 10
_MAX_TOTAL_BYTES = 256 << 10
_MAX_LINES = 512
_MEMORY_EVENT_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_CPUSET = re.compile(r"^[0-9,-]{1,4096}$")


@dataclass(frozen=True, slots=True)
class CapturedCgroupSnapshot:
    snapshot: ContainerResourceSnapshot
    limitations: tuple[str, ...]
    container_identity_sha256: str
    cgroup_identity_sha256: str
    cgroup_inode: int
    snapshot_sha256: str


@dataclass(slots=True)
class _ReadBudget:
    total_bytes: int = 0

    def account(self, amount: int) -> None:
        self.total_bytes += amount
        if self.total_bytes > _MAX_TOTAL_BYTES:
            raise _resource_error("cgroup resource snapshot exceeds its total byte limit")


class CgroupV2ResourceReader:
    """Read only the cgroup directory already bound by a ContainerTargetArtifact."""

    def __init__(
        self,
        target: ResolvedContainerTarget,
        *,
        cgroup_root: Path = Path("/sys/fs/cgroup"),
    ) -> None:
        root = _validate_root(cgroup_root)
        relative_path = target.kernel.cgroup_relative_path
        path = PurePosixPath(relative_path)
        if not relative_path.startswith("/") or ".." in path.parts or str(path) != relative_path:
            raise _resource_error("Verified Docker cgroup path is invalid")
        directory = root.joinpath(*path.parts[1:])
        try:
            resolved = directory.resolve(strict=True)
            metadata = directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise _resource_error("Verified Docker cgroup directory is unavailable") from exc
        if (
            resolved != directory
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_ino != target.kernel.cgroup_inode
            or metadata.st_ino != target.artifact.cgroup.inode
        ):
            raise _resource_error("Verified Docker cgroup directory identity does not match")
        expected_identity = _sha256_text(
            "cgroup-v2",
            target.artifact.container_identity_sha256,
            relative_path,
            str(metadata.st_ino),
        )
        if expected_identity != target.artifact.cgroup.identity_sha256:
            raise _resource_error("Verified Docker cgroup digest does not match its private path")
        self._directory = directory
        self._expected_inode = metadata.st_ino
        self._container_identity_sha256 = target.artifact.container_identity_sha256
        self._cgroup_identity_sha256 = expected_identity

    @property
    def container_identity_sha256(self) -> str:
        return self._container_identity_sha256

    @property
    def cgroup_identity_sha256(self) -> str:
        return self._cgroup_identity_sha256

    @property
    def cgroup_inode(self) -> int:
        return self._expected_inode

    def capture(self, *, observed_at: datetime | None = None) -> CapturedCgroupSnapshot:
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(self._directory, flags)
        except OSError as exc:
            raise _resource_error("Docker cgroup directory cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or opened.st_ino != self._expected_inode:
                raise _resource_error("Docker cgroup inode changed before resource capture")
            budget = _ReadBudget()
            limitations: list[str] = []
            cpu = _parse_cpu_stat(_read_text(descriptor, "cpu.stat", budget=budget))
            for field in (
                "user_usec",
                "system_usec",
                "nr_periods",
                "nr_throttled",
                "throttled_usec",
            ):
                if field not in cpu:
                    limitations.append(f"cpu.stat omits optional {field}.")
            cpu_quota, cpu_period = _parse_cpu_max(
                _read_text(descriptor, "cpu.max", budget=budget)
            )
            cpuset = _parse_cpuset(
                _read_text(descriptor, "cpuset.cpus.effective", budget=budget)
            )
            memory_current = _parse_unsigned_scalar(
                _read_text(descriptor, "memory.current", budget=budget),
                "memory.current",
            )
            memory_max = _parse_max_scalar(
                _read_text(descriptor, "memory.max", budget=budget),
                "memory.max",
            )
            memory_events = _parse_memory_events(
                _read_text(descriptor, "memory.events", budget=budget)
            )
            pids_current = _parse_unsigned_scalar(
                _read_text(descriptor, "pids.current", budget=budget),
                "pids.current",
            )
            pids_max = _parse_max_scalar(
                _read_text(descriptor, "pids.max", budget=budget),
                "pids.max",
            )
            memory_pressure_text = _read_optional_text(
                descriptor,
                "memory.pressure",
                budget=budget,
            )
            if memory_pressure_text is None:
                memory_pressure = None
                limitations.append("memory.pressure is unavailable for this cgroup.")
            else:
                memory_pressure = _parse_pressure(memory_pressure_text, "memory.pressure")
                if (
                    memory_pressure.some_total_us is None
                    or memory_pressure.full_total_us is None
                ):
                    limitations.append("memory.pressure omits a pressure class.")
            io_text = _read_optional_text(descriptor, "io.stat", budget=budget)
            if io_text is None:
                io_devices: tuple[CgroupIoDeviceSnapshot, ...] = ()
                limitations.append("io.stat is unavailable for this cgroup.")
            else:
                io_devices = _parse_io_stat(io_text)
            io_pressure_text = _read_optional_text(
                descriptor,
                "io.pressure",
                budget=budget,
            )
            if io_pressure_text is None:
                io_pressure = None
                limitations.append("io.pressure is unavailable for this cgroup.")
            else:
                io_pressure = _parse_pressure(io_pressure_text, "io.pressure")
                if io_pressure.some_total_us is None or io_pressure.full_total_us is None:
                    limitations.append("io.pressure omits a pressure class.")
            _assert_directory_current(
                self._directory,
                opened_device=opened.st_dev,
                opened_inode=opened.st_ino,
            )
            timestamp = observed_at or datetime.now(tz=UTC)
            snapshot = ContainerResourceSnapshot(
                observed_at=timestamp.isoformat(),
                cpu_usage_usec=cpu["usage_usec"],
                cpu_user_usec=cpu.get("user_usec"),
                cpu_system_usec=cpu.get("system_usec"),
                cpu_nr_periods=cpu.get("nr_periods"),
                cpu_nr_throttled=cpu.get("nr_throttled"),
                cpu_throttled_usec=cpu.get("throttled_usec"),
                cpu_quota_usec=cpu_quota,
                cpu_period_usec=cpu_period,
                cpuset_cpus_effective=cpuset,
                memory_current_bytes=memory_current,
                memory_max_bytes=memory_max,
                memory_events=memory_events,
                memory_pressure=memory_pressure,
                io_devices=io_devices,
                io_pressure=io_pressure,
                pids_current=pids_current,
                pids_max=pids_max,
            )
            limitation_tuple = tuple(sorted(limitations))
            snapshot_sha256 = _captured_snapshot_sha256(
                snapshot,
                limitation_tuple,
                container_identity_sha256=self._container_identity_sha256,
                cgroup_identity_sha256=self._cgroup_identity_sha256,
                cgroup_inode=self._expected_inode,
            )
            return CapturedCgroupSnapshot(
                snapshot,
                limitation_tuple,
                self._container_identity_sha256,
                self._cgroup_identity_sha256,
                self._expected_inode,
                snapshot_sha256,
            )
        finally:
            os.close(descriptor)


def build_container_resource_context(
    reader: CgroupV2ResourceReader,
    before: CapturedCgroupSnapshot,
    after: CapturedCgroupSnapshot,
    *,
    source_collection_id: str,
    source_output_sha256: str,
    created_at: datetime | None = None,
) -> ContainerResourceContextArtifact:
    """Build a bounded container-wide delta without attributing it to one process."""
    _verify_captured_snapshot(reader, before)
    _verify_captured_snapshot(reader, after)
    first = before.snapshot
    second = after.snapshot
    if _parse_timestamp(first.observed_at) >= _parse_timestamp(second.observed_at):
        raise _resource_error("Docker cgroup snapshots are not time ordered")
    limitations = set((*before.limitations, *after.limitations))
    if (
        first.cpu_quota_usec != second.cpu_quota_usec
        or first.cpu_period_usec != second.cpu_period_usec
    ):
        limitations.add("CPU quota changed during the resource observation window.")
    if first.cpuset_cpus_effective != second.cpuset_cpus_effective:
        limitations.add("Effective cpuset changed during the resource observation window.")
    if first.memory_max_bytes != second.memory_max_bytes:
        limitations.add("Memory limit changed during the resource observation window.")
    if first.pids_max != second.pids_max:
        limitations.add("PIDs limit changed during the resource observation window.")
    delta = ContainerResourceDelta(
        cpu_usage_usec=_checked_delta(
            first.cpu_usage_usec,
            second.cpu_usage_usec,
            "cpu usage",
        ),
        cpu_user_usec=_optional_delta(first.cpu_user_usec, second.cpu_user_usec, "CPU user"),
        cpu_system_usec=_optional_delta(
            first.cpu_system_usec,
            second.cpu_system_usec,
            "CPU system",
        ),
        cpu_nr_periods=_optional_delta(
            first.cpu_nr_periods,
            second.cpu_nr_periods,
            "CPU periods",
        ),
        cpu_nr_throttled=_optional_delta(
            first.cpu_nr_throttled,
            second.cpu_nr_throttled,
            "CPU throttled periods",
        ),
        cpu_throttled_usec=_optional_delta(
            first.cpu_throttled_usec,
            second.cpu_throttled_usec,
            "CPU throttled time",
        ),
        memory_event_deltas=_counter_tuple_delta(
            first.memory_events,
            second.memory_events,
            "memory event",
        ),
        io_read_bytes=_io_delta(first.io_devices, second.io_devices, "read_bytes"),
        io_write_bytes=_io_delta(first.io_devices, second.io_devices, "write_bytes"),
        io_read_ios=_io_delta(first.io_devices, second.io_devices, "read_ios"),
        io_write_ios=_io_delta(first.io_devices, second.io_devices, "write_ios"),
        memory_pressure_some_usec=_pressure_delta(
            first.memory_pressure,
            second.memory_pressure,
            full=False,
            label="memory pressure some",
        ),
        memory_pressure_full_usec=_pressure_delta(
            first.memory_pressure,
            second.memory_pressure,
            full=True,
            label="memory pressure full",
        ),
        io_pressure_some_usec=_pressure_delta(
            first.io_pressure,
            second.io_pressure,
            full=False,
            label="I/O pressure some",
        ),
        io_pressure_full_usec=_pressure_delta(
            first.io_pressure,
            second.io_pressure,
            full=True,
            label="I/O pressure full",
        ),
    )
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise _resource_error("Resource context creation timestamp must include a timezone")
    if timestamp < _parse_timestamp(second.observed_at):
        raise _resource_error("Resource context creation precedes its final cgroup snapshot")
    limitation_tuple = tuple(sorted(limitations))
    resource_context_id = derive_container_resource_context_id(
        container_identity_sha256=reader.container_identity_sha256,
        cgroup_identity_sha256=reader.cgroup_identity_sha256,
        source_collection_id=source_collection_id,
        source_output_sha256=source_output_sha256,
        before_observed_at=first.observed_at,
        after_observed_at=second.observed_at,
        created_at=timestamp.isoformat(),
    )
    provisional = ContainerResourceContextArtifact(
        schema_version="1.0",
        perflens_version=__version__,
        resource_context_id=resource_context_id,
        created_at=timestamp.isoformat(),
        container_identity_sha256=reader.container_identity_sha256,
        cgroup_identity_sha256=reader.cgroup_identity_sha256,
        source_collection_id=source_collection_id,
        source_output_sha256=source_output_sha256,
        before=first,
        after=second,
        delta=delta,
        quality_status="partial" if limitation_tuple else "verified",
        limitations=limitation_tuple,
        allowed_conclusions=(
            "Container cgroup CPU, memory, I/O, PIDs, and pressure observations may be reported.",
            "Counter deltas are scoped to the verified entire container cgroup.",
        ),
        forbidden_conclusions=(
            "Container cgroup counters are not exclusive measurements of the selected process.",
            "Resource correlation alone does not establish a source-code performance root cause.",
        ),
        content_sha256="0" * 64,
    )
    return ContainerResourceContextArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _read_text(descriptor: int, name: str, *, budget: _ReadBudget) -> str:
    result = _read_optional_text(descriptor, name, budget=budget)
    if result is None:
        raise _resource_error(f"required cgroup resource file {name} is unavailable")
    return result


def _read_optional_text(descriptor: int, name: str, *, budget: _ReadBudget) -> str | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(name, flags, dir_fd=descriptor)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _resource_error("cgroup resource file cannot be opened safely") from exc
    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _resource_error("cgroup resource entry is not a regular file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(file_descriptor, min(8192, _MAX_FILE_BYTES - total + 1)):
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                raise _resource_error("cgroup resource file exceeds its fixed byte limit")
        budget.account(total)
        try:
            return b"".join(chunks).decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise _resource_error("cgroup resource file is not ASCII") from exc
    finally:
        os.close(file_descriptor)


def _parse_cpu_stat(text: str) -> dict[str, int]:
    values = _parse_counter_lines(text, label="cpu.stat", max_fields=32)
    if "usage_usec" not in values:
        raise _resource_error("cpu.stat omits required usage_usec")
    return values


def _parse_cpu_max(text: str) -> tuple[int | None, int]:
    fields = text.split()
    if len(fields) != 2:
        raise _resource_error("cpu.max must contain a quota and period")
    quota = None if fields[0] == "max" else _parse_unsigned(fields[0], "cpu.max quota")
    period = _parse_unsigned(fields[1], "cpu.max period")
    if quota == 0 or period == 0:
        raise _resource_error("cpu.max quota and period must be positive")
    return quota, period


def _parse_cpuset(text: str) -> str:
    value = text.strip()
    if not _CPUSET.fullmatch(value):
        raise _resource_error("cpuset.cpus.effective has an invalid bounded CPU list")
    previous = -1
    for item in value.split(","):
        parts = item.split("-")
        if len(parts) not in {1, 2}:
            raise _resource_error("cpuset.cpus.effective contains an invalid range")
        start = _parse_unsigned(parts[0], "cpuset CPU")
        end = start if len(parts) == 1 else _parse_unsigned(parts[1], "cpuset CPU")
        if start > end or start <= previous:
            raise _resource_error("cpuset.cpus.effective ranges must be sorted and disjoint")
        previous = end
    return value


def _parse_memory_events(text: str) -> tuple[tuple[str, int], ...]:
    values = _parse_counter_lines(text, label="memory.events", max_fields=64)
    if any(_MEMORY_EVENT_NAME.fullmatch(name) is None for name in values):
        raise _resource_error("memory.events contains an invalid counter name")
    return tuple(sorted(values.items()))


def _parse_pressure(text: str, label: str) -> PressureSnapshot:
    values: dict[str, int] = {}
    lines = text.splitlines()
    if not lines or len(lines) > 2:
        raise _resource_error(f"{label} has an invalid line count")
    for line in lines:
        fields = line.split()
        if not fields or fields[0] not in {"some", "full"} or fields[0] in values:
            raise _resource_error(f"{label} has an invalid pressure class")
        totals = tuple(field[6:] for field in fields[1:] if field.startswith("total="))
        if len(totals) != 1:
            raise _resource_error(f"{label} omits one bounded total counter")
        values[fields[0]] = _parse_unsigned(totals[0], f"{label} total")
    return PressureSnapshot(
        some_total_us=values.get("some"),
        full_total_us=values.get("full"),
    )


def _parse_io_stat(text: str) -> tuple[CgroupIoDeviceSnapshot, ...]:
    devices: list[CgroupIoDeviceSnapshot] = []
    lines = text.splitlines()
    if len(lines) > 256:
        raise _resource_error("io.stat exceeds the fixed device limit")
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        device = fields[0].split(":")
        if len(device) != 2:
            raise _resource_error("io.stat contains an invalid device identity")
        major = _parse_unsigned(device[0], "io.stat major")
        minor = _parse_unsigned(device[1], "io.stat minor")
        counters: dict[str, int] = {}
        for field in fields[1:]:
            key, separator, value = field.partition("=")
            if not separator or key in counters or len(key) > 32:
                raise _resource_error("io.stat contains a malformed counter")
            counters[key] = _parse_unsigned(value, "io.stat counter")
        required = {"rbytes", "wbytes", "rios", "wios"}
        if not required.issubset(counters):
            raise _resource_error("io.stat omits a required read or write counter")
        devices.append(
            CgroupIoDeviceSnapshot(
                major=major,
                minor=minor,
                read_bytes=counters.get("rbytes", 0),
                write_bytes=counters.get("wbytes", 0),
                read_ios=counters.get("rios", 0),
                write_ios=counters.get("wios", 0),
            )
        )
    result = tuple(sorted(devices, key=lambda item: (item.major, item.minor)))
    if len({(item.major, item.minor) for item in result}) != len(result):
        raise _resource_error("io.stat contains duplicate device identities")
    return result


def _parse_counter_lines(text: str, *, label: str, max_fields: int) -> dict[str, int]:
    lines = text.splitlines()
    if not lines or len(lines) > min(max_fields, _MAX_LINES):
        raise _resource_error(f"{label} has an invalid field count")
    values: dict[str, int] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] in values or len(fields[0]) > 64:
            raise _resource_error(f"{label} contains a malformed or duplicate counter")
        values[fields[0]] = _parse_unsigned(fields[1], f"{label} counter")
    return values


def _parse_unsigned_scalar(text: str, label: str) -> int:
    fields = text.split()
    if len(fields) != 1:
        raise _resource_error(f"{label} must contain one integer")
    return _parse_unsigned(fields[0], label)


def _parse_max_scalar(text: str, label: str) -> int | None:
    fields = text.split()
    if len(fields) != 1:
        raise _resource_error(f"{label} must contain one bounded value")
    if fields[0] == "max":
        return None
    value = _parse_unsigned(fields[0], label)
    if value == 0:
        raise _resource_error(f"{label} must be positive or max")
    return value


def _parse_unsigned(value: str, label: str) -> int:
    if not value or not value.isascii() or not value.isdecimal() or len(value) > 20:
        raise _resource_error(f"{label} is not a bounded unsigned integer")
    parsed = int(value)
    if parsed > 18_446_744_073_709_551_615:
        raise _resource_error(f"{label} exceeds the unsigned 64-bit limit")
    return parsed


def _counter_tuple_delta(
    before: tuple[tuple[str, int], ...],
    after: tuple[tuple[str, int], ...],
    label: str,
) -> tuple[tuple[str, int], ...]:
    first = dict(before)
    second = dict(after)
    return tuple(
        (key, _checked_delta(first.get(key, 0), second.get(key, 0), f"{label} {key}"))
        for key in sorted(first.keys() | second.keys())
    )


def _io_delta(
    before: tuple[CgroupIoDeviceSnapshot, ...],
    after: tuple[CgroupIoDeviceSnapshot, ...],
    field: str,
) -> int:
    first = {(item.major, item.minor): getattr(item, field) for item in before}
    second = {(item.major, item.minor): getattr(item, field) for item in after}
    return sum(
        _checked_delta(first.get(device, 0), second.get(device, 0), f"I/O {field}")
        for device in first.keys() | second.keys()
    )


def _pressure_delta(
    before: PressureSnapshot | None,
    after: PressureSnapshot | None,
    *,
    full: bool,
    label: str,
) -> int | None:
    if before is None or after is None:
        return None
    first = before.full_total_us if full else before.some_total_us
    second = after.full_total_us if full else after.some_total_us
    return _optional_delta(first, second, label)


def _optional_delta(before: int | None, after: int | None, label: str) -> int | None:
    if before is None or after is None:
        return None
    return _checked_delta(before, after, label)


def _checked_delta(before: int, after: int, label: str) -> int:
    if after < before:
        raise _resource_error(f"{label} counter decreased within one cgroup identity")
    return after - before


def _assert_directory_current(path: Path, *, opened_device: int, opened_inode: int) -> None:
    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _resource_error(
            "Docker cgroup directory disappeared during resource capture"
        ) from exc
    if (current.st_dev, current.st_ino) != (opened_device, opened_inode):
        raise _resource_error("Docker cgroup directory changed during resource capture")


def _captured_snapshot_sha256(
    snapshot: ContainerResourceSnapshot,
    limitations: tuple[str, ...],
    *,
    container_identity_sha256: str,
    cgroup_identity_sha256: str,
    cgroup_inode: int,
) -> str:
    return _sha256_text(
        "perflens-docker-cgroup-snapshot-v1",
        container_identity_sha256,
        cgroup_identity_sha256,
        str(cgroup_inode),
        contract_content_sha256(snapshot),
        "\n".join(limitations),
    )


def _verify_captured_snapshot(
    reader: CgroupV2ResourceReader,
    captured: CapturedCgroupSnapshot,
) -> None:
    if (
        captured.container_identity_sha256 != reader.container_identity_sha256
        or captured.cgroup_identity_sha256 != reader.cgroup_identity_sha256
        or captured.cgroup_inode != reader.cgroup_inode
    ):
        raise _resource_error("cgroup snapshot belongs to a different Docker target")
    expected = _captured_snapshot_sha256(
        captured.snapshot,
        captured.limitations,
        container_identity_sha256=captured.container_identity_sha256,
        cgroup_identity_sha256=captured.cgroup_identity_sha256,
        cgroup_inode=captured.cgroup_inode,
    )
    if expected != captured.snapshot_sha256:
        raise _resource_error("cgroup snapshot content digest does not match")


def _validate_root(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("cgroup root must be an absolute non-symlink directory")
    resolved = path.resolve(strict=True)
    if resolved != path or not path.is_dir():
        raise ValueError("cgroup root must be a canonical directory")
    return resolved


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise _resource_error("cgroup snapshot timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise _resource_error("cgroup snapshot timestamp must include a timezone")
    return parsed


def _sha256_text(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _resource_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "docker_cgroup",
        message,
        recoverable=True,
    )
