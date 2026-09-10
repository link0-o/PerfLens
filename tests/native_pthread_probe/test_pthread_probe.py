from __future__ import annotations

import json
import os
import shutil
import socket
import statistics
import subprocess
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from perflens.runtime_locks.native_pthread_converter import convert_native_pthread_probe

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROBE_SOURCE = PROJECT_ROOT / "native/pthread_probe/perflens_pthread_probe.c"
PROBE_INCLUDE = PROJECT_ROOT / "native/pthread_probe"
WORKLOAD_SOURCE = Path(__file__).with_name("pthread_probe_workload.c")
OVERHEAD_SOURCE = Path(__file__).with_name("pthread_probe_overhead.c")
LIVE_THREADS_EXIT_SOURCE = Path(__file__).with_name("pthread_probe_live_threads_exit.c")

PROBE_COMPILE_FLAGS = (
    "-std=c11",
    "-shared",
    "-fPIC",
    "-O2",
    "-fvisibility=hidden",
    "-fstack-protector-strong",
    "-D_GNU_SOURCE=1",
    "-D_FORTIFY_SOURCE=3",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wpedantic",
    "-Wformat=2",
    "-Wconversion",
    "-Wshadow",
    "-Wstrict-prototypes",
)


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


def _run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        command,
        check=True,
        text=True,
        capture_output=True,
        timeout=8,
        **kwargs,
    )


def _compile_probe(compiler: str, destination: Path, *extra: str) -> None:
    _run(
        [
            compiler,
            *PROBE_COMPILE_FLAGS,
            *extra,
            str(PROBE_SOURCE),
            "-I",
            str(PROBE_INCLUDE),
            "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack",
            "-ldl",
            "-pthread",
            "-o",
            str(destination),
        ]
    )


def _compile_workload(compiler: str, source: Path, destination: Path, *extra: str) -> None:
    _run(
        [
            compiler,
            "-std=c11",
            "-O2",
            "-D_GNU_SOURCE=1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-Wconversion",
            "-Wshadow",
            *extra,
            str(source),
            "-pthread",
            "-o",
            str(destination),
        ]
    )


@pytest.fixture(scope="module")
def native_assets(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    output = tmp_path_factory.mktemp("native-pthread-probe")
    compiler = _tool("gcc")
    probe = output / "libperflens-pthread-probe.so"
    workload = output / "pthread-probe-workload"
    _compile_probe(compiler, probe)
    _compile_workload(compiler, WORKLOAD_SOURCE, workload)
    return probe, workload


def _capture_probe(
    tmp_path: Path,
    probe: Path,
    workload: Path,
    *,
    mode: str = "exact",
    max_events: int = 20_000,
    threshold_ns: int | None = None,
    preload_prefix: str | None = None,
) -> list[dict[str, object]]:
    evidence = tmp_path / "probe.ndjson"
    descriptor = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        environment = dict(os.environ)
        environment.update(
            {
                "LD_PRELOAD": (
                    f"{preload_prefix}:{probe}" if preload_prefix is not None else str(probe)
                ),
                "PERFLENS_RUNTIME_LOCK_FD": str(descriptor),
                "PERFLENS_RUNTIME_LOCK_MODE": mode,
                "PERFLENS_RUNTIME_LOCK_MAX_EVENTS": str(max_events),
            }
        )
        if threshold_ns is not None:
            environment["PERFLENS_RUNTIME_LOCK_THRESHOLD_NS"] = str(threshold_ns)
        subprocess.run(  # noqa: S603
            [str(workload)],
            check=True,
            env=environment,
            pass_fds=(descriptor,),
            capture_output=True,
            timeout=8,
        )
    finally:
        os.close(descriptor)
    return [json.loads(line) for line in evidence.read_text(encoding="utf-8").splitlines()]


def _events(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return [record for record in records if record["record_type"] == "probe_event"]


def _required_int(record: dict[str, object], field: str) -> int:
    value = record[field]
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


@pytest.mark.parametrize("compiler_name", ["gcc", "clang"])
def test_probe_builds_cleanly_with_supported_compilers(
    tmp_path: Path,
    compiler_name: str,
) -> None:
    probe = tmp_path / f"libperflens-pthread-probe-{compiler_name}.so"
    _compile_probe(_tool(compiler_name), probe)
    assert probe.is_file()
    assert not probe.is_symlink()


def test_exact_stream_is_bounded_private_and_lifo_paired(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    records = _capture_probe(tmp_path, probe, workload)
    header = records[0]
    footer = records[-1]
    events = _events(records)

    assert header["record_type"] == "probe_header"
    assert header["protocol"] == "native_pthread_probe"
    assert header["protocol_version"] == "1.0"
    assert header["semantics"] == "exact"
    assert header["duration_threshold_ns"] is None
    assert footer["record_type"] == "probe_footer"
    assert footer["declared_event_count"] == len(events)
    assert footer["sequence"] == len(events) + 1
    assert footer["lost_event_count"] == 0
    assert footer["truncated"] is False
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert {event["pid"] for event in events} == {header["pid"]}
    assert all(
        isinstance(event["raw_lock_token"], str)
        and len(event["raw_lock_token"]) == 16
        and int(event["raw_lock_token"], 16) >= 0
        for event in events
    )
    assert all("0x" not in json.dumps(record) for record in records)

    recursive = [event for event in events if event["lock_kind"] == "recursive_mutex"]
    recursive_acquires = [
        event["source_event_id"] for event in recursive if event["event_kind"] == "acquire"
    ]
    recursive_releases = [
        event["related_source_event_id"] for event in recursive if event["event_kind"] == "release"
    ]
    assert len(recursive_acquires) == 2
    assert recursive_releases == list(reversed(recursive_acquires))
    assert {event["lock_kind"] for event in events} >= {
        "mutex",
        "recursive_mutex",
        "rwlock_read",
        "rwlock_write",
        "condition",
    }


def test_forked_child_is_fail_closed_outside_bound_pid(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    records = _capture_probe(tmp_path, probe, workload)
    header = records[0]
    assert sum(record["record_type"] == "probe_header" for record in records) == 1
    assert sum(record["record_type"] == "probe_footer" for record in records) == 1
    assert {event["pid"] for event in _events(records)} == {header["pid"]}


def test_footer_is_final_when_main_exits_with_worker_still_active(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, _ = native_assets
    workload = tmp_path / "pthread-probe-live-threads-exit"
    _compile_workload(_tool("gcc"), LIVE_THREADS_EXIT_SOURCE, workload)
    for attempt in range(12):
        evidence_directory = tmp_path / f"attempt-{attempt}"
        evidence_directory.mkdir()
        records = _capture_probe(evidence_directory, probe, workload, max_events=20_000)
        assert records[-1]["record_type"] == "probe_footer"
        assert sum(record["record_type"] == "probe_footer" for record in records) == 1
        assert records[-1]["declared_event_count"] == len(_events(records))


def test_private_stream_is_accepted_by_strict_converter(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    records = _capture_probe(tmp_path, probe, workload)
    private_stream = BytesIO(
        b"".join(
            json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
            for record in records
        )
    )
    receipt = convert_native_pthread_probe(
        private_stream,
        created_at="2026-08-30T00:00:00+00:00",
    )
    evidence = receipt.evidence
    assert len(evidence.events) == len(_events(records))
    assert evidence.target.target_pid == records[0]["pid"]
    assert set(evidence.target.observed_target_tids) == {
        _required_int(event, "tid") for event in _events(records)
    }
    public_json = evidence.model_dump_json()
    assert all(str(event["raw_lock_token"]) not in public_json for event in _events(records))


def test_thresholded_default_keeps_only_qualifying_waits(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    records = _capture_probe(tmp_path, probe, workload, mode="thresholded")
    header = records[0]
    events = _events(records)
    assert header["duration_threshold_ns"] == 1_000
    wait_ends = [event for event in events if event["event_kind"] == "wait_end"]
    assert wait_ends
    assert all(_required_int(event, "duration_ns") >= 1_000 for event in wait_ends)


def test_event_budget_reports_truncation_without_overflow(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    records = _capture_probe(tmp_path, probe, workload, max_events=5)
    footer = records[-1]
    assert len(_events(records)) == 5
    assert footer == {
        "schema_version": "1.0",
        "record_type": "probe_footer",
        "protocol": "native_pthread_probe",
        "pid": records[0]["pid"],
        "sequence": 6,
        "declared_event_count": 5,
        "lost_event_count": footer["lost_event_count"],
        "truncated": True,
    }
    assert _required_int(footer, "lost_event_count") > 0


def test_invalid_probe_configuration_fails_open_without_evidence(
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    environment = dict(os.environ)
    environment.update(
        {
            "LD_PRELOAD": str(probe),
            "PERFLENS_RUNTIME_LOCK_FD": "2",
            "PERFLENS_RUNTIME_LOCK_MODE": "arbitrary",
        }
    )
    result = subprocess.run(  # noqa: S603
        [str(workload)],
        check=False,
        env=environment,
        capture_output=True,
        timeout=8,
    )
    assert result.returncode == 0


def test_probe_without_evidence_fd_passes_through_supported_calls_and_fork(
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("PERFLENS_RUNTIME_LOCK_")
    }
    environment["LD_PRELOAD"] = str(probe)

    # The fixed workload exercises contended and recursive mutexes, read/write
    # locks, a timed condition wait, and a post-fork child.  With no evidence
    # descriptor the constructor must select the immutable pass-through table,
    # preserve every pthread result, and emit no diagnostics or evidence.
    result = subprocess.run(  # noqa: S603
        [str(workload)],
        check=False,
        env=environment,
        capture_output=True,
        timeout=8,
    )

    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""


def test_probe_accepts_private_pipe_but_rejects_socket_output_descriptor(
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets
    environment = dict(os.environ)
    environment.update(
        {
            "LD_PRELOAD": str(probe),
            "PERFLENS_RUNTIME_LOCK_MODE": "exact",
            "PERFLENS_RUNTIME_LOCK_MAX_EVENTS": "20",
        }
    )

    read_fd, write_fd = os.pipe()
    try:
        environment["PERFLENS_RUNTIME_LOCK_FD"] = str(write_fd)
        result = subprocess.run(  # noqa: S603 - fixed test workload and private descriptor
            [str(workload)],
            check=False,
            env=environment,
            pass_fds=(write_fd,),
            capture_output=True,
            timeout=8,
        )
        assert result.returncode == 0
        os.close(write_fd)
        write_fd = -1
        assert os.read(read_fd, 1) == b"{"
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)

    receiver, sender = socket.socketpair()
    try:
        environment["PERFLENS_RUNTIME_LOCK_FD"] = str(sender.fileno())
        result = subprocess.run(  # noqa: S603 - fixed test workload and private descriptor
            [str(workload)],
            check=False,
            env=environment,
            pass_fds=(sender.fileno(),),
            capture_output=True,
            timeout=8,
        )
        assert result.returncode == 0
        sender.close()
        assert receiver.recv(1) == b""
    finally:
        receiver.close()
        sender.close()


def test_probe_accepts_only_exportable_regular_output_in_container_mode(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, workload = native_assets

    def execute(path: Path, mode: int, container_marker: str | None) -> bytes:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            mode,
        )
        os.fchmod(descriptor, mode)
        try:
            environment = {
                **os.environ,
                "LD_PRELOAD": str(probe),
                "PERFLENS_RUNTIME_LOCK_FD": str(descriptor),
                "PERFLENS_RUNTIME_LOCK_MODE": "exact",
                "PERFLENS_RUNTIME_LOCK_MAX_EVENTS": "20",
            }
            if container_marker is not None:
                environment["PERFLENS_RUNTIME_LOCK_CONTAINER"] = container_marker
            result = subprocess.run(  # noqa: S603 - fixed test workload and private descriptor
                [str(workload)],
                check=False,
                env=environment,
                pass_fds=(descriptor,),
                capture_output=True,
                timeout=8,
            )
            assert result.returncode == 0
        finally:
            os.close(descriptor)
        assert path.stat().st_mode & 0o777 == mode
        return path.read_bytes()

    accepted = execute(tmp_path / "container.ndjson", 0o644, "1")
    assert b'"record_type":"probe_header"' in accepted
    assert b'"record_type":"probe_footer"' in accepted

    assert execute(tmp_path / "host-mode.ndjson", 0o600, "1") == b""
    assert execute(tmp_path / "unmarked.ndjson", 0o644, None) == b""
    assert execute(tmp_path / "invalid-marker.ndjson", 0o644, "true") == b""


def test_shared_object_has_hardening_and_only_fixed_exports(
    native_assets: tuple[Path, Path],
) -> None:
    probe, _ = native_assets
    program_headers = _run([_tool("readelf"), "-W", "-l", str(probe)]).stdout
    dynamic = _run([_tool("readelf"), "-W", "-d", str(probe)]).stdout
    symbols = _run([_tool("nm"), "-D", "--defined-only", str(probe)]).stdout
    stack_line = next(line for line in program_headers.splitlines() if "GNU_STACK" in line)
    assert "GNU_RELRO" in program_headers
    assert " E " not in stack_line and not stack_line.rstrip().endswith("RWE")
    assert "BIND_NOW" in dynamic
    assert "RPATH" not in dynamic and "RUNPATH" not in dynamic
    assert "perflens_pthread_probe_abi_version" in symbols
    assert "perflens_pthread_probe_protocol_version" in symbols
    assert "pthread_mutex_lock" in symbols
    assert "pthread_cond_wait" in symbols
    assert " system" not in symbols and " popen" not in symbols


def test_address_sanitizers_accept_probe_lifecycle(
    tmp_path: Path,
) -> None:
    compiler = _tool("clang")
    probe = tmp_path / "libperflens-pthread-probe-sanitized.so"
    workload = tmp_path / "pthread-probe-workload-sanitized"
    sanitizers = (
        "-fsanitize=address,undefined",
        "-shared-libasan",
        "-fno-omit-frame-pointer",
    )
    _compile_probe(compiler, probe, *sanitizers)
    _compile_workload(compiler, WORKLOAD_SOURCE, workload, *sanitizers)
    runtime = _run([compiler, "-print-file-name=libclang_rt.asan-x86_64.so"]).stdout.strip()
    assert Path(runtime).is_file()
    environment = {
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }
    previous = {name: os.environ.get(name) for name in environment}
    try:
        os.environ.update(environment)
        records = _capture_probe(
            tmp_path,
            probe,
            workload,
            preload_prefix=runtime,
        )
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    assert records[-1]["record_type"] == "probe_footer"


def _wait4_cpu_seconds(
    command: list[str],
    environment: dict[str, str],
    *,
    inherited_fd: int | None = None,
) -> float:
    file_actions: list[tuple[int, int, int]] = []
    if inherited_fd is not None:
        # POSIX_SPAWN_DUP2 clears FD_CLOEXEC on the duplicated descriptor while
        # retaining the exact numeric descriptor bound into the probe policy.
        file_actions.append((os.POSIX_SPAWN_DUP2, inherited_fd, inherited_fd))
    pid = os.posix_spawn(
        command[0],
        command,
        environment,
        file_actions=file_actions,
    )
    waited_pid, status, usage = os.wait4(pid, 0)
    assert waited_pid == pid
    assert os.waitstatus_to_exitcode(status) == 0
    return usage.ru_utime + usage.ru_stime


def _timings(command: list[str], environment: dict[str, str], count: int = 5) -> Iterator[float]:
    for _ in range(count):
        yield _wait4_cpu_seconds(command, environment)


@pytest.mark.timeout(30)
@pytest.mark.performance
def test_probe_disabled_and_thresholded_overhead_are_bounded(
    tmp_path: Path,
    native_assets: tuple[Path, Path],
) -> None:
    probe, _ = native_assets
    compiler = _tool("gcc")
    workload = tmp_path / "pthread-probe-overhead"
    _compile_workload(compiler, OVERHEAD_SOURCE, workload)
    command = [str(workload)]
    base_environment = dict(os.environ)
    disabled_environment = {**base_environment, "LD_PRELOAD": str(probe)}
    evidence = tmp_path / "overhead.ndjson"
    descriptor = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        threshold_environment = {
            **disabled_environment,
            "PERFLENS_RUNTIME_LOCK_FD": str(descriptor),
            "PERFLENS_RUNTIME_LOCK_MODE": "thresholded",
            "PERFLENS_RUNTIME_LOCK_THRESHOLD_NS": "1000000000",
            "PERFLENS_RUNTIME_LOCK_MAX_EVENTS": "20000",
        }
        # Interleave and rotate the three modes so CPU frequency and machine
        # load drift cannot systematically favor whichever mode runs first.
        # Repeat a balanced rotation three times so transient CPU-frequency
        # changes and isolated child-process jitter cannot dominate a 1% gate.
        # Every mode occupies every position equally; the published limits are
        # unchanged and are applied to the median of the three balanced-block
        # deltas, so measurements from different load epochs are not mixed.
        baseline_samples: list[float] = []
        disabled_samples: list[float] = []
        thresholded_samples: list[float] = []
        disabled_block_deltas: list[float] = []
        thresholded_block_deltas: list[float] = []
        measurements = {
            "baseline": lambda: next(_timings(command, base_environment, count=1)),
            "disabled": lambda: next(_timings(command, disabled_environment, count=1)),
            "thresholded": lambda: next(
                _timings_with_fd(command, threshold_environment, descriptor, count=1)
            ),
        }
        samples = {
            "baseline": baseline_samples,
            "disabled": disabled_samples,
            "thresholded": thresholded_samples,
        }
        orders = (
            ("baseline", "disabled", "thresholded"),
            ("disabled", "thresholded", "baseline"),
            ("thresholded", "baseline", "disabled"),
        )
        for _ in range(3):
            for order in orders:
                for mode in order:
                    samples[mode].append(measurements[mode]())
            block_baseline = statistics.median(baseline_samples[-3:])
            disabled_block_deltas.append(
                statistics.median(disabled_samples[-3:]) - block_baseline
            )
            thresholded_block_deltas.append(
                statistics.median(thresholded_samples[-3:]) - block_baseline
            )
        baseline = statistics.median(baseline_samples)
        disabled_overhead = statistics.median(disabled_block_deltas)
        thresholded_overhead = statistics.median(thresholded_block_deltas)
    finally:
        os.close(descriptor)
    assert disabled_overhead <= max(0.01 * baseline, 0.002), (
        f"baseline={baseline_samples!r}, disabled={disabled_samples!r}, "
        f"block_deltas={disabled_block_deltas!r}"
    )
    assert thresholded_overhead <= max(0.15 * baseline, 0.002), (
        f"baseline={baseline_samples!r}, thresholded={thresholded_samples!r}, "
        f"block_deltas={thresholded_block_deltas!r}"
    )


def _timings_with_fd(
    command: list[str],
    environment: dict[str, str],
    descriptor: int,
    count: int = 5,
) -> Iterator[float]:
    for _ in range(count):
        yield _wait4_cpu_seconds(command, environment, inherited_fd=descriptor)
