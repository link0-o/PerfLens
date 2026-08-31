#!/usr/bin/python3
"""Fixed CPython ``threading`` launch bootstrap for PerfLens.

This file is installed as a root-owned, non-writable package asset.  It wraps
only the documented constructors in :mod:`threading`; it deliberately does
not replace ``_thread`` objects, C-extension locks, the GIL, or CPython
internal locks.  The private NDJSON stream is consumed by the deterministic
PerfLens converter and is never a public Artifact.
"""

from __future__ import annotations

import json
import os
import runpy
import sys
import sysconfig
import threading
import time
import traceback
from collections.abc import Callable
from contextlib import suppress
from types import TracebackType
from typing import Any

_ORIGINAL_LOCK = threading.Lock
_ORIGINAL_RLOCK = threading.RLock
_ORIGINAL_CONDITION = threading.Condition
_ORIGINAL_SEMAPHORE = threading.Semaphore
_ORIGINAL_BOUNDED_SEMAPHORE = threading.BoundedSemaphore
_SUPPRESSION = threading.local()


class _SuppressNestedInstrumentation:
    def __enter__(self) -> None:
        _SUPPRESSION.depth = getattr(_SUPPRESSION, "depth", 0) + 1

    def __exit__(self, *args: object) -> None:
        _SUPPRESSION.depth -= 1


def _suppressed() -> bool:
    return bool(getattr(_SUPPRESSION, "depth", 0))


class _Recorder:
    def __init__(self, fd: int, semantics: str, threshold_ns: int | None, max_events: int) -> None:
        self.fd = fd
        self.semantics = semantics
        self.threshold_ns = threshold_ns
        self.max_events = max_events
        self.origin_ns = time.monotonic_ns()
        self.sequence = 0
        self.lock_sequence = 0
        self.stack_sequence = 0
        self.lost_events = 0
        self.truncated = False
        self.enabled = True
        self.guard = _ORIGINAL_LOCK()
        self.stack_ids: dict[tuple[tuple[str, str, int], ...], str] = {}
        self.observed_tids: set[int] = {os.getpid()}

    def write(self, record: dict[str, object]) -> None:
        payload = json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        os.write(self.fd, payload.encode("utf-8") + b"\n")

    def next_lock_token(self) -> str:
        with self.guard:
            self.lock_sequence += 1
            return f"lock-{self.lock_sequence}"

    def stack(self) -> str | None:
        frames: list[tuple[str, str, int]] = []
        cwd = os.getcwd()
        for frame in traceback.extract_stack(limit=35)[:-3]:
            if frame.filename == _script_fd_path:
                frames.append((frame.name or "<unknown>", _script_label, frame.lineno or 1))
                continue
            if frame.filename.startswith("<"):
                continue
            filename = os.path.realpath(frame.filename)
            try:
                relative = os.path.relpath(filename, cwd)
            except ValueError:
                continue
            if relative == ".." or relative.startswith(".." + os.sep):
                continue
            frames.append(
                (frame.name or "<unknown>", relative.replace(os.sep, "/"), frame.lineno or 1)
            )
        if not frames:
            return None
        key = tuple(frames[-32:])
        existing = self.stack_ids.get(key)
        if existing is not None:
            return existing
        self.stack_sequence += 1
        stack_id = f"stack-{self.stack_sequence}"
        self.stack_ids[key] = stack_id
        self.write(
            {
                "schema_version": "1.0",
                "record_type": "cpython_stack",
                "stack_id": stack_id,
                "frames": [
                    {
                        "symbol": symbol,
                        "module": "python",
                        "source_file": source_file,
                        "source_line": source_line,
                        "is_runtime": False,
                        "is_unknown": False,
                    }
                    for symbol, source_file, source_line in key
                ],
            }
        )
        return stack_id

    def emit_group(
        self,
        *,
        lock_token: str,
        lock_kind: str,
        started_ns: int,
        finished_ns: int,
        outcome: str,
        include_acquire: bool,
    ) -> str | None:
        if not self.enabled:
            return None
        duration = max(0, finished_ns - started_ns)
        if self.semantics == "thresholded" and duration < (self.threshold_ns or 0):
            return None
        required = 3 if include_acquire and outcome == "acquired" else 2
        with self.guard:
            if self.sequence + required > self.max_events:
                self.lost_events += required
                self.truncated = True
                return None
            tid = threading.get_native_id()
            self.observed_tids.add(tid)
            stack_id = self.stack()
            begin_sequence = self.sequence + 1
            end_sequence = begin_sequence + 1
            begin_id = f"event-{begin_sequence}"
            end_id = f"event-{end_sequence}"
            common = {
                "schema_version": "1.0",
                "record_type": "cpython_event",
                "pid": os.getpid(),
                "tid": tid,
                "raw_lock_token": lock_token,
                "lock_kind": lock_kind,
                "stack_id": stack_id,
            }
            self.write(
                {
                    **common,
                    "sequence": begin_sequence,
                    "source_event_id": begin_id,
                    "event_kind": "wait_begin",
                    "timestamp_ns": started_ns - self.origin_ns,
                    "related_source_event_id": None,
                    "duration_ns": None,
                    "result": "unknown",
                }
            )
            self.write(
                {
                    **common,
                    "sequence": end_sequence,
                    "source_event_id": end_id,
                    "event_kind": "wait_end",
                    "timestamp_ns": finished_ns - self.origin_ns,
                    "related_source_event_id": begin_id,
                    "duration_ns": duration,
                    "result": outcome,
                }
            )
            self.sequence = end_sequence
            if include_acquire and outcome == "acquired":
                self.sequence += 1
                acquire_id = f"event-{self.sequence}"
                self.write(
                    {
                        **common,
                        "sequence": self.sequence,
                        "source_event_id": acquire_id,
                        "event_kind": "acquire",
                        "timestamp_ns": finished_ns - self.origin_ns,
                        "related_source_event_id": end_id,
                        "duration_ns": None,
                        "result": "acquired",
                    }
                )
                return acquire_id
            return None

    def emit_release(self, *, lock_token: str, lock_kind: str) -> None:
        if not self.enabled:
            return
        with self.guard:
            if self.sequence + 1 > self.max_events:
                self.lost_events += 1
                self.truncated = True
                return
            self.sequence += 1
            tid = threading.get_native_id()
            self.observed_tids.add(tid)
            self.write(
                {
                    "schema_version": "1.0",
                    "record_type": "cpython_event",
                    "sequence": self.sequence,
                    "source_event_id": f"event-{self.sequence}",
                    "event_kind": "release",
                    "timestamp_ns": time.monotonic_ns() - self.origin_ns,
                    "pid": os.getpid(),
                    "tid": tid,
                    "raw_lock_token": lock_token,
                    "lock_kind": lock_kind,
                    "related_source_event_id": None,
                    "duration_ns": None,
                    "result": "released",
                    "stack_id": self.stack(),
                }
            )

    def disable_before_fork(self) -> None:
        self.enabled = False

    def enable_after_fork_in_parent(self) -> None:
        self.enabled = True

    def disable_after_fork_in_child(self) -> None:
        self.enabled = False
        with suppress(OSError):
            os.close(self.fd)


_recorder: _Recorder
_script_fd_path = ""
_script_label = ""


class _InstrumentedLock:
    def __init__(self, raw: Any, kind: str) -> None:
        self._raw = raw
        self._kind = kind
        self._token = _recorder.next_lock_token()
        self._state_guard = _ORIGINAL_LOCK()
        self._emitted_acquires: list[bool] = []

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        started = time.monotonic_ns()
        acquired = self._raw.acquire(blocking, timeout)  # type: ignore[attr-defined]
        finished = time.monotonic_ns()
        acquire_id = _recorder.emit_group(
            lock_token=self._token,
            lock_kind=self._kind,
            started_ns=started,
            finished_ns=finished,
            outcome="acquired" if acquired else "timed_out",
            include_acquire=True,
        )
        if acquired:
            with self._state_guard:
                self._emitted_acquires.append(acquire_id is not None)
        return bool(acquired)

    def release(self) -> None:
        self._raw.release()  # type: ignore[attr-defined]
        with self._state_guard:
            emitted = bool(self._emitted_acquires and self._emitted_acquires.pop())
        if emitted:
            _recorder.emit_release(lock_token=self._token, lock_kind=self._kind)

    def locked(self) -> bool:
        return bool(self._raw.locked())  # type: ignore[attr-defined]

    def perflens_raw_lock(self) -> Any:
        return self._raw

    def __enter__(self) -> _InstrumentedLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()


class _InstrumentedCondition:
    def __init__(self, lock: Any | None = None) -> None:
        raw_lock = lock.perflens_raw_lock() if isinstance(lock, _InstrumentedLock) else lock
        with _SuppressNestedInstrumentation():
            self._raw = _ORIGINAL_CONDITION(raw_lock)
        self._token = _recorder.next_lock_token()
        self._state_guard = _ORIGINAL_LOCK()
        self._emitted_acquires: list[bool] = []

    def acquire(self, *args: Any, **kwargs: Any) -> bool:
        started = time.monotonic_ns()
        acquired = bool(self._raw.acquire(*args, **kwargs))
        acquire_id = _recorder.emit_group(
            lock_token=self._token,
            lock_kind="condition",
            started_ns=started,
            finished_ns=time.monotonic_ns(),
            outcome="acquired" if acquired else "timed_out",
            include_acquire=True,
        )
        if acquired:
            with self._state_guard:
                self._emitted_acquires.append(acquire_id is not None)
        return acquired

    def release(self) -> None:
        self._raw.release()
        with self._state_guard:
            emitted = bool(self._emitted_acquires and self._emitted_acquires.pop())
        if emitted:
            _recorder.emit_release(lock_token=self._token, lock_kind="condition")

    def wait(self, timeout: float | None = None) -> bool:
        started = time.monotonic_ns()
        notified = bool(self._raw.wait(timeout))
        _recorder.emit_group(
            lock_token=self._token,
            lock_kind="condition",
            started_ns=started,
            finished_ns=time.monotonic_ns(),
            outcome="notified" if notified else "timed_out",
            include_acquire=False,
        )
        return notified

    def wait_for(self, predicate: Callable[[], object], timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        result = predicate()
        while not result:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                break
            self.wait(remaining)
            result = predicate()
        return bool(result)

    def notify(self, n: int = 1) -> None:
        self._raw.notify(n)

    def notify_all(self) -> None:
        self._raw.notify_all()

    def __enter__(self) -> _InstrumentedCondition:
        self.acquire()
        return self

    def __exit__(self, *args: object) -> None:
        self.release()


class _InstrumentedSemaphore:
    def __init__(self, value: int = 1, *, bounded: bool = False) -> None:
        factory = _ORIGINAL_BOUNDED_SEMAPHORE if bounded else _ORIGINAL_SEMAPHORE
        with _SuppressNestedInstrumentation():
            self._raw = factory(value)
        self._token = _recorder.next_lock_token()
        self._state_guard = _ORIGINAL_LOCK()
        self._emitted_acquires = 0

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        started = time.monotonic_ns()
        acquired = bool(self._raw.acquire(blocking, timeout))
        acquire_id = _recorder.emit_group(
            lock_token=self._token,
            lock_kind="semaphore",
            started_ns=started,
            finished_ns=time.monotonic_ns(),
            outcome="acquired" if acquired else "timed_out",
            include_acquire=True,
        )
        if acquired and acquire_id is not None:
            with self._state_guard:
                self._emitted_acquires += 1
        return acquired

    def release(self, n: int = 1) -> None:
        self._raw.release(n)
        with self._state_guard:
            emitted = min(n, self._emitted_acquires)
            self._emitted_acquires -= emitted
        for _ in range(emitted):
            _recorder.emit_release(lock_token=self._token, lock_kind="semaphore")

    def __enter__(self) -> _InstrumentedSemaphore:
        self.acquire()
        return self

    def __exit__(self, *args: object) -> None:
        self.release()


def _install() -> None:
    threading.Lock = _new_lock  # type: ignore[assignment]
    threading.RLock = _new_rlock  # type: ignore[assignment]
    threading.Condition = _new_condition  # type: ignore[assignment,misc]
    threading.Semaphore = _new_semaphore  # type: ignore[assignment,misc]
    threading.BoundedSemaphore = _new_bounded_semaphore  # type: ignore[assignment]


def _uninstall() -> None:
    threading.Lock = _ORIGINAL_LOCK  # type: ignore[assignment]
    threading.RLock = _ORIGINAL_RLOCK  # type: ignore[assignment]
    threading.Condition = _ORIGINAL_CONDITION  # type: ignore[assignment,misc]
    threading.Semaphore = _ORIGINAL_SEMAPHORE  # type: ignore[assignment,misc]
    threading.BoundedSemaphore = _ORIGINAL_BOUNDED_SEMAPHORE  # type: ignore[assignment]


def _new_lock() -> Any:
    raw = _ORIGINAL_LOCK()
    return raw if _suppressed() else _InstrumentedLock(raw, "mutex")


def _new_rlock() -> Any:
    raw = _ORIGINAL_RLOCK()
    return raw if _suppressed() else _InstrumentedLock(raw, "recursive_mutex")


def _new_condition(lock: Any | None = None) -> Any:
    if _suppressed():
        return _ORIGINAL_CONDITION(lock)
    return _InstrumentedCondition(lock)


def _new_semaphore(value: int = 1) -> Any:
    if _suppressed():
        return _ORIGINAL_SEMAPHORE(value)
    return _InstrumentedSemaphore(value)


def _new_bounded_semaphore(value: int = 1) -> Any:
    if _suppressed():
        return _ORIGINAL_BOUNDED_SEMAPHORE(value)
    return _InstrumentedSemaphore(value, bounded=True)


def _start_ticks() -> int:
    with open("/proc/self/stat", encoding="ascii") as stream:
        fields = stream.read().split()
    return int(fields[21])


def main() -> None:
    if len(sys.argv) < 6:
        raise SystemExit(64)
    output_fd = int(os.environ["PERFLENS_RUNTIME_LOCK_FD"])
    script_fd = int(sys.argv[1])
    script_label = sys.argv[2]
    semantics = sys.argv[3]
    threshold_raw = sys.argv[4]
    max_events = int(sys.argv[5])
    if output_fd < 3 or script_fd < 3 or semantics not in {"exact", "thresholded"}:
        raise SystemExit(64)
    threshold_ns = None if threshold_raw == "none" else int(threshold_raw)
    if (semantics == "exact") != (threshold_ns is None):
        raise SystemExit(64)
    global _recorder, _script_fd_path, _script_label
    _script_fd_path = f"/proc/self/fd/{script_fd}"
    _script_label = script_label
    _recorder = _Recorder(output_fd, semantics, threshold_ns, max_events)
    os.register_at_fork(
        before=_recorder.disable_before_fork,
        after_in_parent=_recorder.enable_after_fork_in_parent,
        after_in_child=_recorder.disable_after_fork_in_child,
    )
    _recorder.write(
        {
            "schema_version": "1.0",
            "record_type": "cpython_header",
            "protocol": "cpython_threading_probe",
            "protocol_version": "1.0",
            "runtime_version": ".".join(map(str, sys.version_info[:3])),
            "free_threaded": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
            "pid": os.getpid(),
            "uid": os.getuid(),
            "target_start_time_ticks": _start_ticks(),
            "semantics": semantics,
            "duration_threshold_ns": threshold_ns,
            "max_events": max_events,
            "visible_lock_kinds": ["condition", "mutex", "recursive_mutex", "semaphore"],
        }
    )
    exit_code = 0
    try:
        _install()
        script_path = _script_fd_path
        sys.argv = [script_label, *sys.argv[6:]]
        sys.path.insert(0, os.getcwd())
        runpy.run_path(script_path, run_name="__main__")
    except SystemExit as exc:
        if isinstance(exc.code, int):
            exit_code = exc.code
        elif exc.code is not None:
            exit_code = 1
    finally:
        _uninstall()
        if _recorder.enabled:
            with _recorder.guard:
                _recorder.write(
                    {
                        "schema_version": "1.0",
                        "record_type": "cpython_footer",
                        "protocol": "cpython_threading_probe",
                        "pid": os.getpid(),
                        "sequence": _recorder.sequence,
                        "declared_event_count": _recorder.sequence,
                        "lost_event_count": _recorder.lost_events,
                        "truncated": _recorder.truncated,
                        "observed_target_tids": sorted(_recorder.observed_tids),
                    }
                )
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
