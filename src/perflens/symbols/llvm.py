"""Long-lived LLVM symbolizer provider using line-delimited JSON output."""

from __future__ import annotations

import json
import math
import os
import selectors
import shutil
import signal
import subprocess
import threading
import time
from collections import OrderedDict
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import cast

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.symbols import ModuleIdentity, ModuleLocation, ResolvedFrame

_QUERY_BATCH_SIZE = 256


class _LlvmProcess:
    def __init__(self, executable: Path, module_path: Path, timeout_seconds: float) -> None:
        self._timeout_seconds = timeout_seconds
        self._stdout_buffer = bytearray()
        self._stderr = bytearray()
        self._selector = selectors.DefaultSelector()
        try:
            self._process = subprocess.Popen(  # noqa: S603 - canonical executable and module paths
                (
                    str(executable),
                    "--output-style=JSON",
                    "--inlines",
                    "--demangle",
                    f"--obj={module_path}",
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
        except OSError as exc:
            self._selector.close()
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "symbolization",
                "Unable to start llvm-symbolizer",
                recoverable=True,
                details={"executable": str(executable)},
            ) from exc
        assert self._process.stdout is not None
        assert self._process.stderr is not None
        self._selector.register(self._process.stdout, selectors.EVENT_READ, "stdout")
        self._selector.register(self._process.stderr, selectors.EVENT_READ, "stderr")

    @property
    def pid(self) -> int:
        return self._process.pid

    def query(self, addresses: Sequence[int]) -> list[tuple[ResolvedFrame, ...]]:
        if not addresses:
            return []
        if self._process.poll() is not None:
            raise self._error("llvm-symbolizer exited before a query")
        assert self._process.stdin is not None
        try:
            self._process.stdin.write(
                "".join(f"0x{address:x}\n" for address in addresses).encode("ascii")
            )
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise self._error("Unable to write to llvm-symbolizer") from exc
        return [parse_llvm_json_line(self._read_line()) for _ in addresses]

    def close(self) -> None:
        if self._process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(self._process.pid, signal.SIGTERM)
            try:
                self._process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(self._process.pid, signal.SIGKILL)
                self._process.wait()
        self._selector.close()
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            if stream is not None:
                stream.close()

    def _read_line(self) -> bytes:
        deadline = time.monotonic() + self._timeout_seconds
        while True:
            newline = self._stdout_buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._stdout_buffer[:newline]).rstrip(b"\r")
                del self._stdout_buffer[: newline + 1]
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise self._error("llvm-symbolizer response timed out", timeout=True)
            for key, _ in self._selector.select(timeout=min(remaining, 0.1)):
                chunk = os.read(key.fd, 16 << 10)
                if not chunk:
                    self._selector.unregister(key.fileobj)
                    if key.data == "stdout":
                        raise self._error("llvm-symbolizer closed its output unexpectedly")
                    continue
                if key.data == "stdout":
                    self._stdout_buffer.extend(chunk)
                    if len(self._stdout_buffer) > 1 << 20:
                        raise self._error("llvm-symbolizer emitted an overlong JSON response")
                elif len(self._stderr) < 64 << 10:
                    self._stderr.extend(chunk[: (64 << 10) - len(self._stderr)])

    def _error(self, message: str, *, timeout: bool = False) -> PerfLensError:
        return PerfLensError(
            ErrorCode.EXTERNAL_TOOL_TIMEOUT if timeout else ErrorCode.EXTERNAL_TOOL_FAILED,
            "symbolization",
            message,
            recoverable=True,
            retryable=timeout,
            details={
                "exit_code": self._process.poll(),
                "stderr": self._stderr.decode("utf-8", errors="replace"),
            },
        )


class LlvmSymbolizerResolver:
    """Resolve module offsets with a per-module process and bounded LRU cache."""

    resolver_version = "llvm-symbolizer-json-v1"

    def __init__(
        self,
        executable: Path | None = None,
        *,
        timeout_seconds: float = 5.0,
        max_cache_entries: int = 100_000,
    ) -> None:
        selected = executable or _find_llvm_symbolizer()
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "symbolization",
                "timeout_seconds must be finite and positive",
            )
        if max_cache_entries < 1:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "symbolization",
                "max_cache_entries must be positive",
            )
        self._executable = _validated_executable(selected)
        self._timeout_seconds = timeout_seconds
        self._max_cache_entries = max_cache_entries
        self._cache: OrderedDict[tuple[str, int, str], tuple[ResolvedFrame, ...]] = OrderedDict()
        self._processes: dict[Path, _LlvmProcess] = {}
        self._lock = threading.Lock()

    @property
    def process_count(self) -> int:
        return len(self._processes)

    @property
    def process_pids(self) -> tuple[int, ...]:
        return tuple(process.pid for process in self._processes.values())

    def resolve(
        self,
        module: ModuleIdentity,
        location: ModuleLocation,
    ) -> tuple[ResolvedFrame, ...]:
        return self.resolve_many(module, (location,))[0]

    def resolve_many(
        self,
        module: ModuleIdentity,
        locations: Sequence[ModuleLocation],
    ) -> tuple[tuple[ResolvedFrame, ...], ...]:
        offsets = tuple(_validated_offset(location) for location in locations)
        with self._lock:
            results: list[tuple[ResolvedFrame, ...] | None] = [None] * len(offsets)
            missing: list[tuple[int, int]] = []
            for index, offset in enumerate(offsets):
                key = (module.build_id, offset, self.resolver_version)
                cached = self._cache.get(key)
                if cached is None:
                    missing.append((index, offset))
                else:
                    self._cache.move_to_end(key)
                    results[index] = cached
            if missing:
                process = self._process_for(module)
                missing_offsets = [offset for _, offset in missing]
                resolved: list[tuple[ResolvedFrame, ...]] = []
                for start in range(0, len(missing_offsets), _QUERY_BATCH_SIZE):
                    resolved.extend(
                        process.query(missing_offsets[start : start + _QUERY_BATCH_SIZE])
                    )
                for (index, offset), frames in zip(missing, resolved, strict=True):
                    key = (module.build_id, offset, self.resolver_version)
                    self._cache[key] = frames
                    results[index] = frames
                    while len(self._cache) > self._max_cache_entries:
                        self._cache.popitem(last=False)
            if any(result is None for result in results):
                raise RuntimeError("symbolizer result alignment failure")
            return tuple(result for result in results if result is not None)

    def close(self) -> None:
        with self._lock:
            for process in self._processes.values():
                process.close()
            self._processes.clear()

    def __enter__(self) -> LlvmSymbolizerResolver:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _process_for(self, module: ModuleIdentity) -> _LlvmProcess:
        module_path = _select_module_path(module)
        process = self._processes.get(module_path)
        if process is None:
            process = _LlvmProcess(self._executable, module_path, self._timeout_seconds)
            self._processes[module_path] = process
        return process


def parse_llvm_json_line(line: bytes) -> tuple[ResolvedFrame, ...]:
    """Parse the stable subset of LLVM's JSON output used by PerfLens."""
    try:
        raw: object = json.loads(line)
    except json.JSONDecodeError as exc:
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "symbolization",
            "llvm-symbolizer returned invalid JSON",
            details={"preview": line[:200].decode("utf-8", errors="replace")},
        ) from exc
    raw_items = cast(list[object], raw) if isinstance(raw, list) else []
    empty_root: dict[str, object] = {}
    root_object: object = (
        (raw_items[0] if raw_items else empty_root) if isinstance(raw, list) else raw
    )
    root = cast(dict[str, object], root_object) if isinstance(root_object, dict) else {}
    symbols_object = root.get("Symbol", [])
    symbols = cast(list[object], symbols_object) if isinstance(symbols_object, list) else []
    frames: list[ResolvedFrame] = []
    for index, item_object in enumerate(symbols):
        if not isinstance(item_object, dict):
            continue
        item = cast(dict[str, object], item_object)
        symbol = str(item.get("FunctionName") or item.get("Function") or "unknown")
        filename = item.get("FileName") or item.get("File")
        parsed_line = _positive_int(item.get("Line"))
        column = _positive_int(item.get("Column"))
        frames.append(
            ResolvedFrame(
                symbol=symbol,
                file=Path(str(filename)) if filename not in {None, "", "??"} else None,
                line=parsed_line,
                column=column,
                is_inline=index + 1 < len(symbols),
            )
        )
    return tuple(frames) or (ResolvedFrame("unknown", None, None),)


def _positive_int(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None
    return value


def _validated_offset(location: ModuleLocation) -> int:
    if location.address_kind != "module_offset" or location.module_offset is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "symbolization",
            "A verified module-relative offset is required for symbolization",
            recoverable=True,
            details={"address_kind": location.address_kind},
        )
    if location.module_offset < 0:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "symbolization",
            "Module offset must be non-negative",
        )
    return location.module_offset


def _select_module_path(module: ModuleIdentity) -> Path:
    for candidate in (*module.debug_file_candidates, module.dso_path):
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    raise PerfLensError(
        ErrorCode.INVALID_INPUT,
        "symbolization",
        "No module or debug file candidate can be resolved",
        details={"dso_path": str(module.dso_path)},
    )


def _find_llvm_symbolizer() -> Path:
    discovered = shutil.which("llvm-symbolizer")
    if discovered is None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "symbolization",
            "llvm-symbolizer was not found",
            recoverable=True,
        )
    return Path(discovered)


def _validated_executable(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "symbolization",
            "llvm-symbolizer executable cannot be resolved",
            details={"path": str(path)},
        ) from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "symbolization",
            "llvm-symbolizer path is not an executable regular file",
            details={"path": str(resolved)},
        )
    return resolved


def llvm_symbolizer_path() -> Path | None:
    discovered = shutil.which("llvm-symbolizer")
    return Path(discovered).resolve(strict=True) if discovered is not None else None
