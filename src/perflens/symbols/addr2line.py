"""Cached, long-lived GNU/elfutils addr2line symbolization provider."""

from __future__ import annotations

import os
import re
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

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.symbols import ModuleIdentity, ModuleLocation, ResolvedFrame

_ADDRESS_LINE = re.compile(rb"^0x[0-9a-fA-F]+$")
_SOURCE_LINE = re.compile(r"^(?P<file>.*?):(?P<line>\d+)(?::(?P<column>\d+))?(?:\s+\(.*\))?$")


class _Addr2LineProcess:
    def __init__(self, executable: Path, module_path: Path, timeout_seconds: float) -> None:
        self._timeout_seconds = timeout_seconds
        self._buffer = bytearray()
        self._stderr = bytearray()
        self._selector = selectors.DefaultSelector()
        self._process = subprocess.Popen(  # noqa: S603 - canonical executable and module paths
            (
                str(executable),
                "-a",
                "-f",
                "-C",
                "-i",
                "-e",
                str(module_path),
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
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
            self._failed("addr2line process exited before a query")
        assert self._process.stdin is not None
        payload = "".join(f"0x{address:x}\n" for address in addresses) + "0x0\n"
        try:
            self._process.stdin.write(payload.encode("ascii"))
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise self._error("Unable to write to addr2line") from exc

        groups: list[list[bytes]] = []
        current: list[bytes] | None = None
        while True:
            line = self._read_line()
            if _ADDRESS_LINE.match(line):
                address = int(line, 16)
                if address == 0:
                    self._read_line()
                    self._read_line()
                    break
                current = []
                groups.append(current)
            elif current is not None:
                current.append(line)
        if len(groups) != len(addresses):
            self._failed("addr2line returned an unexpected number of address groups")
        return [self.parse_group(group) for group in groups]

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
        if self._process.stdin is not None:
            self._process.stdin.close()
        if self._process.stdout is not None:
            self._process.stdout.close()
        if self._process.stderr is not None:
            self._process.stderr.close()

    def _read_line(self) -> bytes:
        deadline = time.monotonic() + self._timeout_seconds
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._buffer[:newline]).rstrip(b"\r")
                del self._buffer[: newline + 1]
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._failed("addr2line response timed out", timeout=True)
            events = self._selector.select(timeout=min(remaining, 0.1))
            for key, _ in events:
                chunk = os.read(key.fd, 16 << 10)
                if not chunk:
                    self._selector.unregister(key.fileobj)
                    if key.data == "stdout":
                        self._failed("addr2line closed its output unexpectedly")
                    continue
                if key.data == "stdout":
                    self._buffer.extend(chunk)
                    if len(self._buffer) > 1 << 20:
                        self._failed("addr2line emitted an overlong response line")
                elif len(self._stderr) < 64 << 10:
                    self._stderr.extend(chunk[: (64 << 10) - len(self._stderr)])

    @staticmethod
    def parse_group(lines: Sequence[bytes]) -> tuple[ResolvedFrame, ...]:
        decoded = [line.decode("utf-8", errors="replace") for line in lines]
        frames: list[ResolvedFrame] = []
        for index in range(0, len(decoded) - 1, 2):
            symbol = decoded[index] or "unknown"
            source = decoded[index + 1]
            match = _SOURCE_LINE.match(source)
            if match is None or source in {"??:0", "??:?"}:
                file = None
                line = None
                column = None
            else:
                file = Path(match.group("file"))
                parsed_line = int(match.group("line"))
                parsed_column = match.group("column")
                line = parsed_line if parsed_line > 0 else None
                column = int(parsed_column) if parsed_column is not None else None
            frames.append(
                ResolvedFrame(
                    symbol=symbol,
                    file=file,
                    line=line,
                    column=column,
                    is_inline=index + 2 < len(decoded),
                )
            )
        return tuple(frames) or (ResolvedFrame("unknown", None, None),)

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

    def _failed(self, message: str, *, timeout: bool = False) -> None:
        raise self._error(message, timeout=timeout)


class Addr2LineResolver:
    """Resolve verified module offsets with process reuse and bounded LRU caching."""

    resolver_version = "addr2line-v1"

    def __init__(
        self,
        executable: Path | None = None,
        *,
        timeout_seconds: float = 5.0,
        max_cache_entries: int = 100_000,
    ) -> None:
        selected = executable or _find_addr2line()
        self._executable = selected.expanduser().resolve(strict=True)
        self._timeout_seconds = timeout_seconds
        self._max_cache_entries = max_cache_entries
        self._cache: OrderedDict[tuple[str, int, str], tuple[ResolvedFrame, ...]] = OrderedDict()
        self._processes: dict[Path, _Addr2LineProcess] = {}
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
        offsets = tuple(self._validated_offset(location) for location in locations)
        with self._lock:
            results: list[tuple[ResolvedFrame, ...] | None] = [None] * len(offsets)
            missing_offsets: list[int] = []
            missing_indices: list[int] = []
            for index, offset in enumerate(offsets):
                key = (module.build_id, offset, self.resolver_version)
                cached = self._cache.get(key)
                if cached is None:
                    missing_offsets.append(offset)
                    missing_indices.append(index)
                else:
                    self._cache.move_to_end(key)
                    results[index] = cached
            if missing_offsets:
                process = self._process_for(module)
                resolved = process.query(missing_offsets)
                for index, offset, frames in zip(
                    missing_indices, missing_offsets, resolved, strict=True
                ):
                    key = (module.build_id, offset, self.resolver_version)
                    self._cache[key] = frames
                    self._cache.move_to_end(key)
                    results[index] = frames
                    while len(self._cache) > self._max_cache_entries:
                        self._cache.popitem(last=False)
            return tuple(result for result in results if result is not None)

    def close(self) -> None:
        with self._lock:
            for process in self._processes.values():
                process.close()
            self._processes.clear()

    def __enter__(self) -> Addr2LineResolver:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _process_for(self, module: ModuleIdentity) -> _Addr2LineProcess:
        module_path = self._select_module_path(module)
        process = self._processes.get(module_path)
        if process is None:
            process = _Addr2LineProcess(self._executable, module_path, self._timeout_seconds)
            self._processes[module_path] = process
        return process

    @staticmethod
    def _select_module_path(module: ModuleIdentity) -> Path:
        candidates = (*module.debug_file_candidates, module.dso_path)
        for candidate in candidates:
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

    @staticmethod
    def _validated_offset(location: ModuleLocation) -> int:
        if location.address_kind != "module_offset" or location.module_offset is None:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "symbolization",
                "A verified module-relative offset is required for symbolization",
                recoverable=True,
                details={"address_kind": location.address_kind},
                suggested_actions=(
                    "Export mmap/build-id data or provide a verified module offset; "
                    "runtime IP is not guessed.",
                ),
            )
        if location.module_offset < 0:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "symbolization",
                "Module offset must be non-negative",
                details={"module_offset": location.module_offset},
            )
        return location.module_offset


def _find_addr2line() -> Path:
    discovered = shutil.which("eu-addr2line") or shutil.which("addr2line")
    if discovered is None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "symbolization",
            "No supported addr2line executable was found",
            recoverable=True,
        )
    return Path(discovered)


def parse_addr2line_group(lines: Sequence[bytes]) -> tuple[ResolvedFrame, ...]:
    """Parse one addr2line response group; exposed for provider contract tests."""
    return _Addr2LineProcess.parse_group(lines)
