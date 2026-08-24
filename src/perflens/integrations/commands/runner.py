"""A bounded subprocess runner for explicitly authorized external tools."""

from __future__ import annotations

import math
import os
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Collection, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from perflens.domain.errors import ErrorCode, PerfLensError


@dataclass(frozen=True, slots=True)
class CommandLimits:
    timeout_seconds: float = 300.0
    terminate_grace_seconds: float = 1.0
    max_stdout_bytes: int = 1 << 30
    max_stderr_bytes: int = 1 << 20
    max_created_file_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout_bytes: int
    stderr_bytes: int
    stderr: str
    stderr_truncated: bool
    duration_seconds: float


class CommandRunner:
    """Run an absolute executable without a shell and drain both output pipes."""

    def __init__(self, allowed_executables: Collection[Path]) -> None:
        resolved_executables: set[Path] = set()
        for executable in allowed_executables:
            try:
                resolved = executable.expanduser().resolve(strict=True)
            except OSError as exc:
                raise PerfLensError(
                    ErrorCode.INVALID_INPUT,
                    "external_tool",
                    "Allowlisted executable cannot be resolved",
                    details={"executable": str(executable)},
                ) from exc
            if not resolved.is_file() or not os.access(resolved, os.X_OK):
                raise PerfLensError(
                    ErrorCode.INVALID_INPUT,
                    "external_tool",
                    "Allowlisted executable is not an executable regular file",
                    details={"executable": str(resolved)},
                )
            resolved_executables.add(resolved)
        self._allowed_executables = frozenset(resolved_executables)

    def run_to_file(
        self,
        argv: Sequence[str],
        stdout: BinaryIO,
        *,
        stdin: BinaryIO | None = None,
        limits: CommandLimits | None = None,
        watched_output: Path | None = None,
        pass_fds: Collection[int] = (),
        after_start: Callable[[], None] | None = None,
    ) -> CommandResult:
        effective_limits = limits or CommandLimits()
        self._validate_limits(effective_limits)
        safe_argv = self._validate_argv(argv)
        safe_pass_fds = self._validate_pass_fds(pass_fds)
        stdin_descriptor = self._validate_stdin(stdin)
        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        stderr_buffer = bytearray()
        stderr_bytes = 0
        stdout_bytes = 0
        stderr_truncated = False
        selector = selectors.DefaultSelector()
        try:
            try:
                process = subprocess.Popen(  # noqa: S603 - canonicalized and allowlisted
                    safe_argv,
                    stdin=(subprocess.DEVNULL if stdin_descriptor is None else stdin_descriptor),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    close_fds=True,
                    pass_fds=safe_pass_fds,
                    start_new_session=True,
                    env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                )
            except OSError as exc:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "external_tool",
                    "Unable to start the external tool",
                    recoverable=True,
                    details={"executable": safe_argv[0]},
                ) from exc
            if after_start is not None:
                after_start()
            assert process.stdout is not None
            assert process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                self._check_created_file(watched_output, effective_limits, process)
                if time.monotonic() - started > effective_limits.timeout_seconds:
                    self._terminate_group(process, effective_limits.terminate_grace_seconds)
                    raise PerfLensError(
                        ErrorCode.EXTERNAL_TOOL_TIMEOUT,
                        "external_tool",
                        "External tool exceeded its execution timeout",
                        recoverable=True,
                        retryable=True,
                        details={"timeout_seconds": effective_limits.timeout_seconds},
                    )
                events = selector.select(timeout=0.05)
                for key, _ in events:
                    chunk = os.read(key.fd, 64 << 10)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        stdout_bytes += len(chunk)
                        if stdout_bytes > effective_limits.max_stdout_bytes:
                            self._terminate_group(process, effective_limits.terminate_grace_seconds)
                            raise PerfLensError(
                                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                                "external_tool",
                                "External tool output exceeds max_stdout_bytes",
                                recoverable=True,
                                details={
                                    "actual_bytes": stdout_bytes,
                                    "max_stdout_bytes": effective_limits.max_stdout_bytes,
                                },
                            )
                        try:
                            stdout.write(chunk)
                        except (OSError, ValueError) as exc:
                            self._terminate_group(process, effective_limits.terminate_grace_seconds)
                            raise PerfLensError(
                                ErrorCode.OUTPUT_WRITE_FAILED,
                                "external_tool",
                                "Unable to write external tool output",
                            ) from exc
                    else:
                        stderr_bytes += len(chunk)
                        remaining = effective_limits.max_stderr_bytes - len(stderr_buffer)
                        if remaining > 0:
                            stderr_buffer.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            stderr_truncated = True
            self._check_created_file(watched_output, effective_limits, process)
            exit_code = process.wait()
            duration = time.monotonic() - started
            stderr_text = stderr_buffer.decode("utf-8", errors="replace")
            result = CommandResult(
                argv=safe_argv,
                exit_code=exit_code,
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
                stderr=stderr_text,
                stderr_truncated=stderr_truncated,
                duration_seconds=duration,
            )
            if exit_code != 0:
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "external_tool",
                    "External tool returned a non-zero exit code",
                    recoverable=True,
                    details={
                        "executable": safe_argv[0],
                        "exit_code": exit_code,
                        "stderr": stderr_text,
                        "stderr_truncated": stderr_truncated,
                    },
                )
            return result
        except BaseException:
            if process is not None and process.poll() is None:
                self._terminate_group(process, effective_limits.terminate_grace_seconds)
            raise
        finally:
            selector.close()
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    def _check_created_file(
        self,
        path: Path | None,
        limits: CommandLimits,
        process: subprocess.Popen[bytes],
    ) -> None:
        maximum = limits.max_created_file_bytes
        if path is None or maximum is None:
            return
        try:
            actual = path.stat().st_size
        except FileNotFoundError:
            return
        except OSError as exc:
            self._terminate_group(process, limits.terminate_grace_seconds)
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                "external_tool",
                "Unable to inspect the external tool output",
                details={"path": str(path)},
            ) from exc
        if actual > maximum:
            self._terminate_group(process, limits.terminate_grace_seconds)
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "external_tool",
                "External tool created output beyond its size limit",
                recoverable=True,
                details={"actual_bytes": actual, "max_created_file_bytes": maximum},
            )

    def _validate_argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        if not argv:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "External command must not be empty",
            )
        executable = Path(argv[0]).expanduser()
        if not executable.is_absolute():
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "external_tool",
                "External executable path must be absolute",
                details={"executable": str(executable)},
            )
        try:
            resolved = executable.resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "External executable does not exist",
                details={"executable": str(executable)},
            ) from exc
        if resolved not in self._allowed_executables:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "external_tool",
                "External executable is not allowlisted",
                details={"executable": str(resolved)},
            )
        return (str(resolved), *argv[1:])

    @staticmethod
    def _validate_stdin(stdin: BinaryIO | None) -> int | None:
        if stdin is None:
            return None
        try:
            descriptor = stdin.fileno()
            metadata = os.fstat(descriptor)
        except (OSError, ValueError) as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "External command input must be an open regular file",
            ) from exc
        if descriptor < 0 or not stat.S_ISREG(metadata.st_mode):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "External command input must be an open regular file",
            )
        return descriptor

    @staticmethod
    def _validate_pass_fds(pass_fds: Collection[int]) -> tuple[int, ...]:
        if len(pass_fds) > 8:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "external_tool",
                "External command file-descriptor allowance exceeds the fixed limit",
            )
        validated: list[int] = []
        for descriptor in pass_fds:
            if type(descriptor) is not int or descriptor < 0:
                raise PerfLensError(
                    ErrorCode.INVALID_INPUT,
                    "external_tool",
                    "External command file descriptors must be non-negative integers",
                )
            try:
                os.fstat(descriptor)
            except OSError as exc:
                raise PerfLensError(
                    ErrorCode.INVALID_INPUT,
                    "external_tool",
                    "External command file descriptor is not open",
                ) from exc
            if descriptor not in validated:
                validated.append(descriptor)
        return tuple(validated)

    @staticmethod
    def _validate_limits(limits: CommandLimits) -> None:
        if not math.isfinite(limits.timeout_seconds) or limits.timeout_seconds <= 0:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "timeout_seconds must be finite and positive",
            )
        if not math.isfinite(limits.terminate_grace_seconds) or limits.terminate_grace_seconds < 0:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "terminate_grace_seconds must be finite and non-negative",
            )
        byte_limits = {
            "max_stdout_bytes": limits.max_stdout_bytes,
            "max_stderr_bytes": limits.max_stderr_bytes,
            "max_created_file_bytes": limits.max_created_file_bytes,
        }
        if any(value is not None and value < 0 for value in byte_limits.values()):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "Command byte limits must be non-negative",
                details=byte_limits,
            )

    @staticmethod
    def _terminate_group(process: subprocess.Popen[bytes], grace_seconds: float) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + grace_seconds
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        process.wait()
