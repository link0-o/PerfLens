"""A bounded subprocess runner for explicitly authorized external tools."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from collections.abc import Collection, Sequence
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
        self._allowed_executables = frozenset(
            executable.expanduser().resolve(strict=True) for executable in allowed_executables
        )

    def run_to_file(
        self,
        argv: Sequence[str],
        stdout: BinaryIO,
        *,
        limits: CommandLimits | None = None,
    ) -> CommandResult:
        effective_limits = limits or CommandLimits()
        safe_argv = self._validate_argv(argv)
        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        stderr_buffer = bytearray()
        stderr_bytes = 0
        stdout_bytes = 0
        stderr_truncated = False
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(  # noqa: S603 - executable is canonicalized and allowlisted
                safe_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
            assert process.stdout is not None
            assert process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
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
                        stdout.write(chunk)
                    else:
                        stderr_bytes += len(chunk)
                        remaining = effective_limits.max_stderr_bytes - len(stderr_buffer)
                        if remaining > 0:
                            stderr_buffer.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            stderr_truncated = True
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
