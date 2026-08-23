"""Adapter from ``perf.data`` to the supported text parser via system perf."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.domain.models import (
    FrameTable,
    ParseDiagnostics,
    ParseWarning,
    ProfileConversionProvenance,
    ResourceLimits,
    StackSample,
)
from perflens.domain.ports import ProfileSource
from perflens.integrations.commands.runner import CommandLimits, CommandResult, CommandRunner
from perflens.profiles.perf_script import (
    PERF_SCRIPT_FIELDS,
    PERF_SCRIPT_FIELDS_WITHOUT_CPU,
    PERF_SCRIPT_PARSER_VERSION,
    PerfScriptStream,
)
from perflens.stacks.normalize import SYMBOL_NORMALIZATION_VERSION

_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class PerfDataAdapter:
    """Convert perf's binary container using an allowlisted ``perf script`` command."""

    def __init__(
        self,
        perf_path: Path | None = None,
        *,
        timeout_seconds: float = 300.0,
        symfs_path: Path | None = None,
        symfs_identity_sha256: str | None = None,
    ) -> None:
        selected = perf_path or _find_perf()
        try:
            self._perf_path = selected.expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "external_tool",
                "perf executable cannot be resolved",
                details={"path": str(selected)},
            ) from exc
        self._timeout_seconds = timeout_seconds
        self._runner = CommandRunner({self._perf_path})
        if (symfs_path is None) != (symfs_identity_sha256 is None):
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "container_symbols",
                "A verified symfs path and identity must be supplied together",
            )
        self._symfs_path: Path | None = None
        self._symfs_identity_sha256: str | None = None
        if symfs_path is not None and symfs_identity_sha256 is not None:
            try:
                resolved_symfs = symfs_path.expanduser().resolve(strict=True)
                metadata = resolved_symfs.stat(follow_symlinks=False)
            except OSError as exc:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "container_symbols",
                    "Verified container symfs is unavailable",
                ) from exc
            if (
                resolved_symfs != symfs_path.expanduser().absolute()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022
                or _SHA256.fullmatch(symfs_identity_sha256) is None
            ):
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "container_symbols",
                    "Verified container symfs identity or permissions are unsafe",
                )
            self._symfs_path = resolved_symfs
            self._symfs_identity_sha256 = symfs_identity_sha256

    def can_handle(self, source: ProfileSource) -> bool:
        return source.source_type == "perf_data" or source.path.name.endswith("perf.data")

    def open(self, source: ProfileSource, limits: ResourceLimits) -> PerfDataStream:
        if not self.can_handle(source):
            raise PerfLensError(
                ErrorCode.UNSUPPORTED_FORMAT,
                "input",
                f"PerfDataAdapter cannot handle source type {source.source_type!r}",
                details={"source_type": source.source_type},
            )
        return PerfDataStream(
            source.path,
            limits,
            perf_path=self._perf_path,
            runner=self._runner,
            timeout_seconds=self._timeout_seconds,
            symfs_path=self._symfs_path,
            symfs_identity_sha256=self._symfs_identity_sha256,
        )


class PerfDataStream:
    """Materialize bounded perf-script text in a private temporary directory."""

    __slots__ = (
        "_argv",
        "_converter_diagnostics",
        "_converter_sha256",
        "_converter_version",
        "_limits",
        "_path",
        "_perf_path",
        "_runner",
        "_sample_cpu_missing",
        "_script_stream",
        "_symfs_identity_sha256",
        "_symfs_path",
        "_temporary_directory",
        "_timeout_seconds",
        "_transcript_bytes",
        "_transcript_sha256",
    )

    def __init__(
        self,
        path: Path,
        limits: ResourceLimits,
        *,
        perf_path: Path,
        runner: CommandRunner,
        timeout_seconds: float,
        symfs_path: Path | None,
        symfs_identity_sha256: str | None,
    ) -> None:
        self._path = path
        self._limits = limits
        self._perf_path = perf_path
        self._runner = runner
        self._timeout_seconds = timeout_seconds
        self._symfs_path = symfs_path
        self._symfs_identity_sha256 = symfs_identity_sha256
        self._sample_cpu_missing = False
        self._argv: tuple[str, ...] = ()
        self._converter_diagnostics: tuple[str, ...] = ()
        self._converter_sha256: str | None = None
        self._converter_version: str | None = None
        self._transcript_bytes = 0
        self._transcript_sha256: str | None = None
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self._script_stream: PerfScriptStream | None = None

    @property
    def frame_table(self) -> FrameTable:
        if self._script_stream is None:
            raise RuntimeError("ProfileStream must be entered before accessing frames")
        return self._script_stream.frame_table

    def __enter__(self) -> Self:
        try:
            safe_input = self._path.expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "input",
                "perf.data input cannot be resolved",
                details={"path": str(self._path)},
            ) from exc
        if not safe_input.is_file():
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "input",
                "perf.data input is not a regular file",
                details={"path": str(safe_input)},
            )
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="perflens-perf-script-")
        text_path = Path(self._temporary_directory.name) / "profile.perf-script"
        try:
            self._inspect_converter(Path(self._temporary_directory.name))
            try:
                result = self._run_perf_script(
                    safe_input, text_path, PERF_SCRIPT_FIELDS, exclusive=True
                )
            except PerfLensError as exc:
                if not _is_missing_sample_cpu_error(exc):
                    raise
                self._sample_cpu_missing = True
                result = self._run_perf_script(
                    safe_input,
                    text_path,
                    PERF_SCRIPT_FIELDS_WITHOUT_CPU,
                    exclusive=False,
                )
            self._argv = self._provenance_argv(result.argv)
            self._capture_converter_diagnostics(result)
            self._transcript_sha256, self._transcript_bytes = _sha256_file(text_path)
            if _sha256_file(self._perf_path)[0] != self._converter_sha256:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    "external_tool",
                    "perf executable changed during profile conversion",
                    details={"path": str(self._perf_path)},
                )
            self._script_stream = PerfScriptStream(text_path, self._limits)
            self._script_stream.__enter__()
            if self._sample_cpu_missing:
                self._script_stream.diagnostics().add_warning(
                    ParseWarning(
                        code="MISSING_SAMPLE_CPU",
                        message=(
                            "perf.data has no sample CPU attribute; analysis continued without "
                            "per-sample CPU identity."
                        ),
                    )
                )
            for diagnostic in self._converter_diagnostics:
                self._script_stream.diagnostics().add_warning(
                    ParseWarning(
                        code="PERF_SCRIPT_DIAGNOSTIC",
                        message="perf script emitted a conversion diagnostic",
                        preview=diagnostic,
                    )
                )
            return self
        except BaseException:
            self._cleanup()
            raise

    def _run_perf_script(
        self,
        safe_input: Path,
        text_path: Path,
        fields: str,
        *,
        exclusive: bool,
    ) -> CommandResult:
        mode = "xb" if exclusive else "wb"
        argv = [
            str(self._perf_path),
            "script",
            "--force",
            "--ns",
        ]
        if self._symfs_path is not None:
            # perf's default inline expansion can emit synthetic inline Frames
            # that contain an IP and symbol but no DSO.  That representation is
            # ambiguous after the target container exits, so container analysis
            # deliberately keeps the physical Frame and its verified module
            # identity.  Full source paths are required for a fail-closed mapping
            # back into the explicitly authorized project workspace.
            argv.extend(
                (
                    "--no-inline",
                    "--full-source-path",
                    "--symfs",
                    str(self._symfs_path),
                )
            )
        argv.extend(("-F", fields, "-i", str(safe_input)))
        with text_path.open(mode) as output:
            return self._runner.run_to_file(
                tuple(argv),
                output,
                limits=CommandLimits(
                    timeout_seconds=self._timeout_seconds,
                    max_stdout_bytes=self._limits.max_input_bytes,
                ),
            )

    def _inspect_converter(self, temporary_root: Path) -> None:
        self._converter_sha256 = _sha256_file(self._perf_path)[0]
        version_path = temporary_root / "perf-version.txt"
        with version_path.open("xb") as output:
            result = self._runner.run_to_file(
                (str(self._perf_path), "--version"),
                output,
                limits=CommandLimits(
                    timeout_seconds=min(self._timeout_seconds, 10.0),
                    max_stdout_bytes=4 << 10,
                    max_stderr_bytes=4 << 10,
                ),
            )
        version = version_path.read_text(encoding="utf-8", errors="replace").strip()
        self._converter_version = version[:512] or None
        self._capture_converter_diagnostics(result)

    def _capture_converter_diagnostics(self, result: CommandResult) -> None:
        diagnostic = result.stderr.strip()
        if not diagnostic:
            return
        bounded = diagnostic[:2_048]
        self._converter_diagnostics = (*self._converter_diagnostics, bounded)

    def conversion_provenance(self) -> ProfileConversionProvenance:
        if self._transcript_sha256 is None or self._converter_sha256 is None:
            raise RuntimeError("ProfileStream must be entered before reading provenance")
        compatibility_fallbacks = ("missing_sample_cpu",) if self._sample_cpu_missing else ()
        if self._symfs_identity_sha256 is not None:
            compatibility_fallbacks = (
                *compatibility_fallbacks,
                f"verified_container_symfs_sha256:{self._symfs_identity_sha256}",
            )
        return ProfileConversionProvenance(
            adapter="perf_data",
            parser_version=PERF_SCRIPT_PARSER_VERSION,
            normalization_version=SYMBOL_NORMALIZATION_VERSION,
            converter_path=str(self._perf_path),
            converter_sha256=self._converter_sha256,
            converter_version=self._converter_version,
            argv=self._argv,
            locale="C",
            transcript_sha256=self._transcript_sha256,
            transcript_bytes=self._transcript_bytes,
            compatibility_fallbacks=compatibility_fallbacks,
            diagnostics=self._converter_diagnostics,
        )

    def _provenance_argv(self, argv: tuple[str, ...]) -> tuple[str, ...]:
        if self._symfs_path is None or self._symfs_identity_sha256 is None:
            return argv
        placeholder = f"@VERIFIED_CONTAINER_SYMFS_SHA256:{self._symfs_identity_sha256}"
        return tuple(placeholder if item == str(self._symfs_path) else item for item in argv)

    def __iter__(self) -> Iterator[StackSample]:
        if self._script_stream is None:
            raise RuntimeError("ProfileStream must be entered before iteration")
        return iter(self._script_stream)

    def diagnostics(self) -> ParseDiagnostics:
        if self._script_stream is None:
            raise RuntimeError("ProfileStream must be entered before diagnostics")
        return self._script_stream.diagnostics()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._script_stream is not None:
            self._script_stream.__exit__(exc_type, exc_value, traceback)
        self._cleanup()

    def _cleanup(self) -> None:
        self._script_stream = None
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None


def _find_perf() -> Path:
    discovered = shutil.which("perf")
    if discovered is None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "external_tool",
            "System perf executable was not found",
            recoverable=True,
            suggested_actions=("Install Linux perf or pass an explicit --perf-path.",),
        )
    return Path(discovered)


def _is_missing_sample_cpu_error(error: PerfLensError) -> bool:
    if error.code is not ErrorCode.EXTERNAL_TOOL_FAILED:
        return False
    stderr = error.details.get("stderr")
    return (
        isinstance(stderr, str)
        and "do not have CPU attribute set" in stderr
        and "Cannot print 'cpu' field" in stderr
    )


def _sha256_file(path: Path, *, chunk_size: int = 1 << 20) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            total += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), total
