"""Bounded container module snapshots and workspace source mappings.

Docker paths are private adapter data.  Public artifacts retain only salted path
digests, Build IDs, content hashes, and paths proven to remain inside the
authorized project workspace.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from perflens import __version__
from perflens.application.evidence import (
    compute_analysis_content_sha256,
    compute_analysis_fingerprint,
    contract_content_sha256,
    verify_collection_artifact,
)
from perflens.application.verify_analysis import verify_analysis_artifact
from perflens.collection.collector import DEFAULT_MAX_OUTPUT_BYTES
from perflens.contracts.artifacts import AnalysisArtifact, CollectionArtifact
from perflens.contracts.docker import (
    ContainerModuleEvidence,
    ContainerModuleSnapshotArtifact,
    ContainerModuleSnapshotLimits,
    ContainerSourceMappingEvidence,
    ContainerSymbolContextArtifact,
    derive_container_module_snapshot_id,
    derive_container_symbol_context_id,
)
from perflens.docker.identity import (
    LinuxContainerIdentityReader,
    assert_container_target_current,
)
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.integrations.commands.runner import CommandLimits, CommandRunner
from perflens.security.paths import validate_input_file
from perflens.symbols.elf import read_elf_build_id
from perflens.symbols.source import PathMapping, SourceLocator

_BUILD_ID_LINE = re.compile(r"^(?P<build_id>[a-fA-F0-9]{8,128})\s+(?P<path>.+)$")
_SOURCE_LOCATION_WITH_LINE = re.compile(
    r"^(?P<path>.+):(?P<line>[1-9][0-9]*)(?::[1-9][0-9]*)?$"
)
_REDACTED_DIAGNOSTIC = re.compile(r"^redacted-diagnostic-sha256:[a-f0-9]{64}$")
_REDACTED_PREVIEW = re.compile(r"^redacted-preview-sha256:[a-f0-9]{64}$")
_RECIPE_ID = "perf-buildid-list-with-hits-v1"
_MAX_BUILD_ID_LINES = 4096
_MAX_BUILD_ID_LINE_CHARS = 8192
_MAX_SOURCE_MAPPINGS = 256
_HASH_CHUNK_BYTES = 1 << 20
_DEFAULT_CONTAINER_WORKSPACE = PurePosixPath("/workspace")


@dataclass(frozen=True, slots=True)
class RecordedModule:
    build_id: str
    container_path: str


@dataclass(frozen=True, slots=True)
class BuildIdListResult:
    records: tuple[RecordedModule, ...]
    observed_record_count: int
    records_truncated: bool
    diagnostic_count: int
    adapter_sha256: str


class PerfBuildIdListAdapter:
    """Run one fixed ``perf buildid-list --with-hits`` conversion."""

    def __init__(
        self,
        perf_path: Path | None = None,
        *,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 1 << 20,
    ) -> None:
        selected = perf_path or _find_perf()
        try:
            self._perf_path = selected.expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "container_symbols",
                "perf executable cannot be resolved for container module inspection",
            ) from exc
        if timeout_seconds <= 0 or max_output_bytes < 1 or max_output_bytes > 16 << 20:
            raise PerfLensError(
                ErrorCode.INVALID_INPUT,
                "container_symbols",
                "container Build ID adapter limits are invalid",
            )
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._runner = CommandRunner({self._perf_path})

    def inspect(self, profile_path: Path) -> BuildIdListResult:
        safe_profile = validate_input_file(profile_path)
        perf_before, _ = _sha256_path(self._perf_path)
        with tempfile.TemporaryFile(mode="w+b") as output:
            self._runner.run_to_file(
                (
                    str(self._perf_path),
                    "buildid-list",
                    "--with-hits",
                    "-i",
                    str(safe_profile),
                ),
                output,
                limits=CommandLimits(
                    timeout_seconds=self._timeout_seconds,
                    max_stdout_bytes=self._max_output_bytes,
                    max_stderr_bytes=64 << 10,
                ),
            )
            output.seek(0)
            payload = output.read(self._max_output_bytes + 1)
        if len(payload) > self._max_output_bytes:
            raise PerfLensError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "container_symbols",
                "perf Build ID output exceeded its fixed bound",
                recoverable=True,
            )
        perf_after, _ = _sha256_path(self._perf_path)
        if perf_after != perf_before:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "container_symbols",
                "perf executable changed during container module inspection",
            )
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PerfLensError(
                ErrorCode.PROFILE_PARSE_FAILED,
                "container_symbols",
                "perf Build ID output is not lossless UTF-8",
            ) from exc
        records: list[RecordedModule] = []
        diagnostics = 0
        observed = 0
        truncated = False
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line_number > _MAX_BUILD_ID_LINES:
                truncated = True
                break
            if not line or len(line) > _MAX_BUILD_ID_LINE_CHARS:
                diagnostics += 1
                continue
            match = _BUILD_ID_LINE.fullmatch(line)
            if match is None:
                diagnostics += 1
                continue
            container_path = match.group("path")
            if not _is_safe_container_module_path(container_path):
                # Kernel pseudo-DSOs and malformed paths are never opened below rootfs.
                diagnostics += 1
                continue
            observed += 1
            records.append(
                RecordedModule(
                    build_id=match.group("build_id").lower(),
                    container_path=container_path,
                )
            )
        records.sort(key=lambda item: (item.container_path, item.build_id))
        return BuildIdListResult(
            records=tuple(records),
            observed_record_count=observed,
            records_truncated=truncated,
            diagnostic_count=diagnostics,
            adapter_sha256=_adapter_identity(perf_before),
        )


def capture_container_module_snapshot(
    collection: CollectionArtifact,
    *,
    perf_path: Path | None = None,
    proc_root: Path = Path("/proc"),
    reader: LinuxContainerIdentityReader | None = None,
    build_id_reader: Callable[[Path], BuildIdListResult] | None = None,
    limits: ContainerModuleSnapshotLimits | None = None,
    created_at: datetime | None = None,
) -> ContainerModuleSnapshotArtifact:
    """Capture only modules with hits in one Docker record Collection.

    Runtime/environment failures yield a truthful partial artifact.  Contract or
    Collection mismatches remain hard failures because no trustworthy binding can
    be published in that case.
    """
    if (
        collection.target_runtime != "docker"
        or collection.container_target is None
        or collection.mode != "record"
        or collection.output_format != "perf_data"
    ):
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "container_symbols",
            "container module snapshots require one Docker record Collection",
        )
    # A module snapshot is derived from immutable raw profile evidence.  Re-hash the
    # profile before invoking perf so a replaced or truncated file cannot be bound to
    # the Collection's stale content digest.  This is deliberately outside the
    # recoverable runtime block below: an unavailable container root may produce a
    # truthful partial snapshot, but raw-evidence tampering must fail closed.
    verify_collection_artifact(
        collection,
        max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
    )
    effective_limits = limits or ContainerModuleSnapshotLimits(
        max_modules=64,
        max_module_bytes=64 << 20,
        max_total_module_bytes=256 << 20,
        max_build_id_output_bytes=1 << 20,
    )
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "container_symbols",
            "container module snapshot timestamp must include a timezone",
        )
    target = collection.container_target
    limitations: list[str] = []
    modules: list[ContainerModuleEvidence] = []
    referenced_count = 0
    modules_truncated = False
    root_identity_sha256: str | None = None
    adapter_sha256 = hashlib.sha256(f"{_RECIPE_ID}\0unavailable".encode()).hexdigest()
    try:
        with _private_profile_snapshot(collection) as profile_snapshot:
            result = (
                build_id_reader(profile_snapshot)
                if build_id_reader is not None
                else PerfBuildIdListAdapter(
                    perf_path,
                    max_output_bytes=effective_limits.max_build_id_output_bytes,
                ).inspect(profile_snapshot)
            )
        adapter_sha256 = result.adapter_sha256
        if result.diagnostic_count:
            limitations.append("Some perf Build ID records were malformed or unsupported.")
        if result.records_truncated:
            limitations.append("Perf Build ID records exceeded their bounded line limit.")
        unique_records, duplicate_conflict = _unique_recorded_modules(result.records)
        if duplicate_conflict:
            limitations.append("A module path had conflicting recorded Build IDs.")
        referenced_count = len(unique_records)
        selected_records = unique_records[: effective_limits.max_modules]
        modules_truncated = referenced_count > len(selected_records) or result.records_truncated
        if modules_truncated:
            limitations.append("Referenced container modules were truncated by policy.")
        assert_container_target_current(target, reader=reader)
        with _PinnedProcessRoot(proc_root, target.host_pid) as pinned_root:
            root_identity_sha256 = _root_identity_sha256(
                target.container_identity_sha256,
                target.namespace.mount_namespace_inode,
                pinned_root.identity,
            )
            consumed_bytes = 0
            for record in selected_records:
                module, charged_bytes = pinned_root.inspect_module(
                    record,
                    container_identity_sha256=target.container_identity_sha256,
                    remaining_bytes=max(
                        0,
                        effective_limits.max_total_module_bytes - consumed_bytes,
                    ),
                    max_module_bytes=effective_limits.max_module_bytes,
                )
                consumed_bytes += charged_bytes
                modules.append(module)
            assert_container_target_current(target, reader=reader)
            pinned_root.assert_unchanged()
    except PerfLensError as exc:
        if exc.stage == "evidence_validation":
            raise
        limitations.append(
            "The target process root or perf module inventory was unavailable; "
            "no module was guessed."
        )
        modules = []
        referenced_count = max(referenced_count, len(modules))
        modules_truncated = referenced_count > 0
        root_identity_sha256 = None

    modules.sort(key=lambda item: item.container_path_sha256)
    if any(item.status != "verified" for item in modules):
        limitations.append("One or more container modules failed identity verification.")
    if not modules:
        limitations.append("No container module could be verified from the sampled mappings.")
    limitation_tuple = tuple(dict.fromkeys(limitations))
    provisional = ContainerModuleSnapshotArtifact(
        perflens_version=__version__,
        module_snapshot_id=derive_container_module_snapshot_id(collection.collection_id),
        created_at=timestamp.isoformat(),
        source_collection_id=collection.collection_id,
        source_output_sha256=collection.output_sha256,
        container_target_id=target.target_id,
        container_target_content_sha256=target.target_content_sha256,
        container_identity_sha256=target.container_identity_sha256,
        mount_namespace_inode=target.namespace.mount_namespace_inode,
        process_root_identity_sha256=root_identity_sha256,
        adapter_recipe_id=_RECIPE_ID,
        adapter_sha256=adapter_sha256,
        status="partial" if limitation_tuple else "verified",
        referenced_module_count=referenced_count,
        modules=tuple(modules),
        modules_truncated=modules_truncated,
        limits=effective_limits,
        limitations=limitation_tuple,
        allowed_conclusions=(
            "Verified module records match capture-time perf Build IDs and stable content hashes.",
            "Only modules referenced by perf build-id hits were opened beneath the target root.",
        ),
        forbidden_conclusions=(
            "The snapshot does not expose or enumerate unrelated container files.",
            "Unavailable or mismatched modules cannot be guessed from a path or address.",
            "A partial module snapshot cannot support complete container symbol attribution.",
        ),
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def build_container_symbol_context(
    analysis: AnalysisArtifact,
    snapshot: ContainerModuleSnapshotArtifact,
    *,
    workspace_root: Path | None,
    container_workspace: PurePosixPath = _DEFAULT_CONTAINER_WORKSPACE,
    created_at: datetime | None = None,
) -> ContainerSymbolContextArtifact:
    _require_contract_content(
        snapshot,
        snapshot.content_sha256,
        "container module snapshot content digest does not match its evidence",
    )
    verify_analysis_artifact(analysis, verify_source=False)
    collection = analysis.metadata.collection
    if (
        collection is None
        or collection.target_runtime != "docker"
        or collection.collection_id != snapshot.source_collection_id
        or collection.output_sha256 != snapshot.source_output_sha256
        or collection.container_target_id != snapshot.container_target_id
        or collection.container_target_content_sha256
        != snapshot.container_target_content_sha256
    ):
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "container_symbols",
            "container symbol context does not match its Analysis and module snapshot",
        )
    safe_workspace: Path | None = None
    if workspace_root is not None:
        try:
            safe_workspace = workspace_root.expanduser().resolve(strict=True)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "container_symbols",
                "authorized Docker workspace is unavailable",
            ) from exc
        if not safe_workspace.is_dir():
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "container_symbols",
                "authorized Docker workspace is not a directory",
            )
    timestamp = created_at or datetime.now(tz=UTC)
    if timestamp.tzinfo is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            "container_symbols",
            "container symbol context timestamp must include a timezone",
        )
    source_locations = _analysis_source_locations(analysis)
    exported_locations = source_locations[:_MAX_SOURCE_MAPPINGS]
    truncated = len(source_locations) > len(exported_locations) or any(
        hotspot.source_locations_truncated or hotspot.symbol_variants_truncated
        for hotspot in analysis.hotspots
    )
    locator = (
        SourceLocator(
            safe_workspace,
            (
                PathMapping(
                    Path(str(container_workspace)),
                    safe_workspace,
                ),
            ),
        )
        if safe_workspace is not None
        else None
    )
    mappings: list[ContainerSourceMappingEvidence] = []
    limitations = list(snapshot.limitations)
    if locator is None:
        limitations.append(
            "No authorized Docker workspace was available for source-path mapping."
        )
    for source_path, line in exported_locations:
        path_digest = _private_path_digest(
            snapshot.container_identity_sha256,
            source_path,
            domain="source",
        )
        status = "unmapped"
        relative: str | None = None
        try:
            if locator is None or safe_workspace is None:
                raise LookupError("authorized workspace is unavailable")
            if not _is_beneath_prefix(source_path, container_workspace):
                raise ValueError("source is not below the authorized container workspace")
            mapped = locator.map_path(Path(source_path))
            relative = mapped.relative_to(safe_workspace).as_posix()
            status = "mapped"
        except PerfLensError:
            status = "rejected"
        except LookupError:
            status = "unavailable"
        except (OSError, ValueError):
            status = "unmapped"
        mappings.append(
            ContainerSourceMappingEvidence(
                container_source_path_sha256=path_digest,
                line=line,
                workspace_relative_path=relative,
                status=status,
            )
        )
    mappings.sort(key=lambda item: (item.container_source_path_sha256, item.line or 0))
    if truncated:
        limitations.append("Container source locations were truncated by policy.")
    if source_locations and any(item.status != "mapped" for item in mappings):
        limitations.append("Some container source paths could not be mapped into the workspace.")
    if not source_locations:
        limitations.append("The sampled profile did not provide container source locations.")
    limitation_tuple = tuple(dict.fromkeys(limitations))
    provisional = ContainerSymbolContextArtifact(
        perflens_version=__version__,
        symbol_context_id=derive_container_symbol_context_id(analysis.analysis_id),
        created_at=timestamp.isoformat(),
        source_analysis_id=analysis.analysis_id,
        source_analysis_content_sha256=analysis.content_sha256,
        source_collection_id=collection.collection_id,
        module_snapshot_id=snapshot.module_snapshot_id,
        module_snapshot_content_sha256=snapshot.content_sha256,
        container_target_id=snapshot.container_target_id,
        container_identity_sha256=snapshot.container_identity_sha256,
        quality_status="partial" if limitation_tuple else "verified",
        module_count=len(snapshot.modules),
        source_location_count=len(source_locations),
        source_mappings=tuple(mappings),
        source_mappings_truncated=truncated,
        limitations=limitation_tuple,
        allowed_conclusions=(
            "Mapped source paths were proven to remain inside the authorized project workspace.",
            "Module evidence is bound to the exact Collection and Analysis content digests.",
        ),
        forbidden_conclusions=(
            "Unmapped source paths cannot be used for exact source attribution.",
            "Container configuration, secrets, labels, and unrelated rootfs files are not "
            "evidence.",
            "Partial symbol evidence cannot support an unqualified profile conclusion.",
        ),
        content_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            )
        }
    )


def project_container_analysis(
    analysis: AnalysisArtifact,
    context: ContainerSymbolContextArtifact,
) -> tuple[AnalysisArtifact, ContainerSymbolContextArtifact]:
    """Create the privacy-safe public Analysis projection for one Docker profile.

    The parser's raw module and source paths are private conversion data.  The
    public Analysis keeps the same measured weights and collection binding while
    replacing those paths with per-container digests or workspace-relative paths.
    The returned symbol context is rebound to the projected Analysis digest.
    """
    verify_analysis_artifact(analysis, verify_source=False)
    _require_contract_content(
        context,
        context.content_sha256,
        "container symbol context content digest does not match its evidence",
    )
    collection = analysis.metadata.collection
    if (
        collection is None
        or collection.target_runtime != "docker"
        or collection.container_target_id != context.container_target_id
        or collection.collection_id != context.source_collection_id
        or context.source_analysis_id != analysis.analysis_id
        or context.source_analysis_content_sha256 != analysis.content_sha256
    ):
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "container_symbols",
            "container Analysis projection does not match its verified symbol context",
        )
    mapping_by_location = {
        (item.container_source_path_sha256, item.line): item
        for item in context.source_mappings
    }

    def public_symbol(value: str) -> str:
        if "/" not in value and "\\" not in value and "\x00" not in value:
            return value
        return "container-symbol-sha256:" + _private_text_digest(
            context.container_identity_sha256,
            value,
            domain="normalized-symbol",
        )

    def public_dso(value: str) -> str:
        if value.startswith("[") and value.endswith("]") and "/" not in value:
            return value
        if "/" not in value and "\\" not in value and "\x00" not in value:
            return value
        digest = _private_path_digest(
            context.container_identity_sha256,
            value,
            domain="module",
        )
        return f"container-module-sha256:{digest}"

    def public_source(value: str) -> str | None:
        parsed = _parse_source_location(value)
        if parsed is None:
            return None
        source_path, line = parsed
        digest = _private_path_digest(
            context.container_identity_sha256,
            source_path,
            domain="source",
        )
        mapping = mapping_by_location.get((digest, line))
        if mapping is not None and mapping.workspace_relative_path is not None:
            return (
                f"{mapping.workspace_relative_path}:{line}"
                if line is not None
                else mapping.workspace_relative_path
            )
        return (
            f"container-source-sha256:{digest}:{line}"
            if line is not None
            else f"container-source-sha256:{digest}"
        )

    def public_symbol_variant(
        value: str,
        *,
        normalized_symbol: str,
        projected_symbol: str,
    ) -> str:
        prefix = f"{normalized_symbol}:"
        if value.startswith(prefix):
            projected_source = public_source(value[len(prefix) :])
            if projected_source is not None:
                return f"{projected_symbol}:{projected_source}"
        if "/" in value or "\\" in value or "\x00" in value:
            return "redacted-symbol-variant-sha256:" + _private_text_digest(
                context.container_identity_sha256,
                value,
                domain="symbol-variant",
            )
        return value

    hotspots = tuple(
        hotspot.model_copy(
            update={
                "symbol": public_symbol(hotspot.symbol),
                "dso": public_dso(hotspot.dso),
                "symbol_variants": tuple(
                    public_symbol_variant(
                        item,
                        normalized_symbol=hotspot.symbol,
                        projected_symbol=public_symbol(hotspot.symbol),
                    )
                    for item in hotspot.symbol_variants
                ),
                "source_locations": tuple(
                    sorted(
                        projected
                        for projected in (
                            public_source(location) for location in hotspot.source_locations
                        )
                        if projected is not None
                    )
                ),
                "top_callers": tuple(public_symbol(item) for item in hotspot.top_callers),
                "top_callees": tuple(public_symbol(item) for item in hotspot.top_callees),
            }
        )
        for hotspot in analysis.hotspots
    )
    call_paths = tuple(
        path.model_copy(
            update={
                "frames": tuple(
                    frame.model_copy(
                        update={
                            "symbol": public_symbol(frame.symbol),
                            "dso": public_dso(frame.dso),
                        }
                    )
                    for frame in path.frames
                )
            }
        )
        for path in analysis.call_paths
    )
    conversion = analysis.metadata.conversion.model_copy(
        update={
            "argv": tuple(
                (
                    "@PRIVATE_CONVERTER@"
                    if index == 0
                    else "@PRIVATE_INPUT@"
                    if item == analysis.metadata.input_path
                    else item
                )
                for index, item in enumerate(analysis.metadata.conversion.argv)
            ),
            "converter_path": "@PRIVATE_CONVERTER@",
            "diagnostics": tuple(
                "redacted-diagnostic-sha256:"
                + _private_text_digest(
                    context.container_identity_sha256,
                    item,
                    domain="converter-diagnostic",
                )
                for item in analysis.metadata.conversion.diagnostics
            ),
        }
    )
    metadata = analysis.metadata.model_copy(
        update={
            "input_path": "@PRIVATE_COLLECTION@",
            "conversion": conversion,
        }
    )
    warnings = tuple(
        warning.model_copy(
            update={
                "preview": (
                    "redacted-preview-sha256:"
                    + _private_text_digest(
                        context.container_identity_sha256,
                        warning.preview,
                        domain="warning-preview",
                    )
                    if warning.preview is not None
                    else None
                )
            }
        )
        for warning in analysis.warnings
    )
    fingerprint = compute_analysis_fingerprint(
        input_sha256=metadata.input_sha256,
        source_type=metadata.source_type,
        aggregation_semantics=analysis.aggregation_semantics,
        limits={key: int(value) for key, value in analysis.limits.model_dump().items()},
        conversion=conversion,
        collection=collection,
    )
    provisional_analysis = analysis.model_copy(
        update={
            "analysis_id": f"analysis-{fingerprint[:16]}",
            "analysis_fingerprint": fingerprint,
            "content_sha256": "0" * 64,
            "metadata": metadata,
            "hotspots": hotspots,
            "call_paths": call_paths,
            "warnings": warnings,
        }
    )
    projected_analysis = provisional_analysis.model_copy(
        update={"content_sha256": compute_analysis_content_sha256(provisional_analysis)}
    )
    provisional_context = context.model_copy(
        update={
            "symbol_context_id": derive_container_symbol_context_id(
                projected_analysis.analysis_id
            ),
            "source_analysis_id": projected_analysis.analysis_id,
            "source_analysis_content_sha256": projected_analysis.content_sha256,
            "content_sha256": "0" * 64,
        }
    )
    projected_context = provisional_context.model_copy(
        update={
            "content_sha256": contract_content_sha256(
                provisional_context,
                exclude={"content_sha256"},
            )
        }
    )
    verify_analysis_artifact(projected_analysis, verify_source=False)
    assert_public_container_analysis(projected_analysis)
    return projected_analysis, projected_context


def assert_public_container_analysis(analysis: AnalysisArtifact) -> None:
    """Reject a Docker Analysis that still contains private container paths."""
    collection = analysis.metadata.collection
    if collection is None or collection.target_runtime != "docker":
        return
    conversion = analysis.metadata.conversion
    public_argv = conversion.argv
    unsafe_values = [
        *(hotspot.symbol for hotspot in analysis.hotspots),
        *(hotspot.dso for hotspot in analysis.hotspots),
        *(item for hotspot in analysis.hotspots for item in hotspot.symbol_variants),
        *(item for hotspot in analysis.hotspots for item in hotspot.source_locations),
        *(item for hotspot in analysis.hotspots for item in hotspot.top_callers),
        *(item for hotspot in analysis.hotspots for item in hotspot.top_callees),
        *(frame.symbol for path in analysis.call_paths for frame in path.frames),
        *(frame.dso for path in analysis.call_paths for frame in path.frames),
    ]
    if (
        analysis.metadata.input_path != "@PRIVATE_COLLECTION@"
        or conversion.adapter != "perf_data"
        or conversion.converter_path != "@PRIVATE_CONVERTER@"
        or not public_argv
        or public_argv[0] != "@PRIVATE_CONVERTER@"
        or public_argv.count("@PRIVATE_INPUT@") != 1
        or any(
            _contains_private_path(item)
            for item in public_argv[1:]
            if item != "@PRIVATE_INPUT@"
        )
        or any(_contains_private_path(value) for value in unsafe_values)
        or any(
            _REDACTED_DIAGNOSTIC.fullmatch(item) is None
            for item in conversion.diagnostics
        )
        or any(
            warning.preview is not None
            and _REDACTED_PREVIEW.fullmatch(warning.preview) is None
            for warning in analysis.warnings
        )
    ):
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "container_symbols",
            "Docker Analysis contains unprojected private path evidence",
        )


class _PinnedProcessRoot:
    def __init__(self, proc_root: Path, host_pid: int) -> None:
        try:
            self._proc_root = proc_root.expanduser().resolve(strict=True)
        except OSError as exc:
            raise _symbol_error("configured procfs root is unavailable") from exc
        self._host_pid = host_pid
        self._root_fd: int | None = None
        self.identity: tuple[int, ...] = ()

    def __enter__(self) -> _PinnedProcessRoot:
        proc_metadata = self._proc_root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(proc_metadata.st_mode):
            raise _symbol_error("configured procfs root is unsafe")
        self._root_fd = self._open_current_root()
        metadata = os.fstat(self._root_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            self.close()
            raise _symbol_error("target process root is not a directory")
        self.identity = _stat_identity(metadata)
        return self

    def inspect_module(
        self,
        record: RecordedModule,
        *,
        container_identity_sha256: str,
        remaining_bytes: int,
        max_module_bytes: int,
    ) -> tuple[ContainerModuleEvidence, int]:
        path_digest = _private_path_digest(
            container_identity_sha256,
            record.container_path,
            domain="module",
        )
        try:
            descriptor = self._open_regular_beneath(record.container_path)
        except PerfLensError:
            return (
                ContainerModuleEvidence(
                    container_path_sha256=path_digest,
                    recorded_build_id=record.build_id,
                    status="unavailable",
                ),
                0,
            )
        try:
            before = os.fstat(descriptor)
            if (
                before.st_size <= 0
                or before.st_size > max_module_bytes
                or before.st_size > remaining_bytes
            ):
                return (
                    ContainerModuleEvidence(
                        container_path_sha256=path_digest,
                        recorded_build_id=record.build_id,
                        status="limit_exceeded",
                    ),
                    0,
                )
            with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
                observed_build_id = _build_id_from_handle(handle)
                content_sha256, file_bytes = _sha256_handle(handle, max_bytes=before.st_size)
            after = os.fstat(descriptor)
            if _stat_identity(before) != _stat_identity(after) or file_bytes != before.st_size:
                return (
                    ContainerModuleEvidence(
                        container_path_sha256=path_digest,
                        recorded_build_id=record.build_id,
                        status="unavailable",
                    ),
                    0,
                )
            try:
                current_descriptor = self._open_regular_beneath(record.container_path)
            except PerfLensError:
                return (
                    ContainerModuleEvidence(
                        container_path_sha256=path_digest,
                        recorded_build_id=record.build_id,
                        status="unavailable",
                    ),
                    0,
                )
            try:
                current = os.fstat(current_descriptor)
            finally:
                os.close(current_descriptor)
            if _stat_identity(after) != _stat_identity(current):
                return (
                    ContainerModuleEvidence(
                        container_path_sha256=path_digest,
                        recorded_build_id=record.build_id,
                        status="unavailable",
                    ),
                    0,
                )
            if observed_build_id is None:
                return (
                    ContainerModuleEvidence(
                        container_path_sha256=path_digest,
                        recorded_build_id=record.build_id,
                        status="unavailable",
                    ),
                    0,
                )
            status = "verified" if observed_build_id == record.build_id else "identity_mismatch"
            return (
                ContainerModuleEvidence(
                    container_path_sha256=path_digest,
                    recorded_build_id=record.build_id,
                    observed_build_id=observed_build_id,
                    content_sha256=content_sha256,
                    file_bytes=file_bytes,
                    status=status,
                ),
                file_bytes,
            )
        finally:
            os.close(descriptor)

    def _open_regular_beneath(self, container_path: str) -> int:
        if self._root_fd is None:
            raise RuntimeError("process root is not open")
        parts = PurePosixPath(container_path).parts
        descriptor = os.dup(self._root_fd)
        try:
            for index, part in enumerate(parts[1:]):
                final = index == len(parts[1:]) - 1
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                if not final:
                    flags |= os.O_DIRECTORY
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise _symbol_error("container module is not a regular file")
            return descriptor
        except (OSError, PerfLensError) as exc:
            os.close(descriptor)
            if isinstance(exc, PerfLensError):
                raise
            raise _symbol_error("container module could not be safely opened") from exc

    def assert_unchanged(self) -> None:
        if self._root_fd is None or _stat_identity(os.fstat(self._root_fd)) != self.identity:
            raise _symbol_error("target process root changed during module inspection")
        current_root = self._open_current_root()
        try:
            if _stat_identity(os.fstat(current_root)) != self.identity:
                raise _symbol_error("target process root changed during module inspection")
        finally:
            os.close(current_root)

    def _open_current_root(self) -> int:
        process_path = self._proc_root / str(self._host_pid)
        try:
            process_fd = os.open(
                process_path,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                return os.open(
                    "root",
                    os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=process_fd,
                )
            finally:
                os.close(process_fd)
        except OSError as exc:
            raise _symbol_error("target process root is unavailable") from exc

    def close(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __exit__(self, *_args: object) -> None:
        self.close()


def _analysis_source_locations(
    analysis: AnalysisArtifact,
) -> tuple[tuple[str, int | None], ...]:
    locations: set[tuple[str, int | None]] = set()
    for hotspot in analysis.hotspots:
        for value in hotspot.source_locations:
            parsed = _parse_source_location(value)
            if parsed is not None:
                locations.add(parsed)
        prefix = f"{hotspot.symbol}:"
        for value in hotspot.symbol_variants:
            if not value.startswith(prefix):
                continue
            parsed = _parse_source_location(value[len(prefix) :])
            if parsed is not None:
                locations.add(parsed)
    return tuple(sorted(locations, key=lambda item: (item[0], item[1] or 0)))


def _parse_source_location(value: str) -> tuple[str, int | None] | None:
    match = _SOURCE_LOCATION_WITH_LINE.fullmatch(value)
    if match is not None:
        path = match.group("path")
        if _is_safe_container_module_path(path):
            return path, int(match.group("line"))
        return None
    if _is_safe_container_module_path(value):
        return value, None
    return None


def _unique_recorded_modules(
    records: tuple[RecordedModule, ...],
) -> tuple[tuple[RecordedModule, ...], bool]:
    by_path: dict[str, RecordedModule] = {}
    conflict = False
    for record in records:
        existing = by_path.get(record.container_path)
        if existing is not None and existing.build_id != record.build_id:
            conflict = True
            continue
        by_path[record.container_path] = record
    return tuple(by_path[path] for path in sorted(by_path)), conflict


def _build_id_from_handle(handle: BinaryIO) -> str | None:
    try:
        return read_elf_build_id(handle)
    except Exception:
        return None


def _sha256_handle(handle: BinaryIO, *, max_bytes: int) -> tuple[str, int]:
    handle.seek(0)
    digest = hashlib.sha256()
    total = 0
    while chunk := handle.read(min(_HASH_CHUNK_BYTES, max_bytes - total + 1)):
        total += len(chunk)
        if total > max_bytes:
            raise _symbol_error("container module grew beyond its bound")
        digest.update(chunk)
    return digest.hexdigest(), total


def _sha256_path(path: Path) -> tuple[str, int]:
    with path.open("rb") as handle:
        return _sha256_handle(handle, max_bytes=1 << 30)


@contextmanager
def _private_profile_snapshot(collection: CollectionArtifact) -> Generator[Path]:
    candidate = Path(collection.output_path).expanduser()
    source_descriptor = -1
    try:
        source_descriptor = os.open(
            candidate,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != collection.output_bytes
            or before.st_size > DEFAULT_MAX_OUTPUT_BYTES
        ):
            raise _profile_binding_error("Collection profile identity or size is unsafe")
        with tempfile.TemporaryDirectory(prefix="perflens-container-profile-") as directory:
            snapshot_path = Path(directory) / "profile.data"
            digest = hashlib.sha256()
            copied = 0
            with snapshot_path.open("xb") as output:
                snapshot_path.chmod(0o600)
                while copied <= collection.output_bytes:
                    chunk = os.read(
                        source_descriptor,
                        min(1 << 20, collection.output_bytes + 1 - copied),
                    )
                    if not chunk:
                        break
                    copied += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
            after = os.fstat(source_descriptor)
            if (
                _stat_identity(before) != _stat_identity(after)
                or copied != collection.output_bytes
                or digest.hexdigest() != collection.output_sha256
            ):
                raise _profile_binding_error(
                    "Collection profile changed while creating its private snapshot"
                )
            _require_current_profile_identity(candidate, before)
            snapshot_identity = snapshot_path.stat(follow_symlinks=False)
            try:
                yield snapshot_path
            finally:
                _require_private_profile_snapshot(
                    snapshot_path,
                    snapshot_identity,
                    collection,
                )
                _require_current_profile_identity(candidate, before)
    except PerfLensError:
        raise
    except OSError as exc:
        raise _profile_binding_error("Collection profile cannot be snapshotted safely") from exc
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)


def _require_current_profile_identity(
    candidate: Path,
    expected: os.stat_result,
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            candidate,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        current = os.fstat(descriptor)
    except OSError as exc:
        raise _profile_binding_error("Collection profile path changed after verification") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if _stat_identity(current) != _stat_identity(expected):
        raise _profile_binding_error("Collection profile path changed after verification")


def _require_private_profile_snapshot(
    snapshot_path: Path,
    expected: os.stat_result,
    collection: CollectionArtifact,
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            snapshot_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        current = os.fstat(descriptor)
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
            digest, size = _sha256_handle(handle, max_bytes=collection.output_bytes)
    except (OSError, PerfLensError) as exc:
        raise _profile_binding_error(
            "Private Collection profile snapshot changed during module inspection"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        _stat_identity(current) != _stat_identity(expected)
        or size != collection.output_bytes
        or digest != collection.output_sha256
    ):
        raise _profile_binding_error(
            "Private Collection profile snapshot changed during module inspection"
        )


def _adapter_identity(perf_sha256: str) -> str:
    return hashlib.sha256(f"{_RECIPE_ID}\0{perf_sha256}".encode()).hexdigest()


def _private_path_digest(container_identity_sha256: str, path: str, *, domain: str) -> str:
    material = f"perflens-container-{domain}-path-v1\0{container_identity_sha256}\0{path}"
    return hashlib.sha256(material.encode()).hexdigest()


def _private_text_digest(container_identity_sha256: str, value: str, *, domain: str) -> str:
    material = f"perflens-container-{domain}-v1\0{container_identity_sha256}\0{value}"
    return hashlib.sha256(material.encode()).hexdigest()


def _contains_private_path(value: str) -> bool:
    return (
        "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or ":/" in value
        or any(part == ".." for part in PurePosixPath(value).parts)
    )


def _require_contract_content(
    artifact: ContainerModuleSnapshotArtifact | ContainerSymbolContextArtifact,
    expected_sha256: str,
    message: str,
) -> None:
    if expected_sha256 != contract_content_sha256(
        artifact,
        exclude={"content_sha256"},
    ):
        raise PerfLensError(
            ErrorCode.PROFILE_PARSE_FAILED,
            "container_symbols",
            message,
        )


def _root_identity_sha256(
    container_identity_sha256: str,
    mount_namespace_inode: int,
    identity: tuple[int, ...],
) -> str:
    material = "\0".join(
        (
            "perflens-container-root-v1",
            container_identity_sha256,
            str(mount_namespace_inode),
            *(str(item) for item in identity),
        )
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _is_safe_container_module_path(value: str) -> bool:
    if not value.startswith("/") or "\x00" in value or len(value) > 4096:
        return False
    path = PurePosixPath(value)
    return ".." not in path.parts and str(path) == value and len(path.parts) > 1


def _is_beneath_prefix(value: str, prefix: PurePosixPath) -> bool:
    try:
        PurePosixPath(value).relative_to(prefix)
    except ValueError:
        return False
    return _is_safe_container_module_path(value)


def _find_perf() -> Path:
    discovered = shutil.which("perf")
    if discovered is None:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            "container_symbols",
            "System perf executable was not found",
            recoverable=True,
        )
    return Path(discovered)


def _symbol_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PATH_SAFETY_VIOLATION,
        "container_symbols",
        message,
        recoverable=True,
    )


def _profile_binding_error(message: str) -> PerfLensError:
    return PerfLensError(
        ErrorCode.PROFILE_PARSE_FAILED,
        "evidence_validation",
        message,
    )
