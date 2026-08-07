"""Auditable archive-then-prune lifecycle for Collector spool evidence."""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import stat
import tempfile
import zipfile
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from perflens import __version__
from perflens.admin.deploy import (
    CollectorDeploymentPolicy,
    CollectorSystemLayout,
    invoking_uid,
    load_collector_config,
    parse_collector_deployment_policy,
)
from perflens.artifacts.filesystem import serialize_json
from perflens.collector_broker.state import (
    collection_artifact_name,
    replay_marker,
    safe_replay_marker_metadata,
)
from perflens.contracts.artifacts import (
    CollectorSpoolArchiveArtifact,
    CollectorSpoolArchiveEntry,
    CollectorSpoolArchiveManifest,
    CollectorSpoolArchiveVerificationArtifact,
    CollectorSpoolPruneArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError

SPOOL_PRUNE_AUTHORIZATION = "I_EXPLICITLY_AUTHORIZE_ARCHIVED_SPOOL_PRUNE"

_COPY_CHUNK_BYTES = 1 << 20
_MAX_ARCHIVE_ARTIFACTS = 10_000
_MAX_ARCHIVE_TOTAL_BYTES = 1 << 40
_MAX_ARCHIVE_MANIFEST_BYTES = 8 << 20
_MAX_ARCHIVE_OVERHEAD_BYTES = 32 << 20


@dataclass(frozen=True, slots=True)
class _SpoolSnapshot:
    name: str
    metadata: os.stat_result


@dataclass(frozen=True, slots=True)
class _SpoolIdentity:
    directory_uid: int
    directory_gid: int
    artifact_uid: int
    artifact_gid: int
    replay_uid: int
    replay_gid: int


def archive_collector_spool(
    output_path: Path,
    *,
    config_path: Path = Path("/etc/perflens/collector.toml"),
    older_than_days: int = 7,
    keep_latest: int = 20,
    max_artifacts: int = 1000,
    max_total_bytes: int = 10 << 30,
    dry_run: bool = False,
    layout: CollectorSystemLayout | None = None,
    require_root: bool = True,
    require_root_owned_tools: bool = True,
    service_uid: int | None = None,
    service_gid: int | None = None,
    now: datetime | None = None,
) -> CollectorSpoolArchiveArtifact:
    """Create a verified immutable archive without removing spool evidence."""
    stage = "collector_spool_archive"
    _validate_archive_limits(
        older_than_days=older_than_days,
        keep_latest=keep_latest,
        max_artifacts=max_artifacts,
        max_total_bytes=max_total_bytes,
        stage=stage,
    )
    effective_layout = layout or CollectorSystemLayout()
    source = load_collector_config(config_path, stage=stage)
    policy = parse_collector_deployment_policy(
        source.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root_owned_tools,
        stage=stage,
    )
    policy, identity = _managed_spool_context(
        policy,
        effective_layout,
        service_uid=service_uid,
        service_gid=service_gid,
        stage=stage,
    )
    if os.geteuid() not in {0, policy.allowed_uids[0]}:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Only root or the policy-authorized user may archive Collector evidence",
        )
    if policy.privilege_mode == "paranoid3_helper" and require_root and os.geteuid() != 0:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Rust Helper spool archival requires an explicit administrator invocation",
            recoverable=True,
            suggested_actions=("Run sudo perflens-admin archive-spool after reviewing dry-run.",),
        )
    if require_root and not dry_run and os.geteuid() != 0:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector spool archival must be started explicitly by an administrator",
            recoverable=True,
        )
    safe_output = _new_archive_path(
        output_path,
        policy.spool_root,
        require_root_owner=require_root,
        stage=stage,
    )
    effective_now = now or datetime.now(tz=UTC)
    if effective_now.tzinfo is None:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Archive selection time must include a timezone",
        )
    policy_raw = source.raw_text.encode("utf-8")

    spool_descriptor = _open_spool(
        policy,
        identity=identity,
        stage=stage,
    )
    try:
        snapshots = _scan_managed_spool(
            spool_descriptor,
            identity=identity,
            stage=stage,
        )
        selected, eligible_count = _select_snapshots(
            snapshots,
            cutoff=effective_now - timedelta(days=older_than_days),
            keep_latest=keep_latest,
            max_artifacts=max_artifacts,
            max_total_bytes=max_total_bytes,
        )
        if dry_run:
            entries = tuple(
                _capture_entry(
                    spool_descriptor,
                    snapshot,
                    identity=identity,
                    archive=None,
                    stage=stage,
                )
                for snapshot in selected
            )
            manifest = _archive_manifest(
                source_path=source.path,
                policy=policy,
                policy_raw=policy_raw,
                entries=entries,
                created_at=effective_now,
                older_than_days=older_than_days,
                keep_latest=keep_latest,
                max_artifacts=max_artifacts,
                max_total_bytes=max_total_bytes,
                eligible_count=eligible_count,
            )
            return _archive_result(
                "dry_run",
                safe_output,
                None,
                manifest,
            )
        if not selected:
            manifest = _archive_manifest(
                source_path=source.path,
                policy=policy,
                policy_raw=policy_raw,
                entries=(),
                created_at=effective_now,
                older_than_days=older_than_days,
                keep_latest=keep_latest,
                max_artifacts=max_artifacts,
                max_total_bytes=max_total_bytes,
                eligible_count=eligible_count,
            )
            return _archive_result(
                "nothing_to_archive",
                safe_output,
                None,
                manifest,
            )
        manifest = _write_archive(
            spool_descriptor,
            safe_output,
            selected,
            source_path=source.path,
            policy=policy,
            policy_raw=policy_raw,
            identity=identity,
            created_at=effective_now,
            older_than_days=older_than_days,
            keep_latest=keep_latest,
            max_artifacts=max_artifacts,
            max_total_bytes=max_total_bytes,
            eligible_count=eligible_count,
        )
    finally:
        os.close(spool_descriptor)
    archive_sha256 = _trusted_file_sha256(
        safe_output,
        max_bytes=max_total_bytes + _MAX_ARCHIVE_OVERHEAD_BYTES,
        stage=stage,
    )
    return _archive_result("archived", safe_output, archive_sha256, manifest)


def verify_collector_spool_archive(
    archive_path: Path,
    *,
    config_path: Path = Path("/etc/perflens/collector.toml"),
    verify_sources: bool = False,
    layout: CollectorSystemLayout | None = None,
    require_root: bool = True,
    service_uid: int | None = None,
    service_gid: int | None = None,
) -> CollectorSpoolArchiveVerificationArtifact:
    """Verify a root-managed archive and optionally cross-check surviving sources."""
    stage = "collector_spool_archive_verification"
    effective_layout = layout or CollectorSystemLayout()
    source = load_collector_config(config_path, stage=stage)
    policy = parse_collector_deployment_policy(
        source.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root,
        stage=stage,
    )
    policy, identity = _managed_spool_context(
        policy,
        effective_layout,
        service_uid=service_uid,
        service_gid=service_gid,
        stage=stage,
    )
    resolved_archive, archive_sha256, manifest = _verify_archive(
        archive_path,
        policy=policy,
        require_root_owner=require_root,
        stage=stage,
    )
    present_count: int | None = None
    absent_count: int | None = None
    if verify_sources:
        spool_descriptor = _open_spool(
            policy,
            identity=identity,
            stage=stage,
        )
        try:
            present_count = 0
            absent_count = 0
            for entry in manifest.entries:
                if _entry_exists(spool_descriptor, entry.name, stage=stage):
                    _verify_source_entry(
                        spool_descriptor,
                        entry,
                        identity=identity,
                        stage=stage,
                    )
                    present_count += 1
                else:
                    absent_count += 1
        finally:
            os.close(spool_descriptor)
    return _archive_verification_result(
        resolved_archive,
        archive_sha256,
        source.path,
        manifest,
        source_artifacts_checked=verify_sources,
        present_source_artifact_count=present_count,
        absent_source_artifact_count=absent_count,
    )


def prune_archived_collector_spool(
    archive_path: Path,
    *,
    config_path: Path = Path("/etc/perflens/collector.toml"),
    dry_run: bool = False,
    authorization: str | None = None,
    layout: CollectorSystemLayout | None = None,
    require_root: bool = True,
    service_uid: int | None = None,
    service_gid: int | None = None,
) -> CollectorSpoolPruneArtifact:
    """Remove only source files proven to exist in one verified archive."""
    stage = "collector_spool_prune"
    effective_layout = layout or CollectorSystemLayout()
    source = load_collector_config(config_path, stage=stage)
    policy = parse_collector_deployment_policy(
        source.raw_text,
        expected_spool=effective_layout.state_directory,
        require_root_owned_tools=require_root,
        stage=stage,
    )
    policy, identity = _managed_spool_context(
        policy,
        effective_layout,
        service_uid=service_uid,
        service_gid=service_gid,
        stage=stage,
    )
    resolved_archive, archive_sha256, manifest = _verify_archive(
        archive_path,
        policy=policy,
        require_root_owner=require_root,
        stage=stage,
    )
    spool_descriptor = _open_spool(
        policy,
        identity=identity,
        stage=stage,
    )
    try:
        present: list[CollectorSpoolArchiveEntry] = []
        already_absent = 0
        for entry in manifest.entries:
            if _entry_exists(spool_descriptor, entry.name, stage=stage):
                _verify_source_entry(
                    spool_descriptor,
                    entry,
                    identity=identity,
                    stage=stage,
                )
                present.append(entry)
            else:
                already_absent += 1
        planned_bytes = sum(entry.logical_bytes for entry in present)
        if dry_run:
            return _prune_result(
                "dry_run",
                resolved_archive,
                archive_sha256,
                manifest,
                present,
                planned_bytes=planned_bytes,
                already_absent=already_absent,
                removed_count=0,
                removed_bytes=0,
            )
        if not present:
            return _prune_result(
                "nothing_to_prune",
                resolved_archive,
                archive_sha256,
                manifest,
                (),
                planned_bytes=0,
                already_absent=already_absent,
                removed_count=0,
                removed_bytes=0,
            )
        if authorization != SPOOL_PRUNE_AUTHORIZATION:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                stage,
                "Archived spool pruning requires the exact explicit authorization phrase",
                recoverable=True,
                suggested_actions=(
                    f"Pass --authorization {SPOOL_PRUNE_AUTHORIZATION} after reviewing dry-run.",
                ),
            )
        if require_root and os.geteuid() != 0:
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                stage,
                "Archived spool pruning must be started explicitly by an administrator",
                recoverable=True,
            )
        removed_count = 0
        removed_bytes = 0
        for entry in present:
            _verify_source_entry(
                spool_descriptor,
                entry,
                identity=identity,
                stage=stage,
            )
            try:
                current = os.stat(entry.name, dir_fd=spool_descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (
                    entry.source_device,
                    entry.source_inode,
                ):
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        stage,
                        "Collector artifact changed immediately before pruning",
                        details={"entry": entry.name},
                    )
                os.unlink(entry.name, dir_fd=spool_descriptor)
                removed_count += 1
                removed_bytes += entry.logical_bytes
            except PerfLensError:
                raise
            except OSError as exc:
                raise PerfLensError(
                    ErrorCode.OUTPUT_WRITE_FAILED,
                    stage,
                    "Unable to remove a verified archived Collector artifact",
                    recoverable=True,
                    details={
                        "entry": entry.name,
                        "removed_artifact_count": removed_count,
                        "removed_logical_bytes": removed_bytes,
                    },
                    suggested_actions=(
                        "The archive is preserved; inspect the spool before retrying.",
                    ),
                ) from exc
        try:
            os.fsync(spool_descriptor)
        except OSError as exc:
            raise PerfLensError(
                ErrorCode.OUTPUT_WRITE_FAILED,
                stage,
                "Pruned artifacts but could not sync the Collector spool directory",
                recoverable=True,
                details={
                    "removed_artifact_count": removed_count,
                    "removed_logical_bytes": removed_bytes,
                },
            ) from exc
    finally:
        os.close(spool_descriptor)
    return _prune_result(
        "pruned",
        resolved_archive,
        archive_sha256,
        manifest,
        present,
        planned_bytes=planned_bytes,
        already_absent=already_absent,
        removed_count=removed_count,
        removed_bytes=removed_bytes,
    )


def _validate_archive_limits(
    *,
    older_than_days: int,
    keep_latest: int,
    max_artifacts: int,
    max_total_bytes: int,
    stage: str,
) -> None:
    values: tuple[object, ...] = (
        older_than_days,
        keep_latest,
        max_artifacts,
        max_total_bytes,
    )
    if any(not _is_strict_integer(value) for value in values):
        raise PerfLensError(ErrorCode.INVALID_INPUT, stage, "Archive limits must be integers")
    if (
        not 0 <= older_than_days <= 36_500
        or not 0 <= keep_latest <= _MAX_ARCHIVE_ARTIFACTS
        or not 1 <= max_artifacts <= _MAX_ARCHIVE_ARTIFACTS
        or not 1 <= max_total_bytes <= _MAX_ARCHIVE_TOTAL_BYTES
    ):
        raise PerfLensError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            stage,
            "Archive selection limits are outside the bounded product range",
        )


def _is_strict_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _collector_service_identity(
    uid: object | None,
    gid: object | None,
    *,
    stage: str,
) -> tuple[int, int]:
    if uid is not None or gid is not None:
        if (
            isinstance(uid, bool)
            or not isinstance(uid, int)
            or uid < 0
            or isinstance(gid, bool)
            or not isinstance(gid, int)
            or gid < 0
        ):
            raise PerfLensError(ErrorCode.INVALID_INPUT, stage, "Service identity is invalid")
        return uid, gid
    try:
        account = pwd.getpwnam("perflens")
        return account.pw_uid, account.pw_gid
    except KeyError as exc:
        raise PerfLensError(
            ErrorCode.EXTERNAL_TOOL_FAILED,
            stage,
            "Dedicated perflens service account does not exist",
            suggested_actions=("Deploy the Collector before managing its spool.",),
        ) from exc


def _managed_spool_context(
    policy: CollectorDeploymentPolicy,
    layout: CollectorSystemLayout,
    *,
    service_uid: object | None,
    service_gid: object | None,
    stage: str,
) -> tuple[CollectorDeploymentPolicy, _SpoolIdentity]:
    """Resolve the active spool and independently bounded ownership domains."""
    if service_uid is not None or service_gid is not None:
        uid, gid = _collector_service_identity(service_uid, service_gid, stage=stage)
        identity = _SpoolIdentity(uid, gid, uid, gid, uid, gid)
    elif policy.privilege_mode == "paranoid3_helper":
        try:
            artifact_group = pwd.getpwnam("perflens").pw_gid
            internal_group = grp.getgrnam("perflens-internal").gr_gid
        except KeyError as exc:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                stage,
                "Dedicated PerfLens service groups do not exist",
                suggested_actions=("Deploy the Collector before managing its spool.",),
            ) from exc
        identity = _SpoolIdentity(
            directory_uid=0,
            directory_gid=internal_group,
            artifact_uid=0,
            artifact_gid=artifact_group,
            replay_uid=0,
            replay_gid=internal_group,
        )
    else:
        uid, gid = _collector_service_identity(None, None, stage=stage)
        identity = _SpoolIdentity(uid, gid, uid, gid, uid, gid)
    if policy.privilege_mode == "paranoid3_helper":
        policy = replace(policy, spool_root=layout.helper_state_directory)
    return policy, identity


def _new_archive_path(
    path: Path,
    spool_root: Path,
    *,
    require_root_owner: bool,
    stage: str,
) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute() or expanded.name in {"", ".", ".."}:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive output must be an absolute ZIP path",
        )
    if expanded.suffix != ".zip":
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector archive output must use the .zip suffix",
        )
    try:
        parent = expanded.parent.resolve(strict=True)
        metadata = parent.stat()
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive parent cannot be resolved",
        ) from exc
    expected_owners = {0} if require_root_owner else {0, invoking_uid()}
    if not parent.is_dir() or metadata.st_uid not in expected_owners or metadata.st_mode & 0o022:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive parent must be trusted-owned and not group/other writable",
        )
    resolved = parent / expanded.name
    if resolved.exists() or resolved.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive output must not already exist",
        )
    resolved_spool = spool_root.resolve(strict=True)
    if parent == resolved_spool or resolved_spool in parent.parents:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive output must be outside the fixed spool",
        )
    return resolved


def _open_spool(
    policy: CollectorDeploymentPolicy,
    *,
    identity: _SpoolIdentity,
    stage: str,
) -> int:
    descriptor = -1
    try:
        descriptor = os.open(
            policy.spool_root,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        metadata = os.fstat(descriptor)
        path_metadata = policy.spool_root.stat(follow_symlinks=False)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector spool cannot be opened safely",
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != identity.directory_uid
        or metadata.st_gid != identity.directory_gid
        or metadata.st_mode & 0o022
        or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        os.close(descriptor)
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector spool ownership, permissions, or identity are unsafe",
        )
    return descriptor


def _scan_managed_spool(
    descriptor: int,
    *,
    identity: _SpoolIdentity,
    stage: str,
) -> tuple[_SpoolSnapshot, ...]:
    snapshots: list[_SpoolSnapshot] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if replay_marker(entry.name):
                    if not safe_replay_marker_metadata(
                        metadata,
                        expected_uid=identity.replay_uid,
                        expected_gid=identity.replay_gid,
                    ):
                        raise PerfLensError(
                            ErrorCode.PATH_SAFETY_VIOLATION,
                            stage,
                            "Collector spool contains an unsafe replay marker",
                            details={"entry": entry.name},
                        )
                    continue
                if not collection_artifact_name(entry.name):
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        stage,
                        "Collector spool contains an unmanaged entry",
                        details={"entry": entry.name},
                    )
                _validate_source_metadata(
                    entry.name,
                    metadata,
                    expected_artifact_uid=identity.artifact_uid,
                    expected_artifact_gid=identity.artifact_gid,
                    stage=stage,
                )
                snapshots.append(_SpoolSnapshot(entry.name, metadata))
                if len(snapshots) > 1_000_000:
                    raise PerfLensError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        stage,
                        "Collector spool scan exceeded its artifact bound",
                    )
    except PerfLensError:
        raise
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            stage,
            "Unable to scan Collector spool safely",
        ) from exc
    return tuple(snapshots)


def _select_snapshots(
    snapshots: tuple[_SpoolSnapshot, ...],
    *,
    cutoff: datetime,
    keep_latest: int,
    max_artifacts: int,
    max_total_bytes: int,
) -> tuple[tuple[_SpoolSnapshot, ...], int]:
    cutoff_ns = int(cutoff.timestamp() * 1_000_000_000)
    newest_first = sorted(
        snapshots,
        key=lambda snapshot: (snapshot.metadata.st_mtime_ns, snapshot.name),
        reverse=True,
    )
    eligible = sorted(
        (
            snapshot
            for snapshot in newest_first[keep_latest:]
            if snapshot.metadata.st_mtime_ns <= cutoff_ns
        ),
        key=lambda snapshot: (snapshot.metadata.st_mtime_ns, snapshot.name),
    )
    selected: list[_SpoolSnapshot] = []
    total_bytes = 0
    for snapshot in eligible:
        if len(selected) >= max_artifacts:
            break
        if total_bytes + snapshot.metadata.st_size > max_total_bytes:
            break
        selected.append(snapshot)
        total_bytes += snapshot.metadata.st_size
    return tuple(selected), len(eligible)


def _capture_entry(
    spool_descriptor: int,
    snapshot: _SpoolSnapshot,
    *,
    identity: _SpoolIdentity,
    archive: zipfile.ZipFile | None,
    stage: str,
) -> CollectorSpoolArchiveEntry:
    descriptor = -1
    written = 0
    digest = hashlib.sha256()
    try:
        descriptor = os.open(
            snapshot.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=spool_descriptor,
        )
        before = os.fstat(descriptor)
        _match_snapshot(snapshot, before, stage=stage)
        _validate_source_metadata(
            snapshot.name,
            before,
            expected_artifact_uid=identity.artifact_uid,
            expected_artifact_gid=identity.artifact_gid,
            stage=stage,
        )
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            destination = (
                archive.open(_artifact_zip_info(snapshot.name), "w")
                if archive is not None
                else None
            )
            try:
                while True:
                    chunk = source.read(_COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > before.st_size:
                        raise PerfLensError(
                            ErrorCode.PATH_SAFETY_VIOLATION,
                            stage,
                            "Collector artifact grew while it was being archived",
                            details={"entry": snapshot.name},
                        )
                    digest.update(chunk)
                    if destination is not None:
                        destination.write(chunk)
                after = os.fstat(source.fileno())
            finally:
                if destination is not None:
                    destination.close()
    except PerfLensError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            stage,
            "Unable to read or archive a Collector artifact",
            details={"entry": snapshot.name},
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if written != before.st_size:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector artifact size changed while it was being archived",
            details={"entry": snapshot.name},
        )
    _match_snapshot(snapshot, after, stage=stage)
    return CollectorSpoolArchiveEntry(
        name=snapshot.name,
        logical_bytes=written,
        modified_time_ns=before.st_mtime_ns,
        source_device=before.st_dev,
        source_inode=before.st_ino,
        sha256=digest.hexdigest(),
    )


def _validate_source_metadata(
    name: str,
    metadata: os.stat_result,
    *,
    expected_artifact_uid: int,
    expected_artifact_gid: int,
    stage: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_artifact_uid
        or metadata.st_gid != expected_artifact_gid
        or metadata.st_mode & 0o022
        or metadata.st_size < 0
        or metadata.st_size > _MAX_ARCHIVE_TOTAL_BYTES
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector artifact ownership, permissions, type, or size are unsafe",
            details={"entry": name},
        )


def _match_snapshot(
    snapshot: _SpoolSnapshot,
    metadata: os.stat_result,
    *,
    stage: str,
) -> None:
    expected = snapshot.metadata
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    ) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_size,
        expected.st_mtime_ns,
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector artifact changed after spool selection",
            details={"entry": snapshot.name},
        )


def _archive_manifest(
    *,
    source_path: Path,
    policy: CollectorDeploymentPolicy,
    policy_raw: bytes,
    entries: tuple[CollectorSpoolArchiveEntry, ...],
    created_at: datetime,
    older_than_days: int,
    keep_latest: int,
    max_artifacts: int,
    max_total_bytes: int,
    eligible_count: int,
) -> CollectorSpoolArchiveManifest:
    total_bytes = sum(entry.logical_bytes for entry in entries)
    policy_sha256 = hashlib.sha256(policy_raw).hexdigest()
    return CollectorSpoolArchiveManifest(
        perflens_version=__version__,
        archive_id=_archive_id(policy_sha256, str(policy.spool_root), entries),
        created_at=created_at.astimezone(UTC).isoformat(),
        config_path=str(source_path),
        spool_root=str(policy.spool_root),
        allowed_uid=policy.allowed_uids[0],
        privilege_mode=policy.privilege_mode,
        policy_sha256=policy_sha256,
        older_than_days=older_than_days,
        keep_latest=keep_latest,
        max_artifacts=max_artifacts,
        max_total_bytes=max_total_bytes,
        eligible_artifact_count=eligible_count,
        selection_truncated=len(entries) < eligible_count,
        artifact_count=len(entries),
        total_logical_bytes=total_bytes,
        entries=entries,
    )


def _write_archive(
    spool_descriptor: int,
    output: Path,
    snapshots: tuple[_SpoolSnapshot, ...],
    *,
    source_path: Path,
    policy: CollectorDeploymentPolicy,
    policy_raw: bytes,
    identity: _SpoolIdentity,
    created_at: datetime,
    older_than_days: int,
    keep_latest: int,
    max_artifacts: int,
    max_total_bytes: int,
    eligible_count: int,
) -> CollectorSpoolArchiveManifest:
    stage = "collector_spool_archive"
    temporary: Path | None = None
    published = False
    published_identity: tuple[int, int] | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "w+b") as handle:
            with zipfile.ZipFile(
                handle,
                mode="w",
                compression=zipfile.ZIP_STORED,
                allowZip64=True,
            ) as archive:
                entries = tuple(
                    _capture_entry(
                        spool_descriptor,
                        snapshot,
                        identity=identity,
                        archive=archive,
                        stage=stage,
                    )
                    for snapshot in snapshots
                )
                manifest = _archive_manifest(
                    source_path=source_path,
                    policy=policy,
                    policy_raw=policy_raw,
                    entries=entries,
                    created_at=created_at,
                    older_than_days=older_than_days,
                    keep_latest=keep_latest,
                    max_artifacts=max_artifacts,
                    max_total_bytes=max_total_bytes,
                    eligible_count=eligible_count,
                )
                payload = serialize_json(manifest)
                if len(payload) > _MAX_ARCHIVE_MANIFEST_BYTES:
                    raise PerfLensError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        stage,
                        "Collector archive manifest exceeds its size bound",
                    )
                archive.writestr(_manifest_zip_info(), payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        temporary_metadata = temporary.stat(follow_symlinks=False)
        published_identity = (temporary_metadata.st_dev, temporary_metadata.st_ino)
        os.link(temporary, output)
        published = True
        os.chmod(output, 0o600)
        temporary.unlink()
        temporary = None
        return manifest
    except PerfLensError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            stage,
            "Unable to publish the Collector spool archive",
            details={"output": str(output)},
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if published and published_identity is not None:
            try:
                current = output.stat(follow_symlinks=False)
            except OSError:
                pass
            else:
                if (
                    current.st_dev,
                    current.st_ino,
                ) == published_identity and current.st_mode & 0o777 != 0o600:
                    output.unlink(missing_ok=True)


def _artifact_zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(f"artifacts/{name}", date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _manifest_zip_info() -> zipfile.ZipInfo:
    info = zipfile.ZipInfo("manifest.json", date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _verify_archive(
    path: Path,
    *,
    policy: CollectorDeploymentPolicy,
    require_root_owner: bool,
    stage: str,
) -> tuple[Path, str, CollectorSpoolArchiveManifest]:
    resolved, descriptor, metadata = _open_trusted_archive(
        path,
        require_root_owner=require_root_owner,
        stage=stage,
    )
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            while True:
                chunk = handle.read(_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
            if handle.tell() != metadata.st_size:
                raise PerfLensError(
                    ErrorCode.PATH_SAFETY_VIOLATION,
                    stage,
                    "Collector archive size changed while it was read",
                )
            handle.seek(0)
            with zipfile.ZipFile(handle, mode="r") as archive:
                infos = archive.infolist()
                if len(infos) > _MAX_ARCHIVE_ARTIFACTS + 1:
                    raise PerfLensError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        stage,
                        "Collector archive contains too many entries",
                    )
                names = [info.filename for info in infos]
                if len(names) != len(set(names)) or "manifest.json" not in names:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        stage,
                        "Collector archive has duplicate entries or no manifest",
                    )
                manifest_info = archive.getinfo("manifest.json")
                _validate_zip_info(
                    manifest_info,
                    expected_size=None,
                    max_bytes=_MAX_ARCHIVE_MANIFEST_BYTES,
                    stage=stage,
                )
                with archive.open(manifest_info, "r") as manifest_stream:
                    manifest_raw = manifest_stream.read(_MAX_ARCHIVE_MANIFEST_BYTES + 1)
                if len(manifest_raw) > _MAX_ARCHIVE_MANIFEST_BYTES:
                    raise PerfLensError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        stage,
                        "Collector archive manifest exceeds its size bound",
                    )
                try:
                    manifest = CollectorSpoolArchiveManifest.model_validate_json(manifest_raw)
                except (ValidationError, ValueError) as exc:
                    raise PerfLensError(
                        ErrorCode.INVALID_INPUT,
                        stage,
                        "Collector archive manifest failed schema validation",
                    ) from exc
                _validate_manifest_consistency(manifest, policy=policy, stage=stage)
                expected_names = {"manifest.json"}
                for entry in manifest.entries:
                    member_name = f"artifacts/{entry.name}"
                    expected_names.add(member_name)
                    try:
                        info = archive.getinfo(member_name)
                    except KeyError as exc:
                        raise PerfLensError(
                            ErrorCode.INVALID_INPUT,
                            stage,
                            "Collector archive is missing a manifest artifact",
                            details={"entry": entry.name},
                        ) from exc
                    _validate_zip_info(
                        info,
                        expected_size=entry.logical_bytes,
                        max_bytes=manifest.max_total_bytes,
                        stage=stage,
                    )
                    member_digest = hashlib.sha256()
                    read_bytes = 0
                    with archive.open(info, "r") as member:
                        while True:
                            chunk = member.read(_COPY_CHUNK_BYTES)
                            if not chunk:
                                break
                            read_bytes += len(chunk)
                            if read_bytes > entry.logical_bytes:
                                raise PerfLensError(
                                    ErrorCode.PATH_SAFETY_VIOLATION,
                                    stage,
                                    "Collector archive member exceeds its manifest size",
                                )
                            member_digest.update(chunk)
                    if (
                        read_bytes != entry.logical_bytes
                        or member_digest.hexdigest() != entry.sha256
                    ):
                        raise PerfLensError(
                            ErrorCode.PATH_SAFETY_VIOLATION,
                            stage,
                            "Collector archive member failed size or SHA-256 verification",
                            details={"entry": entry.name},
                        )
                if set(names) != expected_names:
                    raise PerfLensError(
                        ErrorCode.PATH_SAFETY_VIOLATION,
                        stage,
                        "Collector archive contains an unexpected member",
                    )
            after = os.fstat(handle.fileno())
    except PerfLensError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector archive cannot be read as a safe ZIP",
        ) from exc
    try:
        path_after = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive path disappeared during verification",
        ) from exc
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    ) or (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive changed while it was being verified",
        )
    return resolved, digest.hexdigest(), manifest


def _open_trusted_archive(
    path: Path,
    *,
    require_root_owner: bool,
    stage: str,
) -> tuple[Path, int, os.stat_result]:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive must be an absolute non-symbolic-link path",
        )
    descriptor = -1
    try:
        resolved = candidate.resolve(strict=True)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector archive cannot be resolved safely",
        ) from exc
    expected_owners = {0} if require_root_owner else {0, invoking_uid()}
    try:
        parent_metadata = resolved.parent.stat()
    except OSError as exc:
        os.close(descriptor)
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive parent cannot be inspected safely",
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in expected_owners
        or metadata.st_mode & 0o022
        or metadata.st_size > _MAX_ARCHIVE_TOTAL_BYTES + _MAX_ARCHIVE_OVERHEAD_BYTES
        or not resolved.parent.is_dir()
        or parent_metadata.st_uid not in expected_owners
        or parent_metadata.st_mode & 0o022
    ):
        os.close(descriptor)
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive ownership, permissions, type, or size are unsafe",
        )
    return resolved, descriptor, metadata


def _validate_zip_info(
    info: zipfile.ZipInfo,
    *,
    expected_size: int | None,
    max_bytes: int,
    stage: str,
) -> None:
    mode = info.external_attr >> 16
    if (
        info.is_dir()
        or info.flag_bits & 0x1
        or info.compress_type != zipfile.ZIP_STORED
        or info.file_size != info.compress_size
        or info.file_size > max_bytes
        or (expected_size is not None and info.file_size != expected_size)
        or not stat.S_ISREG(mode)
        or mode & 0o022
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive member violates the stored-file safety profile",
            details={"member": info.filename},
        )


def _validate_manifest_consistency(
    manifest: CollectorSpoolArchiveManifest,
    *,
    policy: CollectorDeploymentPolicy,
    stage: str,
) -> None:
    names = [entry.name for entry in manifest.entries]
    total_bytes = sum(entry.logical_bytes for entry in manifest.entries)
    try:
        created_at = datetime.fromisoformat(manifest.created_at)
    except ValueError as exc:
        raise PerfLensError(
            ErrorCode.INVALID_INPUT,
            stage,
            "Collector archive manifest has an invalid creation timestamp",
        ) from exc
    if (
        manifest.spool_root != str(policy.spool_root)
        or manifest.allowed_uid != policy.allowed_uids[0]
        or manifest.privilege_mode != policy.privilege_mode
        or created_at.tzinfo is None
        or manifest.archive_id
        != _archive_id(manifest.policy_sha256, manifest.spool_root, manifest.entries)
        or manifest.artifact_count != len(manifest.entries)
        or manifest.total_logical_bytes != total_bytes
        or len(names) != len(set(names))
        or manifest.artifact_count > manifest.max_artifacts
        or manifest.total_logical_bytes > manifest.max_total_bytes
        or manifest.artifact_count > manifest.eligible_artifact_count
        or manifest.selection_truncated
        != (manifest.artifact_count < manifest.eligible_artifact_count)
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Collector archive manifest is inconsistent with policy or contents",
        )


def _entry_exists(descriptor: int, name: str, *, stage: str) -> bool:
    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            stage,
            "Unable to inspect an archived Collector source artifact",
            details={"entry": name},
        ) from exc


def _verify_source_entry(
    spool_descriptor: int,
    entry: CollectorSpoolArchiveEntry,
    *,
    identity: _SpoolIdentity,
    stage: str,
) -> None:
    try:
        metadata = os.stat(entry.name, dir_fd=spool_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Archived Collector source cannot be inspected safely",
            details={"entry": entry.name},
        ) from exc
    snapshot = _SpoolSnapshot(entry.name, metadata)
    metadata = snapshot.metadata
    if (
        metadata.st_dev != entry.source_device
        or metadata.st_ino != entry.source_inode
        or metadata.st_size != entry.logical_bytes
        or metadata.st_mtime_ns != entry.modified_time_ns
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Archived Collector source identity no longer matches the manifest",
            details={"entry": entry.name},
        )
    captured = _capture_entry(
        spool_descriptor,
        snapshot,
        identity=identity,
        archive=None,
        stage=stage,
    )
    if captured.sha256 != entry.sha256:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Archived Collector source SHA-256 no longer matches the manifest",
            details={"entry": entry.name},
        )


def _trusted_file_sha256(path: Path, *, max_bytes: int, stage: str) -> str:
    descriptor = -1
    digest = hashlib.sha256()
    read_bytes = 0
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            while True:
                chunk = handle.read(_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                read_bytes += len(chunk)
                if read_bytes > max_bytes:
                    raise PerfLensError(
                        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                        stage,
                        "Collector archive exceeds its output size bound",
                    )
                digest.update(chunk)
            after = os.fstat(handle.fileno())
    except PerfLensError:
        raise
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.OUTPUT_WRITE_FAILED,
            stage,
            "Unable to hash the published Collector archive",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        path_after = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Published Collector archive path disappeared while hashing",
        ) from exc
    if (
        read_bytes != metadata.st_size
        or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mtime_ns,
        )
        != (after.st_dev, after.st_ino, after.st_mtime_ns)
        or (
            path_after.st_dev,
            path_after.st_ino,
        )
        != (after.st_dev, after.st_ino)
    ):
        raise PerfLensError(
            ErrorCode.PATH_SAFETY_VIOLATION,
            stage,
            "Published Collector archive changed while it was being hashed",
        )
    return digest.hexdigest()


def _archive_id(
    policy_sha256: str,
    spool_root: str,
    entries: tuple[CollectorSpoolArchiveEntry, ...],
) -> str:
    identity = "|".join(
        (
            policy_sha256,
            spool_root,
            *(f"{entry.name}:{entry.sha256}:{entry.source_inode}" for entry in entries),
        )
    )
    return f"spool-archive-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"


def _archive_result(
    status: Literal["dry_run", "archived", "nothing_to_archive"],
    output: Path,
    archive_sha256: str | None,
    manifest: CollectorSpoolArchiveManifest,
) -> CollectorSpoolArchiveArtifact:
    return CollectorSpoolArchiveArtifact(
        perflens_version=__version__,
        status=status,
        archive_path=str(output),
        archive_sha256=archive_sha256,
        archive_created=status == "archived",
        manifest=manifest,
        next_steps=(
            "Keep the archive on independent storage before pruning source artifacts.",
            "Run prune-archived-spool --dry-run and review every planned artifact name.",
        ),
    )


def _archive_verification_result(
    archive_path: Path,
    archive_sha256: str,
    config_path: Path,
    manifest: CollectorSpoolArchiveManifest,
    *,
    source_artifacts_checked: bool,
    present_source_artifact_count: int | None,
    absent_source_artifact_count: int | None,
) -> CollectorSpoolArchiveVerificationArtifact:
    checked_at = datetime.now(tz=UTC).isoformat()
    identity = "\0".join((archive_sha256, checked_at, str(source_artifacts_checked)))
    next_steps = [
        "Keep the verified archive on independent storage for the required retention period."
    ]
    if not source_artifacts_checked:
        next_steps.append(
            "Rerun verify-spool-archive with --verify-sources to cross-check surviving sources."
        )
    elif present_source_artifact_count:
        next_steps.append(
            "Use prune-archived-spool --dry-run only if source-space reclamation is intended."
        )
    else:
        next_steps.append("No matching source artifact remains in the Collector spool.")
    return CollectorSpoolArchiveVerificationArtifact(
        perflens_version=__version__,
        verification_id=(
            f"archive-verification-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"
        ),
        checked_at=checked_at,
        archive_path=str(archive_path),
        archive_sha256=archive_sha256,
        archive_id=manifest.archive_id,
        archive_created_at=manifest.created_at,
        config_path=str(config_path),
        spool_root=manifest.spool_root,
        artifact_count=manifest.artifact_count,
        total_logical_bytes=manifest.total_logical_bytes,
        source_artifacts_checked=source_artifacts_checked,
        present_source_artifact_count=present_source_artifact_count,
        absent_source_artifact_count=absent_source_artifact_count,
        next_steps=tuple(next_steps),
    )


def _prune_result(
    status: Literal["dry_run", "pruned", "nothing_to_prune"],
    archive_path: Path,
    archive_sha256: str,
    manifest: CollectorSpoolArchiveManifest,
    present: tuple[CollectorSpoolArchiveEntry, ...] | list[CollectorSpoolArchiveEntry],
    *,
    planned_bytes: int,
    already_absent: int,
    removed_count: int,
    removed_bytes: int,
) -> CollectorSpoolPruneArtifact:
    return CollectorSpoolPruneArtifact(
        perflens_version=__version__,
        status=status,
        archive_path=str(archive_path),
        archive_sha256=archive_sha256,
        archive_id=manifest.archive_id,
        config_path=manifest.config_path,
        spool_root=manifest.spool_root,
        planned_artifact_names=tuple(entry.name for entry in present),
        planned_logical_bytes=planned_bytes,
        already_absent_artifact_count=already_absent,
        removed_artifact_count=removed_count,
        removed_logical_bytes=removed_bytes,
        next_steps=(
            "Keep the verified archive until its retention and independent backup checks pass.",
            "Run perflens-admin spool-status to confirm the reclaimed capacity.",
        ),
    )
