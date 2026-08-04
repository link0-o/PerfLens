from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

import perflens.admin.spool as admin_spool
from perflens.admin.app import app
from perflens.admin.deploy import CollectorSystemLayout
from perflens.admin.spool import (
    SPOOL_PRUNE_AUTHORIZATION,
    archive_collector_spool,
    prune_archived_collector_spool,
)
from perflens.contracts.artifacts import (
    CollectorSpoolArchiveArtifact,
    CollectorSpoolPruneArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def _spool_inputs(
    tmp_path: Path,
) -> tuple[Path, CollectorSystemLayout, Path, datetime]:
    perf = tmp_path / "perf"
    perf.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    perf.chmod(0o555)
    layout = CollectorSystemLayout(
        config_directory=tmp_path / "system/etc/perflens",
        config_path=tmp_path / "system/etc/perflens/collector.toml",
        service_path=tmp_path / "system/etc/systemd/perflens-collector.service",
        state_directory=tmp_path / "system/var/lib/perflens",
        socket_path=tmp_path / "system/run/perflens/collector.sock",
    )
    layout.state_directory.mkdir(parents=True)
    layout.state_directory.chmod(0o750)
    config = tmp_path / "collector.toml"
    config.write_text(
        "[collector]\n"
        f'spool_root = "{layout.state_directory}"\n'
        f'perf_path = "{perf}"\n'
        f"allowed_uids = [{os.geteuid()}]\n"
        'allowed_modes = ["record", "stat"]\n'
        "allow_other_target_uids = false\n"
        "max_output_bytes = 1048576\n"
        "max_spool_bytes = 10737418240\n"
        "max_spool_artifacts = 1000\n"
        "min_free_bytes = 0\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    archive_directory = tmp_path / "archives"
    archive_directory.mkdir()
    archive_directory.chmod(0o700)
    return config, layout, archive_directory, datetime(2026, 8, 4, tzinfo=UTC)


def _artifact(
    layout: CollectorSystemLayout,
    suffix_id: int,
    content: bytes,
    *,
    modified_at: datetime,
    stat_output: bool = False,
) -> Path:
    suffix = "stat.csv" if stat_output else "perf.data"
    path = layout.state_directory / f"plan-{suffix_id:020x}.{suffix}"
    path.write_bytes(content)
    path.chmod(0o640)
    timestamp_ns = int(modified_at.timestamp() * 1_000_000_000)
    os.utime(path, ns=(timestamp_ns, timestamp_ns))
    return path


def _archive(
    output: Path,
    config: Path,
    layout: CollectorSystemLayout,
    now: datetime,
    **kwargs: object,
) -> CollectorSpoolArchiveArtifact:
    return archive_collector_spool(
        output,
        config_path=config,
        layout=layout,
        require_root=False,
        require_root_owned_tools=False,
        service_uid=os.geteuid(),
        service_gid=os.getegid(),
        now=now,
        **kwargs,  # type: ignore[arg-type]
    )


def _prune(
    archive: Path,
    config: Path,
    layout: CollectorSystemLayout,
    **kwargs: object,
) -> CollectorSpoolPruneArtifact:
    return prune_archived_collector_spool(
        archive,
        config_path=config,
        layout=layout,
        require_root=False,
        service_uid=os.geteuid(),
        service_gid=os.getegid(),
        **kwargs,  # type: ignore[arg-type]
    )


def test_archive_plan_copy_and_explicit_prune_form_a_verified_lifecycle(
    tmp_path: Path,
) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    oldest = _artifact(layout, 1, b"oldest", modified_at=now - timedelta(days=10))
    second = _artifact(
        layout,
        2,
        b"second",
        modified_at=now - timedelta(days=9),
        stat_output=True,
    )
    third = _artifact(layout, 3, b"third", modified_at=now - timedelta(days=8))
    latest = _artifact(layout, 4, b"latest", modified_at=now - timedelta(days=1))
    output = archive_directory / "evidence.zip"

    dry_run = _archive(
        output,
        config,
        layout,
        now,
        dry_run=True,
        older_than_days=7,
        keep_latest=1,
        max_artifacts=2,
        max_total_bytes=1024,
    )
    assert dry_run.schema_version == "1.0"
    assert dry_run.status == "dry_run"
    assert dry_run.archive_path == str(output)
    assert dry_run.archive_created is False
    assert dry_run.archive_sha256 is None
    assert dry_run.manifest.eligible_artifact_count == 3
    assert dry_run.manifest.selection_truncated is True
    assert [entry.name for entry in dry_run.manifest.entries] == [
        oldest.name,
        second.name,
    ]
    assert not output.exists()

    archived = _archive(
        output,
        config,
        layout,
        now,
        older_than_days=7,
        keep_latest=1,
        max_artifacts=2,
        max_total_bytes=1024,
    )
    assert archived.status == "archived"
    assert archived.archive_created is True
    assert archived.archive_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert archived.manifest == dry_run.manifest
    assert output.stat().st_mode & 0o777 == 0o600
    assert all(path.exists() for path in (oldest, second, third, latest))
    with zipfile.ZipFile(output) as bundle:
        assert set(bundle.namelist()) == {
            "manifest.json",
            f"artifacts/{oldest.name}",
            f"artifacts/{second.name}",
        }
        assert bundle.read(f"artifacts/{oldest.name}") == b"oldest"

    prune_plan = _prune(output, config, layout, dry_run=True)
    assert prune_plan.status == "dry_run"
    assert prune_plan.removed_artifact_count == 0
    assert prune_plan.planned_artifact_names == (oldest.name, second.name)
    with pytest.raises(PerfLensError) as unauthorized:
        _prune(output, config, layout)
    assert unauthorized.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert all(path.exists() for path in (oldest, second, third, latest))

    pruned = _prune(
        output,
        config,
        layout,
        authorization=SPOOL_PRUNE_AUTHORIZATION,
    )
    assert pruned.status == "pruned"
    assert pruned.removed_artifact_count == 2
    assert pruned.removed_logical_bytes == len(b"oldestsecond")
    assert not oldest.exists()
    assert not second.exists()
    assert third.read_bytes() == b"third"
    assert latest.read_bytes() == b"latest"
    assert output.exists()

    repeated = _prune(output, config, layout)
    assert repeated.status == "nothing_to_prune"
    assert repeated.already_absent_artifact_count == 2


def test_archive_refuses_unmanaged_spool_entries_and_output_inside_spool(
    tmp_path: Path,
) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    unmanaged = layout.state_directory / "administrator-note.txt"
    unmanaged.write_text("keep", encoding="utf-8")
    unmanaged.chmod(0o640)

    with pytest.raises(PerfLensError) as rejected:
        _archive(
            archive_directory / "unsafe.zip",
            config,
            layout,
            now,
            dry_run=True,
            older_than_days=0,
            keep_latest=0,
        )
    assert rejected.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert rejected.value.details["entry"] == unmanaged.name
    assert unmanaged.read_text(encoding="utf-8") == "keep"

    unmanaged.unlink()
    with pytest.raises(PerfLensError) as inside:
        _archive(
            layout.state_directory / "archive.zip",
            config,
            layout,
            now,
            dry_run=True,
            older_than_days=0,
            keep_latest=0,
        )
    assert inside.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    outside = tmp_path / "outside.data"
    outside.write_bytes(b"outside")
    linked = layout.state_directory / "plan-00000000000000000001.perf.data"
    linked.symlink_to(outside)
    with pytest.raises(PerfLensError) as symlinked:
        _archive(
            archive_directory / "linked.zip",
            config,
            layout,
            now,
            dry_run=True,
            older_than_days=0,
            keep_latest=0,
        )
    assert symlinked.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert outside.read_bytes() == b"outside"


def test_empty_spool_and_invalid_archive_inputs_remain_non_mutating(tmp_path: Path) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    output = archive_directory / "empty.zip"
    empty = _archive(
        output,
        config,
        layout,
        now,
        older_than_days=0,
        keep_latest=0,
    )
    assert empty.status == "nothing_to_archive"
    assert empty.manifest.artifact_count == 0
    assert empty.archive_created is False
    assert not output.exists()

    with pytest.raises(PerfLensError) as invalid_limit:
        _archive(
            output,
            config,
            layout,
            now,
            dry_run=True,
            older_than_days=-1,
        )
    assert invalid_limit.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(PerfLensError) as relative:
        _archive(
            Path("relative.zip"),
            config,
            layout,
            now,
            dry_run=True,
        )
    assert relative.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError) as wrong_suffix:
        _archive(
            archive_directory / "archive.tar",
            config,
            layout,
            now,
            dry_run=True,
        )
    assert wrong_suffix.value.code is ErrorCode.INVALID_INPUT

    invalid_zip = archive_directory / "invalid.zip"
    invalid_zip.write_bytes(b"not a zip")
    invalid_zip.chmod(0o600)
    with pytest.raises(PerfLensError) as invalid_archive:
        _prune(invalid_zip, config, layout, dry_run=True)
    assert invalid_archive.value.code is ErrorCode.INVALID_INPUT

    archive_link = archive_directory / "linked-archive.zip"
    archive_link.symlink_to(invalid_zip)
    with pytest.raises(PerfLensError) as linked_archive:
        _prune(archive_link, config, layout, dry_run=True)
    assert linked_archive.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_archive_rejects_missing_admin_and_unsafe_runtime_parameters(tmp_path: Path) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    output = archive_directory / "parameters.zip"
    with pytest.raises(PerfLensError) as administrator_required:
        archive_collector_spool(
            output,
            config_path=config,
            layout=layout,
            require_root=True,
            require_root_owned_tools=False,
            service_uid=os.geteuid(),
            service_gid=os.getegid(),
            now=now,
        )
    assert administrator_required.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError) as naive_time:
        _archive(
            output,
            config,
            layout,
            now.replace(tzinfo=None),
            dry_run=True,
        )
    assert naive_time.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(PerfLensError) as invalid_uid:
        archive_collector_spool(
            output,
            config_path=config,
            dry_run=True,
            layout=layout,
            require_root=False,
            require_root_owned_tools=False,
            service_uid=-1,
            service_gid=os.getegid(),
            now=now,
        )
    assert invalid_uid.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(PerfLensError) as wrong_gid:
        archive_collector_spool(
            output,
            config_path=config,
            dry_run=True,
            layout=layout,
            require_root=False,
            require_root_owned_tools=False,
            service_uid=os.geteuid(),
            service_gid=os.getegid() + 1,
            now=now,
        )
    assert wrong_gid.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError) as boolean_limit:
        _archive(
            output,
            config,
            layout,
            now,
            dry_run=True,
            older_than_days=True,
        )
    assert boolean_limit.value.code is ErrorCode.INVALID_INPUT

    output.write_bytes(b"existing")
    output.chmod(0o600)
    with pytest.raises(PerfLensError) as existing:
        _archive(output, config, layout, now, dry_run=True)
    assert existing.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    output.unlink()
    archive_directory.chmod(0o770)
    with pytest.raises(PerfLensError) as unsafe_parent:
        _archive(output, config, layout, now, dry_run=True)
    assert unsafe_parent.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_prune_rejects_changed_source_without_removing_anything(tmp_path: Path) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    source = _artifact(layout, 1, b"original", modified_at=now - timedelta(days=10))
    output = archive_directory / "changed-source.zip"
    _archive(
        output,
        config,
        layout,
        now,
        older_than_days=0,
        keep_latest=0,
    )
    source.write_bytes(b"modified")
    source.chmod(0o640)
    with zipfile.ZipFile(output) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
    modified_time_ns = manifest["entries"][0]["modified_time_ns"]
    os.utime(source, ns=(modified_time_ns, modified_time_ns))

    with pytest.raises(PerfLensError) as changed:
        _prune(output, config, layout, dry_run=True)
    assert changed.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert source.read_bytes() == b"modified"
    assert output.exists()


def test_prune_rejects_tampered_or_duplicate_archive_members(tmp_path: Path) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    source = _artifact(layout, 1, b"evidence", modified_at=now - timedelta(days=10))
    output = archive_directory / "tampered.zip"
    _archive(
        output,
        config,
        layout,
        now,
        older_than_days=0,
        keep_latest=0,
    )
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(output, mode="a", compression=zipfile.ZIP_STORED) as bundle,
    ):
        bundle.writestr("manifest.json", b"{}")
    output.chmod(0o600)

    with pytest.raises(PerfLensError) as tampered:
        _prune(output, config, layout, dry_run=True)
    assert tampered.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert source.read_bytes() == b"evidence"


@pytest.mark.parametrize(
    ("tamper", "expected_code"),
    [
        ("invalid_manifest", ErrorCode.INVALID_INPUT),
        ("invalid_timestamp", ErrorCode.INVALID_INPUT),
        ("missing_member", ErrorCode.INVALID_INPUT),
        ("changed_member", ErrorCode.PATH_SAFETY_VIOLATION),
        ("unexpected_member", ErrorCode.PATH_SAFETY_VIOLATION),
    ],
)
def test_prune_rejects_structurally_tampered_archives(
    tmp_path: Path,
    tamper: str,
    expected_code: ErrorCode,
) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    source = _artifact(layout, 1, b"evidence", modified_at=now - timedelta(days=10))
    original = archive_directory / "original.zip"
    _archive(
        original,
        config,
        layout,
        now,
        older_than_days=0,
        keep_latest=0,
    )
    tampered = archive_directory / f"{tamper}.zip"
    with zipfile.ZipFile(original, "r") as source_bundle:
        members = [
            (info, source_bundle.read(info.filename)) for info in source_bundle.infolist()
        ]
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_STORED) as output_bundle:
        for info, payload in members:
            if tamper == "missing_member" and info.filename.startswith("artifacts/"):
                continue
            if info.filename == "manifest.json":
                if tamper == "invalid_manifest":
                    payload = b"{}"
                elif tamper == "invalid_timestamp":
                    decoded = json.loads(payload)
                    decoded["created_at"] = "not-a-timestamp"
                    payload = json.dumps(decoded).encode()
            elif tamper == "changed_member":
                payload = b"Evidence"
            output_bundle.writestr(info, payload)
        if tamper == "unexpected_member":
            extra = zipfile.ZipInfo("unexpected.txt", date_time=(1980, 1, 1, 0, 0, 0))
            extra.compress_type = zipfile.ZIP_STORED
            extra.external_attr = (0o100600) << 16
            output_bundle.writestr(extra, b"unexpected")
    tampered.chmod(0o600)

    with pytest.raises(PerfLensError) as rejected:
        _prune(tampered, config, layout, dry_run=True)
    assert rejected.value.code is expected_code
    assert source.read_bytes() == b"evidence"


def test_prune_reports_partial_unlink_failure_and_preserves_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    first = _artifact(layout, 1, b"first", modified_at=now - timedelta(days=10))
    second = _artifact(layout, 2, b"second", modified_at=now - timedelta(days=9))
    output = archive_directory / "partial.zip"
    _archive(
        output,
        config,
        layout,
        now,
        older_than_days=0,
        keep_latest=0,
    )
    real_unlink = admin_spool.os.unlink

    def fail_second_unlink(
        path: str | bytes | Path,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if path == second.name:
            raise OSError("simulated unlink failure")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(admin_spool.os, "unlink", fail_second_unlink)
    with pytest.raises(PerfLensError) as failed:
        _prune(
            output,
            config,
            layout,
            authorization=SPOOL_PRUNE_AUTHORIZATION,
        )
    assert failed.value.code is ErrorCode.OUTPUT_WRITE_FAILED
    assert failed.value.details["removed_artifact_count"] == 1
    assert not first.exists()
    assert second.read_bytes() == b"second"
    assert output.exists()


def test_archive_and_prune_cli_emit_versioned_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, layout, archive_directory, now = _spool_inputs(tmp_path)
    _artifact(layout, 1, b"evidence", modified_at=now - timedelta(days=10))
    output = archive_directory / "cli.zip"
    archive_result = _archive(
        output,
        config,
        layout,
        now,
        dry_run=True,
        older_than_days=0,
        keep_latest=0,
    )

    def fake_archive(_output: Path, **_kwargs: object) -> CollectorSpoolArchiveArtifact:
        return archive_result

    monkeypatch.setattr("perflens.admin.app.archive_collector_spool", fake_archive)
    archive_cli = CliRunner().invoke(
        app,
        ["archive-spool", "--output", str(output), "--dry-run"],
    )
    assert archive_cli.exit_code == 0, archive_cli.output
    assert '"schema_version": "1.0"' in archive_cli.output
    assert '"status": "dry_run"' in archive_cli.output

    actual_archive = _archive(
        output,
        config,
        layout,
        now,
        older_than_days=0,
        keep_latest=0,
    )
    del actual_archive
    prune_result = _prune(output, config, layout, dry_run=True)

    def fake_prune(_archive: Path, **_kwargs: object) -> CollectorSpoolPruneArtifact:
        return prune_result

    monkeypatch.setattr("perflens.admin.app.prune_archived_collector_spool", fake_prune)
    prune_cli = CliRunner().invoke(
        app,
        ["prune-archived-spool", "--archive", str(output), "--dry-run"],
    )
    assert prune_cli.exit_code == 0, prune_cli.output
    assert '"schema_version": "1.0"' in prune_cli.output
    assert '"status": "dry_run"' in prune_cli.output
