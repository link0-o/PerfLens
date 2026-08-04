from __future__ import annotations

import sys
from pathlib import Path

import pytest

from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.distribution.onboarding import run_project_setup
from perflens.distribution.status import inspect_runtime_status
from perflens.domain.errors import ErrorCode, PerfLensError


def _prepare_automatic_setup(tmp_path: Path) -> None:
    mcp = tmp_path / "perflens-mcp"
    mcp.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    mcp.chmod(0o500)
    collector = tmp_path / "perflens-collector"
    collector.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    collector.chmod(0o500)
    run_project_setup(
        tmp_path,
        mcp_command=mcp,
        perf_path=Path("/bin/true"),
        collector_command=collector,
        prepare_collector=True,
        automatic_collection=True,
    )


def test_runtime_status_reports_missing_setup_without_mutation(tmp_path: Path) -> None:
    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )

    assert artifact.schema_version == "1.0"
    assert artifact.setup_status == "missing"
    assert artifact.skill_status == "missing"
    assert artifact.mcp_config_status == "missing"
    assert artifact.automatic_collection_status == "not_configured"
    assert "setup_missing" in artifact.issues
    assert not (tmp_path / "perflens-setup").exists()


def test_runtime_status_tracks_generated_automatic_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_automatic_setup(tmp_path)

    def member() -> str:
        return "member"

    monkeypatch.setattr("perflens.distribution.status._collector_group_status", member)
    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )

    assert artifact.setup_status == "ready"
    assert artifact.skill_status == "ready"
    assert artifact.mcp_config_status == "ready"
    assert artifact.automatic_collection_requested is True
    assert artifact.collector_assets_status == "ready"
    assert artifact.collector_socket_status == "missing"
    assert artifact.collector_group_status == "member"
    assert artifact.automatic_collection_status == "collector_unavailable"


def test_runtime_status_rejects_setup_escape_and_marks_symlink_incomplete(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    with pytest.raises(PerfLensError) as escaped:
        inspect_runtime_status(
            tmp_path,
            setup_directory=outside,
            collector_socket=tmp_path / "missing.sock",
            perf_path=Path("/bin/true"),
        )
    assert escaped.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    target = tmp_path / "target"
    target.mkdir()
    setup_link = tmp_path / "perflens-setup"
    setup_link.symlink_to(target, target_is_directory=True)
    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )
    assert artifact.setup_status == "incomplete"
    assert "setup_unsafe" in artifact.issues


def test_runtime_status_host_status_matches_capability_snapshot(tmp_path: Path) -> None:
    capabilities = inspect_collection_capabilities(Path("/bin/true"))
    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )
    statuses = {mode.status for mode in capabilities.modes}
    if statuses == {"available"}:
        assert artifact.host_collection_status == "available"
    elif statuses == {"blocked"}:
        assert artifact.host_collection_status == "blocked"
    else:
        assert artifact.host_collection_status == "conditional"


def test_runtime_status_rejects_invalid_project_paths(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(PerfLensError) as absent:
        inspect_runtime_status(missing, perf_path=Path("/bin/true"))
    assert absent.value.code is ErrorCode.INVALID_INPUT

    regular_file = tmp_path / "project.txt"
    regular_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(PerfLensError) as wrong_type:
        inspect_runtime_status(regular_file, perf_path=Path("/bin/true"))
    assert wrong_type.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    ("artifact_content", "expected_issue"),
    [
        (None, "setup_artifact_missing"),
        (b"not-json", "setup_artifact_invalid"),
        (b"x" * ((1 << 20) + 1), "setup_artifact_invalid"),
    ],
)
def test_runtime_status_reports_incomplete_setup_artifacts(
    tmp_path: Path,
    artifact_content: bytes | None,
    expected_issue: str,
) -> None:
    setup = tmp_path / "perflens-setup"
    setup.mkdir()
    if artifact_content is not None:
        (setup / "setup.json").write_bytes(artifact_content)

    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "not-a-socket",
        perf_path=Path("/bin/true"),
    )

    assert artifact.setup_status == "incomplete"
    assert expected_issue in artifact.issues
    assert artifact.collector_socket_status == "missing"


def test_runtime_status_reports_incomplete_collector_assets(tmp_path: Path) -> None:
    _prepare_automatic_setup(tmp_path)
    (tmp_path / "perflens-setup/collector-assets/perflens.sysusers").unlink()

    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )

    assert artifact.collector_assets_status == "incomplete"
    assert artifact.automatic_collection_status == "configuration_incomplete"
    assert "collector_assets_incomplete" in artifact.issues


@pytest.mark.parametrize(
    ("socket_status", "group_status", "expected"),
    [
        ("inaccessible", "member", "access_denied"),
        ("ready", "not_member", "access_denied"),
        ("ready", "member", "ready_for_verification"),
    ],
)
def test_runtime_status_distinguishes_collector_access_and_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    socket_status: str,
    group_status: str,
    expected: str,
) -> None:
    _prepare_automatic_setup(tmp_path)

    def reported_socket_status(_path: Path) -> str:
        return socket_status

    def reported_group_status() -> str:
        return group_status

    monkeypatch.setattr(
        "perflens.distribution.status._inspect_socket", reported_socket_status
    )
    monkeypatch.setattr(
        "perflens.distribution.status._collector_group_status", reported_group_status
    )

    artifact = inspect_runtime_status(tmp_path, perf_path=Path("/bin/true"))

    assert artifact.automatic_collection_status == expected
    if expected == "ready_for_verification":
        assert artifact.next_steps == (
            "Run perflens accept-collector --authorize-host-acceptance.",
        )
