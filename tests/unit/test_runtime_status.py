from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

from perflens.collection.capabilities import inspect_collection_capabilities
from perflens.contracts.artifacts import CollectorHealthArtifact, RuntimeStatusArtifact
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


def test_runtime_status_artifact_accepts_pre_health_fields_payload(tmp_path: Path) -> None:
    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )
    payload = artifact.model_dump()
    for field in (
        "collector_health_status",
        "collector_health_error_code",
        "collector_service_pid",
        "collector_service_uid",
        "collector_policy_version",
        "collector_allowed_modes",
        "collector_spool_root",
    ):
        payload.pop(field)

    restored = RuntimeStatusArtifact.model_validate(payload)

    assert restored.collector_health_status == "not_checked"
    assert restored.collector_health_error_code is None
    assert restored.collector_service_pid is None
    assert restored.collector_allowed_modes == ()


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


def test_runtime_status_accepts_host_level_collector_without_project_assets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mcp = tmp_path / "perflens-mcp"
    mcp.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    mcp.chmod(0o500)
    run_project_setup(
        tmp_path,
        mcp_command=mcp,
        perf_path=Path("/bin/true"),
        automatic_collection=True,
    )
    monkeypatch.setattr(
        "perflens.distribution.status._collector_group_status",
        lambda: "member",
    )

    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )

    assert artifact.collector_assets_status == "not_requested"
    assert artifact.automatic_collection_status == "collector_unavailable"
    assert "collector_assets_missing" not in artifact.issues


def test_runtime_status_accepts_claude_only_project_activation(tmp_path: Path) -> None:
    mcp = tmp_path / "perflens-mcp"
    mcp.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    mcp.chmod(0o500)
    run_project_setup(
        tmp_path,
        install_skill=False,
        install_codex_config=False,
        install_claude_skill=True,
        install_claude_config=True,
        codex_enabled=False,
        claude_enabled=True,
        mcp_command=mcp,
        perf_path=Path("/bin/true"),
    )

    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )

    assert artifact.setup_status == "ready"
    assert artifact.skill_status == "ready"
    assert artifact.mcp_config_status == "ready"
    assert artifact.automatic_collection_status == "not_configured"


def test_runtime_status_requires_active_project_mcp_configuration(tmp_path: Path) -> None:
    _prepare_automatic_setup(tmp_path)
    config = tmp_path / ".codex/config.toml"
    config.unlink()

    missing = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )
    assert missing.mcp_config_status == "missing"
    assert "mcp_project_config_missing" in missing.issues
    assert missing.automatic_collection_status == "configuration_incomplete"

    config.write_text("not valid = [toml", encoding="utf-8")
    incomplete = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )
    assert incomplete.mcp_config_status == "incomplete"
    assert "mcp_project_config_incomplete" in incomplete.issues

    generated = (tmp_path / "perflens-setup/codex-mcp.toml").read_text(encoding="utf-8")
    config.write_text(generated.replace("tool_timeout_sec = 300", "tool_timeout_sec = 301"))
    mismatched = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )
    assert mismatched.mcp_config_status == "incomplete"
    assert mismatched.automatic_collection_status == "configuration_incomplete"

    config.write_text(generated, encoding="utf-8")
    (tmp_path / "perflens-mcp").unlink()
    missing_command = inspect_runtime_status(
        tmp_path,
        collector_socket=tmp_path / "missing.sock",
        perf_path=Path("/bin/true"),
    )
    assert missing_command.mcp_config_status == "incomplete"
    assert "mcp_project_config_incomplete" in missing_command.issues
    assert missing_command.automatic_collection_status == "configuration_incomplete"


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
    ("socket_status", "group_status", "health_status", "expected"),
    [
        ("inaccessible", "member", "not_checked", "access_denied"),
        ("ready", "not_member", "not_checked", "access_denied"),
        ("ready", "member", "unreachable", "collector_unavailable"),
        ("ready", "member", "rejected", "collector_unavailable"),
        ("ready", "member", "ready", "ready_for_verification"),
    ],
)
def test_runtime_status_distinguishes_collector_access_and_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    socket_status: str,
    group_status: str,
    health_status: str,
    expected: str,
) -> None:
    _prepare_automatic_setup(tmp_path)

    def reported_socket_status(_path: Path) -> str:
        return socket_status

    def reported_group_status() -> str:
        return group_status

    health_artifact = CollectorHealthArtifact(
        perflens_version="test",
        policy_version=1,
        service_pid=123,
        service_uid=456,
        peer_uid=789,
        allowed_modes=("stat",),
        spool_root="/var/lib/perflens",
    )

    def reported_service_uid() -> int:
        return 456

    class ReportedBrokerClient:
        def __init__(self, _path: Path, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 0.5

        def health(self, *, expected_service_uid: int | None) -> CollectorHealthArtifact:
            assert expected_service_uid == 456
            if health_status == "ready":
                return health_artifact
            if health_status == "unreachable":
                raise PerfLensError(
                    ErrorCode.EXTERNAL_TOOL_FAILED,
                    "collector_broker",
                    "unreachable",
                )
            raise PerfLensError(
                ErrorCode.PATH_SAFETY_VIOLATION,
                "collector_broker",
                "rejected",
            )

    monkeypatch.setattr("perflens.distribution.status._inspect_socket", reported_socket_status)
    monkeypatch.setattr(
        "perflens.distribution.status._collector_group_status", reported_group_status
    )
    monkeypatch.setattr("perflens.distribution.status._collector_service_uid", reported_service_uid)
    monkeypatch.setattr("perflens.distribution.status.CollectorBrokerClient", ReportedBrokerClient)

    artifact = inspect_runtime_status(tmp_path, perf_path=Path("/bin/true"))

    assert artifact.automatic_collection_status == expected
    assert artifact.collector_health_status == health_status
    if expected == "ready_for_verification":
        assert artifact.collector_service_pid == 123
        assert artifact.collector_service_uid == 456
        assert artifact.collector_allowed_modes == ("stat",)
        assert artifact.next_steps == (
            "Run perflens accept-collector --authorize-host-acceptance.",
        )


def test_runtime_status_uses_authenticated_full_diagnostics_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_automatic_setup(tmp_path)
    setup_path = tmp_path / "perflens-setup/setup.json"
    setup_payload = json.loads(setup_path.read_text(encoding="utf-8"))
    setup_payload["collector_feature_profile"] = "full_diagnostics"
    setup_path.write_text(json.dumps(setup_payload), encoding="utf-8")
    health = CollectorHealthArtifact(
        perflens_version="test",
        policy_version=1,
        service_pid=123,
        service_uid=456,
        peer_uid=789,
        allowed_modes=("stat", "record", "sched", "off_cpu", "lock"),
        spool_root="/var/lib/perflens",
        feature_profile="full_diagnostics",
    )

    class ReportedBrokerClient:
        def __init__(self, _path: Path, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 0.5

        def health(self, *, expected_service_uid: int | None) -> CollectorHealthArtifact:
            assert expected_service_uid == 456
            return health

    def ready_socket(_path: Path) -> str:
        return "ready"

    monkeypatch.setattr("perflens.distribution.status._inspect_socket", ready_socket)
    monkeypatch.setattr("perflens.distribution.status._collector_group_status", lambda: "member")
    monkeypatch.setattr("perflens.distribution.status._collector_service_uid", lambda: 456)
    monkeypatch.setattr("perflens.distribution.status.CollectorBrokerClient", ReportedBrokerClient)

    artifact = inspect_runtime_status(tmp_path, perf_path=Path("/bin/true"))

    assert artifact.feature_profile == "full_diagnostics"
    assert artifact.trace_backend_status == "available"
    assert "collector_trace_backend_unavailable" not in artifact.issues


def test_runtime_status_rejects_stale_socket_as_unreachable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_automatic_setup(tmp_path)
    socket_path = tmp_path / "stale.sock"
    stale_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale_socket.bind(str(socket_path))
    stale_socket.close()
    monkeypatch.setattr("perflens.distribution.status._collector_group_status", lambda: "member")
    monkeypatch.setattr("perflens.distribution.status._collector_service_uid", lambda: 456)

    artifact = inspect_runtime_status(
        tmp_path,
        collector_socket=socket_path,
        perf_path=Path("/bin/true"),
    )

    assert artifact.collector_socket_status == "ready"
    assert artifact.collector_health_status == "unreachable"
    assert artifact.collector_health_error_code == ErrorCode.EXTERNAL_TOOL_FAILED.value
    assert artifact.automatic_collection_status == "collector_unavailable"
    assert "collector_health_unreachable" in artifact.issues


def test_runtime_status_requires_dedicated_collector_service_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_automatic_setup(tmp_path)

    def ready_socket(_path: Path) -> str:
        return "ready"

    monkeypatch.setattr("perflens.distribution.status._inspect_socket", ready_socket)
    monkeypatch.setattr("perflens.distribution.status._collector_group_status", lambda: "member")
    monkeypatch.setattr("perflens.distribution.status._collector_service_uid", lambda: None)

    artifact = inspect_runtime_status(tmp_path, perf_path=Path("/bin/true"))

    assert artifact.collector_health_status == "rejected"
    assert artifact.collector_health_error_code == ErrorCode.PATH_SAFETY_VIOLATION.value
    assert artifact.automatic_collection_status == "collector_unavailable"
    assert "collector_service_user_missing" in artifact.issues
