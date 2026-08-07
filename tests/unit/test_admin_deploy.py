from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from typer.testing import CliRunner

import perflens.admin.deploy as admin_deploy
from perflens.admin.app import app
from perflens.admin.deploy import (
    CollectorSystemLayout,
    deploy_collector,
    inspect_collector_spool,
    undeploy_collector,
    update_collector_policy,
    upgrade_collector,
)
from perflens.collector_broker.state import replay_marker_name
from perflens.contracts.artifacts import (
    CollectorDeploymentArtifact,
    CollectorPolicyUpdateArtifact,
    CollectorSpoolStatusArtifact,
    CollectorUndeploymentArtifact,
    CollectorUpgradeArtifact,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def _deployment_inputs(tmp_path: Path) -> tuple[Path, Path, Path, CollectorSystemLayout]:
    perf = tmp_path / "perf"
    perf.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    perf.chmod(0o555)
    collector = tmp_path / "perflens-collector"
    collector.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    collector.chmod(0o555)
    layout = CollectorSystemLayout(
        config_directory=tmp_path / "system/etc/perflens",
        config_path=tmp_path / "system/etc/perflens/collector.toml",
        service_path=tmp_path / "system/etc/systemd/perflens-collector.service",
        state_directory=tmp_path / "system/var/lib/perflens",
        socket_path=tmp_path / "system/run/perflens/collector.sock",
        helper_service_path=tmp_path / "system/etc/systemd/perflens-privileged-helper.service",
        helper_state_directory=tmp_path / "system/var/lib/perflens-helper",
        helper_socket_path=tmp_path / "system/run/perflens-helper/helper.sock",
    )
    config = tmp_path / "collector.toml"
    config.write_text(
        "[collector]\n"
        f'spool_root = "{layout.state_directory}"\n'
        f'perf_path = "{perf}"\n'
        f"allowed_uids = [{os.geteuid()}]\n"
        'allowed_modes = ["record", "stat"]\n'
        "allow_other_target_uids = false\n"
        "max_duration_seconds = 30.0\n"
        "max_frequency_hz = 99\n"
        "max_output_bytes = 1048576\n"
        "max_spool_bytes = 10737418240\n"
        "max_spool_artifacts = 1000\n"
        "min_free_bytes = 1073741824\n"
        "max_plan_ttl_seconds = 300\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config, perf, collector, layout


def _configure_paranoid3(config: Path) -> None:
    config.write_text(
        config.read_text(encoding="utf-8")
        .replace(
            "[collector]\n",
            '[collector]\nprivilege_mode = "paranoid3_helper"\n',
        )
        .replace("max_plan_ttl_seconds = 300", "max_plan_ttl_seconds = 120")
        .replace("max_spool_bytes = 10737418240", "max_spool_bytes = 5368709120")
        .replace("max_spool_artifacts = 1000", "max_spool_artifacts = 500")
        .replace("min_free_bytes = 1073741824", "min_free_bytes = 2147483648"),
        encoding="utf-8",
    )


def test_admin_cli_help_is_chinese_first_and_keeps_stable_commands() -> None:
    runner = CliRunner()
    root_help = runner.invoke(app, ["--help"])
    assert root_help.exit_code == 0, root_help.output
    assert "用于可选 PerfLens Collector 的显式管理员操作" in root_help.output
    assert "undeploy" in root_help.output
    assert "停止并移除托管服务" in root_help.output
    assert "archive-spool" in root_help.output
    assert "归档旧的托管 spool 证据" in root_help.output
    assert "Explicit administrator operations" not in root_help.output

    archive_help = runner.invoke(app, ["archive-spool", "--help"])
    assert archive_help.exit_code == 0, archive_help.output
    assert "只选择早于该天数的产物" in archive_help.output
    assert "单次最多归档的产物数量" in archive_help.output
    assert "只计算哈希并显示计划" in archive_help.output


def test_admin_deploy_dry_run_is_read_only_and_cli_reports_chinese_or_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)

    result = deploy_collector(
        config,
        dry_run=True,
        layout=layout,
        collector_command=collector,
        require_root=False,
    )

    assert result.schema_version == "1.0"
    assert result.status == "dry_run"
    assert result.allowed_uids == (os.geteuid(),)
    assert not layout.config_directory.exists()

    def fake_deploy(
        _config: Path,
        *,
        dry_run: bool = False,
        collector_command: Path | None = None,
        acknowledge_cap_sys_admin_risk: bool = False,
    ) -> CollectorDeploymentArtifact:
        del dry_run, collector_command, acknowledge_cap_sys_admin_risk
        return result

    monkeypatch.setattr("perflens.admin.app.deploy_collector", fake_deploy)
    summary = CliRunner().invoke(
        app,
        [
            "deploy",
            "--config",
            str(config),
            "--dry-run",
        ],
    )
    assert summary.exit_code == 0, summary.output
    assert "PerfLens Collector 部署" in summary.output
    assert "状态: 预检通过; 尚未修改系统" in summary.output
    assert f"授权普通用户 UID: {os.geteuid()}" in summary.output
    assert "计划执行的固定系统命令:" in summary.output
    assert "确认以上路径、UID 和命令符合预期后" in summary.output
    trusted_admin = collector.with_name("perflens-admin")
    assert f"sudo {trusted_admin} deploy" in summary.output
    assert "--collector-command" in summary.output
    assert "--json" in summary.output
    assert '"schema_version"' not in summary.output

    json_result = CliRunner().invoke(
        app,
        [
            "deploy",
            "--config",
            str(config),
            "--dry-run",
            "--json",
        ],
    )
    assert json_result.exit_code == 0, json_result.output
    assert '"schema_version":"1.0"'.replace(" ", "") in json_result.output.replace(" ", "")
    assert '"status":"dry_run"'.replace(" ", "") in json_result.output.replace(" ", "")


def test_admin_deploy_installs_fixed_assets_runs_allowlist_and_checks_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    commands: list[tuple[str, ...]] = []
    checked_sockets: list[Path] = []
    checked_service_uids: list[int | None] = []

    def execute(command: tuple[str, ...]) -> None:
        commands.append(command)

    def wait_for_socket(path: Path, *, expected_service_uid: int | None = None) -> None:
        checked_sockets.append(path)
        checked_service_uids.append(expected_service_uid)

    monkeypatch.setattr(admin_deploy, "_wait_for_socket", wait_for_socket)

    result = deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=execute,
        service_identity=(os.geteuid(), os.getegid()),
    )

    assert result.status == "deployed"
    assert layout.config_path.read_text(encoding="utf-8") == config.read_text(encoding="utf-8")
    service = layout.service_path.read_text(encoding="utf-8")
    assert f"ExecStart={collector.resolve()} " in service
    assert commands[0][0] == "/usr/bin/systemd-sysusers"
    assert Path(commands[0][1]).name == "perflens.sysusers"
    assert ("/usr/bin/systemctl", "daemon-reload") in commands
    assert commands[-1] == (
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "perflens-collector.service",
    )
    assert checked_sockets == [layout.socket_path]

    repeated = deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=execute,
        service_identity=(os.geteuid(), os.getegid()),
    )
    assert repeated.status == "deployed"
    assert checked_sockets == [layout.socket_path, layout.socket_path]
    assert checked_service_uids == [os.geteuid(), os.geteuid()]


def test_admin_deploy_paranoid3_helper_requires_risk_acknowledgement_and_two_units(
    tmp_path: Path,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    _configure_paranoid3(config)
    dry_run = deploy_collector(
        config,
        dry_run=True,
        layout=layout,
        collector_command=collector,
        require_root=False,
    )
    assert dry_run.privilege_mode == "paranoid3_helper"
    assert any(
        command[-1] == "perflens-privileged-helper.service" for command in dry_run.planned_commands
    )
    with pytest.raises(PerfLensError, match="risk acknowledgement"):
        deploy_collector(
            config,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )

    commands: list[tuple[str, ...]] = []
    deployed = deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=commands.append,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
        acknowledge_cap_sys_admin_risk=True,
    )
    assert deployed.status == "deployed"
    broker_unit = layout.service_path.read_text(encoding="utf-8")
    helper_unit = layout.helper_service_path.read_text(encoding="utf-8")
    assert "CapabilityBoundingSet=" in broker_unit
    assert "CAP_SYS_ADMIN" not in broker_unit
    assert "CapabilityBoundingSet=CAP_PERFMON CAP_SYS_ADMIN" in helper_unit
    assert f"--broker-uid {os.geteuid()}" in helper_unit
    assert f"--allowed-uid {os.geteuid()}" in helper_unit
    assert f"--artifact-gid {os.getegid()}" in helper_unit


def test_admin_deploy_cli_reports_completed_health_and_acceptance_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    dry_run = deploy_collector(
        config,
        dry_run=True,
        layout=layout,
        collector_command=collector,
        require_root=False,
    )
    deployed = dry_run.model_copy(update={"status": "deployed"})

    def fake_deploy(
        _config: Path,
        *,
        dry_run: bool = False,
        collector_command: Path | None = None,
        acknowledge_cap_sys_admin_risk: bool = False,
    ) -> CollectorDeploymentArtifact:
        del dry_run, collector_command, acknowledge_cap_sys_admin_risk
        return deployed

    monkeypatch.setattr("perflens.admin.app.deploy_collector", fake_deploy)

    result = CliRunner().invoke(app, ["deploy", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert "状态: 部署完成; Collector 健康握手通过" in result.output
    assert "已执行的固定系统命令:" in result.output
    assert "请退出当前登录会话后重新登录" in result.output
    assert "perflens accept-collector --authorize-host-acceptance" in result.output
    assert '"schema_version"' not in result.output


def test_admin_deploy_preserves_trusted_collector_entrypoint_symlink(
    tmp_path: Path,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    tools = tmp_path / "trusted-tools"
    tools.mkdir(mode=0o755)
    launcher = tools / "perflens-launcher"
    launcher.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    launcher.chmod(0o555)
    entrypoint = tools / "perflens-collector"
    entrypoint.symlink_to(launcher.name)

    dry_run = deploy_collector(
        config,
        dry_run=True,
        layout=layout,
        collector_command=entrypoint,
        require_root=False,
    )

    assert dry_run.collector_command == str(entrypoint)

    deploy_collector(
        config,
        layout=layout,
        collector_command=entrypoint,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )

    service = layout.service_path.read_text(encoding="utf-8")
    assert f"ExecStart={entrypoint} " in service
    assert f"ExecStart={launcher} " not in service


def test_admin_deploy_rejects_collector_symlink_in_writable_directory(
    tmp_path: Path,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    tools = tmp_path / "writable-tools"
    tools.mkdir(mode=0o755)
    launcher = tools / "perflens-launcher"
    launcher.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    launcher.chmod(0o555)
    entrypoint = tools / "perflens-collector"
    entrypoint.symlink_to(launcher.name)
    tools.chmod(0o777)

    with pytest.raises(PerfLensError) as captured:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=entrypoint,
            require_root=False,
        )

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "trusted directory" in captured.value.message


def test_admin_deploy_rejects_perf_symlink_to_a_different_executable(tmp_path: Path) -> None:
    config, perf, collector, layout = _deployment_inputs(tmp_path)
    replacement = tmp_path / "different-tool"
    replacement.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    replacement.chmod(0o555)
    perf.unlink()
    perf.symlink_to(replacement.name)

    with pytest.raises(PerfLensError) as captured:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_admin_dry_run_rejects_systemd_path_expansion_characters(tmp_path: Path) -> None:
    config, perf, collector, layout = _deployment_inputs(tmp_path)
    unsafe_directory = tmp_path / "perf-%u"
    unsafe_directory.mkdir()
    unsafe_perf = unsafe_directory / "perf"
    unsafe_perf.write_bytes(perf.read_bytes())
    unsafe_perf.chmod(0o555)
    config.write_text(
        config.read_text(encoding="utf-8").replace(str(perf), str(unsafe_perf)),
        encoding="utf-8",
    )

    with pytest.raises(PerfLensError) as captured:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_admin_deploy_rolls_back_new_files_after_service_failure(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    commands: list[tuple[str, ...]] = []

    def fail_on_enable(command: tuple[str, ...]) -> None:
        commands.append(command)
        if "enable" in command and command[-1] == "perflens-collector.service":
            raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "test", "failed")

    with pytest.raises(PerfLensError):
        deploy_collector(
            config,
            layout=layout,
            collector_command=collector,
            require_root=False,
            command_executor=fail_on_enable,
            socket_waiter=lambda _path: None,
            service_identity=(os.geteuid(), os.getegid()),
        )

    assert not layout.config_path.exists()
    assert not layout.service_path.exists()
    assert (
        "/usr/bin/systemctl",
        "disable",
        "--now",
        "perflens-collector.service",
    ) in commands
    assert commands[-1] == ("/usr/bin/systemctl", "daemon-reload")


def test_admin_deploy_failure_stops_new_helper_and_broker_before_removing_units(
    tmp_path: Path,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    _configure_paranoid3(config)
    commands: list[tuple[str, ...]] = []

    def execute(command: tuple[str, ...]) -> None:
        commands.append(command)

    def fail_health(_path: Path) -> None:
        raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "test", "health failed")

    with pytest.raises(PerfLensError, match="health failed"):
        deploy_collector(
            config,
            layout=layout,
            collector_command=collector,
            require_root=False,
            command_executor=execute,
            socket_waiter=fail_health,
            service_identity=(os.geteuid(), os.getegid()),
            acknowledge_cap_sys_admin_risk=True,
        )

    rollback = [command for command in commands if "disable" in command]
    assert rollback == [
        ("/usr/bin/systemctl", "disable", "--now", "perflens-collector.service"),
        (
            "/usr/bin/systemctl",
            "disable",
            "--now",
            "perflens-privileged-helper.service",
        ),
    ]
    assert commands[-1] == ("/usr/bin/systemctl", "daemon-reload")
    assert not layout.config_path.exists()
    assert not layout.service_path.exists()
    assert not layout.helper_service_path.exists()


def test_admin_deploy_preserves_unit_and_policy_when_failed_service_cannot_be_stopped(
    tmp_path: Path,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)

    def fail_health(_path: Path) -> None:
        raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "test", "health failed")

    def fail_rollback_stop(command: tuple[str, ...]) -> None:
        if "disable" in command:
            raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "test", "stop failed")

    with pytest.raises(PerfLensError, match="could not be fully rolled back") as failed:
        deploy_collector(
            config,
            layout=layout,
            collector_command=collector,
            require_root=False,
            command_executor=fail_rollback_stop,
            socket_waiter=fail_health,
            service_identity=(os.geteuid(), os.getegid()),
        )

    assert failed.value.code is ErrorCode.OUTPUT_WRITE_FAILED
    assert layout.config_path.is_file()
    assert layout.service_path.is_file()


def test_admin_upgrade_dry_run_and_restart_preserve_policy_and_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    artifact = layout.state_directory / "retained.data"
    artifact.write_bytes(b"evidence")
    policy_before = layout.config_path.read_bytes()
    service_before = layout.service_path.read_bytes()

    dry_run = upgrade_collector(
        layout.config_path,
        dry_run=True,
        layout=layout,
        collector_command=collector,
        require_root=False,
    )
    assert dry_run.schema_version == "1.0"
    assert dry_run.status == "dry_run"
    assert dry_run.service_update_required is False
    assert dry_run.service_updated is False
    assert dry_run.previous_service_sha256 == dry_run.candidate_service_sha256
    assert layout.service_path.read_bytes() == service_before

    commands: list[tuple[str, ...]] = []
    sockets: list[Path] = []
    service_uids: list[int | None] = []

    def service_account(_name: str) -> SimpleNamespace:
        return SimpleNamespace(pw_uid=os.geteuid())

    def wait_for_upgrade_socket(
        path: Path,
        *,
        expected_service_uid: int | None = None,
    ) -> None:
        sockets.append(path)
        service_uids.append(expected_service_uid)

    monkeypatch.setattr(admin_deploy.pwd, "getpwnam", service_account)
    monkeypatch.setattr(
        admin_deploy,
        "_wait_for_upgrade_socket",
        wait_for_upgrade_socket,
    )

    restarted = upgrade_collector(
        layout.config_path,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=commands.append,
    )
    assert restarted.status == "restarted"
    assert restarted.service_updated is False
    assert restarted.config_preserved is True
    assert restarted.state_preserved is True
    assert layout.config_path.read_bytes() == policy_before
    assert artifact.read_bytes() == b"evidence"
    assert commands == [
        ("/usr/bin/systemctl", "daemon-reload"),
        ("/usr/bin/systemctl", "restart", "perflens-collector.service"),
    ]
    assert sockets == [layout.socket_path]
    assert service_uids == [os.geteuid()]


def test_admin_upgrade_replaces_only_managed_unit_and_cli_is_versioned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    policy_before = layout.config_path.read_bytes()
    old_service = layout.service_path.read_text(encoding="utf-8") + "# old template\n"
    layout.service_path.write_text(old_service, encoding="utf-8")

    upgraded = upgrade_collector(
        layout.config_path,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
    )
    assert upgraded.status == "upgraded"
    assert upgraded.service_update_required is True
    assert upgraded.service_updated is True
    assert "# old template" not in layout.service_path.read_text(encoding="utf-8")
    assert layout.config_path.read_bytes() == policy_before

    def fake_upgrade(
        *,
        dry_run: bool = False,
        collector_command: Path | None = None,
    ) -> CollectorUpgradeArtifact:
        del dry_run, collector_command
        return upgraded

    monkeypatch.setattr("perflens.admin.app.upgrade_collector", fake_upgrade)
    cli_result = CliRunner().invoke(app, ["upgrade", "--dry-run"])
    assert cli_result.exit_code == 0, cli_result.output
    assert '"schema_version": "1.0"' in cli_result.output
    assert '"status": "upgraded"' in cli_result.output


def test_admin_upgrade_rolls_back_unit_when_restart_fails(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    old_service = layout.service_path.read_text(encoding="utf-8") + "# old template\n"
    layout.service_path.write_text(old_service, encoding="utf-8")
    restart_attempts = 0

    def execute(command: tuple[str, ...]) -> None:
        nonlocal restart_attempts
        if command[1] == "restart":
            restart_attempts += 1
            if restart_attempts == 1:
                raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "test", "restart failed")

    with pytest.raises(PerfLensError) as failed:
        upgrade_collector(
            layout.config_path,
            layout=layout,
            collector_command=collector,
            require_root=False,
            command_executor=execute,
            socket_waiter=lambda _path: None,
        )
    assert failed.value.message == "restart failed"
    assert restart_attempts == 2
    assert layout.service_path.read_text(encoding="utf-8") == old_service


def test_admin_upgrade_updates_broker_and_helper_units_together(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    _configure_paranoid3(config)
    identity = (os.geteuid(), os.getegid())
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=identity,
        acknowledge_cap_sys_admin_risk=True,
    )
    old_broker = layout.service_path.read_text(encoding="utf-8") + "# old broker\n"
    old_helper = layout.helper_service_path.read_text(encoding="utf-8") + "# old helper\n"
    layout.service_path.write_text(old_broker, encoding="utf-8")
    layout.helper_service_path.write_text(old_helper, encoding="utf-8")

    dry_run = upgrade_collector(
        layout.config_path,
        dry_run=True,
        layout=layout,
        collector_command=collector,
        require_root=False,
        service_identity=identity,
    )
    assert dry_run.service_update_required is True
    assert dry_run.helper_service_update_required is True
    assert dry_run.previous_helper_service_sha256 != dry_run.candidate_helper_service_sha256
    assert dry_run.helper_service_path == str(layout.helper_service_path)

    upgraded = upgrade_collector(
        layout.config_path,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=identity,
    )
    assert upgraded.status == "upgraded"
    assert upgraded.service_updated is True
    assert upgraded.helper_service_updated is True
    assert "# old broker" not in layout.service_path.read_text(encoding="utf-8")
    helper_text = layout.helper_service_path.read_text(encoding="utf-8")
    assert "# old helper" not in helper_text
    assert f"--perf-path {_perf}" in helper_text


def test_admin_upgrade_rolls_back_broker_and_helper_when_activation_fails(
    tmp_path: Path,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    _configure_paranoid3(config)
    identity = (os.geteuid(), os.getegid())
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=identity,
        acknowledge_cap_sys_admin_risk=True,
    )
    old_broker = layout.service_path.read_text(encoding="utf-8") + "# retained broker\n"
    old_helper = layout.helper_service_path.read_text(encoding="utf-8") + "# retained helper\n"
    layout.service_path.write_text(old_broker, encoding="utf-8")
    layout.helper_service_path.write_text(old_helper, encoding="utf-8")
    commands: list[tuple[str, ...]] = []
    broker_restart_failed = False

    def fail_first_broker_restart(command: tuple[str, ...]) -> None:
        nonlocal broker_restart_failed
        commands.append(command)
        if (
            command[1] == "restart"
            and command[-1] == "perflens-collector.service"
            and not broker_restart_failed
        ):
            broker_restart_failed = True
            raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "test", "activation failed")

    with pytest.raises(PerfLensError, match="activation failed"):
        upgrade_collector(
            layout.config_path,
            layout=layout,
            collector_command=collector,
            require_root=False,
            command_executor=fail_first_broker_restart,
            socket_waiter=lambda _path: None,
            service_identity=identity,
        )

    assert layout.service_path.read_text(encoding="utf-8") == old_broker
    assert layout.helper_service_path.read_text(encoding="utf-8") == old_helper
    assert (
        commands.count(("/usr/bin/systemctl", "restart", "perflens-privileged-helper.service")) == 2
    )
    assert commands.count(("/usr/bin/systemctl", "restart", "perflens-collector.service")) == 2


def test_admin_upgrade_rejects_alternate_policy_and_unmanaged_unit(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    with pytest.raises(PerfLensError) as alternate:
        upgrade_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert alternate.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    layout.service_path.write_text("[Unit]\nDescription=unmanaged\n", encoding="utf-8")
    with pytest.raises(PerfLensError) as unmanaged:
        upgrade_collector(
            layout.config_path,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert unmanaged.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_admin_policy_update_dry_run_and_unchanged_are_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    candidate = tmp_path / "candidate.toml"
    candidate.write_bytes(layout.config_path.read_bytes())
    candidate.chmod(0o600)
    before = layout.config_path.read_bytes()

    dry_run = update_collector_policy(
        candidate,
        dry_run=True,
        layout=layout,
        require_root=False,
    )
    assert dry_run.schema_version == "1.0"
    assert dry_run.status == "dry_run"
    assert dry_run.policy_change_required is False
    assert dry_run.policy_updated is False
    assert dry_run.service_restarted is False
    assert dry_run.planned_commands == ()

    unchanged = update_collector_policy(
        candidate,
        layout=layout,
        require_root=False,
    )
    assert unchanged.status == "unchanged"
    assert unchanged.previous_policy_sha256 == unchanged.candidate_policy_sha256
    assert layout.config_path.read_bytes() == before

    def fake_update(
        _config: Path,
        *,
        dry_run: bool = False,
    ) -> CollectorPolicyUpdateArtifact:
        del dry_run
        return unchanged

    monkeypatch.setattr("perflens.admin.app.update_collector_policy", fake_update)
    cli_result = CliRunner().invoke(
        app,
        ["update-policy", "--config", str(candidate), "--dry-run"],
    )
    assert cli_result.exit_code == 0, cli_result.output
    assert '"schema_version": "1.0"' in cli_result.output
    assert '"status": "unchanged"' in cli_result.output


def test_admin_policy_update_applies_tunables_and_preserves_service_and_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    artifact = layout.state_directory / "retained.data"
    artifact.write_bytes(b"evidence")
    service_before = layout.service_path.read_bytes()
    candidate = tmp_path / "candidate.toml"
    candidate.write_text(
        layout.config_path.read_text(encoding="utf-8")
        .replace('allowed_modes = ["record", "stat"]', 'allowed_modes = ["stat"]')
        .replace("max_duration_seconds = 30.0", "max_duration_seconds = 12.5"),
        encoding="utf-8",
    )
    candidate.chmod(0o600)
    commands: list[tuple[str, ...]] = []
    sockets: list[tuple[Path, int | None]] = []

    def service_account(_name: str) -> SimpleNamespace:
        return SimpleNamespace(pw_uid=os.geteuid())

    def wait_for_policy_socket(
        path: Path,
        *,
        expected_service_uid: int | None = None,
    ) -> None:
        sockets.append((path, expected_service_uid))

    monkeypatch.setattr(admin_deploy.pwd, "getpwnam", service_account)
    monkeypatch.setattr(
        admin_deploy,
        "_wait_for_policy_update_socket",
        wait_for_policy_socket,
    )

    result = update_collector_policy(
        candidate,
        layout=layout,
        require_root=False,
        command_executor=commands.append,
    )

    assert result.status == "updated"
    assert result.policy_change_required is True
    assert result.policy_updated is True
    assert result.service_restarted is True
    assert result.allowed_modes == ("stat",)
    assert layout.config_path.read_bytes() == candidate.read_bytes()
    assert layout.service_path.read_bytes() == service_before
    assert artifact.read_bytes() == b"evidence"
    assert commands == [("/usr/bin/systemctl", "restart", "perflens-collector.service")]
    assert sockets == [(layout.socket_path, os.geteuid())]


def test_admin_policy_update_rolls_back_exact_policy_after_health_failure(
    tmp_path: Path,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    previous = layout.config_path.read_bytes()
    previous_mode = layout.config_path.stat().st_mode & 0o777
    candidate = tmp_path / "candidate.toml"
    candidate.write_text(
        previous.decode("utf-8").replace("max_frequency_hz = 99", "max_frequency_hz = 49"),
        encoding="utf-8",
    )
    candidate.chmod(0o600)
    commands: list[tuple[str, ...]] = []
    health_attempts = 0

    def health(_path: Path) -> None:
        nonlocal health_attempts
        health_attempts += 1
        if health_attempts == 1:
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "test",
                "candidate health failed",
            )

    with pytest.raises(PerfLensError) as failed:
        update_collector_policy(
            candidate,
            layout=layout,
            require_root=False,
            command_executor=commands.append,
            socket_waiter=health,
        )
    assert failed.value.message == "candidate health failed"
    assert layout.config_path.read_bytes() == previous
    assert layout.config_path.stat().st_mode & 0o777 == previous_mode
    assert commands == [
        ("/usr/bin/systemctl", "restart", "perflens-collector.service"),
        ("/usr/bin/systemctl", "restart", "perflens-collector.service"),
    ]
    assert health_attempts == 2


def test_admin_policy_update_reports_failed_service_recovery(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    previous = layout.config_path.read_bytes()
    candidate = tmp_path / "candidate.toml"
    candidate.write_text(
        previous.decode("utf-8").replace("max_frequency_hz = 99", "max_frequency_hz = 49"),
        encoding="utf-8",
    )
    candidate.chmod(0o600)

    def fail_restart(_command: tuple[str, ...]) -> None:
        raise PerfLensError(ErrorCode.EXTERNAL_TOOL_FAILED, "test", "restart failed")

    with pytest.raises(PerfLensError) as failed:
        update_collector_policy(
            candidate,
            layout=layout,
            require_root=False,
            command_executor=fail_restart,
            socket_waiter=lambda _path: None,
        )
    assert failed.value.code is ErrorCode.OUTPUT_WRITE_FAILED
    assert failed.value.stage == "collector_policy_update"
    assert failed.value.details["rollback_errors"] == ["PerfLensError"]
    assert layout.config_path.read_bytes() == previous


def test_admin_policy_update_rejects_in_place_edit_uid_and_privilege_mode_change(
    tmp_path: Path,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    with pytest.raises(PerfLensError) as in_place:
        update_collector_policy(
            layout.config_path,
            dry_run=True,
            layout=layout,
            require_root=False,
        )
    assert in_place.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    candidate = tmp_path / "candidate.toml"
    candidate.write_text(
        layout.config_path.read_text(encoding="utf-8").replace(
            f"allowed_uids = [{os.geteuid()}]",
            f"allowed_uids = [{os.geteuid() + 1}]",
        ),
        encoding="utf-8",
    )
    candidate.chmod(0o600)
    with pytest.raises(PerfLensError) as changed_uid:
        update_collector_policy(
            candidate,
            dry_run=True,
            layout=layout,
            require_root=False,
        )
    assert changed_uid.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "cannot change the authorized user UID" in changed_uid.value.message

    candidate.write_text(
        layout.config_path.read_text(encoding="utf-8")
        .replace("[collector]\n", '[collector]\nprivilege_mode = "paranoid3_helper"\n')
        .replace("max_spool_bytes = 10737418240", "max_spool_bytes = 5368709120")
        .replace("max_spool_artifacts = 1000", "max_spool_artifacts = 500")
        .replace("min_free_bytes = 1073741824", "min_free_bytes = 2147483648")
        .replace("max_plan_ttl_seconds = 300", "max_plan_ttl_seconds = 120"),
        encoding="utf-8",
    )
    candidate.chmod(0o600)
    with pytest.raises(PerfLensError) as changed_privilege_mode:
        update_collector_policy(
            candidate,
            dry_run=True,
            layout=layout,
            require_root=False,
        )
    assert changed_privilege_mode.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "cannot change the deployed privilege mode" in changed_privilege_mode.value.message


def test_admin_undeploy_removes_only_service_and_preserves_data(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=lambda _command: None,
        socket_waiter=lambda _path: None,
        service_identity=(os.geteuid(), os.getegid()),
    )
    artifact = layout.state_directory / "collection.json"
    artifact.write_text("{}", encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    dry_run = undeploy_collector(
        dry_run=True,
        layout=layout,
        require_root=False,
        command_executor=commands.append,
    )
    assert dry_run.status == "dry_run"
    assert layout.service_path.exists()
    assert commands == []

    removed = undeploy_collector(
        layout=layout,
        require_root=False,
        command_executor=commands.append,
    )
    assert removed.schema_version == "1.0"
    assert removed.status == "removed"
    assert removed.config_preserved is True
    assert removed.state_preserved is True
    assert not layout.service_path.exists()
    assert layout.config_path.exists()
    assert artifact.exists()
    assert commands == [
        ("/usr/bin/systemctl", "disable", "--now", "perflens-collector.service"),
        ("/usr/bin/systemctl", "daemon-reload"),
    ]

    absent = undeploy_collector(layout=layout, require_root=False)
    assert absent.status == "already_absent"
    assert absent.planned_commands == ()


def test_admin_undeploy_rejects_unmanaged_and_symlink_units(tmp_path: Path) -> None:
    _config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.service_path.parent.mkdir(parents=True)
    layout.service_path.write_text("[Unit]\nDescription=not managed\n", encoding="utf-8")

    with pytest.raises(PerfLensError) as unmanaged:
        undeploy_collector(layout=layout, require_root=False)
    assert unmanaged.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert layout.service_path.exists()

    layout.service_path.unlink()
    target = tmp_path / "managed.service"
    target.write_text("# Managed by PerfLens.\n[Unit]\n", encoding="utf-8")
    layout.service_path.symlink_to(target)
    with pytest.raises(PerfLensError) as linked:
        undeploy_collector(layout=layout, require_root=False)
    assert linked.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_admin_undeploy_cli_emits_versioned_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = CollectorSystemLayout(
        config_directory=tmp_path / "etc/perflens",
        config_path=tmp_path / "etc/perflens/collector.toml",
        service_path=tmp_path / "systemd/perflens-collector.service",
        state_directory=tmp_path / "var/lib/perflens",
        socket_path=tmp_path / "run/perflens/collector.sock",
    )
    artifact = undeploy_collector(layout=layout, require_root=False)

    def fake_undeploy(*, dry_run: bool = False) -> CollectorUndeploymentArtifact:
        del dry_run
        return artifact

    monkeypatch.setattr("perflens.admin.app.undeploy_collector", fake_undeploy)
    result = CliRunner().invoke(app, ["undeploy", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert '"schema_version": "1.0"' in result.output
    assert '"status": "already_absent"' in result.output


def test_admin_spool_status_reports_versioned_read_only_capacity(tmp_path: Path) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)
    first = layout.state_directory / "plan-00000000000000000002.perf.data"
    second = layout.state_directory / "plan-00000000000000000003.stat.csv"
    first.write_bytes(b"profile")
    second.write_bytes(b"{}")
    replay_state = layout.state_directory / replay_marker_name("plan-00000000000000000001")
    replay_state.touch(mode=0o600)
    before = {path.name: path.read_bytes() for path in layout.state_directory.iterdir()}

    result = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )

    assert result.schema_version == "1.0"
    assert result.status_id.startswith("spool-status-")
    assert result.status == "ready"
    assert result.scan_complete is True
    assert result.observed_artifact_count == 2
    assert result.observed_logical_bytes == 9
    assert result.remaining_artifact_slots == 998
    assert result.max_collectable_output_bytes == 1048576
    assert {path.name: path.read_bytes() for path in layout.state_directory.iterdir()} == before


def test_admin_spool_status_uses_private_helper_spool_in_paranoid3_mode(
    tmp_path: Path,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8")
        .replace("[collector]\n", '[collector]\nprivilege_mode = "paranoid3_helper"\n')
        .replace("max_spool_bytes = 10737418240", "max_spool_bytes = 5368709120")
        .replace("max_spool_artifacts = 1000", "max_spool_artifacts = 500")
        .replace("min_free_bytes = 1073741824", "min_free_bytes = 2147483648")
        .replace("max_plan_ttl_seconds = 300", "max_plan_ttl_seconds = 120"),
        encoding="utf-8",
    )
    config.chmod(0o600)
    layout.state_directory.mkdir(parents=True)
    layout.helper_state_directory.mkdir(parents=True)
    artifact = layout.helper_state_directory / "plan-00000000000000000003.stat.csv"
    artifact.write_bytes(b"metric")

    result = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )

    assert result.status == "ready"
    assert result.spool_root == str(layout.helper_state_directory)
    assert result.observed_artifact_count == 1
    assert result.observed_logical_bytes == 6


def test_admin_spool_status_rejects_unsafe_replay_state(tmp_path: Path) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)
    replay_state = layout.state_directory / replay_marker_name("plan-00000000000000000001")
    replay_state.write_bytes(b"unexpected-content")
    replay_state.chmod(0o600)

    result = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )

    assert result.status == "unsafe"
    assert result.scan_complete is False
    assert result.observed_artifact_count == 0
    assert result.issues == ("unsafe_replay_marker",)


def test_admin_spool_status_rejects_unmanaged_regular_files(tmp_path: Path) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)
    unmanaged = layout.state_directory / "administrator-note.txt"
    unmanaged.write_text("not Collector evidence", encoding="utf-8")

    result = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )

    assert result.status == "unsafe"
    assert result.scan_complete is False
    assert result.observed_artifact_count == 0
    assert result.issues == ("unmanaged_spool_entry",)
    assert unmanaged.read_text(encoding="utf-8") == "not Collector evidence"


def test_admin_spool_status_warns_and_reports_exhausted_count(tmp_path: Path) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)
    config.write_text(
        config.read_text(encoding="utf-8")
        .replace("max_spool_bytes = 10737418240", "max_spool_bytes = 10485760")
        .replace("max_spool_artifacts = 1000", "max_spool_artifacts = 2"),
        encoding="utf-8",
    )
    large = layout.state_directory / "plan-00000000000000000001.perf.data"
    large.write_bytes(b"")
    with large.open("r+b") as handle:
        handle.truncate(8 * 1024 * 1024)

    warning = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )
    assert warning.status == "warning"
    assert warning.scan_complete is True
    assert "spool_byte_quota_above_80_percent" in warning.issues

    (layout.state_directory / "plan-00000000000000000002.stat.csv").write_bytes(b"x")
    exhausted = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )
    assert exhausted.status == "exhausted"
    assert exhausted.scan_complete is False
    assert exhausted.remaining_artifact_slots == 0
    assert exhausted.remaining_spool_bytes is None
    assert exhausted.max_collectable_output_bytes == 0
    assert "artifact_count_quota_exhausted" in exhausted.issues


def test_admin_spool_status_reports_byte_exhaustion_and_count_warning(
    tmp_path: Path,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)
    config.write_text(
        config.read_text(encoding="utf-8")
        .replace("max_spool_bytes = 10737418240", "max_spool_bytes = 1048576")
        .replace("max_spool_artifacts = 1000", "max_spool_artifacts = 5"),
        encoding="utf-8",
    )
    full = layout.state_directory / "plan-00000000000000000001.perf.data"
    full.write_bytes(b"")
    with full.open("r+b") as handle:
        handle.truncate(1024 * 1024)

    exhausted = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )
    assert exhausted.status == "exhausted"
    assert exhausted.remaining_spool_bytes == 0
    assert exhausted.remaining_artifact_slots is None
    assert "spool_byte_quota_exhausted" in exhausted.issues

    full.unlink()
    for index in range(4):
        (layout.state_directory / f"plan-{index + 1:020x}.perf.data").write_bytes(b"x")
    warning = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )
    assert warning.status == "warning"
    assert "artifact_count_quota_above_80_percent" in warning.issues


@pytest.mark.parametrize(
    ("available_bytes", "expected_status", "expected_issue"),
    [
        (0, "exhausted", "filesystem_free_space_reserve_exhausted"),
        (
            (1 << 30) + (512 << 10),
            "warning",
            "full_size_collection_cannot_be_reserved",
        ),
    ],
)
def test_admin_spool_status_applies_filesystem_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    available_bytes: int,
    expected_status: str,
    expected_issue: str,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)

    def filesystem_status(_descriptor: int) -> os.statvfs_result:
        return os.statvfs_result(
            (1, 1, available_bytes, available_bytes, available_bytes, 0, 0, 0, 255, 255)
        )

    monkeypatch.setattr(admin_deploy.os, "fstatvfs", filesystem_status)
    result = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )

    assert result.status == expected_status
    assert expected_issue in result.issues


def test_admin_spool_status_reports_filesystem_inspection_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)

    def fail_filesystem_status(_descriptor: int) -> os.statvfs_result:
        raise OSError("simulated statvfs failure")

    monkeypatch.setattr(admin_deploy.os, "fstatvfs", fail_filesystem_status)
    result = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )

    assert result.status == "unavailable"
    assert result.scan_complete is True
    assert result.issues == ("spool_capacity_inspection_failed",)


@pytest.mark.parametrize("entry_kind", ["directory", "symlink"])
def test_admin_spool_status_reports_unsafe_entries_without_following_or_removing(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    layout.state_directory.mkdir(parents=True)
    unexpected = layout.state_directory / "unexpected"
    target = tmp_path / "outside.data"
    target.write_bytes(b"outside")
    if entry_kind == "directory":
        unexpected.mkdir()
    else:
        unexpected.symlink_to(target)

    result = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )

    assert result.status == "unsafe"
    assert result.scan_complete is False
    assert result.max_collectable_output_bytes is None
    assert result.issues == ("unexpected_non_regular_entry",)
    assert unexpected.exists() or unexpected.is_symlink()
    assert target.read_bytes() == b"outside"


def test_admin_spool_status_reports_unavailable_spool_and_cli_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    artifact = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )
    assert artifact.status == "unavailable"
    assert artifact.filesystem_free_bytes is None
    assert artifact.max_collectable_output_bytes is None

    def fake_status(_config: Path) -> CollectorSpoolStatusArtifact:
        return artifact

    monkeypatch.setattr("perflens.admin.app.inspect_collector_spool", fake_status)
    summary = CliRunner().invoke(app, ["spool-status", "--config", str(config)])
    assert summary.exit_code == 0, summary.output
    assert "PerfLens Collector 存储检查 (只读)" in summary.output
    assert "状态: 当前无法检查" in summary.output

    result = CliRunner().invoke(
        app,
        ["spool-status", "--config", str(config), "--json"],
    )
    assert result.exit_code == 0, result.output
    assert '"schema_version": "1.0"' in result.output
    assert '"status": "unavailable"' in result.output


def test_admin_spool_status_explains_private_helper_capacity_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _perf, _collector, layout = _deployment_inputs(tmp_path)
    base = inspect_collector_spool(
        config,
        layout=layout,
        require_root_owned_tools=False,
    )
    artifact = base.model_copy(
        update={
            "status": "warning",
            "spool_root": "/var/lib/perflens-helper",
        }
    )

    def fake_helper_status(_config: Path) -> CollectorSpoolStatusArtifact:
        return artifact

    monkeypatch.setattr("perflens.admin.app.inspect_collector_spool", fake_helper_status)
    summary = CliRunner().invoke(app, ["spool-status", "--config", str(config)])

    assert summary.exit_code == 0, summary.output
    assert "停止新的采集并保留 Helper 私有证据" in summary.output
    assert "尚不支持对该目录归档或清理" in summary.output


def test_admin_helpers_reject_commands_and_report_system_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_admin_command = cast(
        Callable[[tuple[str, ...]], None],
        vars(admin_deploy)["_run_admin_command"],
    )
    run_admin_undeploy_command = cast(
        Callable[[tuple[str, ...]], None],
        vars(admin_deploy)["_run_admin_undeploy_command"],
    )
    wait_for_socket = cast(
        Callable[[Path], None],
        vars(admin_deploy)["_wait_for_socket"],
    )
    with pytest.raises(PerfLensError) as denied:
        run_admin_command(("/bin/sh", "-c", "true"))
    assert denied.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    def failed_run(
        _command: tuple[str, ...],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(_command, 1, "", "bounded failure")

    monkeypatch.setattr(admin_deploy.subprocess, "run", failed_run)
    with pytest.raises(PerfLensError) as failed:
        run_admin_command(("/usr/bin/systemctl", "daemon-reload"))
    assert failed.value.code is ErrorCode.EXTERNAL_TOOL_FAILED
    assert failed.value.details["stderr"] == "bounded failure"
    with pytest.raises(PerfLensError) as undeploy_failed:
        run_admin_undeploy_command(
            ("/usr/bin/systemctl", "disable", "--now", "perflens-collector.service")
        )
    assert undeploy_failed.value.stage == "collector_undeploy"

    socket_path = tmp_path / "collector.sock"

    class FakeHealth:
        status = "ready"

    class FakeClient:
        def __init__(self, path: Path, *, timeout_seconds: float) -> None:
            assert path == socket_path
            assert timeout_seconds == 0.5

        def health(
            self,
            *,
            expected_service_uid: int | None = None,
        ) -> FakeHealth:
            assert expected_service_uid is None
            return FakeHealth()

    monkeypatch.setattr(admin_deploy, "CollectorBrokerClient", FakeClient)
    wait_for_socket(socket_path)


def test_admin_socket_waiter_rejects_stale_unresponsive_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wait_for_socket = cast(
        Callable[[Path], None],
        vars(admin_deploy)["_wait_for_socket"],
    )
    moments = iter((0.0, 0.0, 6.0))

    class FailedClient:
        def __init__(self, _path: Path, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 0.5

        def health(self, *, expected_service_uid: int | None = None) -> None:
            assert expected_service_uid is None
            raise PerfLensError(
                ErrorCode.EXTERNAL_TOOL_FAILED,
                "collector_broker",
                "stale socket refused the health handshake",
            )

    def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(admin_deploy, "CollectorBrokerClient", FailedClient)
    monkeypatch.setattr(admin_deploy.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(admin_deploy.time, "sleep", no_sleep)

    with pytest.raises(PerfLensError) as failed:
        wait_for_socket(tmp_path / "stale.sock")
    assert failed.value.code is ErrorCode.EXTERNAL_TOOL_FAILED
    assert failed.value.details["last_error"] == ("stale socket refused the health handshake")


def test_admin_deploy_rejects_unsafe_policy_and_symlink(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "allow_other_target_uids = false",
            "allow_other_target_uids = true",
        ),
        encoding="utf-8",
    )
    with pytest.raises(PerfLensError) as unsafe:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert unsafe.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    target = tmp_path / "target.toml"
    target.write_text("[collector]\n", encoding="utf-8")
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    with pytest.raises(PerfLensError) as symlink:
        deploy_collector(
            link,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert symlink.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    cli_error = CliRunner().invoke(
        app,
        ["deploy", "--config", str(link), "--dry-run"],
    )
    assert cli_error.exit_code == 5
    assert "PerfLens 操作失败" in cli_error.stderr
    assert "错误代码: PATH_SAFETY_VIOLATION" in cli_error.stderr

    json_error = CliRunner().invoke(
        app,
        ["--json-errors", "deploy", "--config", str(link), "--dry-run"],
    )
    assert json_error.exit_code == 5
    assert '"schema_version": "1.0"' in json_error.stderr


@pytest.mark.parametrize(
    "replacement",
    [
        "policy_version = 2\n",
        "policy_version = true\n",
        "unknown = true\n",
        "allowed_uids = [0]\n",
        "allowed_uids = [1000, 1001]\n",
        'socket_mode = "0666"\n',
        'artifact_mode = "0600"\n',
        'artifact_mode = "0620"\n',
        "max_duration_seconds = nan\n",
        "max_spool_bytes = 1\n",
        "max_spool_artifacts = 0\n",
        "min_free_bytes = -1\n",
        "min_free_bytes = false\n",
    ],
)
def test_admin_deploy_rejects_invalid_bounded_fields(
    tmp_path: Path,
    replacement: str,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    text = config.read_text(encoding="utf-8")
    if replacement.startswith("allowed_uids"):
        text = text.replace(f"allowed_uids = [{os.geteuid()}]\n", replacement)
    elif replacement.startswith("max_duration"):
        text = text.replace("max_duration_seconds = 30.0\n", replacement)
    elif replacement.startswith("max_spool_bytes"):
        text = text.replace("max_spool_bytes = 10737418240\n", replacement)
    elif replacement.startswith("max_spool_artifacts"):
        text = text.replace("max_spool_artifacts = 1000\n", replacement)
    elif replacement.startswith("min_free_bytes"):
        text = text.replace("min_free_bytes = 1073741824\n", replacement)
    else:
        text += replacement
    config.write_text(text, encoding="utf-8")

    with pytest.raises(PerfLensError):
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )


def test_admin_deploy_rejects_unsafe_bytes_toml_and_missing_binary(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    original = config.read_bytes()

    config.chmod(0o620)
    with pytest.raises(PerfLensError) as writable:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert writable.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    config.chmod(0o600)
    config.write_bytes(b"\xff")
    with pytest.raises(PerfLensError) as encoded:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert encoded.value.code is ErrorCode.INVALID_INPUT

    config.write_text("[collector", encoding="utf-8")
    with pytest.raises(PerfLensError) as malformed:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert malformed.value.code is ErrorCode.INVALID_INPUT

    config.write_bytes(original)
    collector.unlink()
    with pytest.raises(PerfLensError) as missing:
        deploy_collector(
            config,
            dry_run=True,
            layout=layout,
            collector_command=collector,
            require_root=False,
        )
    assert missing.value.code is ErrorCode.INVALID_INPUT
