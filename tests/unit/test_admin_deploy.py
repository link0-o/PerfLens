from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

import perflens.admin.deploy as admin_deploy
from perflens.admin.app import app
from perflens.admin.deploy import CollectorSystemLayout, deploy_collector
from perflens.contracts.artifacts import CollectorDeploymentArtifact
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
        "max_plan_ttl_seconds = 300\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config, perf, collector, layout


def test_admin_deploy_dry_run_is_read_only_and_cli_reports_versioned_plan(
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
    ) -> CollectorDeploymentArtifact:
        del dry_run, collector_command
        return result

    monkeypatch.setattr("perflens.admin.app.deploy_collector", fake_deploy)
    cli_result = CliRunner().invoke(
        app,
        [
            "deploy",
            "--config",
            str(config),
            "--dry-run",
        ],
    )
    assert cli_result.exit_code == 0, cli_result.output
    assert '"schema_version":"1.0"'.replace(" ", "") in cli_result.output.replace(" ", "")
    assert '"status":"dry_run"'.replace(" ", "") in cli_result.output.replace(" ", "")


def test_admin_deploy_installs_fixed_assets_runs_allowlist_and_checks_socket(
    tmp_path: Path,
) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)
    commands: list[tuple[str, ...]] = []
    checked_sockets: list[Path] = []

    def execute(command: tuple[str, ...]) -> None:
        commands.append(command)
    result = deploy_collector(
        config,
        layout=layout,
        collector_command=collector,
        require_root=False,
        command_executor=execute,
        socket_waiter=checked_sockets.append,
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
        socket_waiter=checked_sockets.append,
        service_identity=(os.geteuid(), os.getegid()),
    )
    assert repeated.status == "deployed"


def test_admin_deploy_rolls_back_new_files_after_service_failure(tmp_path: Path) -> None:
    config, _perf, collector, layout = _deployment_inputs(tmp_path)

    def fail_on_enable(command: tuple[str, ...]) -> None:
        if command[-1] == "perflens-collector.service":
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


def test_admin_helpers_reject_commands_and_report_system_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_admin_command = cast(
        Callable[[tuple[str, ...]], None],
        vars(admin_deploy)["_run_admin_command"],
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

    socket_path = tmp_path / "collector.sock"

    def socket_metadata(_path: Path) -> os.stat_result:
        return os.stat_result((stat.S_IFSOCK | 0o660, 0, 0, 1, 0, 0, 0, 0, 0, 0))

    monkeypatch.setattr(Path, "stat", socket_metadata)
    wait_for_socket(socket_path)


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
    assert '"schema_version": "1.0"' in cli_error.stderr


@pytest.mark.parametrize(
    "replacement",
    [
        "policy_version = 2\n",
        "policy_version = true\n",
        "unknown = true\n",
        "allowed_uids = [0]\n",
        'socket_mode = "0666"\n',
        "max_duration_seconds = nan\n",
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
