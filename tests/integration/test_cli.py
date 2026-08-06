from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Literal

import pytest
from typer.testing import CliRunner

from perflens import __version__
from perflens.application.analyze import analyze_folded
from perflens.artifacts.filesystem import write_json_atomic
from perflens.cli.app import app
from perflens.collection.collector import ACTIVE_COLLECTION_AUTHORIZATION
from perflens.contracts.artifacts import (
    CollectionCapabilityArtifact,
    CollectionModeCapability,
    RuntimeStatusArtifact,
)
from perflens.distribution.skill import SKILL_NAME

runner = CliRunner()


def test_cli_help_is_chinese_first_without_changing_public_command_names() -> None:
    root_help = runner.invoke(app, ["--help"])
    assert root_help.exit_code == 0, root_help.output
    assert "基于证据的 Linux 性能分析工具" in root_help.output
    assert "setup" in root_help.output
    assert "init" in root_help.output
    assert "未 init 的项目不可见" in root_help.output
    assert "为一个项目生成安全、中文优先的安装引导" in root_help.output
    assert "accept-collector" in root_help.output
    assert "无需选择 PID" in root_help.output
    assert "Evidence-driven Linux performance analysis" not in root_help.output

    setup_help = runner.invoke(app, ["setup", "--help"])
    assert setup_help.exit_code == 0, setup_help.output
    assert "用于安装 Skill 和引导文件的现有项目" in setup_help.output
    assert "不会安装或提权" in setup_help.output
    assert "可信 perflens-mcp 入口路径" in setup_help.output

    collection_help = runner.invoke(app, ["collect-profile", "--help"])
    assert collection_help.exit_code == 0, collection_help.output
    assert "每次明确授权后才执行有界 perf 采集" in collection_help.output
    assert "PID 附加的完整显式授权短语" in collection_help.output
    assert "--duration-seconds" in collection_help.output


def test_cli_exposes_version_and_release_setup_commands(tmp_path: Path) -> None:
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0, version.output
    assert version.output == f"{__version__}\n"

    project = tmp_path / "project"
    project.mkdir()
    installed = runner.invoke(app, ["install-skill", "--project", str(project)])
    assert installed.exit_code == 0, installed.output
    skill_path = project / ".agents" / "skills" / SKILL_NAME
    assert installed.output.strip() == str(skill_path)
    assert (skill_path / "SKILL.md").is_file()

    config = runner.invoke(
        app,
        [
            "codex-config",
            "--workspace",
            str(project),
            "--mcp-command",
            sys.executable,
            "--allow-process-execution",
        ],
    )
    assert config.exit_code == 0, config.output
    assert "[mcp_servers.perflens]" in config.output
    assert '"--allow-process-execution"' in config.output

    claude_config = runner.invoke(
        app,
        [
            "claude-config",
            "--workspace",
            str(project),
            "--mcp-command",
            sys.executable,
            "--allow-process-execution",
        ],
    )
    assert claude_config.exit_code == 0, claude_config.output
    claude_server = json.loads(claude_config.output)["mcpServers"]["perflens"]
    assert claude_server["type"] == "stdio"
    assert "--allow-process-execution" in claude_server["args"]

    doctor = runner.invoke(app, ["doctor"])
    assert doctor.exit_code == 0, doctor.output
    assert "PerfLens 采集能力检查 (只读)" in doctor.output
    assert "综合结论:" in doctor.output
    assert "采集模式:" in doctor.output
    assert "本命令没有运行 perf" in doctor.output

    doctor_json = runner.invoke(app, ["doctor", "--json"])
    assert doctor_json.exit_code == 0, doctor_json.output
    doctor_payload = json.loads(doctor_json.output)
    assert doctor_payload["schema_version"] == "1.0"
    assert {item["mode"] for item in doctor_payload["modes"]} == {
        "record",
        "stat",
        "sched",
        "lock",
        "off_cpu",
    }
    doctor_output = tmp_path / "doctor.json"
    doctor_written = runner.invoke(app, ["doctor", "--output", str(doctor_output)])
    assert doctor_written.exit_code == 0, doctor_written.output
    assert doctor_written.output.strip() == str(doctor_output)
    assert json.loads(doctor_output.read_text(encoding="utf-8"))["schema_version"] == "1.0"

    denied_probe = runner.invoke(
        app,
        [
            "verify-collector",
            "--socket",
            str(tmp_path / "missing.sock"),
            "--pid",
            str(os.getppid()),
        ],
    )
    assert denied_probe.exit_code == 5
    assert "explicit target authorization" in denied_probe.stderr

    denied_acceptance = runner.invoke(app, ["accept-collector"])
    assert denied_acceptance.exit_code == 5
    assert "explicit authorization" in denied_acceptance.stderr

    guided_project = tmp_path / "guided-project"
    guided_project.mkdir()
    guided = runner.invoke(
        app,
        [
            "setup",
            "--project",
            str(guided_project),
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
            "--automatic-collection",
        ],
    )
    assert guided.exit_code == 0, guided.output
    assert "PerfLens 引导文件已经生成" in guided.output
    assert "Skill: 已安装" in guided.output
    assert "采集状态:" in guided.output
    assert "项目自动运行: 已启用" in guided.output
    assert "检查当前状态: perflens status" in guided.output
    assert f"--setup-directory {guided_project / 'perflens-setup'}" in guided.output
    assert (guided_project / "perflens-setup/下一步.zh-CN.md").is_file()
    assert (guided_project / ".agents/skills/perflens/SKILL.md").is_file()
    generated_config = (guided_project / "perflens-setup/codex-mcp.toml").read_text(
        encoding="utf-8"
    )
    assert '"--allow-project-execution"' in generated_config
    assert '"--allow-pid-attach"' not in generated_config


def test_init_exposes_bounded_collection_policy_and_optional_pid_attach(
    tmp_path: Path,
) -> None:
    project = tmp_path / "policy-project"
    project.mkdir()

    initialized = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--client",
            "codex",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
            "--automatic-mode",
            "stat",
            "--automatic-max-duration-seconds",
            "12",
            "--automatic-max-frequency-hz",
            "77",
            "--automatic-max-output-bytes",
            "123456",
            "--automatic-plan-ttl-seconds",
            "45",
            "--allow-existing-pid-attach",
        ],
    )

    assert initialized.exit_code == 0, initialized.output
    config = (project / ".codex/config.toml").read_text(encoding="utf-8")
    assert config.count('"--automatic-mode"') == 1
    for value in ("12.0", "77", "123456", "45"):
        assert f'"{value}"' in config
    assert '"--allow-pid-attach"' in config


def test_init_activates_selected_clients_only_inside_the_project(tmp_path: Path) -> None:
    project = tmp_path / "claude-project"
    project.mkdir()

    initialized = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--client",
            "claude-code",
            "--read-only",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
        ],
    )

    assert initialized.exit_code == 0, initialized.output
    assert "其他未运行 init 的项目不会发现这些集成" in initialized.output
    assert "Claude Code Skill:" in initialized.output
    assert "Codex Skill:" not in initialized.output
    assert not (project / ".agents").exists()
    assert not (project / ".codex").exists()
    assert (project / ".claude/skills/perflens/SKILL.md").is_file()
    server = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"][
        "perflens"
    ]
    assert "--allow-writes" in server["args"]
    assert "--allow-automatic-collection" not in server["args"]


def test_init_defaults_to_codex_and_claude_code_project_activation(tmp_path: Path) -> None:
    project = tmp_path / "both-project"
    project.mkdir()

    initialized = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--read-only",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
        ],
    )

    assert initialized.exit_code == 0, initialized.output
    assert (project / ".agents/skills/perflens/SKILL.md").is_file()
    assert (project / ".codex/config.toml").is_file()
    assert (project / ".claude/skills/perflens/SKILL.md").is_file()
    assert (project / ".mcp.json").is_file()

    repeated = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--read-only",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
        ],
    )
    assert repeated.exit_code != 0
    assert "--update" in repeated.output

    updated = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--read-only",
            "--update",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
        ],
    )
    assert updated.exit_code == 0, updated.output
    assert "更新模式" in updated.output


def test_cli_detach_one_client_then_updates_to_narrower_scope(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    initialized = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--read-only",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
        ],
    )
    assert initialized.exit_code == 0, initialized.output

    blocked = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--client",
            "codex",
            "--read-only",
            "--update",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
        ],
    )
    assert blocked.exit_code != 0
    assert "detach --client" in blocked.output

    preview = runner.invoke(
        app,
        [
            "detach",
            "--project",
            str(project),
            "--client",
            "claude-code",
            "--dry-run",
        ],
    )
    assert preview.exit_code == 0, preview.output
    assert "Claude Code MCP: 预演通过" in preview.output
    assert "Codex MCP: 未选择此客户端" in preview.output
    assert "--client claude-code" in preview.output

    detached = runner.invoke(
        app,
        ["detach", "--project", str(project), "--client", "claude-code"],
    )
    assert detached.exit_code == 0, detached.output
    assert "Claude Code Skill: 已移除" in detached.output
    assert not (project / ".claude/skills/perflens").exists()

    updated = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--client",
            "codex",
            "--read-only",
            "--update",
            "--mcp-command",
            sys.executable,
            "--perf-path",
            "/bin/true",
        ],
    )
    assert updated.exit_code == 0, updated.output
    assert not (project / ".claude/skills/perflens").exists()
    assert (
        "perflens"
        not in json.loads((project / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    )


def test_doctor_translates_mode_reasons_warnings_and_recommendations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = CollectionCapabilityArtifact(
        capability_id="capability-doctor-summary",
        platform="Linux",
        kernel_release="test",
        effective_uid=1000,
        perf_executable=None,
        perf_version="malicious\x1b[31m\nversion",
        tracefs_accessible=False,
        modes=(
            CollectionModeCapability(
                mode="record",
                status="available",
                required_privilege="none",
                reason="The current credential has a perf monitoring privilege.",
            ),
            CollectionModeCapability(
                mode="stat",
                status="conditional",
                required_privilege="cap_perfmon",
                reason=(
                    "Own-process user-space collection depends on the selected events and "
                    "kernel policy."
                ),
            ),
            CollectionModeCapability(
                mode="sched",
                status="blocked",
                required_privilege="cap_sys_admin_or_policy_change",
                reason="The system perf executable is unavailable.",
            ),
        ),
        warnings=("Unable to read /proc/sys/kernel/perf_event_paranoid.",),
        recommendations=(
            "Prefer a dedicated collector service with a narrow policy over running the MCP "
            "server as root.",
        ),
    )

    def inspected(_path: Path | None = None) -> CollectionCapabilityArtifact:
        return artifact

    monkeypatch.setattr("perflens.cli.app.inspect_collection_capabilities", inspected)
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "record: 可用; 无需额外权限" in result.output
    assert "stat: 需要真实验收; 需要受限 perf 采集权限" in result.output
    assert "sched: 受阻; 需要管理员审查内核策略或 Collector 权限" in result.output
    assert "无法读取内核 perf_event_paranoid" in result.output
    assert "不要让 MCP 或 Agent 以 root 运行" in result.output
    assert "The system perf executable" not in result.output
    assert "\x1b" not in result.output
    assert "malicious?[31m?version" in result.output


def test_cli_analyzes_folded_profile(fixture_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "nested" / "analysis.json"
    result = runner.invoke(
        app,
        [
            "analyze-folded",
            "--input",
            str(fixture_root / "folded" / "normal.folded"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text())
    assert payload["schema_version"] == "1.0"
    assert payload["metadata"]["total_weight"] == 471
    assert payload["hotspots"][0]["symbol"] == "compute"


def test_cli_status_is_chinese_first_and_can_write_json(tmp_path: Path) -> None:
    displayed = runner.invoke(
        app,
        [
            "status",
            "--project",
            str(tmp_path),
            "--collector-socket",
            str(tmp_path / "missing.sock"),
            "--perf-path",
            "/bin/true",
        ],
    )
    assert displayed.exit_code == 0, displayed.output
    assert "PerfLens 状态检查 (只读)" in displayed.output
    assert "引导目录: 未生成" in displayed.output
    assert "Collector 健康握手: 未执行 (前置条件未满足)" in displayed.output
    assert "自动采集: 未配置" in displayed.output
    assert "下一步:" in displayed.output
    assert "perflens init" in displayed.output

    output = tmp_path / "status.json"
    written = runner.invoke(
        app,
        [
            "status",
            "--project",
            str(tmp_path),
            "--collector-socket",
            str(tmp_path / "missing.sock"),
            "--perf-path",
            "/bin/true",
            "--output",
            str(output),
        ],
    )
    assert written.exit_code == 0, written.output
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "1.0"


@pytest.mark.parametrize(
    ("automatic_status", "expected"),
    [
        ("configuration_incomplete", "重新生成完整自动采集资产"),
        ("collector_unavailable", "下一步.zh-CN.md"),
        ("access_denied", "退出当前 Linux 登录会话并重新登录"),
        ("ready_for_verification", "accept-collector --socket"),
    ],
)
def test_cli_status_prints_copyable_state_specific_next_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    automatic_status: Literal[
        "configuration_incomplete",
        "collector_unavailable",
        "access_denied",
        "ready_for_verification",
    ],
    expected: str,
) -> None:
    artifact = RuntimeStatusArtifact(
        perflens_version="test",
        status_id="status-0123456789abcdef",
        checked_at="2026-08-04T00:00:00+00:00",
        project_root=str(tmp_path),
        setup_directory=str(tmp_path / "custom-setup"),
        setup_status="ready",
        skill_status="ready",
        mcp_config_status="ready",
        automatic_collection_requested=True,
        collector_assets_status="ready",
        collector_socket="/run/perflens/custom.sock",
        collector_socket_status="ready",
        collector_group_status="member",
        capability_id="capability-test",
        host_collection_status="conditional",
        automatic_collection_status=automatic_status,
    )

    def reported_status(*_args: object, **_kwargs: object) -> RuntimeStatusArtifact:
        return artifact

    monkeypatch.setattr("perflens.cli.app.inspect_runtime_status", reported_status)
    displayed = runner.invoke(app, ["status", "--project", str(tmp_path)])

    assert displayed.exit_code == 0, displayed.output
    assert "下一步:" in displayed.output
    assert expected in displayed.output
    if automatic_status == "configuration_incomplete":
        assert displayed.output.count("--prepare-collector") == 1
        assert displayed.output.count("--automatic-collection") == 1


def test_cli_refuses_to_overwrite_source(tmp_path: Path) -> None:
    source = tmp_path / "input.folded"
    source.write_text("main 1\n")
    result = runner.invoke(
        app,
        ["analyze-folded", "--input", str(source), "--output", str(source)],
    )
    assert result.exit_code == 5
    assert "PerfLens 操作失败" in result.stderr
    assert "错误代码: PATH_SAFETY_VIOLATION" in result.stderr
    assert "--json-errors" in result.stderr

    machine_result = runner.invoke(
        app,
        [
            "--json-errors",
            "analyze-folded",
            "--input",
            str(source),
            "--output",
            str(source),
        ],
    )
    assert machine_result.exit_code == 5
    payload = json.loads(machine_result.stderr)
    assert payload["error"]["code"] == "PATH_SAFETY_VIOLATION"

    environment_result = runner.invoke(
        app,
        [
            "analyze-folded",
            "--input",
            str(source),
            "--output",
            str(source),
        ],
        env={"PERFLENS_JSON_ERRORS": "1"},
    )
    assert environment_result.exit_code == 5
    assert json.loads(environment_result.stderr)["error"]["code"] == ("PATH_SAFETY_VIOLATION")
    assert source.read_text() == "main 1\n"


def test_cli_resource_limit_has_stable_exit_code(fixture_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "analysis.json"
    result = runner.invoke(
        app,
        [
            "analyze-folded",
            "--input",
            str(fixture_root / "folded" / "normal.folded"),
            "--output",
            str(output),
            "--max-input-bytes",
            "1",
        ],
    )
    assert result.exit_code == 4
    assert not output.exists()


def test_cli_analyzes_perf_script(fixture_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "perf-script-analysis.json"
    result = runner.invoke(
        app,
        [
            "analyze-perf-script",
            "--input",
            str(fixture_root / "perf_script" / "normal.perf-script"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metadata"]["source_type"] == "perf_script"
    assert payload["metadata"]["total_weight"] == 100


def test_cli_classifies_and_renders_report(tmp_path: Path) -> None:
    profile = tmp_path / "input.folded"
    profile.write_text("main;malloc 10\n")
    analysis_path = tmp_path / "analysis.json"
    write_json_atomic(analyze_folded(profile), analysis_path, max_output_bytes=1 << 20)
    diagnosis_path = tmp_path / "diagnosis.json"
    report_path = tmp_path / "report.md"

    classified = runner.invoke(
        app,
        ["classify", "--analysis", str(analysis_path), "--output", str(diagnosis_path)],
    )
    reported = runner.invoke(
        app,
        [
            "report",
            "--analysis",
            str(analysis_path),
            "--output",
            str(report_path),
            "--problem",
            "Throughput regression",
        ],
    )

    assert classified.exit_code == 0, classified.output
    assert reported.exit_code == 0, reported.output
    diagnosis = json.loads(diagnosis_path.read_text(encoding="utf-8"))
    assert diagnosis["classifications"][0]["conclusion_status"] == "candidate"
    assert "Throughput regression" in report_path.read_text(encoding="utf-8")


def test_cli_normalizes_benchmark_and_compares_profiles(fixture_root: Path, tmp_path: Path) -> None:
    benchmark_output = tmp_path / "benchmark.json"
    normalized = runner.invoke(
        app,
        [
            "normalize-benchmark",
            "--input",
            str(fixture_root / "benchmarks" / "hyperfine.json"),
            "--output",
            str(benchmark_output),
        ],
    )
    assert normalized.exit_code == 0, normalized.output
    assert json.loads(benchmark_output.read_text())["source_format"] == "hyperfine"

    baseline_profile = tmp_path / "baseline.folded"
    candidate_profile = tmp_path / "candidate.folded"
    baseline_profile.write_text("main;old 70\nmain;shared 30\n")
    candidate_profile.write_text("main;new 60\nmain;shared 40\n")
    baseline_analysis = tmp_path / "baseline-analysis.json"
    candidate_analysis = tmp_path / "candidate-analysis.json"
    write_json_atomic(analyze_folded(baseline_profile), baseline_analysis, max_output_bytes=1 << 20)
    write_json_atomic(
        analyze_folded(candidate_profile), candidate_analysis, max_output_bytes=1 << 20
    )
    comparison_output = tmp_path / "comparison.json"
    markdown_output = tmp_path / "comparison.md"
    compared = runner.invoke(
        app,
        [
            "compare-profiles",
            "--baseline",
            str(baseline_analysis),
            "--candidate",
            str(candidate_analysis),
            "--output",
            str(comparison_output),
            "--markdown-output",
            str(markdown_output),
        ],
    )
    assert compared.exit_code == 0, compared.output
    assert json.loads(comparison_output.read_text())["hotspot_deltas"]
    assert "Profile Comparison" in markdown_output.read_text()


def test_cli_active_collection_is_double_authorized_and_never_overwrites(tmp_path: Path) -> None:
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'PERFILE2')\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)
    data_output = tmp_path / "profile.data"
    metadata_output = tmp_path / "collection.json"
    arguments = [
        "collect-profile",
        "--data-output",
        str(data_output),
        "--metadata-output",
        str(metadata_output),
        "--executable",
        str(Path(sys.executable)),
        "--perf-path",
        str(fake_perf),
        "--authorization",
        ACTIVE_COLLECTION_AUTHORIZATION,
    ]

    denied = runner.invoke(app, arguments)
    assert denied.exit_code == 5
    assert not data_output.exists()

    collected = runner.invoke(app, [*arguments, "--authorize-target"])
    assert collected.exit_code == 0, collected.output
    metadata = json.loads(metadata_output.read_text(encoding="utf-8"))
    assert metadata["mode"] == "record"
    assert metadata["authorization"] == "explicit"
    assert data_output.read_bytes() == b"PERFILE2"

    repeated = runner.invoke(app, [*arguments, "--authorize-target"])
    assert repeated.exit_code == 5
    assert data_output.read_bytes() == b"PERFILE2"
