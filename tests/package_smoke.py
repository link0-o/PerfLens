"""Smoke test an installed PerfLens wheel or source distribution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from perflens import __version__


def main() -> None:
    perflens = _command("perflens")
    perflens_mcp = _command("perflens-mcp")
    perflens_collector = _command("perflens-collector")
    perflens_admin = _command("perflens-admin")
    _run(perflens, "--version", expected=__version__)
    _run(perflens_mcp, "--version", expected=__version__)
    _run(perflens_collector, "--version", expected=__version__)
    _run(perflens_admin, "--version", expected=__version__)
    root_help = _run(perflens, "--help", expected="基于证据的 Linux 性能分析工具")
    assert "--json-errors" in root_help
    init_help = _run(perflens, "init", "--help", expected="未 init 的项目不可见")
    assert "--client" in init_help
    assert "claude-code" in init_help
    assert "--setup-directory" in init_help
    assert "--update" in init_help
    assert "--automatic-mode" in init_help
    assert "--automatic-max-frequency-hz" in init_help
    assert "--automatic-max-output-bytes" in init_help
    assert "--automatic-plan-ttl-seconds" in init_help
    assert "--allow-existing-pid-attach" in init_help
    detach_help = _run(perflens, "detach", "--help")
    assert "--dry-run" in detach_help
    assert "--json" in detach_help
    assert "--client" in detach_help
    assert "--keep-skills" in detach_help
    assert "--json-errors" in _run(perflens_admin, "--help")
    doctor_help = _run(perflens, "doctor", "--help")
    assert "--json" in doctor_help
    assert "--output" in doctor_help
    doctor_summary = _run(
        perflens,
        "doctor",
        "--perf-path",
        "/bin/true",
        expected="PerfLens 采集能力检查 (只读)",
    )
    assert "采集模式:" in doctor_summary
    doctor_payload = json.loads(
        _run(perflens, "doctor", "--perf-path", "/bin/true", "--json")
    )
    assert doctor_payload["schema_version"] == "1.0"
    deploy_help = _run(
        perflens_admin,
        "deploy",
        "--help",
        expected="默认输出中文摘要",
    )
    assert "--json" in deploy_help
    _run(
        perflens_admin,
        "undeploy",
        "--help",
        expected="停止并移除托管服务",
    )
    _run(
        perflens_admin,
        "upgrade",
        "--help",
        expected="安全升级并重启 Collector",
    )
    _run(
        perflens_admin,
        "spool-status",
        "--help",
        expected="只读显示 spool 使用量",
    )
    _run(
        perflens_admin,
        "update-policy",
        "--help",
        expected="安全更新策略",
    )
    _run(
        perflens_admin,
        "archive-spool",
        "--help",
        expected="归档旧的托管 spool 证据",
    )
    _run(
        perflens_admin,
        "prune-archived-spool",
        "--help",
        expected="只清理已经由归档 manifest 精确证明的源文件",
    )
    _run(
        perflens_admin,
        "verify-spool-archive",
        "--help",
        expected="不清理任何证据",
    )
    verification_help = _run(
        perflens, "verify-collector", "--help", expected="有界真实 perf stat 验收"
    )
    assert "--json" in verification_help
    assert "--output" in verification_help
    acceptance_help = _run(
        perflens,
        "accept-collector",
        "--help",
        expected="无需选择 PID",
    )
    assert "--json" in acceptance_help
    assert "完整、带版本的验收 JSON" in acceptance_help

    with tempfile.TemporaryDirectory(prefix="perflens-package-smoke-") as directory:
        root = Path(directory)
        profile = root / "profile.folded"
        analysis = root / "analysis.json"
        project = root / "project"
        initialized_project = root / "initialized-project"
        profile.write_text("main;worker 7\nmain;compute 13\n", encoding="utf-8")
        project.mkdir()
        initialized_project.mkdir()

        doctor_output = root / "doctor.json"
        _run(
            perflens,
            "doctor",
            "--perf-path",
            "/bin/true",
            "--output",
            str(doctor_output),
        )
        assert json.loads(doctor_output.read_text(encoding="utf-8"))["schema_version"] == "1.0"

        _run(
            perflens,
            "analyze-folded",
            "--input",
            str(profile),
            "--output",
            str(analysis),
        )
        payload = json.loads(analysis.read_text(encoding="utf-8"))
        assert payload["schema_version"] == "1.0"
        assert payload["metadata"]["total_weight"] == 20

        human_error = _run_failure(
            perflens,
            "analyze-folded",
            "--input",
            str(profile),
            "--output",
            str(profile),
            expected_exit_code=5,
        )
        assert "PerfLens 操作失败" in human_error
        assert "错误代码: PATH_SAFETY_VIOLATION" in human_error
        machine_error = _run_failure(
            perflens,
            "--json-errors",
            "analyze-folded",
            "--input",
            str(profile),
            "--output",
            str(profile),
            expected_exit_code=5,
        )
        assert json.loads(machine_error)["error"]["code"] == "PATH_SAFETY_VIOLATION"

        missing_policy = root / "missing-collector.toml"
        admin_error = _run_failure(
            perflens_admin,
            "deploy",
            "--config",
            str(missing_policy),
            "--dry-run",
            expected_exit_code=2,
        )
        assert "PerfLens 操作失败" in admin_error
        admin_machine_error = _run_failure(
            perflens_admin,
            "--json-errors",
            "deploy",
            "--config",
            str(missing_policy),
            "--dry-run",
            expected_exit_code=2,
        )
        assert json.loads(admin_machine_error)["error"]["code"] == "INVALID_INPUT"

        _run(perflens, "install-skill", "--project", str(project))
        skill = (
            project
            / ".agents"
            / "skills"
            / "perflens"
            / "SKILL.md"
        )
        assert skill.is_file()

        _run(
            perflens,
            "init",
            str(initialized_project),
            "--read-only",
            "--mcp-command",
            perflens_mcp,
            "--perf-path",
            "/bin/true",
        )
        assert (
            initialized_project
            / ".agents/skills/perflens/SKILL.md"
        ).is_file()
        assert (
            initialized_project
            / ".claude/skills/perflens/SKILL.md"
        ).is_file()
        assert (initialized_project / ".codex/config.toml").is_file()
        claude_project = json.loads(
            (initialized_project / ".mcp.json").read_text(encoding="utf-8")
        )
        assert claude_project["mcpServers"]["perflens"]["type"] == "stdio"
        _run(
            perflens,
            "init",
            str(initialized_project),
            "--read-only",
            "--update",
            "--mcp-command",
            perflens_mcp,
            "--perf-path",
            "/bin/true",
            expected="更新模式",
        )

        _run(
            perflens,
            "setup",
            "--project",
            str(project),
            "--output-directory",
            "guided-setup",
            "--mcp-command",
            perflens_mcp,
            "--perf-path",
            "/bin/true",
            "--automatic-collection",
        )
        guided_setup = project / "guided-setup"
        chinese_guide = (guided_setup / "下一步.zh-CN.md").read_text(encoding="utf-8")
        assert f"--setup-directory {guided_setup}" in chinese_guide
        setup_payload = json.loads(
            (guided_setup / "setup.json").read_text(encoding="utf-8")
        )
        assert setup_payload["schema_version"] == "1.0"
        assert setup_payload["skill_status"] == "existing"
        assert setup_payload["automatic_collection_enabled"] is True
        assert setup_payload["codex_project_config_status"] in {"installed", "updated"}
        generated_mcp = (guided_setup / "codex-mcp.toml").read_text(encoding="utf-8")
        assert f'command = "{perflens_mcp}"' in generated_mcp
        assert '"--allow-project-execution"' in generated_mcp
        assert '"--allow-pid-attach"' not in generated_mcp
        assert '"268435456"' in generated_mcp
        assert '"120"' in generated_mcp
        project_mcp = (project / ".codex/config.toml").read_text(encoding="utf-8")
        assert "BEGIN PerfLens managed MCP configuration" in project_mcp
        assert '"--allow-project-execution"' in project_mcp
        status = _run(
            perflens,
            "status",
            "--project",
            str(project),
            "--setup-directory",
            "guided-setup",
            "--collector-socket",
            str(root / "missing.sock"),
            "--perf-path",
            "/bin/true",
        )
        assert "PerfLens 状态检查 (只读)" in status
        assert "Skill: 就绪" in status
        assert "项目 MCP 配置: 已接入" in status

        collector_assets = root / "collector-assets"
        _run(
            perflens,
            "stage-collector-assets",
            "--output-directory",
            str(collector_assets),
            "--allowed-uid",
            str(os.geteuid()),
            "--collector-command",
            perflens_collector,
            "--perf-path",
            "/usr/bin/perf",
        )
        assert (collector_assets / "perflens-collector.service").is_file()
        assert collector_assets.stat().st_mode & 0o777 == 0o700
        assert (collector_assets / "collector.toml").stat().st_mode & 0o777 == 0o600
        policy_text = (collector_assets / "collector.toml").read_text(encoding="utf-8")
        service_text = (collector_assets / "perflens-collector.service").read_text(
            encoding="utf-8"
        )
        assert f"allowed_uids = [{os.geteuid()}]" in policy_text
        assert "policy_version = 1" in policy_text
        assert "max_spool_bytes = 5368709120" in policy_text
        assert "exactly one UID is supported" in policy_text
        assert "允许连接 Collector 的唯一普通用户 UID" in policy_text
        assert "The only ordinary-user UID allowed to call this Collector" in policy_text
        assert f"ExecStart={perflens_collector} " in service_text

        config = _run(
            perflens,
            "codex-config",
            "--workspace",
            str(project),
            "--mcp-command",
            perflens_mcp,
        )
        assert "[mcp_servers.perflens]" in config
        assert "--allow-active-collection" not in config

        active_config = project / ".codex/config.toml"
        before_detach = active_config.read_text(encoding="utf-8")
        preview = _run(
            perflens,
            "detach",
            "--project",
            str(project),
            "--setup-directory",
            str(project / "guided-setup"),
            "--dry-run",
            expected="预演通过; 尚未修改文件",
        )
        assert "不删除引导目录、分析结果或系统 Collector 数据" in preview
        assert active_config.read_text(encoding="utf-8") == before_detach
        detach_payload = json.loads(
            _run(
                perflens,
                "detach",
                "--project",
                str(project),
                "--setup-directory",
                str(project / "guided-setup"),
                "--json",
            )
        )
        assert detach_payload["schema_version"] == "1.0"
        assert detach_payload["codex_config_status"] == "removed"
        assert "BEGIN PerfLens managed MCP configuration" not in active_config.read_text(
            encoding="utf-8"
        )
        assert detach_payload["codex_skill_status"] == "removed"
        assert not (project / ".agents/skills/perflens").exists()
        assert (project / "guided-setup/setup.json").is_file()


def _command(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"{name} is not installed on PATH")
    return resolved


def _run(command: str, *arguments: str, expected: str | None = None) -> str:
    completed = subprocess.run(  # noqa: S603 - command is resolved from the isolated PATH
        [command, *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    output = completed.stdout.strip()
    if expected is not None and expected not in output:
        raise AssertionError(f"{command} output did not contain {expected!r}: {output!r}")
    return output


def _run_failure(
    command: str,
    *arguments: str,
    expected_exit_code: int,
) -> str:
    completed = subprocess.run(  # noqa: S603 - command is resolved from isolated PATH
        [command, *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != expected_exit_code:
        raise AssertionError(
            f"{command} returned {completed.returncode}, expected {expected_exit_code}: "
            f"{completed.stderr!r}"
        )
    return completed.stderr.strip()


if __name__ == "__main__":
    main()
