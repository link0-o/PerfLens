from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from perflens.distribution.claude import (
    plan_claude_project_config,
    plan_claude_project_config_removal,
    render_claude_config,
)
from perflens.distribution.codex import (
    plan_codex_project_config,
    plan_codex_project_config_removal,
    render_codex_config,
)
from perflens.distribution.collector import install_collector_assets
from perflens.distribution.skill import (
    SKILL_NAME,
    bundled_skill_fingerprint,
    install_project_skill,
    plan_project_skill_removal,
    project_skill_fingerprint,
    refresh_project_skill,
)
from perflens.domain.errors import ErrorCode, PerfLensError


def test_project_skill_install_copies_the_complete_skill_and_refuses_overwrite(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()

    installed = install_project_skill(project)

    assert installed == project / ".agents" / "skills" / SKILL_NAME
    assert (installed / "SKILL.md").is_file()
    assert (installed / "agents" / "openai.yaml").is_file()
    assert (installed / "assets" / "diagnosis-report-template.md").is_file()
    assert len(tuple((installed / "references").glob("*.md"))) == 8

    skill_text = (installed / "SKILL.md").read_text(encoding="utf-8")
    with pytest.raises(PerfLensError) as captured:
        install_project_skill(project)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert (installed / "SKILL.md").read_text(encoding="utf-8") == skill_text


def test_project_skill_install_rejects_parent_symlink_escape(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / ".agents").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PerfLensError) as captured:
        install_project_skill(project)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert not (outside / "skills").exists()


def test_project_skill_install_refuses_legacy_destination(tmp_path: Path) -> None:
    project = tmp_path / "project"
    legacy = project / ".agents/skills/perflens-performance-analysis"
    legacy.mkdir(parents=True)
    (legacy / "SKILL.md").write_text("legacy", encoding="utf-8")

    with pytest.raises(PerfLensError) as captured:
        install_project_skill(project)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert legacy.is_dir()
    assert not (legacy.parent / "perflens").exists()


def test_project_skill_can_be_activated_only_for_claude_code(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    installed = install_project_skill(project, client="claude-code")

    assert installed == project / ".claude" / "skills" / SKILL_NAME
    assert (installed / "SKILL.md").is_file()
    assert not (project / ".agents").exists()


def test_skill_fingerprint_refresh_and_removal_are_content_bound(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    installed = install_project_skill(project)
    bundled = bundled_skill_fingerprint()
    assert project_skill_fingerprint(installed) == bundled
    unchanged, status = refresh_project_skill(
        project,
        client="codex",
        expected_fingerprint=bundled,
    )
    assert unchanged == installed
    assert status == "existing"

    skill = installed / "SKILL.md"
    skill.write_text(
        skill.read_text(encoding="utf-8") + "\nold managed version\n",
        encoding="utf-8",
    )
    old_fingerprint = project_skill_fingerprint(installed)
    refreshed, status = refresh_project_skill(
        project,
        client="codex",
        expected_fingerprint=old_fingerprint,
    )
    assert status == "updated"
    assert project_skill_fingerprint(refreshed) == bundled

    removal = plan_project_skill_removal(
        project,
        client="codex",
        expected_fingerprint=bundled,
    )
    assert removal is not None
    (refreshed / "SKILL.md").write_text("changed after planning", encoding="utf-8")
    with pytest.raises(PerfLensError) as changed:
        removal.apply()
    assert changed.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert refreshed.exists()


def test_skill_refresh_migrates_unchanged_legacy_directory_name(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    installed = install_project_skill(project)
    legacy = installed.with_name("perflens-performance-analysis")
    installed.rename(legacy)
    fingerprint = project_skill_fingerprint(legacy)

    refreshed, status = refresh_project_skill(
        project,
        client="codex",
        expected_fingerprint=fingerprint,
        current_path=legacy,
    )

    assert status == "updated"
    assert refreshed == project / ".agents/skills/perflens"
    assert refreshed.is_dir()
    assert not legacy.exists()
    assert project_skill_fingerprint(refreshed) == bundled_skill_fingerprint()


def test_skill_removal_refuses_wrong_fingerprint_and_symlink(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    installed = install_project_skill(project)

    with pytest.raises(PerfLensError) as wrong:
        plan_project_skill_removal(
            project,
            client="codex",
            expected_fingerprint="0" * 64,
        )
    assert wrong.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_text("keep", encoding="utf-8")
    link = installed / "unsafe-link"
    link.symlink_to(outside / "file")
    with pytest.raises(PerfLensError) as linked:
        project_skill_fingerprint(installed)
    assert linked.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert (outside / "file").read_text(encoding="utf-8") == "keep"


def test_collector_assets_are_staged_without_overwrite(tmp_path: Path) -> None:
    target = install_collector_assets(
        tmp_path / "collector-assets",
        allowed_uids=(1000, 1000),
        collector_command=Path("/opt/perflens/bin/perflens-collector"),
        perf_path=Path("/usr/lib/linux-tools/perf"),
    )
    assert {path.name for path in target.iterdir()} == {
        "collector.toml",
        "perflens-collector.service",
        "perflens.sysusers",
    }
    policy = (target / "collector.toml").read_text(encoding="utf-8")
    service = (target / "perflens-collector.service").read_text(encoding="utf-8")
    assert "allowed_uids = [1000]" in policy
    assert "policy_version = 1" in policy
    assert 'perf_path = "/usr/lib/linux-tools/perf"' in policy
    assert "允许连接 Collector 的唯一普通用户 UID" in policy
    assert "The only ordinary-user UID allowed to call this Collector" in policy
    assert "强烈建议保持 false" in policy
    assert "Security-sensitive; keep false" in policy
    assert "max_output_bytes = 268435456" in policy
    assert "max_spool_bytes = 5368709120" in policy
    assert "max_spool_artifacts = 500" in policy
    assert "min_free_bytes = 2147483648" in policy
    assert "max_plan_ttl_seconds = 120" in policy
    assert "PerfLens never deletes old evidence automatically" in policy
    assert "perflens-admin spool-status checks quotas read-only" in policy
    assert "exactly one UID is supported" in policy
    assert "ExecStart=/opt/perflens/bin/perflens-collector " in service
    with pytest.raises(PerfLensError) as captured:
        install_collector_assets(target)
    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


@pytest.mark.parametrize("process_umask", [0o002, 0o000])
def test_collector_assets_have_fixed_safe_modes_independent_of_umask(
    tmp_path: Path,
    process_umask: int,
) -> None:
    previous = os.umask(process_umask)
    try:
        target = install_collector_assets(tmp_path / f"assets-{process_umask:o}")
    finally:
        os.umask(previous)

    assert target.stat().st_mode & 0o777 == 0o700
    assert (target / "collector.toml").stat().st_mode & 0o777 == 0o600
    assert (target / "perflens-collector.service").stat().st_mode & 0o777 == 0o644
    assert (target / "perflens.sysusers").stat().st_mode & 0o777 == 0o644


def test_collector_asset_rendering_rejects_unsafe_deployment_values(tmp_path: Path) -> None:
    with pytest.raises(PerfLensError):
        install_collector_assets(tmp_path / "empty", allowed_uids=())
    with pytest.raises(PerfLensError):
        install_collector_assets(
            tmp_path / "multiple-users",
            allowed_uids=(1000, 1001),
        )
    with pytest.raises(PerfLensError):
        install_collector_assets(
            tmp_path / "relative",
            collector_command=Path("relative/perflens-collector"),
        )
    with pytest.raises(PerfLensError):
        install_collector_assets(
            tmp_path / "space",
            collector_command=Path("/opt/Perf Lens/perflens-collector"),
        )
    with pytest.raises(PerfLensError):
        install_collector_assets(tmp_path / "perf", perf_path=Path("perf"))


def test_codex_config_uses_canonical_paths_and_optional_process_gate(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = Path(sys.executable).resolve()

    config = render_codex_config(
        workspace,
        allow_process_execution=True,
        mcp_command=executable,
    )

    assert f'command = "{executable}"' in config
    assert f'  "{workspace.resolve()}"' in config
    assert f'  "{workspace.resolve() / "perflens-results"}"' in config
    assert '"--allow-writes"' in config
    assert '"--allow-process-execution"' in config
    assert "--allow-active-collection" not in config


def test_codex_config_preserves_trusted_shared_launcher_entrypoint(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tools = tmp_path / "trusted-tools"
    tools.mkdir(mode=0o755)
    launcher = tools / "perflens-launcher"
    launcher.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    launcher.chmod(0o555)
    entrypoint = tools / "perflens-mcp"
    entrypoint.symlink_to(launcher.name)

    config = render_codex_config(workspace, mcp_command=entrypoint)

    assert f'command = "{entrypoint}"' in config
    assert f'command = "{launcher}"' not in config


def test_codex_config_rejects_shared_launcher_link_in_writable_directory(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tools = tmp_path / "writable-tools"
    tools.mkdir(mode=0o755)
    launcher = tools / "perflens-launcher"
    launcher.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    launcher.chmod(0o555)
    entrypoint = tools / "perflens-mcp"
    entrypoint.symlink_to(launcher.name)
    tools.chmod(0o777)

    with pytest.raises(PerfLensError) as captured:
        render_codex_config(workspace, mcp_command=entrypoint)

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert "trusted directory" in captured.value.message


def test_codex_config_rejects_artifact_root_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()

    with pytest.raises(PerfLensError) as captured:
        render_codex_config(
            workspace,
            artifact_root=outside,
            mcp_command=Path(sys.executable),
        )

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_codex_config_generates_complete_project_collection_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    config = render_codex_config(
        workspace,
        automatic_collection=True,
        allow_project_execution=True,
        automatic_modes=("stat", "record", "stat"),
        automatic_max_duration_seconds=12,
        automatic_max_frequency_hz=77,
        automatic_max_output_bytes=123456,
        automatic_plan_ttl_seconds=45,
        mcp_command=Path(sys.executable),
    )

    assert '  "/var/lib/perflens"' in config
    assert '  "--collector-socket"' in config
    assert '  "/run/perflens/collector.sock"' in config
    assert '  "--allow-automatic-collection"' in config
    assert '  "--allow-project-execution"' in config
    assert config.count('  "--automatic-mode"') == 2
    assert '  "12"' in config
    assert '  "77"' in config
    assert '  "123456"' in config
    assert '  "45"' in config
    assert '  "--allow-pid-attach"' not in config

    pid_config = render_codex_config(
        workspace,
        automatic_collection=True,
        allow_pid_attach=True,
        mcp_command=Path(sys.executable),
    )
    assert '  "--allow-pid-attach"' in pid_config

    with pytest.raises(PerfLensError):
        render_codex_config(
            workspace,
            allow_project_execution=True,
            mcp_command=Path(sys.executable),
        )


def test_claude_config_reuses_the_same_bounded_mcp_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    config = json.loads(
        render_claude_config(
            workspace,
            automatic_collection=True,
            allow_project_execution=True,
            automatic_max_duration_seconds=12,
            mcp_command=Path(sys.executable),
        )
    )
    server = config["mcpServers"]["perflens"]

    assert server["type"] == "stdio"
    assert server["command"] == str(Path(sys.executable).resolve())
    assert str(workspace.resolve()) in server["args"]
    assert "--allow-project-execution" in server["args"]
    assert "--allow-automatic-collection" in server["args"]
    assert server["env"] == {}


def test_claude_project_config_preserves_other_servers_and_refuses_conflicts(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = workspace / ".mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "keep": {"type": "stdio", "command": "/bin/true", "args": []}
                }
            }
        ),
        encoding="utf-8",
    )
    generated = render_claude_config(workspace, mcp_command=Path(sys.executable))

    plan = plan_claude_project_config(workspace, generated)
    assert plan.status == "updated"
    plan.apply()
    merged = json.loads(path.read_text(encoding="utf-8"))
    assert set(merged["mcpServers"]) == {"keep", "perflens"}
    assert plan_claude_project_config(workspace, generated).status == "existing"

    merged["mcpServers"]["perflens"]["args"] = ["--unsafe-change"]
    path.write_text(json.dumps(merged), encoding="utf-8")
    with pytest.raises(PerfLensError) as conflict:
        plan_claude_project_config(workspace, generated)
    assert conflict.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["keep"]


def test_claude_project_config_rejects_symlink_and_invalid_json(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside.json"
    workspace.mkdir()
    outside.write_text("{}", encoding="utf-8")
    path = workspace / ".mcp.json"
    path.symlink_to(outside)
    generated = render_claude_config(workspace, mcp_command=Path(sys.executable))

    with pytest.raises(PerfLensError) as linked:
        plan_claude_project_config(workspace, generated)
    assert linked.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    path.unlink()
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(PerfLensError) as invalid:
        plan_claude_project_config(workspace, generated)
    assert invalid.value.code is ErrorCode.INVALID_INPUT


def test_claude_managed_config_can_update_and_detach_without_touching_others(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    old = render_claude_config(workspace, mcp_command=Path(sys.executable))
    plan_claude_project_config(workspace, old).apply()
    config_path = workspace / ".mcp.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    payload["mcpServers"]["keep"] = {
        "type": "stdio",
        "command": "/bin/true",
        "args": [],
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    new = render_claude_config(
        workspace,
        automatic_collection=True,
        allow_project_execution=True,
        mcp_command=Path(sys.executable),
    )

    update = plan_claude_project_config(
        workspace,
        new,
        managed_configuration=old,
    )
    assert update.status == "updated"
    update.apply()
    removal = plan_claude_project_config_removal(
        workspace,
        managed_configuration=new,
    )
    assert removal is not None
    removal.apply()

    remaining = json.loads(config_path.read_text(encoding="utf-8"))["mcpServers"]
    assert set(remaining) == {"keep"}


def test_claude_detach_preserves_user_modified_entry(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    generated = render_claude_config(workspace, mcp_command=Path(sys.executable))
    plan_claude_project_config(workspace, generated).apply()
    path = workspace / ".mcp.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["mcpServers"]["perflens"]["args"] = ["user-change"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PerfLensError) as modified:
        plan_claude_project_config_removal(
            workspace,
            managed_configuration=generated,
        )

    assert modified.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["perflens"]


def test_codex_project_config_install_preserves_and_updates_managed_block(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    config_dir = workspace / ".codex"
    config_dir.mkdir(parents=True)
    config_path = config_dir / "config.toml"
    config_path.write_text('model = "gpt-existing"\n', encoding="utf-8")
    basic = render_codex_config(workspace, mcp_command=Path(sys.executable))

    initial = plan_codex_project_config(workspace, basic)
    assert initial.status == "updated"
    initial.apply()
    installed = config_path.read_text(encoding="utf-8")
    assert 'model = "gpt-existing"' in installed
    assert installed.count("BEGIN PerfLens managed MCP configuration") == 1
    assert '"--allow-project-execution"' not in installed

    unchanged = plan_codex_project_config(workspace, basic)
    assert unchanged.status == "existing"
    unchanged.apply()

    automatic = render_codex_config(
        workspace,
        automatic_collection=True,
        allow_project_execution=True,
        mcp_command=Path(sys.executable),
    )
    update = plan_codex_project_config(workspace, automatic)
    assert update.status == "updated"
    update.apply()
    updated = config_path.read_text(encoding="utf-8")
    assert 'model = "gpt-existing"' in updated
    assert updated.count("BEGIN PerfLens managed MCP configuration") == 1
    assert '"--allow-project-execution"' in updated


def test_codex_project_config_install_refuses_user_table_and_unsafe_path(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    config_dir = workspace / ".codex"
    config_dir.mkdir(parents=True)
    config_path = config_dir / "config.toml"
    config_path.write_text(
        '[mcp_servers.perflens]\ncommand = "/custom/perflens-mcp"\n',
        encoding="utf-8",
    )
    generated = render_codex_config(workspace, mcp_command=Path(sys.executable))

    with pytest.raises(PerfLensError) as conflict:
        plan_codex_project_config(workspace, generated)
    assert conflict.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert config_path.read_text(encoding="utf-8").endswith(
        'command = "/custom/perflens-mcp"\n'
    )

    config_path.unlink()
    config_dir.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    config_dir.symlink_to(outside, target_is_directory=True)
    with pytest.raises(PerfLensError) as escaped:
        plan_codex_project_config(workspace, generated)
    assert escaped.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert not (outside / "config.toml").exists()


def test_codex_project_config_removal_preserves_unrelated_settings(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    config_dir = workspace / ".codex"
    config_dir.mkdir(parents=True)
    config_path = config_dir / "config.toml"
    config_path.write_text('model = "keep-me"\n', encoding="utf-8")
    generated = render_codex_config(workspace, mcp_command=Path(sys.executable))
    plan_codex_project_config(workspace, generated).apply()

    removal = plan_codex_project_config_removal(workspace)
    assert removal is not None
    assert 'model = "keep-me"' in removal.content
    assert "mcp_servers.perflens" not in removal.content
    removal.apply()

    assert config_path.read_text(encoding="utf-8") == 'model = "keep-me"\n\n'
    assert plan_codex_project_config_removal(workspace) is None


def test_codex_managed_block_rejects_mixed_user_configuration(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    generated = render_codex_config(workspace, mcp_command=Path(sys.executable))
    plan_codex_project_config(workspace, generated).apply()
    config = workspace / ".codex/config.toml"
    content = config.read_text(encoding="utf-8")
    config.write_text(
        content.replace(
            "# END PerfLens managed MCP configuration",
            '[mcp_servers.other]\ncommand = "/keep/me"\n'
            "# END PerfLens managed MCP configuration",
        ),
        encoding="utf-8",
    )

    with pytest.raises(PerfLensError, match="markers"):
        plan_codex_project_config(workspace, generated)
    with pytest.raises(PerfLensError, match="markers"):
        plan_codex_project_config_removal(workspace)
    assert '[mcp_servers.other]\ncommand = "/keep/me"' in config.read_text(
        encoding="utf-8"
    )
