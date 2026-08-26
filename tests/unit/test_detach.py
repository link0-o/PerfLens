from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from perflens.contracts.artifacts import ProjectDetachmentArtifact
from perflens.distribution.detach import detach_project_integration
from perflens.distribution.onboarding import run_project_setup
from perflens.domain.errors import ErrorCode, PerfLensError


def test_detach_dry_run_and_removal_cover_both_clients_and_preserve_evidence(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config_dir = project / ".codex"
    config_dir.mkdir()
    config = config_dir / "config.toml"
    config.write_text('model = "keep-me"\n', encoding="utf-8")
    run_project_setup(
        project,
        install_claude_skill=True,
        install_claude_config=True,
        codex_enabled=True,
        claude_enabled=True,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    results = project / "perflens-results"
    results.mkdir()
    before = config.read_text(encoding="utf-8")

    preview = detach_project_integration(project, dry_run=True)

    assert preview.schema_version == "1.0"
    assert preview.codex_config_status == "planned"
    assert preview.claude_config_status == "planned"
    assert preview.codex_skill_status == "planned"
    assert preview.claude_skill_status == "planned"
    assert config.read_text(encoding="utf-8") == before
    assert (project / ".mcp.json").is_file()
    assert (project / ".agents/skills/perflens").is_dir()
    assert (project / ".claude/skills/perflens").is_dir()
    assert str(project / "perflens-setup") in preview.preserved_paths
    assert str(results) in preview.preserved_paths

    detached = detach_project_integration(project)

    assert detached.codex_config_status == "removed"
    assert detached.claude_config_status == "removed"
    assert detached.codex_skill_status == "removed"
    assert detached.claude_skill_status == "removed"
    assert config.read_text(encoding="utf-8") == 'model = "keep-me"\n\n'
    assert (
        "perflens"
        not in json.loads((project / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    )
    assert not (project / ".agents/skills/perflens").exists()
    assert not (project / ".claude/skills/perflens").exists()
    assert (project / "perflens-setup/setup.json").is_file()
    assert results.is_dir()
    repeated = detach_project_integration(project)
    assert repeated.codex_config_status == "not_found"
    assert repeated.claude_config_status == "not_found"
    assert repeated.codex_skill_status == "not_found"
    assert repeated.claude_skill_status == "not_found"


def test_detach_can_select_one_client_and_preserve_skills(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    run_project_setup(
        project,
        install_claude_skill=True,
        install_claude_config=True,
        codex_enabled=True,
        claude_enabled=True,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    detached = detach_project_integration(
        project,
        client="claude-code",
        remove_skills=False,
    )

    assert detached.codex_config_status == "skipped"
    assert detached.codex_skill_status == "skipped"
    assert detached.claude_config_status == "removed"
    assert detached.claude_skill_status == "preserved"
    assert "mcp_servers.perflens" in (project / ".codex/config.toml").read_text(encoding="utf-8")
    assert (project / ".claude/skills/perflens/SKILL.md").is_file()


@pytest.mark.parametrize("client", ["opencode", "copilot"])
def test_detach_removes_explicit_client_configs_and_shared_skill(
    tmp_path: Path,
    client: str,
) -> None:
    project = tmp_path / client
    project.mkdir()
    run_project_setup(
        project,
        install_skill=True,
        install_codex_config=False,
        install_opencode_config=client == "opencode",
        install_copilot_config=client == "copilot",
        install_copilot_vscode_config=client == "copilot",
        codex_enabled=False,
        opencode_enabled=client == "opencode",
        copilot_enabled=client == "copilot",
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    detached = detach_project_integration(project, client=client)  # pyright: ignore[reportArgumentType]

    assert not (project / ".agents/skills/perflens").exists()
    if client == "opencode":
        assert detached.opencode_config_status == "removed"
        target = project / ".opencode/opencode.json"
        assert "perflens" not in json.loads(target.read_text(encoding="utf-8"))["mcp"]
    else:
        assert detached.copilot_config_status == "removed"
        assert detached.copilot_vscode_config_status == "removed"
        assert "perflens" not in json.loads(
            (project / ".mcp.json").read_text(encoding="utf-8")
        )["mcpServers"]
        assert "perflens" not in json.loads(
            (project / ".vscode/mcp.json").read_text(encoding="utf-8")
        )["servers"]


def test_detach_shared_claude_copilot_config_is_preserved_or_removed_once(
    tmp_path: Path,
) -> None:
    project = tmp_path / "shared-mcp"
    project.mkdir()
    run_project_setup(
        project,
        install_skill=True,
        install_codex_config=False,
        install_claude_skill=True,
        install_claude_config=True,
        install_copilot_config=True,
        install_copilot_vscode_config=True,
        codex_enabled=False,
        claude_enabled=True,
        copilot_enabled=True,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    claude_only = detach_project_integration(project, client="claude-code")
    assert claude_only.claude_config_status == "skipped"
    assert "perflens" in json.loads(
        (project / ".mcp.json").read_text(encoding="utf-8")
    )["mcpServers"]

    detached = detach_project_integration(project)
    assert detached.claude_config_status == "removed"
    assert detached.copilot_config_status == "removed"
    assert detached.removed_paths.count(str(project / ".mcp.json")) == 1
    assert "perflens" not in json.loads(
        (project / ".mcp.json").read_text(encoding="utf-8")
    )["mcpServers"]


def test_detach_refuses_modified_skill_before_removing_any_config(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    run_project_setup(
        project,
        install_claude_skill=True,
        install_claude_config=True,
        codex_enabled=True,
        claude_enabled=True,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    codex_before = (project / ".codex/config.toml").read_text(encoding="utf-8")
    claude_before = (project / ".mcp.json").read_text(encoding="utf-8")
    skill = project / ".claude/skills/perflens/SKILL.md"
    skill.write_text(skill.read_text(encoding="utf-8") + "\nuser edit\n", encoding="utf-8")

    with pytest.raises(PerfLensError) as modified:
        detach_project_integration(project)

    assert modified.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert (project / ".codex/config.toml").read_text(encoding="utf-8") == codex_before
    assert (project / ".mcp.json").read_text(encoding="utf-8") == claude_before
    assert "user edit" in skill.read_text(encoding="utf-8")


def test_detachment_artifact_accepts_original_codex_only_payload(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifact = ProjectDetachmentArtifact(
        perflens_version="0.1.1",
        detachment_id="detachment-0123456789abcdef",
        project_root=str(project),
        dry_run=False,
        codex_config_path=str(project / ".codex/config.toml"),
        codex_config_status="removed",
    )
    payload = artifact.model_dump()
    for field in (
        "selected_clients",
        "remove_skills",
        "setup_directory",
        "claude_config_path",
        "claude_config_status",
        "codex_skill_path",
        "codex_skill_status",
        "claude_skill_path",
        "claude_skill_status",
        "opencode_config_path",
        "opencode_config_status",
        "copilot_config_path",
        "copilot_config_status",
        "copilot_vscode_config_path",
        "copilot_vscode_config_status",
        "opencode_skill_path",
        "opencode_skill_status",
        "copilot_skill_path",
        "copilot_skill_status",
        "removed_paths",
    ):
        payload.pop(field)

    restored = ProjectDetachmentArtifact.model_validate(payload)

    assert restored.selected_clients == ("codex",)
    assert restored.remove_skills is False
    assert restored.claude_config_status == "skipped"


def test_detach_rejects_non_directory_project(tmp_path: Path) -> None:
    project_file = tmp_path / "not-a-project"
    project_file.write_text("data", encoding="utf-8")

    with pytest.raises(PerfLensError) as invalid:
        detach_project_integration(project_file)

    assert invalid.value.code is ErrorCode.INVALID_INPUT


def test_detach_handles_uninitialized_project_and_rejects_unsafe_setup_path(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()

    empty = detach_project_integration(project, client="codex")
    assert empty.codex_config_status == "not_found"
    assert empty.codex_skill_status == "not_found"

    with pytest.raises(PerfLensError) as escaped:
        detach_project_integration(project, setup_directory=outside)
    assert escaped.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    (project / "perflens-setup").symlink_to(outside, target_is_directory=True)
    with pytest.raises(PerfLensError) as linked:
        detach_project_integration(project)
    assert linked.value.code is ErrorCode.PATH_SAFETY_VIOLATION
