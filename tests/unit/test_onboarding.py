from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from perflens.contracts.artifacts import SetupArtifact
from perflens.distribution import onboarding
from perflens.distribution.claude import render_claude_config
from perflens.distribution.onboarding import run_project_setup
from perflens.distribution.skill import install_project_skill
from perflens.domain.errors import ErrorCode, PerfLensError


def test_setup_creates_guided_bundle_and_installs_skill(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    artifact = run_project_setup(
        project,
        output_directory=Path("setup-one"),
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    output = project / "setup-one"
    assert artifact.schema_version == "1.0"
    assert artifact.skill_status == "installed"
    assert artifact.collection_status in {"available", "conditional", "blocked"}
    assert (project / ".agents/skills/perflens/SKILL.md").is_file()
    assert (project / ".codex/config.toml").is_file()
    assert artifact.codex_project_config_status == "installed"
    assert artifact.codex_project_config_path == str(project / ".codex/config.toml")
    assert (output / "codex-mcp.toml").is_file()
    assert (output / "collection-capabilities.json").is_file()
    assert (output / "下一步.zh-CN.md").is_file()
    payload = json.loads((output / "setup.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["project_root"] == str(project.resolve())
    assert all(Path(path).exists() for path in payload["generated_files"])

    repeated = run_project_setup(
        project,
        output_directory=Path("setup-two"),
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
        prepare_collector=True,
        automatic_collection=True,
        collector_uid=os.geteuid(),
        collector_command=Path("/opt/perflens/bin/perflens-collector"),
    )
    assert repeated.skill_status == "existing"
    assert repeated.codex_project_config_status == "updated"
    assert repeated.automatic_collection_enabled is True
    assert repeated.collector_assets_path is not None
    policy = Path(repeated.collector_assets_path) / "collector.toml"
    assert f"allowed_uids = [{os.geteuid()}]" in policy.read_text(encoding="utf-8")
    mcp_config = (project / "setup-two/codex-mcp.toml").read_text(encoding="utf-8")
    assert '"--allow-project-execution"' in mcp_config
    assert '"--allow-project-execution"' in (project / ".codex/config.toml").read_text(
        encoding="utf-8"
    )
    guide = (project / "setup-two/下一步.zh-CN.md").read_text(encoding="utf-8")
    assert "用户不需要查找或输入 PID" in guide
    assert "/opt/perflens/bin/perflens-admin deploy" in guide
    assert (
        f"perflens status --project {project} --setup-directory {project / 'setup-two'}"
        in guide
    )


def test_setup_uses_trusted_native_package_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()

    def trusted(path: Path) -> bool:
        return path == Path("/usr/bin/perflens-collector")

    monkeypatch.setattr("perflens.distribution.onboarding._trusted_packaged_entrypoint", trusted)
    artifact = run_project_setup(
        project,
        prepare_collector=True,
        install_skill=False,
        perf_path=Path("/bin/true"),
    )

    assert artifact.collector_assets_path is not None
    assets = Path(artifact.collector_assets_path)
    service = (assets / "perflens-collector.service").read_text(encoding="utf-8")
    chinese = (project / "perflens-setup/下一步.zh-CN.md").read_text(encoding="utf-8")
    english = (project / "perflens-setup/NEXT_STEPS.md").read_text(encoding="utf-8")
    assert "ExecStart=/usr/bin/perflens-collector" in service
    assert "/usr/bin/perflens-admin deploy" in chinese
    assert "/opt/perflens/bin/perflens-admin" not in chinese
    assert "/usr/bin/perflens-admin deploy" in english


def test_setup_can_generate_without_installing_codex_project_config(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    artifact = run_project_setup(
        project,
        install_codex_config=False,
        install_skill=False,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    assert artifact.codex_project_config_status == "skipped"
    assert artifact.codex_project_config_path is None
    assert not (project / ".codex").exists()
    assert (project / "perflens-setup/codex-mcp.toml").is_file()
    guide = (project / "perflens-setup/下一步.zh-CN.md").read_text(encoding="utf-8")
    assert "--skip-codex-config" in guide


def test_setup_can_activate_claude_code_without_exposing_codex_skill(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    artifact = run_project_setup(
        project,
        install_skill=False,
        install_codex_config=False,
        install_claude_skill=True,
        install_claude_config=True,
        codex_enabled=False,
        claude_enabled=True,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    assert artifact.skill_status == "skipped"
    assert artifact.codex_project_config_status == "skipped"
    assert artifact.claude_skill_status == "installed"
    assert artifact.claude_project_config_status == "installed"
    assert artifact.claude_project_config_managed is True
    assert not (project / ".agents").exists()
    assert not (project / ".codex").exists()
    assert (project / ".claude/skills/perflens/SKILL.md").is_file()
    assert json.loads((project / ".mcp.json").read_text(encoding="utf-8"))[
        "mcpServers"
    ]["perflens"]
    guide = (project / "perflens-setup/下一步.zh-CN.md").read_text(encoding="utf-8")
    assert "Codex Skill (未启用)" in guide
    assert "Claude Code (已启用)" in guide


def test_setup_update_replaces_owned_bundle_and_both_client_configs(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    first = run_project_setup(
        project,
        install_claude_skill=True,
        install_claude_config=True,
        codex_enabled=True,
        claude_enabled=True,
        automatic_collection=True,
        allow_process_execution=True,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    old_setup = (project / "perflens-setup/setup.json").read_text(encoding="utf-8")
    assert first.skill_fingerprint is not None
    assert first.claude_skill_fingerprint is not None
    assert "--allow-automatic-collection" in (project / ".mcp.json").read_text(
        encoding="utf-8"
    )

    updated = run_project_setup(
        project,
        install_claude_skill=True,
        install_claude_config=True,
        codex_enabled=True,
        claude_enabled=True,
        automatic_collection=False,
        allow_process_execution=False,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
        update_existing=True,
    )

    assert updated.automatic_collection_enabled is False
    assert updated.codex_project_config_status == "updated"
    assert updated.claude_project_config_status == "updated"
    assert "--allow-automatic-collection" not in (project / ".mcp.json").read_text(
        encoding="utf-8"
    )
    assert "--allow-automatic-collection" not in (
        project / ".codex/config.toml"
    ).read_text(encoding="utf-8")
    assert (project / "perflens-setup/setup.json").read_text(encoding="utf-8") != old_setup
    assert not (project / ".perflens-setup.perflens-backup").exists()


def test_setup_update_migrates_v012_legacy_skill_path(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    first = run_project_setup(
        project,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    current = project / ".agents/skills/perflens"
    legacy = current.with_name("perflens-performance-analysis")
    current.rename(legacy)
    setup_path = project / "perflens-setup/setup.json"
    payload = json.loads(setup_path.read_text(encoding="utf-8"))
    payload["perflens_version"] = "0.1.2"
    payload["skill_path"] = str(legacy)
    setup_path.write_text(json.dumps(payload), encoding="utf-8")

    updated = run_project_setup(
        project,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
        update_existing=True,
    )

    assert first.skill_fingerprint == updated.skill_fingerprint
    assert updated.skill_status == "updated"
    assert updated.skill_path == str(current)
    assert current.is_dir()
    assert not legacy.exists()


def test_setup_without_update_records_existing_legacy_skill_path(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    current = install_project_skill(project)
    legacy = current.with_name("perflens-performance-analysis")
    current.rename(legacy)

    artifact = run_project_setup(
        project,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    assert artifact.skill_status == "existing"
    assert artifact.skill_path == str(legacy)
    assert legacy.is_dir()
    assert not current.exists()


def test_setup_update_refuses_modified_skill_and_preserves_previous_setup(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    run_project_setup(
        project,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    setup_path = project / "perflens-setup/setup.json"
    before = setup_path.read_text(encoding="utf-8")
    skill = project / ".agents/skills/perflens/SKILL.md"
    skill.write_text(skill.read_text(encoding="utf-8") + "\nuser change\n", encoding="utf-8")

    with pytest.raises(PerfLensError) as modified:
        run_project_setup(
            project,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
            update_existing=True,
        )

    assert modified.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert setup_path.read_text(encoding="utf-8") == before
    assert "user change" in skill.read_text(encoding="utf-8")


def test_setup_update_requires_valid_ownership_and_unused_backup(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    run_project_setup(
        project,
        install_skill=False,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    backup = project / ".perflens-setup.perflens-backup"
    backup.mkdir()
    with pytest.raises(PerfLensError) as occupied_backup:
        run_project_setup(
            project,
            install_skill=False,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
            update_existing=True,
        )
    assert occupied_backup.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    backup.rmdir()

    setup_path = project / "perflens-setup/setup.json"
    payload = json.loads(setup_path.read_text(encoding="utf-8"))
    payload["project_root"] = str(tmp_path)
    setup_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PerfLensError) as wrong_owner:
        run_project_setup(
            project,
            install_skill=False,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
            update_existing=True,
        )
    assert wrong_owner.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_setup_update_refuses_unowned_existing_output(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    output = project / "perflens-setup"
    output.mkdir()
    (output / "user-file").write_text("keep", encoding="utf-8")

    with pytest.raises(PerfLensError) as unowned:
        run_project_setup(
            project,
            install_skill=False,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
            update_existing=True,
        )

    assert unowned.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert (output / "user-file").read_text(encoding="utf-8") == "keep"


def test_setup_does_not_claim_modified_preexisting_skill(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    skill = install_project_skill(project)
    skill_file = skill / "SKILL.md"
    skill_file.write_text(
        skill_file.read_text(encoding="utf-8") + "\nuser-owned change\n",
        encoding="utf-8",
    )

    artifact = run_project_setup(
        project,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    assert artifact.skill_status == "existing"
    assert artifact.skill_fingerprint is None
    assert "user-owned change" in skill_file.read_text(encoding="utf-8")


def test_setup_does_not_claim_identical_preexisting_claude_entry(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        render_claude_config(project, mcp_command=Path(sys.executable)),
        encoding="utf-8",
    )

    artifact = run_project_setup(
        project,
        install_skill=False,
        install_codex_config=False,
        install_claude_skill=False,
        install_claude_config=True,
        codex_enabled=False,
        claude_enabled=True,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )

    assert artifact.claude_project_config_status == "existing"
    assert artifact.claude_project_config_managed is False


def test_setup_update_refuses_extra_files_and_preserves_staged_collector_assets(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    run_project_setup(
        project,
        prepare_collector=True,
        collector_command=Path("/opt/perflens/bin/perflens-collector"),
        collector_uid=os.geteuid(),
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    policy = project / "perflens-setup/collector-assets/collector.toml"
    policy.write_text(policy.read_text(encoding="utf-8") + "\n# reviewed\n", encoding="utf-8")
    extra = project / "perflens-setup/user-notes.txt"
    extra.write_text("keep", encoding="utf-8")

    with pytest.raises(PerfLensError) as unknown:
        run_project_setup(
            project,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
            update_existing=True,
        )
    assert unknown.value.code is ErrorCode.PATH_SAFETY_VIOLATION
    assert extra.read_text(encoding="utf-8") == "keep"

    extra.unlink()
    updated = run_project_setup(
        project,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
        update_existing=True,
    )
    assert updated.collector_assets_path == str(project / "perflens-setup/collector-assets")
    assert "# reviewed" in policy.read_text(encoding="utf-8")


def test_setup_artifact_accepts_payload_before_project_config_fields(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    artifact = run_project_setup(
        project,
        install_codex_config=False,
        install_skill=False,
        mcp_command=Path(sys.executable),
        perf_path=Path("/bin/true"),
    )
    payload = artifact.model_dump()
    payload.pop("codex_project_config_path")
    payload.pop("codex_project_config_status")
    payload.pop("skill_fingerprint")
    payload.pop("claude_skill_status")
    payload.pop("claude_skill_path")
    payload.pop("claude_skill_fingerprint")
    payload.pop("claude_mcp_config_path")
    payload.pop("claude_project_config_path")
    payload.pop("claude_project_config_status")
    payload.pop("claude_project_config_managed")

    restored = SetupArtifact.model_validate(payload)

    assert restored.codex_project_config_path is None
    assert restored.codex_project_config_status == "skipped"
    assert restored.skill_fingerprint is None
    assert restored.claude_skill_status == "skipped"
    assert restored.claude_project_config_status == "skipped"
    assert restored.claude_project_config_managed is False
    assert restored.claude_skill_fingerprint is None


def test_setup_explains_missing_native_collector_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()

    def trusted(path: Path) -> bool:
        return path == Path("/usr/bin/perflens")

    monkeypatch.setattr("perflens.distribution.onboarding._trusted_packaged_entrypoint", trusted)

    with pytest.raises(PerfLensError) as missing:
        run_project_setup(
            project,
            prepare_collector=True,
            install_skill=False,
            perf_path=Path("/bin/true"),
        )

    assert missing.value.code is ErrorCode.INVALID_INPUT
    assert "缺少 Collector" in missing.value.message
    assert "perflens-collector" in missing.value.suggested_actions[0]
    assert not (project / "perflens-setup").exists()


def test_native_entrypoint_trust_rejects_writable_launcher_or_target(
    tmp_path: Path,
) -> None:
    native_bin = tmp_path / "usr/bin"
    runtime = tmp_path / "usr/lib/perflens"
    native_bin.mkdir(parents=True)
    runtime.mkdir(parents=True)
    native_bin.chmod(0o755)
    runtime.chmod(0o755)
    launcher = runtime / "perflens-launcher"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.chmod(0o555)
    entrypoint = native_bin / "perflens-collector"
    entrypoint.symlink_to(launcher)
    trusted_entrypoint = onboarding._trusted_packaged_entrypoint  # pyright: ignore[reportPrivateUsage]

    assert trusted_entrypoint(
        entrypoint,
        native_parent=native_bin,
        trusted_owner=os.geteuid(),
    )

    launcher.chmod(0o775)
    assert not trusted_entrypoint(
        entrypoint,
        native_parent=native_bin,
        trusted_owner=os.geteuid(),
    )
    launcher.chmod(0o555)
    native_bin.chmod(0o777)
    assert not trusted_entrypoint(
        entrypoint,
        native_parent=native_bin,
        trusted_owner=os.geteuid(),
    )


def test_setup_refuses_overwrite_escape_and_unsafe_existing_skill(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / "occupied").mkdir()

    with pytest.raises(PerfLensError) as occupied:
        run_project_setup(
            project,
            output_directory=Path("occupied"),
            install_skill=False,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
        )
    assert occupied.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with pytest.raises(PerfLensError) as escaped:
        run_project_setup(
            project,
            output_directory=outside / "setup",
            install_skill=False,
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
        )
    assert escaped.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    skill_parent = project / ".agents" / "skills"
    skill_parent.mkdir(parents=True)
    (skill_parent / "perflens").symlink_to(
        outside,
        target_is_directory=True,
    )
    with pytest.raises(PerfLensError) as unsafe_skill:
        run_project_setup(
            project,
            output_directory=Path("safe-output"),
            mcp_command=Path(sys.executable),
            perf_path=Path("/bin/true"),
        )
    assert unsafe_skill.value.code is ErrorCode.PATH_SAFETY_VIOLATION
