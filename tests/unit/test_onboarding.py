from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from perflens.contracts.artifacts import SetupArtifact
from perflens.distribution import onboarding
from perflens.distribution.onboarding import run_project_setup
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
    assert (project / ".agents/skills/perflens-performance-analysis/SKILL.md").is_file()
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

    restored = SetupArtifact.model_validate(payload)

    assert restored.codex_project_config_path is None
    assert restored.codex_project_config_status == "skipped"


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
    (skill_parent / "perflens-performance-analysis").symlink_to(
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
