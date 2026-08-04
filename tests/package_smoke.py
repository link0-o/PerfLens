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
    _run(
        perflens_admin,
        "undeploy",
        "--help",
        expected="preserving policy and artifacts",
    )
    _run(perflens, "verify-collector", "--help", expected="bounded real perf-stat probe")

    with tempfile.TemporaryDirectory(prefix="perflens-package-smoke-") as directory:
        root = Path(directory)
        profile = root / "profile.folded"
        analysis = root / "analysis.json"
        project = root / "project"
        profile.write_text("main;worker 7\nmain;compute 13\n", encoding="utf-8")
        project.mkdir()

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

        _run(perflens, "install-skill", "--project", str(project))
        skill = (
            project
            / ".agents"
            / "skills"
            / "perflens-performance-analysis"
            / "SKILL.md"
        )
        assert skill.is_file()

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
        assert (guided_setup / "下一步.zh-CN.md").is_file()
        setup_payload = json.loads(
            (guided_setup / "setup.json").read_text(encoding="utf-8")
        )
        assert setup_payload["schema_version"] == "1.0"
        assert setup_payload["skill_status"] == "existing"
        assert setup_payload["automatic_collection_enabled"] is True
        assert '"--allow-project-execution"' in (
            guided_setup / "codex-mcp.toml"
        ).read_text(encoding="utf-8")
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
        policy_text = (collector_assets / "collector.toml").read_text(encoding="utf-8")
        service_text = (collector_assets / "perflens-collector.service").read_text(
            encoding="utf-8"
        )
        assert f"allowed_uids = [{os.geteuid()}]" in policy_text
        assert "policy_version = 1" in policy_text
        assert "允许连接 Collector 的普通用户 UID" in policy_text
        assert "Ordinary-user UIDs allowed to call the Collector" in policy_text
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


if __name__ == "__main__":
    main()
