"""Smoke test an installed PerfLens wheel or source distribution."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from perflens import __version__


def main() -> None:
    perflens = _command("perflens")
    perflens_mcp = _command("perflens-mcp")
    perflens_collector = _command("perflens-collector")
    _run(perflens, "--version", expected=__version__)
    _run(perflens_mcp, "--version", expected=__version__)
    _run(perflens_collector, "--version", expected=__version__)

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

        collector_assets = root / "collector-assets"
        _run(
            perflens,
            "stage-collector-assets",
            "--output-directory",
            str(collector_assets),
        )
        assert (collector_assets / "perflens-collector.service").is_file()

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
