from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from typer.testing import CliRunner

from perflens import __version__
from perflens.application.analyze import analyze_folded
from perflens.artifacts.filesystem import write_json_atomic
from perflens.cli.app import app
from perflens.collection.collector import ACTIVE_COLLECTION_AUTHORIZATION
from perflens.distribution.skill import SKILL_NAME

runner = CliRunner()


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

    doctor = runner.invoke(app, ["doctor"])
    assert doctor.exit_code == 0, doctor.output
    doctor_payload = json.loads(doctor.output)
    assert doctor_payload["schema_version"] == "1.0"
    assert {item["mode"] for item in doctor_payload["modes"]} == {
        "record",
        "stat",
        "sched",
        "lock",
        "off_cpu",
    }

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
    assert (guided_project / "perflens-setup/下一步.zh-CN.md").is_file()
    assert (guided_project / ".agents/skills/perflens-performance-analysis/SKILL.md").is_file()
    generated_config = (guided_project / "perflens-setup/codex-mcp.toml").read_text(
        encoding="utf-8"
    )
    assert '"--allow-project-execution"' in generated_config


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


def test_cli_refuses_to_overwrite_source(tmp_path: Path) -> None:
    source = tmp_path / "input.folded"
    source.write_text("main 1\n")
    result = runner.invoke(
        app,
        ["analyze-folded", "--input", str(source), "--output", str(source)],
    )
    assert result.exit_code == 5
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "PATH_SAFETY_VIOLATION"
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
