from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

from typer.testing import CliRunner

from perflens.cli.app import app

runner = CliRunner()


def test_perf_data_uses_explicit_perf_script_adapter(tmp_path: Path) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"opaque perf container")
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "expected = ['script', '--ns', '-F', "
        "'comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline', '-i']\n"
        "assert sys.argv[1:6] == expected, sys.argv\n"
        "print('app 9/10 [001] 1.25: 11 cycles: 400010 leaf (/app) /src/app.c:7')\n"
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)
    output = tmp_path / "analysis.json"

    result = runner.invoke(
        app,
        [
            "analyze-perf-data",
            "--input",
            str(profile),
            "--output",
            str(output),
            "--perf-path",
            str(fake_perf),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metadata"]["source_type"] == "perf_data"
    assert payload["metadata"]["total_weight"] == 11
    assert payload["hotspots"][0]["symbol"] == "leaf"


def test_perf_data_retries_without_cpu_for_legacy_recordings(tmp_path: Path) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"opaque perf container without sample cpu")
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "fields = sys.argv[sys.argv.index('-F') + 1]\n"
        "if ',cpu,' in fields:\n"
        "    print(\"Samples for 'cpu-clock' event do not have CPU attribute set. "
        "Cannot print 'cpu' field.\", file=sys.stderr)\n"
        "    raise SystemExit(255)\n"
        "assert fields == 'comm,pid,tid,time,event,period,ip,sym,dso,srcline'\n"
        "print('app 9/10 1.25: 11 cpu-clock: 400010 leaf (/app) /src/app.c:7')\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)
    output = tmp_path / "analysis.json"

    result = runner.invoke(
        app,
        [
            "analyze-perf-data",
            "--input",
            str(profile),
            "--output",
            str(output),
            "--perf-path",
            str(fake_perf),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metadata"]["sample_count"] == 1
    assert payload["hotspots"][0]["symbol"] == "leaf"
    assert any(warning["code"] == "MISSING_SAMPLE_CPU" for warning in payload["warnings"])


def test_perf_data_does_not_retry_unrelated_perf_failure(tmp_path: Path) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"invalid perf container")
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "fields = sys.argv[sys.argv.index('-F') + 1]\n"
        "if fields == 'comm,pid,tid,time,event,period,ip,sym,dso,srcline':\n"
        "    print('unsafe broad retry occurred')\n"
        "    raise SystemExit(0)\n"
        "print('unrelated corrupt perf.data error', file=sys.stderr)\n"
        "raise SystemExit(255)\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)

    output = tmp_path / "analysis.json"
    result = runner.invoke(
        app,
        [
            "analyze-perf-data",
            "--input",
            str(profile),
            "--output",
            str(output),
            "--perf-path",
            str(fake_perf),
        ],
    )

    assert result.exit_code != 0
    assert not output.exists()
