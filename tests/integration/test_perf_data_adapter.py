from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from perflens.application.analyze import analyze_perf_data
from perflens.cli.app import app
from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.profiles.perf_data import PerfDataAdapter

runner = CliRunner()


def test_perf_data_uses_explicit_perf_script_adapter(tmp_path: Path) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"opaque perf container")
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('perf version test-1')\n"
        "    raise SystemExit(0)\n"
        "expected = ['script', '--force', '--ns', '-F', "
        "'comm,pid,tid,cpu,time,event,period,ip,sym,dso,srcline', '-i']\n"
        "assert sys.argv[1:7] == expected, sys.argv\n"
        "print('app 9/10 [001] 1.25: 11 cycles: 400010 leaf (/tmp/perf-9.map)')\n"
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
    assert payload["metadata"]["conversion"]["converter_version"] == "perf version test-1"
    assert payload["metadata"]["conversion"]["argv"][1] == "script"
    assert payload["metadata"]["conversion"]["argv"][2] == "--force"
    assert payload["hotspots"][0]["symbol"] == "leaf"
    assert "cross_time_jit_symbol_replay" in payload["evidence_quality"]["forbidden_conclusions"]
    verification = tmp_path / "verification.json"
    verified = runner.invoke(
        app,
        [
            "verify-analysis",
            "--input",
            str(output),
            "--output",
            str(verification),
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verification.read_text(encoding="utf-8"))["status"] == "partial"


def test_perf_data_retries_without_cpu_for_legacy_recordings(tmp_path: Path) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"opaque perf container without sample cpu")
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('perf version test-1')\n"
        "    raise SystemExit(0)\n"
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


def test_perf_data_uses_verified_symfs_without_publishing_private_path(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"opaque container perf data")
    symfs = tmp_path / "private-symfs"
    symfs.mkdir(mode=0o700)
    symfs_identity = "a" * 64
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import pathlib\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('perf version symfs-test')\n"
        "    raise SystemExit(0)\n"
        "assert args[:4] == ['script', '--force', '--ns', '--symfs'], args\n"
        f"assert pathlib.Path(args[4]) == pathlib.Path({str(symfs)!r}), args\n"
        "print('app 9/10 [001] 1.25: 11 cpu-clock: 400010 leaf (/workspace/app)')\n",
        encoding="utf-8",
    )
    fake_perf.chmod(fake_perf.stat().st_mode | stat.S_IXUSR)

    analysis = analyze_perf_data(
        profile,
        perf_path=fake_perf,
        symfs_path=symfs,
        symfs_identity_sha256=symfs_identity,
    )

    conversion = analysis.metadata.conversion
    assert str(symfs) not in conversion.argv
    assert f"@VERIFIED_CONTAINER_SYMFS_SHA256:{symfs_identity}" in conversion.argv
    assert f"verified_container_symfs_sha256:{symfs_identity}" in conversion.compatibility_fallbacks
    assert analysis.hotspots[0].symbol == "leaf"


def test_perf_data_rejects_unpaired_or_unsafe_symfs_inputs(tmp_path: Path) -> None:
    fake_perf = tmp_path / "perf"
    fake_perf.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_perf.chmod(0o500)
    safe_symfs = tmp_path / "safe-symfs"
    safe_symfs.mkdir(mode=0o700)

    with pytest.raises(PerfLensError) as unpaired:
        PerfDataAdapter(fake_perf, symfs_path=safe_symfs)
    assert unpaired.value.code is ErrorCode.INVALID_INPUT

    with pytest.raises(PerfLensError) as missing:
        PerfDataAdapter(
            fake_perf,
            symfs_path=tmp_path / "missing-symfs",
            symfs_identity_sha256="a" * 64,
        )
    assert missing.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    safe_symfs.chmod(0o770)
    with pytest.raises(PerfLensError) as writable:
        PerfDataAdapter(
            fake_perf,
            symfs_path=safe_symfs,
            symfs_identity_sha256="not-a-sha256",
        )
    assert writable.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_empty_perf_data_is_a_verified_partial_analysis(tmp_path: Path) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"opaque perf container with no samples")
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('perf version test-empty')\n"
        "    raise SystemExit(0)\n"
        "assert sys.argv[1] == 'script', sys.argv\n",
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
    assert payload["status"] == "partial"
    assert payload["metadata"]["sample_count"] == 0
    assert payload["metadata"]["event"] == "unknown"
    assert payload["metadata"]["weight_unit"] == "sample_count"
    assert payload["metadata"]["weight_source"] == "sample_count_fallback"
    assert payload["hotspots"] == []
    assert payload["call_paths"] == []
    assert payload["evidence_quality"]["allowed_conclusions"] == []
    assert (
        "The profile contains no usable weighted samples."
        in payload["evidence_quality"]["limitations"]
    )


def test_perf_data_does_not_retry_unrelated_perf_failure(tmp_path: Path) -> None:
    profile = tmp_path / "perf.data"
    profile.write_bytes(b"invalid perf container")
    fake_perf = tmp_path / "perf"
    fake_perf.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('perf version test-1')\n"
        "    raise SystemExit(0)\n"
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
