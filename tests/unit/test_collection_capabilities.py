from __future__ import annotations

# pyright: reportPrivateUsage=false
import os
import stat
import sys
from pathlib import Path

import pytest

from perflens.collection import capabilities


def _executable(tmp_path: Path, body: str) -> Path:
    path = tmp_path / f"tool-{len(tuple(tmp_path.iterdir()))}"
    path.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_optional_executable_and_version_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    warnings: list[str] = []

    def missing_which(_name: str) -> None:
        return None

    monkeypatch.setattr(capabilities.shutil, "which", missing_which)
    assert capabilities._resolve_optional_executable(None, "missing", warnings) is None
    assert warnings

    warnings.clear()
    assert (
        capabilities._resolve_optional_executable(tmp_path / "missing", "perf", warnings) is None
    )
    assert "cannot be resolved" in warnings[0]

    plain_file = tmp_path / "plain"
    plain_file.write_text("not executable", encoding="utf-8")
    warnings.clear()
    assert capabilities._resolve_optional_executable(plain_file, "perf", warnings) is None
    assert "not an executable" in warnings[0]

    version_tool = _executable(tmp_path, "print('perf version test')")
    warnings.clear()
    assert capabilities._read_perf_version(version_tool, warnings) == "perf version test"
    assert capabilities._read_perf_version(None, warnings) is None

    failing_tool = _executable(tmp_path, "raise SystemExit(2)")
    assert capabilities._read_perf_version(failing_tool, warnings) is None
    assert any("query" in warning for warning in warnings)


def test_kernel_and_capability_read_failures_are_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    integer = tmp_path / "integer"
    integer.write_text("3\n", encoding="ascii")
    warnings: list[str] = []
    assert capabilities._read_kernel_integer(str(integer), warnings) == 3
    integer.write_text("not-an-int", encoding="ascii")
    assert capabilities._read_kernel_integer(str(integer), warnings) is None

    def fail_read_text(_self: Path, *args: object, **kwargs: object) -> str:
        raise OSError("denied")

    monkeypatch.setattr(Path, "read_text", fail_read_text)
    assert capabilities._process_capabilities(warnings) == ()
    assert any("effective process" in warning for warning in warnings)


def test_file_capability_detection_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    perf = _executable(tmp_path, "raise SystemExit(0)")
    fake_getcap = _executable(
        tmp_path,
        "print('perf cap_perfmon,cap_syslog=ep')",
    )
    def find_fake_getcap(_name: str) -> str:
        return str(fake_getcap)

    monkeypatch.setattr(capabilities.shutil, "which", find_fake_getcap)
    warnings: list[str] = []
    assert capabilities._file_capabilities(perf, warnings) == ("cap_syslog", "cap_perfmon")

    failing_getcap = _executable(tmp_path, "raise SystemExit(1)")
    def find_failing_getcap(_name: str) -> str:
        return str(failing_getcap)

    monkeypatch.setattr(capabilities.shutil, "which", find_failing_getcap)
    assert capabilities._file_capabilities(perf, warnings) == ()
    assert any("file capabilities" in warning for warning in warnings)
    assert capabilities._file_capabilities(None, warnings) == ()

    def missing_getcap(_name: str) -> None:
        return None

    monkeypatch.setattr(capabilities.shutil, "which", missing_getcap)
    assert capabilities._file_capabilities(perf, warnings) == ()


@pytest.mark.parametrize(
    ("paranoid", "uid", "caps", "tracefs", "perf_available", "expected"),
    [
        (3, 1000, frozenset[str](), False, False, ("blocked",) * 5),
        (3, 1000, frozenset[str](), False, True, ("blocked",) * 5),
        (3, 0, frozenset[str](), True, True, ("available",) * 5),
        (
            2,
            1000,
            frozenset({"cap_perfmon"}),
            False,
            True,
            ("available", "available", "conditional", "conditional", "conditional"),
        ),
        (-1, 1000, frozenset[str](), True, True, ("conditional",) * 5),
        (
            2,
            1000,
            frozenset[str](),
            False,
            True,
            ("conditional", "conditional", "blocked", "blocked", "blocked"),
        ),
    ],
)
def test_mode_capability_matrix(
    paranoid: int,
    uid: int,
    caps: frozenset[str],
    tracefs: bool,
    perf_available: bool,
    expected: tuple[str, ...],
) -> None:
    result = capabilities._mode_capabilities(
        paranoid=paranoid,
        effective_uid=uid,
        capabilities=caps,
        tracefs_accessible=tracefs,
        perf_available=perf_available,
    )
    assert tuple(item.status for item in result) == expected


def test_recommendations_cover_missing_perf_and_blocked_modes() -> None:
    modes = capabilities._mode_capabilities(
        paranoid=3,
        effective_uid=1000,
        capabilities=frozenset(),
        tracefs_accessible=False,
        perf_available=False,
    )
    recommendations = capabilities._recommendations(
        paranoid=3,
        perf_available=False,
        modes=modes,
    )
    assert len(recommendations) == 4


def test_tracefs_accessible_handles_readable_and_denied_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def is_file(_path: Path) -> bool:
        return True

    def readable(_path: object, _mode: int) -> bool:
        return True

    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(os, "access", readable)
    assert capabilities._tracefs_accessible() is True

    def denied(_path: Path) -> bool:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "is_file", denied)
    assert capabilities._tracefs_accessible() is False
