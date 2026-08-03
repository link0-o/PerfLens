from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from perflens.domain.errors import ErrorCode, PerfLensError
from perflens.workloads.project import (
    PROJECT_EXECUTION_AUTHORIZATION,
    ProjectWorkloadRequest,
    collect_project_workload,
)


def test_project_workload_rejects_missing_authorization_before_launch(tmp_path: Path) -> None:
    executable = tmp_path / "workload"
    executable.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    executable.chmod(0o500)

    with pytest.raises(PerfLensError) as captured:
        collect_project_workload(
            ProjectWorkloadRequest(
                project_root=tmp_path,
                executable=executable,
                authorization="not-authorized",
            ),
            policy=None,  # type: ignore[arg-type] - authorization fails before policy use
            capabilities=None,  # type: ignore[arg-type] - authorization fails before use
            collector_socket=tmp_path / "missing.sock",
        )

    assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_project_workload_rejects_executable_escape_and_argument_overflow(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    outside.chmod(0o500)
    common = {
        "policy": None,
        "capabilities": None,
        "collector_socket": tmp_path / "missing.sock",
    }
    with pytest.raises(PerfLensError) as escaped:
        collect_project_workload(
            ProjectWorkloadRequest(
                project_root=project,
                executable=outside,
                authorization=PROJECT_EXECUTION_AUTHORIZATION,
            ),
            **common,  # type: ignore[arg-type]
        )
    assert escaped.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    executable = project / "workload"
    executable.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    executable.chmod(0o500)
    with pytest.raises(PerfLensError) as overflow:
        collect_project_workload(
            ProjectWorkloadRequest(
                project_root=project,
                executable=executable,
                arguments=("x",) * 129,
                authorization=PROJECT_EXECUTION_AUTHORIZATION,
            ),
            **common,  # type: ignore[arg-type]
        )
    assert overflow.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    executable.chmod(executable.stat().st_mode | stat.S_ISUID)
    with pytest.raises(PerfLensError) as setid:
        collect_project_workload(
            ProjectWorkloadRequest(
                project_root=project,
                executable=executable,
                authorization=PROJECT_EXECUTION_AUTHORIZATION,
            ),
            **common,  # type: ignore[arg-type]
        )
    assert setid.value.code is ErrorCode.PATH_SAFETY_VIOLATION
