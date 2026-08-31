from __future__ import annotations

import os
from pathlib import Path

import pytest

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks.java_jfr_profiles import load_java_jfr_profiles

SOURCE = Path(__file__).parents[2] / "src/perflens/runtime_locks/jfr"


def test_packaged_java_jfr_profiles_are_fixed() -> None:
    profiles = load_java_jfr_profiles(SOURCE, trusted_owner_uids=(os.getuid(),))

    assert len(profiles) == 6
    assert {(p.jdk_major, p.profile_id) for p in profiles} == {
        (major, profile) for major in (17, 21, 25) for profile in ("balanced", "deep")
    }
    assert {p.measurement_semantics for p in profiles} == {"thresholded"}
    assert {p.threshold_ns for p in profiles} == {1_000_000, 10_000_000}
    assert all(len(p.sha256) == 64 for p in profiles)


def test_java_jfr_profile_rejects_writable_asset(tmp_path: Path) -> None:
    root = tmp_path / "jfr"
    root.mkdir()
    for source in SOURCE.iterdir():
        target = root / source.name
        target.write_bytes(source.read_bytes())
        target.chmod(0o644)
    (root / "jdk17-balanced.jfc").chmod(0o666)

    with pytest.raises(PerfLensError, match="identity is unsafe"):
        load_java_jfr_profiles(root, trusted_owner_uids=(os.getuid(),))


def test_java_jfr_profile_rejects_extra_event(tmp_path: Path) -> None:
    root = tmp_path / "jfr"
    root.mkdir()
    for source in SOURCE.iterdir():
        raw = source.read_text()
        if source.name == "jdk21-deep.jfc":
            raw = raw.replace(
                "</configuration>",
                '<event name="jdk.SocketRead"><setting name="enabled">true</setting>'
                "</event></configuration>",
            )
        target = root / source.name
        target.write_text(raw)
        target.chmod(0o644)

    with pytest.raises(PerfLensError, match="event surface"):
        load_java_jfr_profiles(root, trusted_owner_uids=(os.getuid(),))
