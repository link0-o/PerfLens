# pyright: reportPrivateUsage=false
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from scripts import prepare_test_runtimes as preparation

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks.go_pprof_adapter import inspect_go_pprof_installation
from perflens.runtime_locks.java_jfr_capability import inspect_java_jfr_installation
from perflens.runtime_locks.java_jfr_launcher import JavaJfrFilePolicy


def _source(root: Path) -> Path:
    (root / "bin").mkdir(parents=True)
    binary = root / "bin/go"
    binary.write_bytes(b"trusted test source")
    binary.chmod(0o777)
    return binary


def _missing_tool(_name: str) -> None:
    return None


@pytest.mark.parametrize("mode", [0o555, 0o700, 0o755, 0o775, 0o777])
def test_runtime_copy_normalizes_only_private_files(tmp_path: Path, mode: int) -> None:
    source = tmp_path / "source"
    binary = _source(source)
    binary.chmod(mode)
    (source / "bin").chmod(0o777)
    alias = source / "bin/alias"
    os.link(binary, alias)
    linked = source / "bin/link"
    linked.symlink_to(binary.name)
    payload = source / "release"
    payload.write_bytes(b"payload")
    payload.chmod(0o666)
    before = binary.stat()
    destination = tmp_path / "copy"

    preparation._copy_runtime(source, destination, ("bin", "release"))

    for name in ("go", "alias", "link"):
        copied = destination / "bin" / name
        assert not copied.is_symlink()
        assert copied.read_bytes() == binary.read_bytes()
        assert stat.S_IMODE(copied.stat().st_mode) == 0o755
        assert copied.stat().st_nlink == 1
        assert copied.stat().st_uid == os.geteuid()
        assert copied.stat().st_ino != before.st_ino
    assert stat.S_IMODE((destination / "bin").stat().st_mode) == 0o755
    assert stat.S_IMODE((destination / "release").stat().st_mode) == 0o644
    after = binary.stat()
    assert (after.st_mode, after.st_ino, after.st_nlink, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_mode,
        before.st_ino,
        before.st_nlink,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    assert stat.S_IMODE(payload.stat().st_mode) == 0o666
    assert linked.is_symlink()


def test_runtime_copy_ignores_dangling_jdk_sources_not_runtime_libraries(tmp_path: Path) -> None:
    source = tmp_path / "jdk"
    library = source / "lib"
    library.mkdir(parents=True)
    (library / "src.zip").symlink_to("missing-sources.zip")
    (library / "libjava.so").write_bytes(b"native library")
    (library / "linked.so").symlink_to("libjava.so")

    preparation._copy_runtime(source, tmp_path / "copy", ("lib",))

    assert not (tmp_path / "copy/lib/src.zip").exists()
    assert (tmp_path / "copy/lib/linked.so").read_bytes() == b"native library"
    assert not (tmp_path / "copy/lib/linked.so").is_symlink()


@pytest.mark.parametrize("kind", ["existing", "symlink", "inside-source"])
def test_runtime_preparation_rejects_unsafe_destination_before_copy(
    tmp_path: Path, kind: str
) -> None:
    binary = _source(tmp_path / "go")
    java = tmp_path / "jdk/bin/java"
    java.parent.mkdir(parents=True)
    java.write_bytes(b"java")
    destination = tmp_path / "destination"
    if kind == "existing":
        destination.mkdir()
        (destination / "sentinel").write_bytes(b"do not overwrite")
    elif kind == "symlink":
        destination.symlink_to(tmp_path / "missing", target_is_directory=True)
    else:
        destination = binary.parent.parent / "copy"

    with pytest.raises(ValueError, match=r"must not already exist|must be outside"):
        preparation.prepare_test_runtimes(destination, go=binary, java=java)

    assert binary.read_bytes() == b"trusted test source"
    if kind == "existing":
        assert (destination / "sentinel").read_bytes() == b"do not overwrite"


def test_runtime_preparation_rejects_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preparation.shutil, "which", _missing_tool)
    with pytest.raises(ValueError, match="Required test tool is missing: go"):
        preparation._tool("go", None)


@pytest.mark.parametrize("mode", [0o775, 0o777])
def test_production_go_and_java_still_reject_writable_runtime_tools(
    tmp_path: Path, mode: int
) -> None:
    binary = _source(tmp_path / "go")
    binary.chmod(mode)

    installation = inspect_go_pprof_installation(go_path=binary, trusted_owner_uids=(os.geteuid(),))
    assert installation.availability == "unavailable"
    assert installation.tool is None
    assert any(
        "owner, links, mode, or size are unsafe" in item for item in installation.limitations
    )
    with pytest.raises(PerfLensError, match="Java JFR policy mode is unsupported"):
        JavaJfrFilePolicy(binary, "a" * 64, os.geteuid(), mode)


@pytest.mark.parametrize("relative_path", ["release", "lib/modules"])
@pytest.mark.parametrize("mode", [0o755, 0o777])
def test_production_java_still_rejects_executable_runtime_data(
    tmp_path: Path, relative_path: str, mode: int
) -> None:
    from tests.unit.test_java_jfr_capability import _executable_jdk

    jdk = _executable_jdk(tmp_path)
    (jdk / relative_path).chmod(mode)

    capability = inspect_java_jfr_installation(jdk, trusted_owner_uids=(os.geteuid(),))

    assert capability.availability == "unavailable"
    assert any("JDK runtime payload identity is unsafe" in item for item in capability.limitations)
    assert stat.S_IMODE((jdk / relative_path).stat().st_mode) == mode


def test_missing_go_remains_an_explicit_optional_test_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.unit import test_go_pprof_launcher

    monkeypatch.setattr(test_go_pprof_launcher.shutil, "which", _missing_tool)
    with pytest.raises(pytest.skip.Exception, match="Go toolchain is unavailable"):
        test_go_pprof_launcher._go_installation()


def test_present_but_unsafe_go_fails_instead_of_silently_skipping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.unit import test_go_pprof_launcher

    binary = _source(tmp_path / "go")

    def selected_tool(_name: str) -> str:
        return str(binary)

    monkeypatch.setattr(test_go_pprof_launcher.shutil, "which", selected_tool)
    with pytest.raises(AssertionError, match="Prepare private test runtimes"):
        test_go_pprof_launcher._go_installation()


@pytest.mark.parametrize(
    ("release_mode", "modules_mode"),
    [
        (0o444, 0o444),
        (0o644, 0o644),
        (0o666, 0o666),
        (0o755, 0o644),
        (0o644, 0o755),
        (0o777, 0o777),
    ],
)
def test_preparation_builds_missing_matching_pprof_offline_then_checks_both_adapters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, release_mode: int, modules_mode: int
) -> None:
    from tests.unit.test_java_jfr_capability import _executable_jdk

    go = _source(tmp_path / "go-source")
    go.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "root = Path(__file__).resolve().parent.parent\n"
        "if sys.argv[1:] == ['version']:\n"
        "    print('go version go1.25.14 linux/amd64')\n"
        "elif sys.argv[1:] == ['env', 'GOTOOLDIR']:\n"
        "    print(root / 'pkg/tool/linux_amd64')\n"
        "elif sys.argv[1] == 'build':\n"
        "    assert os.environ['GOTOOLCHAIN'] == 'local'\n"
        "    assert os.environ['GOPROXY'] == os.environ['GOSUMDB'] == 'off'\n"
        "    assert os.environ['GOENV'] == os.environ['GOWORK'] == 'off'\n"
        "    assert os.environ['GOFLAGS'] == ''\n"
        "    assert sys.argv[2:5] == ['-trimpath', '-buildvcs=false', '-o']\n"
        "    assert sys.argv[-1] == 'cmd/pprof'\n"
        "    output = root / 'pkg/tool/linux_amd64/pprof'\n"
        "    assert sys.argv[5] == str(output)\n"
        "    output.write_bytes(b'matching pprof test binary')\n"
        "else:\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    source = go.parent.parent
    for name in ("src", "lib", "pkg/tool/linux_amd64"):
        (source / name).mkdir(parents=True)
    for name in ("VERSION", "go.env"):
        (source / name).write_bytes(b"test")
    jdk = _executable_jdk(tmp_path)
    for name in ("javac", "jar"):
        (jdk / "bin" / name).write_bytes(b"unused fixture compiler")
        (jdk / "bin" / name).chmod(0o777)
    (jdk / "conf").mkdir()
    (jdk / "lib/jfr").mkdir()
    (jdk / "lib/jfr/default.jfc").write_bytes(b"test profile")
    # Hosted images can apply broad modes to the entire JDK, not just bin/java.
    # Native helpers must remain executable, but release/modules are data files.
    (jdk / "lib/jspawnhelper").write_bytes(b"executable process-launch helper")
    for path in (jdk, *jdk.rglob("*")):
        path.chmod(0o777)
    (jdk / "release").chmod(release_mode)
    (jdk / "lib/modules").chmod(modules_mode)
    source_metadata = {path: path.stat() for path in (jdk, *jdk.rglob("*"))}
    monkeypatch.setenv("GOTOOLCHAIN", "auto")
    monkeypatch.setenv("GOFLAGS", "-an-unwanted-host-option")

    destination = preparation.prepare_test_runtimes(
        tmp_path / "staged", go=go, java=jdk / "bin/java"
    )

    assert (destination / "go/pkg/tool/linux_amd64/pprof").read_bytes() == (
        b"matching pprof test binary"
    )
    assert not (source / "pkg/tool/linux_amd64/pprof").exists()
    assert stat.S_IMODE(go.stat().st_mode) == 0o777
    assert stat.S_IMODE((jdk / "bin/java").stat().st_mode) == 0o777
    for relative_path in ("release", "lib/modules"):
        copied = destination / "jdk" / relative_path
        assert stat.S_IMODE(copied.stat().st_mode) == 0o644
        assert copied.stat().st_nlink == 1
        assert copied.stat().st_uid == os.geteuid()
        assert copied.stat().st_ino != (jdk / relative_path).stat().st_ino
        assert copied.read_bytes() == (jdk / relative_path).read_bytes()
    for relative_path in ("bin/java", "bin/javac", "bin/jar", "bin/jfr", "lib/jspawnhelper"):
        assert stat.S_IMODE((destination / "jdk" / relative_path).stat().st_mode) == 0o755
    for path, before in source_metadata.items():
        after = path.stat()
        assert (
            after.st_mode,
            after.st_ino,
            after.st_nlink,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) == (
            before.st_mode,
            before.st_ino,
            before.st_nlink,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
