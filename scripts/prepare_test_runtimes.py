#!/usr/bin/env python3
"""Stage private Go/JDK copies for development tests, without changing host tools.

This is test infrastructure, not a PerfLens installer or a runtime trust bypass.
The inputs are the developer/CI image's existing, trusted build toolchains.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
from pathlib import Path

from perflens.runtime_locks.go_pprof_adapter import inspect_go_pprof_installation
from perflens.runtime_locks.java_jfr_capability import inspect_java_jfr_installation


def _tool(name: str, selected: Path | None) -> Path:
    candidate = str(selected) if selected is not None else shutil.which(name)
    if candidate is None:
        raise ValueError(f"Required test tool is missing: {name}")
    path = Path(candidate).resolve(strict=True)
    if not path.is_file() or path.parent.name != "bin" or path.name != name:
        raise ValueError(f"Expected a toolchain bin/{name} executable: {path}")
    metadata = path.stat()
    print(
        f"Source {name}: {path} uid={metadata.st_uid} "
        f"mode={stat.S_IMODE(metadata.st_mode):04o} links={metadata.st_nlink}"
    )
    return path


def _copy_file(source: str | Path, destination: str | Path) -> str:
    # copyfile does not preserve hard links, ownership, capabilities, or xattrs.
    copied = shutil.copyfile(source, destination)
    Path(destination).chmod(0o755 if Path(source).stat().st_mode & 0o111 else 0o644)
    return str(copied)


def _copy_runtime(source: Path, destination: Path, entries: tuple[str, ...]) -> None:
    destination.mkdir(mode=0o755)
    for name in entries:
        entry = source / name
        target = destination / name
        if entry.is_dir():
            shutil.copytree(
                entry,
                target,
                symlinks=False,
                copy_function=_copy_file,
                # JDK source archives are not needed to run javac/JFR; distro
                # packages may leave a dangling link when sources are absent.
                ignore=shutil.ignore_patterns("src.zip"),
            )
        else:
            _copy_file(entry, target)
    # copytree copies directory modes, so normalize only the new private tree.
    for root, _directories, _files in os.walk(destination):
        Path(root).chmod(0o755)


def _run(command: tuple[str, ...], *, env: dict[str, str], cwd: Path) -> str:
    result = subprocess.run(  # noqa: S603 - explicit tools from the private test copy
        command,
        env=env,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=240,
    )
    return result.stdout.strip()


def prepare_test_runtimes(
    directory: Path,
    *,
    go: Path | None = None,
    java: Path | None = None,
) -> Path:
    go_source = _tool("go", go).parent.parent
    java_source = _tool("java", java).parent.parent
    if directory.is_symlink() or directory.exists():
        raise ValueError("Test runtime destination must not already exist or be a symlink")
    directory = directory.parent.resolve(strict=True) / directory.name
    if any(directory.is_relative_to(source) for source in (go_source, java_source)):
        raise ValueError("Test runtime destination must be outside the source toolchains")
    directory.mkdir(mode=0o700)
    go_root = directory / "go"
    jdk_root = directory / "jdk"
    _copy_runtime(go_source, go_root, ("bin", "pkg", "src", "lib", "VERSION", "go.env"))
    _copy_runtime(java_source, jdk_root, ("bin", "lib", "conf", "release"))
    # These JDK payloads are data even when an image makes the whole tree
    # executable. Normalize their role only in the independent test copy;
    # bin tools and native launch helpers such as lib/jspawnhelper keep +x.
    for relative_path in ("release", "lib/modules"):
        payload = jdk_root / relative_path
        payload.chmod(0o644)
        metadata = payload.stat()
        print(
            f"Staged JDK payload: {payload} uid={metadata.st_uid} "
            f"mode={stat.S_IMODE(metadata.st_mode):04o} links={metadata.st_nlink} "
            f"size={metadata.st_size}",
            flush=True,
        )
    for name in ("java", "javac", "jar", "jfr"):
        if not (jdk_root / "bin" / name).is_file():
            raise ValueError(f"A complete test JDK is required; missing bin/{name}")
    if not (jdk_root / "lib/jfr/default.jfc").is_file():
        raise ValueError("The test JDK must provide lib/jfr/default.jfc")

    env = {
        **os.environ,
        "GOROOT": str(go_root),
        "GOTOOLCHAIN": "local",
        "GOENV": "off",
        "GOFLAGS": "",
        "GOWORK": "off",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "CGO_ENABLED": "0",
        "GOCACHE": str(directory / "go-cache"),
        "GOPATH": str(directory / "go-path"),
    }
    go_binary = str(go_root / "bin/go")
    tool_directory = Path(_run((go_binary, "env", "GOTOOLDIR"), env=env, cwd=directory))
    if tool_directory != go_root / "pkg/tool/linux_amd64":
        raise ValueError("Tests require the copied Linux amd64 Go tool directory")
    # Recent Go distributions omit this executable. Build it offline from the
    # matching bundled stdlib source, before pytest's per-test timeout starts.
    pprof = tool_directory / "pprof"
    _run(
        (go_binary, "build", "-trimpath", "-buildvcs=false", "-o", str(pprof), "cmd/pprof"),
        env=env,
        cwd=directory,
    )
    pprof.chmod(0o755)

    owners = (os.geteuid(),)
    installation = inspect_go_pprof_installation(go_path=Path(go_binary), trusted_owner_uids=owners)
    if installation.tool is None or installation.pprof_tool is None:
        raise ValueError(f"Staged Go preflight failed: {installation.limitations}")
    if installation.pprof_tool.path != pprof:
        raise ValueError("Go preflight escaped the private toolchain copy")
    capability = inspect_java_jfr_installation(jdk_root, trusted_owner_uids=owners)
    if capability.availability == "unavailable":
        raise ValueError(f"Staged JDK preflight failed: {capability.limitations}")
    for label, tool in (("go", installation.tool), ("pprof", installation.pprof_tool)):
        print(
            f"Staged {label}: {tool.path} version={tool.version} "
            f"uid={tool.owner_uid} mode={tool.mode:04o} sha256={tool.sha256}"
        )
    print(f"Staged JDK: {jdk_root} version={capability.java_version}")
    print(f"TEST_RUNTIME_DIRECTORY={directory}")
    return directory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--go", type=Path)
    parser.add_argument("--java", type=Path)
    arguments = parser.parse_args()
    try:
        prepare_test_runtimes(arguments.directory, go=arguments.go, java=arguments.java)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        parser.exit(1, f"Test runtime preparation failed: {str(detail)[-4096:]}\n")


if __name__ == "__main__":
    main()
