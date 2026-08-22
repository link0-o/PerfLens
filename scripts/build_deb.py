#!/usr/bin/env python3
"""Build split, non-activating Debian packages from a locked PerfLens wheel."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import cast

from perflens import __version__
from perflens.distribution.debian import DEBIAN_PACKAGE_REVISION

_SOURCE_DATE_EPOCH = 1_577_836_800  # 2020-01-01 UTC
_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
_ARCHITECTURE = re.compile(r"^[a-z0-9][a-z0-9-]+$")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--output-directory", type=Path, default=Path("dist"))
    parser.add_argument("--python", type=Path, default=Path("/usr/bin/python3"))
    parser.add_argument("--uv", type=Path)
    parser.add_argument(
        "--helper-binary",
        type=Path,
        help="Prebuilt release perflens-privileged-helper binary.",
    )
    parser.add_argument(
        "--trace-helper-binary",
        type=Path,
        help="Prebuilt release perflens-trace-helper binary.",
    )
    parser.add_argument(
        "--container-gate-binary",
        type=Path,
        help="Prebuilt release perflens-container-gate binary.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Require every locked dependency to already exist in the uv cache.",
    )
    arguments = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    version = _project_version(project_root / "pyproject.toml")
    if version != __version__:
        parser.error("pyproject.toml and runtime versions do not match")
    wheel_argument = arguments.wheel or (
        project_root / "dist" / f"perflens-{version}-py3-none-any.whl"
    )
    wheel = _regular_input(wheel_argument, parser, "wheel")
    if wheel.name != f"perflens-{version}-py3-none-any.whl":
        parser.error(f"wheel must be named perflens-{version}-py3-none-any.whl")
    output = _existing_directory(arguments.output_directory, parser, "output directory")
    helper_binary = _executable(
        arguments.helper_binary or project_root / "target/release/perflens-privileged-helper",
        parser,
        "Rust Helper binary",
    )
    trace_helper_binary = _executable(
        arguments.trace_helper_binary
        or project_root / "target/release/perflens-trace-helper",
        parser,
        "Rust Trace Helper binary",
    )
    container_gate_binary = _executable(
        arguments.container_gate_binary
        or project_root / "target/release/perflens-container-gate",
        parser,
        "Rust container Gate binary",
    )
    python = _executable(arguments.python, parser, "Python interpreter")
    uv_candidate = arguments.uv or _which_path("uv", parser)
    uv = _executable(uv_candidate, parser, "uv executable")
    dpkg_deb = _executable(_which_path("dpkg-deb", parser), parser, "dpkg-deb")
    dpkg = _executable(_which_path("dpkg", parser), parser, "dpkg")
    architecture = _capture((str(dpkg), "--print-architecture"), cwd=project_root)
    if not _ARCHITECTURE.fullmatch(architecture):
        parser.error(f"dpkg returned an invalid architecture: {architecture!r}")
    python_abi = _capture(
        (
            str(python),
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ),
        cwd=project_root,
    )
    if python_abi not in {"3.12", "3.13"}:
        parser.error("Debian package builds require the supported system Python 3.12 or 3.13")

    debian_version = f"{version}-{DEBIAN_PACKAGE_REVISION}"
    main_output = output / f"perflens_{debian_version}_{architecture}.deb"
    collector_output = output / f"perflens-collector_{debian_version}_{architecture}.deb"
    for destination in (main_output, collector_output):
        if destination.exists() or destination.is_symlink():
            parser.error(f"refusing to overwrite existing package: {destination.name}")

    with tempfile.TemporaryDirectory(prefix="perflens-deb-") as temporary:
        work = Path(temporary)
        requirements = work / "runtime-requirements.txt"
        _export_locked_requirements(uv, project_root, requirements)
        main_root = work / "perflens"
        collector_root = work / "perflens-collector"
        _build_main_tree(
            main_root,
            project_root=project_root,
            wheel=wheel,
            requirements=requirements,
            uv=uv,
            python=python,
            version=debian_version,
            architecture=architecture,
            python_abi=python_abi,
            offline=arguments.offline,
            container_gate_binary=container_gate_binary,
        )
        _build_collector_tree(
            collector_root,
            project_root=project_root,
            version=debian_version,
            architecture=architecture,
            helper_binary=helper_binary,
            trace_helper_binary=trace_helper_binary,
        )
        _build_archive(dpkg_deb, main_root, main_output, project_root)
        _build_archive(dpkg_deb, collector_root, collector_output, project_root)

    print(main_output)
    print(collector_output)


def _build_main_tree(
    root: Path,
    *,
    project_root: Path,
    wheel: Path,
    requirements: Path,
    uv: Path,
    python: Path,
    version: str,
    architecture: str,
    python_abi: str,
    offline: bool,
    container_gate_binary: Path,
) -> None:
    runtime = root / "usr/lib/perflens"
    runtime.mkdir(parents=True)
    install_dependencies = [
        str(uv),
        "pip",
        "install",
        "--python",
        str(python),
        "--target",
        str(runtime),
        "--requirements",
        str(requirements),
        "--require-hashes",
        "--no-compile-bytecode",
        "--link-mode",
        "copy",
    ]
    if offline:
        install_dependencies.append("--offline")
    _run(tuple(install_dependencies), cwd=project_root)
    install_project = [
        str(uv),
        "pip",
        "install",
        "--python",
        str(python),
        "--target",
        str(runtime),
        "--no-deps",
        "--no-compile-bytecode",
        "--link-mode",
        "copy",
        str(wheel),
    ]
    if offline:
        install_project.append("--offline")
    _run(tuple(install_project), cwd=project_root)
    _remove_nondeterministic_uv_metadata(runtime)

    launcher_source = project_root / "packaging/debian/perflens-launcher.py"
    launcher = runtime / "perflens-launcher"
    shutil.copyfile(launcher_source, launcher)
    launcher.chmod(0o755)
    container_gate = runtime / "perflens-container-gate"
    shutil.copyfile(container_gate_binary, container_gate)
    container_gate.chmod(0o755)
    binary_directory = root / "usr/bin"
    binary_directory.mkdir(parents=True)
    for command in ("perflens", "perflens-mcp"):
        (binary_directory / command).symlink_to("../lib/perflens/perflens-launcher")
    _install_docs(root, project_root, "perflens")

    control = _control_text(
        package="perflens",
        version=version,
        architecture=architecture,
        depends=(
            f"python3 (>= {python_abi})",
            f"python3 (<< {_next_minor(python_abi)})",
            "libc6 (>= 2.17)",
            "libgcc-s1",
        ),
        installed_size=_tree_kib(root),
        description=(
            "Evidence-driven Linux performance analysis toolkit\n"
            " PerfLens provides an unprivileged CLI, MCP server, bundled Skill,\n"
            " deterministic profile analysis, a bounded Docker workload gate,\n"
            " and guided project setup."
        ),
    )
    _install_control(root, control)
    _install_maintainer_script(
        root,
        "postinst",
        project_root / "packaging/debian/perflens.postinst",
    )
    _normalize_tree(root)


def _build_collector_tree(
    root: Path,
    *,
    project_root: Path,
    version: str,
    architecture: str,
    helper_binary: Path,
    trace_helper_binary: Path,
) -> None:
    binary_directory = root / "usr/bin"
    binary_directory.mkdir(parents=True)
    for command in ("perflens-admin", "perflens-collector"):
        (binary_directory / command).symlink_to("../lib/perflens/perflens-launcher")
    helper_destination = root / "usr/lib/perflens/perflens-privileged-helper"
    helper_destination.parent.mkdir(parents=True)
    shutil.copyfile(helper_binary, helper_destination)
    helper_destination.chmod(0o755)
    trace_helper_destination = root / "usr/lib/perflens/perflens-trace-helper"
    shutil.copyfile(trace_helper_binary, trace_helper_destination)
    trace_helper_destination.chmod(0o755)
    _install_docs(root, project_root, "perflens-collector")
    examples = root / "usr/share/perflens/collector"
    examples.mkdir(parents=True)
    for filename in (
        "collector.example.toml",
        "trace.example.toml",
        "perflens-collector.service",
        "perflens-collector-helper.service",
        "perflens-privileged-helper.service",
        "perflens-collector-trace.service",
        "perflens-collector-helper-trace.service",
        "perflens-trace-helper.service",
        "perflens.sysusers",
    ):
        shutil.copyfile(project_root / "packaging/collector" / filename, examples / filename)
    control = _control_text(
        package="perflens-collector",
        version=version,
        architecture=architecture,
        depends=(
            f"perflens (= {version})",
            "systemd",
            "passwd",
            "libc6 (>= 2.17)",
            "libbpf1",
            "libelf1",
            "zlib1g",
            "libzstd1",
        ),
        recommends=("linux-perf",),
        installed_size=_tree_kib(root),
        description=(
            "Optional policy-bounded Collector and Rust Helpers for PerfLens\n"
            " This package adds administrator, Collector, stat/record Helper, and independent\n"
            " target-filtered Trace Helper entry points.\n"
            " Installation does not enable the service or alter kernel policy."
        ),
    )
    _install_control(root, control)
    _normalize_tree(root)


def _install_docs(root: Path, project_root: Path, package: str) -> None:
    destination = root / "usr/share/doc" / package
    destination.mkdir(parents=True)
    for source_name, destination_name in (
        ("packaging/debian/README.Debian", "README.Debian"),
        ("packaging/debian/copyright", "copyright"),
    ):
        shutil.copyfile(project_root / source_name, destination / destination_name)
    changelog = (project_root / "CHANGELOG.md").read_bytes()
    (destination / "changelog.gz").write_bytes(gzip.compress(changelog, compresslevel=9, mtime=0))


def _install_control(root: Path, text: str) -> None:
    metadata = root / "DEBIAN"
    metadata.mkdir(mode=0o755)
    control = metadata / "control"
    control.write_text(text, encoding="utf-8")
    control.chmod(0o644)
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and not path.is_relative_to(metadata):
            lines.append(f"{_md5(path)}  {path.relative_to(root).as_posix()}")
    (metadata / "md5sums").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _install_maintainer_script(root: Path, name: str, source: Path) -> None:
    if name not in {"postinst", "preinst", "prerm", "postrm"}:
        raise ValueError("unsupported Debian maintainer script")
    destination = root / "DEBIAN" / name
    shutil.copyfile(source, destination)
    destination.chmod(0o755)


def _control_text(
    *,
    package: str,
    version: str,
    architecture: str,
    depends: tuple[str, ...],
    installed_size: int,
    description: str,
    recommends: tuple[str, ...] = (),
) -> str:
    if not _PACKAGE_NAME.fullmatch(package):
        raise ValueError("invalid Debian package name")
    fields = [
        f"Package: {package}",
        f"Version: {version}",
        "Section: devel",
        "Priority: optional",
        f"Architecture: {architecture}",
        "Maintainer: PerfLens contributors <link0-o@users.noreply.github.com>",
        f"Installed-Size: {installed_size}",
        f"Depends: {', '.join(depends)}",
    ]
    if recommends:
        fields.append(f"Recommends: {', '.join(recommends)}")
    fields.extend(("Homepage: https://github.com/link0-o/PerfLens", f"Description: {description}"))
    return "\n".join(fields) + "\n"


def _export_locked_requirements(uv: Path, project_root: Path, output: Path) -> None:
    _run(
        (
            str(uv),
            "--quiet",
            "export",
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements.txt",
            "--output-file",
            str(output),
        ),
        cwd=project_root,
    )


def _build_archive(dpkg_deb: Path, root: Path, output: Path, cwd: Path) -> None:
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = str(_SOURCE_DATE_EPOCH)
    _run(
        (
            str(dpkg_deb),
            "--build",
            "--root-owner-group",
            "--uniform-compression",
            "-Zxz",
            "-z9",
            str(root),
            str(output),
        ),
        cwd=cwd,
        env=environment,
    )
    output.chmod(0o644)


def _normalize_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.name == "__pycache__" or path.suffix == ".pyc":
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
    root.chmod(0o755)
    for path in sorted(root.rglob("*")):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)
    launcher = root / "usr/lib/perflens/perflens-launcher"
    if launcher.is_file():
        launcher.chmod(0o755)
    for helper_name in (
        "perflens-container-gate",
        "perflens-privileged-helper",
        "perflens-trace-helper",
    ):
        helper = root / "usr/lib/perflens" / helper_name
        if helper.is_file():
            helper.chmod(0o755)
    for script_name in ("postinst", "preinst", "prerm", "postrm"):
        maintainer_script = root / "DEBIAN" / script_name
        if maintainer_script.is_file():
            maintainer_script.chmod(0o755)
    for path in sorted(root.rglob("*")):
        os.utime(path, (_SOURCE_DATE_EPOCH, _SOURCE_DATE_EPOCH), follow_symlinks=False)
    os.utime(root, (_SOURCE_DATE_EPOCH, _SOURCE_DATE_EPOCH))


def _remove_nondeterministic_uv_metadata(runtime: Path) -> None:
    """Drop installer metadata that embeds timestamps or source wheel paths."""
    for metadata in sorted(runtime.glob("*.dist-info")):
        variable_files = tuple(
            path
            for name in ("uv_cache.json", "direct_url.json")
            if (path := metadata / name).is_file()
        )
        if not variable_files:
            continue
        record = metadata / "RECORD"
        try:
            lines = record.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise RuntimeError(f"unable to read wheel RECORD for {metadata.name}") from exc
        retained = lines
        for variable_file in variable_files:
            relative = variable_file.relative_to(runtime).as_posix()
            filtered = [line for line in retained if line.partition(",")[0] != relative]
            if len(filtered) != len(retained) - 1:
                raise RuntimeError(f"wheel RECORD does not uniquely list {relative}")
            retained = filtered
        try:
            record.write_text("\n".join(retained) + "\n", encoding="utf-8")
            for variable_file in variable_files:
                variable_file.unlink()
        except OSError as exc:
            raise RuntimeError(f"unable to normalize install metadata for {metadata.name}") from exc


def _tree_kib(root: Path) -> int:
    total = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    return max(1, (total + 1023) // 1024)


def _next_minor(version: str) -> str:
    major, minor = (int(part) for part in version.split("."))
    return f"{major}.{minor + 1}"


def _regular_input(path: Path, parser: argparse.ArgumentParser, label: str) -> Path:
    candidate = path.expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        parser.error(f"{label} cannot be resolved: {exc}")
    if candidate.is_symlink() or not resolved.is_file():
        parser.error(f"{label} must be a non-symlink regular file")
    return resolved


def _existing_directory(path: Path, parser: argparse.ArgumentParser, label: str) -> Path:
    candidate = path.expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        parser.error(f"{label} cannot be resolved: {exc}")
    if candidate.is_symlink() or not resolved.is_dir():
        parser.error(f"{label} must be a non-symlink directory")
    return resolved


def _executable(path: Path, parser: argparse.ArgumentParser, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        parser.error(f"{label} cannot be resolved: {exc}")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        parser.error(f"{label} must resolve to an executable regular file")
    return resolved


def _which_path(name: str, parser: argparse.ArgumentParser) -> Path:
    resolved = shutil.which(name)
    if resolved is None:
        parser.error(f"required executable is unavailable: {name}")
    return Path(resolved)


def _run(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> None:
    try:
        subprocess.run(  # noqa: S603 - executables are resolved and arguments are structured
            command,
            cwd=cwd,
            env=env,
            check=True,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"command failed: {Path(command[0]).name}") from exc


def _capture(command: tuple[str, ...], *, cwd: Path) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - executable is resolved before invocation
            command,
            cwd=cwd,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"command failed: {Path(command[0]).name}") from exc
    return completed.stdout.strip()


def _md5(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_version(path: Path) -> str:
    with path.open("rb") as handle:
        payload = cast(dict[str, object], tomllib.load(handle))
    project = payload.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml requires [project]")
    version = cast(dict[str, object], project).get("version")
    if not isinstance(version, str):
        raise ValueError("pyproject.toml requires project.version")
    return version


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
