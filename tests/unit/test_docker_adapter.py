from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.docker.adapter import (
    DockerCommandAdapter,
    DockerEndpointSnapshot,
    ManagedDockerCreateRequest,
    inspect_docker_cli,
)
from perflens.docker.capability import (
    discover_docker_capability,
    open_local_docker_adapter,
)
from perflens.domain.errors import ErrorCode, PerfLensError

_FAKE_DOCKER = """#!/usr/bin/python3
import json
import os
import sys

args = sys.argv[1:]
command = args[4:]
common = {
    "ObservedArgs": args,
    "ObservedEnv": {
        "LANG": os.environ.get("LANG"),
        "LC_ALL": os.environ.get("LC_ALL"),
        "PATH": os.environ.get("PATH"),
        "DOCKER_HOST": os.environ.get("DOCKER_HOST"),
        "DOCKER_CONTEXT": os.environ.get("DOCKER_CONTEXT"),
    },
}
variant = {variant!r}
with open({log_path!r}, "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\\n")
if command[:1] == ["version"]:
    if variant == "malformed-version":
        sys.stdout.write("not-json")
    elif variant == "invalid-version-shape":
        json.dump({"Client": {"Version": "28.0.1"}}, sys.stdout)
    else:
        common.update({
            "Client": {"Version": "28.0.1", "ApiVersion": "1.48"},
            "Server": {"ApiVersion": "1.48"},
        })
        json.dump(common, sys.stdout)
elif command[:1] == ["info"]:
    common.update({
        "OSType": "windows" if variant == "windows" else "linux",
        "CgroupVersion": "1" if variant == "cgroup-v1" else "2",
    })
    json.dump(common, sys.stdout)
elif command[:2] == ["container", "inspect"]:
    reference = command[-1]
    if reference == "malformed-json":
        sys.stdout.write("{")
    elif reference == "array-json":
        json.dump([], sys.stdout)
    elif reference == "stdout-flood":
        sys.stdout.write("x" * 1048577)
    elif reference == "fail":
        sys.stderr.write("bounded failure")
        raise SystemExit(9)
    else:
        common.update({"Id": "a" * 64, "Name": reference})
        json.dump(common, sys.stdout)
elif command[:2] == ["container", "top"]:
    if command[2] == "nonutf8":
        os.write(1, b"PID PPID COMMAND\\n1 0 \\xff\\n")
    else:
        sys.stdout.write("PID PPID COMMAND\\n1 0 workload\\n")
elif command[:2] == ["container", "create"]:
    sys.stdout.write("a" * 64 + "\\n")
elif command[:2] in (["container", "start"], ["container", "stop"], ["container", "rm"]):
    sys.stdout.write("a" * 64 + "\\n")
elif command[:2] == ["container", "wait"]:
    sys.stdout.write("7\\n")
else:
    raise SystemExit(64)
"""


@dataclass(slots=True)
class _DockerSandbox:
    root: Path
    cli: Path
    config: Path
    endpoint: Path
    listener: socket.socket
    log: Path


@contextmanager
def _docker_sandbox(*, variant: str = "normal") -> Generator[_DockerSandbox]:
    root = Path(tempfile.mkdtemp(prefix="perflens-docker-adapter-test-"))
    os.chmod(root, 0o700)
    cli = root / "docker"
    log = root / "commands.ndjson"
    cli.write_text(
        _FAKE_DOCKER.replace("{variant!r}", repr(variant)).replace(
            "{log_path!r}", repr(str(log))
        ),
        encoding="utf-8",
    )
    os.chmod(cli, 0o500)
    config = root / "empty-config"
    config.mkdir(mode=0o500)
    endpoint = root / "docker.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    os.chmod(endpoint, 0o600)
    try:
        yield _DockerSandbox(root, cli, config, endpoint, listener, log)
    finally:
        listener.close()
        if config.exists():
            os.chmod(config, 0o700)
        shutil.rmtree(root)


def _adapter(sandbox: _DockerSandbox) -> DockerCommandAdapter:
    uid = os.geteuid()
    return DockerCommandAdapter(
        docker_path=sandbox.cli,
        endpoint_path=sandbox.endpoint,
        endpoint_kind="local_rootless",
        config_directory=sandbox.config,
        trusted_cli_owner_uids=_trusted_owner_uids(),
        trusted_gate_owner_uids=_trusted_owner_uids(),
        invoking_uid=uid,
    )


def _trusted_owner_uids() -> tuple[int, ...]:
    return tuple(dict.fromkeys((0, os.geteuid(), Path("/").stat().st_uid)))


def _observed_commands(sandbox: _DockerSandbox) -> list[list[str]]:
    if not sandbox.log.exists():
        return []
    return [
        list(value)
        for value in (
            json.loads(line)
            for line in sandbox.log.read_text(encoding="utf-8").splitlines()
        )
    ]


def _managed_request(sandbox: _DockerSandbox) -> ManagedDockerCreateRequest:
    project = sandbox.root / "project"
    scratch = sandbox.root / "scratch"
    control = sandbox.root / "control"
    for directory in (project, scratch, control):
        directory.mkdir(mode=0o700)
    gate = sandbox.root / "perflens-container-gate"
    gate.write_bytes(b"fixed-gate")
    gate.chmod(0o500)
    return ManagedDockerCreateRequest(
        container_name="perflens-" + "1" * 20,
        image_digest="sha256:" + "2" * 64,
        project_root=project,
        scratch_root=scratch,
        control_root=control,
        gate_path=gate,
        gate_sha256=hashlib.sha256(gate.read_bytes()).hexdigest(),
        workload_entrypoint="/usr/bin/python3",
        workload_arguments=("/workspace/bench.py", "--rounds", "3"),
        working_directory="/workspace",
        container_user=f"{os.geteuid()}:{os.getegid()}",
        cpus="2",
        memory_bytes=536_870_912,
        pids=64,
        session_identity_sha256="3" * 64,
        workload_spec_sha256="4" * 64,
        creation_receipt_sha256="5" * 64,
    )


def test_adapter_uses_only_fixed_local_arguments_and_clean_environment() -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        version = adapter.version_info()
        assert version["ObservedArgs"] == [
            "--config",
            str(sandbox.config),
            "--host",
            f"unix://{sandbox.endpoint}",
            "version",
            "--format",
            "{{json .}}",
        ]
        assert version["ObservedEnv"] == {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "DOCKER_HOST": None,
            "DOCKER_CONTEXT": None,
        }
        inspected = adapter.inspect_container("service-1")
        assert inspected["ObservedArgs"][-5:] == [
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            "service-1",
        ]
        assert adapter.top_container("service-1").endswith("1 0 workload\n")


def test_managed_adapter_derives_one_fixed_sandbox_and_lifecycle() -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        request = _managed_request(sandbox)
        container_id = adapter.create_managed_container(request)
        assert container_id == "a" * 64
        create = _observed_commands(sandbox)[-1][4:]
        assert create[:2] == ["container", "create"]
        assert "--privileged" not in create
        assert "--pid" not in create
        assert "--device" not in create
        assert "--env" not in create
        assert create[create.index("--pull") + 1] == "never"
        assert "--network" in create
        assert create[create.index("--network") + 1] == "none"
        assert create[create.index("--restart") + 1] == "no"
        assert "--read-only" in create
        assert create[create.index("--cap-drop") + 1] == "ALL"
        assert create[create.index("--security-opt") + 1] == "no-new-privileges=true"
        assert create[-7:] == [
            "--control",
            "/run/perflens-gate/control.sock",
            "--",
            "/usr/bin/python3",
            "/workspace/bench.py",
            "--rounds",
            "3",
        ]
        mounts = tuple(
            create[index + 1]
            for index, value in enumerate(create)
            if value == "--mount"
        )
        assert mounts == (
            f"type=bind,src={request.project_root},dst=/workspace,readonly",
            f"type=bind,src={request.scratch_root},dst=/perflens-scratch",
            f"type=bind,src={request.control_root},dst=/run/perflens-gate,readonly",
            "type=bind,src="
            f"{request.gate_path},dst=/usr/lib/perflens/perflens-container-gate,readonly",
        )

        adapter.start_managed_container(container_id)
        assert adapter.wait_managed_container(container_id, timeout_seconds=10) == 7
        adapter.stop_managed_container(container_id)
        adapter.remove_managed_container(container_id)
        commands = tuple(tuple(command[4:7]) for command in _observed_commands(sandbox)[-4:])
        assert commands == (
            ("container", "start", container_id),
            ("container", "wait", container_id),
            ("container", "stop", "--time"),
            ("container", "rm", container_id),
        )


def test_managed_adapter_rejects_unsafe_recipe_before_docker_exec() -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        request = _managed_request(sandbox)
        before = len(_observed_commands(sandbox))
        unsafe = replace(
            request,
            workload_entrypoint="python3",
        )
        with pytest.raises(PerfLensError):
            adapter.create_managed_container(unsafe)
        assert len(_observed_commands(sandbox)) == before

        request.gate_path.chmod(0o522)
        with pytest.raises(PerfLensError):
            adapter.create_managed_container(request)
        assert len(_observed_commands(sandbox)) == before


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("gate_sha256", "0" * 64),
        ("scratch_root", None),
        ("cpus", "02"),
        ("cpus", "1.0000000"),
        ("memory_bytes", (6 << 20) - 1),
        ("pids", 0),
    ),
)
def test_managed_adapter_rejects_tampered_gate_overlaps_and_limits(
    field: str,
    value: object,
) -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        request = _managed_request(sandbox)
        replacement = request.project_root if field == "scratch_root" else value
        before = len(_observed_commands(sandbox))
        with pytest.raises(PerfLensError) as captured:
            adapter.create_managed_container(replace(request, **{field: replacement}))
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
        assert len(_observed_commands(sandbox)) == before


def test_managed_adapter_rejects_gate_owner_outside_policy() -> None:
    with _docker_sandbox() as sandbox:
        request = _managed_request(sandbox)
        adapter = DockerCommandAdapter(
            docker_path=sandbox.cli,
            endpoint_path=sandbox.endpoint,
            endpoint_kind="local_rootless",
            config_directory=sandbox.config,
            trusted_cli_owner_uids=_trusted_owner_uids(),
            trusted_gate_owner_uids=(os.geteuid() + 1,),
            invoking_uid=os.geteuid(),
        )
        before = len(_observed_commands(sandbox))
        with pytest.raises(PerfLensError) as captured:
            adapter.create_managed_container(request)
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
        assert len(_observed_commands(sandbox)) == before


@pytest.mark.parametrize("container_id", ["short", "g" * 64, "a" * 63])
def test_managed_lifecycle_requires_full_container_id(container_id: str) -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        before = len(_observed_commands(sandbox))
        with pytest.raises(PerfLensError):
            adapter.remove_managed_container(container_id)
        assert len(_observed_commands(sandbox)) == before


@pytest.mark.parametrize("reference", ("../escape", "--privileged", "name/id", "", "x" * 129))
def test_adapter_rejects_unbounded_container_references(reference: str) -> None:
    with _docker_sandbox() as sandbox:
        with pytest.raises(PerfLensError) as captured:
            _adapter(sandbox).inspect_container(reference)
        assert captured.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize("reference", ("malformed-json", "array-json"))
def test_adapter_rejects_malformed_or_unexpected_json(reference: str) -> None:
    with _docker_sandbox() as sandbox:
        with pytest.raises(PerfLensError) as captured:
            _adapter(sandbox).inspect_container(reference)
        assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_adapter_enforces_output_limit_and_utf8_inventory() -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        with pytest.raises(PerfLensError) as captured:
            adapter.inspect_container("stdout-flood")
        assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
        with pytest.raises(PerfLensError) as captured:
            adapter.top_container("nonutf8")
        assert captured.value.code is ErrorCode.PROFILE_PARSE_FAILED


def test_adapter_preserves_bounded_external_tool_failure() -> None:
    with _docker_sandbox() as sandbox:
        with pytest.raises(PerfLensError) as captured:
            _adapter(sandbox).inspect_container("fail")
        assert captured.value.code is ErrorCode.EXTERNAL_TOOL_FAILED
        assert captured.value.details["exit_code"] == 9


def test_adapter_detects_cli_replacement() -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        replacement = sandbox.root / "replacement"
        replacement.write_text(
            _FAKE_DOCKER.replace("{variant!r}", repr("normal")),
            encoding="utf-8",
        )
        os.chmod(replacement, 0o500)
        replacement.replace(sandbox.cli)
        with pytest.raises(PerfLensError) as captured:
            adapter.version_info()
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_adapter_detects_endpoint_replacement() -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        sandbox.listener.close()
        sandbox.endpoint.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(sandbox.endpoint))
        os.chmod(sandbox.endpoint, 0o600)
        try:
            with pytest.raises(PerfLensError) as captured:
                adapter.version_info()
            assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
        finally:
            replacement.close()


def test_adapter_detects_reused_endpoint_inode_by_change_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _docker_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        original = adapter.endpoint_identity

        def changed_endpoint(
            *_args: object,
            **_kwargs: object,
        ) -> DockerEndpointSnapshot:
            return replace(original, ctime_ns=original.ctime_ns + 1)

        monkeypatch.setattr(
            "perflens.docker.adapter.inspect_docker_endpoint",
            changed_endpoint,
        )
        with pytest.raises(PerfLensError) as captured:
            adapter.version_info()
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_adapter_rejects_unsafe_cli_config_and_endpoint() -> None:
    with _docker_sandbox() as sandbox:
        os.chmod(sandbox.cli, 0o522)  # noqa: S103 - deliberate unsafe-mode rejection
        with pytest.raises(PerfLensError) as captured:
            inspect_docker_cli(sandbox.cli, trusted_owner_uids=_trusted_owner_uids())
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with _docker_sandbox() as sandbox:
        os.chmod(sandbox.config, 0o700)
        (sandbox.config / "config.json").write_text("{}", encoding="utf-8")
        os.chmod(sandbox.config, 0o500)
        with pytest.raises(PerfLensError) as captured:
            _adapter(sandbox)
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with _docker_sandbox() as sandbox:
        os.chmod(sandbox.endpoint, 0o602)  # noqa: S103 - deliberate unsafe-mode rejection
        with pytest.raises(PerfLensError) as captured:
            _adapter(sandbox)
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_adapter_rejects_cli_config_and_endpoint_symlinks() -> None:
    with _docker_sandbox() as sandbox:
        cli_link = sandbox.root / "docker-link"
        cli_link.symlink_to(sandbox.cli)
        with pytest.raises(PerfLensError) as captured:
            inspect_docker_cli(cli_link, trusted_owner_uids=_trusted_owner_uids())
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with _docker_sandbox() as sandbox:
        config_link = sandbox.root / "config-link"
        config_link.symlink_to(sandbox.config, target_is_directory=True)
        with pytest.raises(PerfLensError) as captured:
            DockerCommandAdapter(
                docker_path=sandbox.cli,
                endpoint_path=sandbox.endpoint,
                endpoint_kind="local_rootless",
                config_directory=config_link,
                trusted_cli_owner_uids=_trusted_owner_uids(),
                invoking_uid=os.geteuid(),
            )
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION

    with _docker_sandbox() as sandbox:
        endpoint_link = sandbox.root / "endpoint-link.sock"
        endpoint_link.symlink_to(sandbox.endpoint)
        with pytest.raises(PerfLensError) as captured:
            DockerCommandAdapter(
                docker_path=sandbox.cli,
                endpoint_path=endpoint_link,
                endpoint_kind="local_rootless",
                config_directory=sandbox.config,
                trusted_cli_owner_uids=_trusted_owner_uids(),
                invoking_uid=os.geteuid(),
            )
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_capability_discovers_rootless_linux_cgroup_v2_and_binds_content() -> None:
    uid = os.geteuid()
    checked_at = datetime(2026, 8, 21, tzinfo=UTC)
    with _docker_sandbox() as sandbox:
        adapter = open_local_docker_adapter(
            docker_path=sandbox.cli,
            config_directory=sandbox.config,
            rootless_socket=sandbox.endpoint,
            rootful_socket=sandbox.root / "missing.sock",
            invoking_uid=uid,
            trusted_cli_owner_uids=_trusted_owner_uids(),
        )
        capability = discover_docker_capability(
            docker_path=sandbox.cli,
            config_directory=sandbox.config,
            rootless_socket=sandbox.endpoint,
            rootful_socket=sandbox.root / "missing.sock",
            invoking_uid=uid,
            checked_at=checked_at,
            trusted_cli_owner_uids=_trusted_owner_uids(),
        )
        assert adapter.endpoint_identity.path == sandbox.endpoint
        assert adapter.version_info()["Client"]["Version"] == "28.0.1"
    assert capability.status == "available"
    assert capability.endpoint_kind == "local_rootless"
    assert capability.daemon_mode == "rootless"
    assert capability.docker_cli is not None
    assert capability.docker_cli.version == "28.0.1"
    assert capability.content_sha256 == contract_content_sha256(
        capability,
        exclude={"content_sha256"},
    )


@pytest.mark.parametrize(
    ("variant", "expected_status", "limitation_fragment"),
    (
        ("cgroup-v1", "partial", "cgroup v2"),
        ("windows", "partial", "native Linux"),
        ("malformed-version", "unavailable", "PROFILE_PARSE_FAILED"),
        ("invalid-version-shape", "unavailable", "INVALID_RESPONSE"),
    ),
)
def test_capability_reports_partial_or_unavailable_without_escaping_errors(
    variant: str,
    expected_status: str,
    limitation_fragment: str,
) -> None:
    uid = os.geteuid()
    with _docker_sandbox(variant=variant) as sandbox:
        capability = discover_docker_capability(
            docker_path=sandbox.cli,
            config_directory=sandbox.config,
            rootless_socket=sandbox.endpoint,
            rootful_socket=sandbox.root / "missing.sock",
            invoking_uid=uid,
            trusted_cli_owner_uids=_trusted_owner_uids(),
        )
    assert capability.status == expected_status
    assert limitation_fragment in capability.limitations[0]


def test_capability_reports_missing_endpoint_without_running_docker() -> None:
    with _docker_sandbox() as sandbox:
        missing = sandbox.root / "missing.sock"
        capability = discover_docker_capability(
            docker_path=sandbox.cli,
            config_directory=sandbox.config,
            rootless_socket=missing,
            rootful_socket=missing,
            invoking_uid=os.geteuid(),
            trusted_cli_owner_uids=_trusted_owner_uids(),
        )
    assert capability.status == "unavailable"
    assert capability.endpoint_kind == "missing"
    assert capability.docker_cli is None


def test_capability_explains_missing_fixed_cli_config_directory() -> None:
    with _docker_sandbox() as sandbox:
        capability = discover_docker_capability(
            docker_path=sandbox.cli,
            config_directory=sandbox.root / "missing-config",
            rootless_socket=sandbox.endpoint,
            rootful_socket=sandbox.root / "missing.sock",
            invoking_uid=os.geteuid(),
            trusted_cli_owner_uids=_trusted_owner_uids(),
        )

    assert capability.status == "unavailable"
    assert capability.docker_cli is None
    assert capability.limitations == (
        "Local Docker capability check failed: PATH_SAFETY_VIOLATION; "
        "Docker CLI config directory cannot be inspected safely.",
    )
