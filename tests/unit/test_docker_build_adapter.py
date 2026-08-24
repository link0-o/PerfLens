from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest

from perflens.application.evidence import contract_content_sha256
from perflens.contracts.docker import DockerRuntimeCapabilityArtifact
from perflens.docker.build_adapter import TypedDockerBuildAdapter
from perflens.docker.build_capability import project_docker_build_capability
from perflens.docker.build_context import (
    build_docker_build_recipe,
    capture_docker_build_context,
)
from perflens.docker.builder_policy import (
    DockerAdministratorBuilderPolicy,
    load_docker_administrator_builder_policy,
)
from perflens.docker.project_config import (
    DockerProjectPolicy,
    load_docker_project_policy,
    render_default_docker_project_policy,
)
from perflens.domain.errors import ErrorCode, PerfLensError

NOW = datetime(2026, 8, 24, tzinfo=UTC)
BASE_DIGEST = "sha256:" + "d" * 64
SESSION_SHA256 = "e" * 64

_FAKE_DOCKER = r"""#!/usr/bin/python3
import hashlib
import json
import pathlib
import sys

state_path = pathlib.Path(STATE_PATH)
log_path = pathlib.Path(LOG_PATH)
args = sys.argv[1:]
command = args[4:]
state = json.loads(state_path.read_text(encoding="utf-8"))
with log_path.open("a", encoding="utf-8") as log:
    log.write(json.dumps(command) + "\n")

def save():
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

def image(reference):
    if reference == BASE_DIGEST and state.get("base_present"):
        return {
            "Id": BASE_DIGEST,
            "RepoTags": [],
            "RepoDigests": ["registry.example/base@" + BASE_DIGEST],
            "Os": "linux",
            "Architecture": "amd64",
            "Size": 1024,
            "Config": {"Labels": {}},
        }
    return state.get("images", {}).get(reference)

if command[:1] == ["version"]:
    json.dump({"Version": "29.7.2"}, sys.stdout)
elif command[:2] == ["buildx", "version"]:
    sys.stdout.write("github.com/docker/buildx v0.30.1\n")
elif command[:2] == ["buildx", "inspect"]:
    json.dump({
        "Name": command[command.index("--builder") + 1],
        "Driver": state.get("driver", "docker"),
        "Nodes": [{
            "Name": "node0",
            "Endpoint": "unix:///fixed",
            "Generation": state.get("generation", 1),
        }],
    }, sys.stdout)
elif command[:2] == ["image", "inspect"]:
    found = image(command[-1])
    if found is None:
        sys.stderr.write("Error: No such image\n")
        raise SystemExit(1)
    json.dump(found, sys.stdout)
elif command[:2] == ["image", "pull"]:
    state["base_present"] = True
    save()
    sys.stdout.write(command[-1] + "\n")
elif command[:2] == ["buildx", "build"]:
    context = sys.stdin.buffer.read()
    tag = command[command.index("--tag") + 1]
    iid_path = pathlib.Path(command[command.index("--iidfile") + 1])
    metadata_path = pathlib.Path(command[command.index("--metadata-file") + 1])
    digest = "sha256:" + hashlib.sha256(context + "\0".join(command).encode()).hexdigest()
    labels = {}
    for index, value in enumerate(command):
        if value == "--label":
            key, label_value = command[index + 1].split("=", 1)
            labels[key] = label_value
    if state.get("wrong_label"):
        labels["io.perflens.optimization-session-sha256"] = "f" * 64
    iid_path.write_text(digest + "\n", encoding="ascii")
    metadata = {
        "containerimage.config.digest": digest,
        "containerimage.digest": digest,
        "buildx.build.provenance": {
            "builder": "fixed",
            "context_sha256": hashlib.sha256(context).hexdigest(),
        },
    }
    if state.get("missing_provenance"):
        metadata.pop("buildx.build.provenance")
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    state.setdefault("images", {})[tag] = {
        "Id": digest,
        "RepoTags": [tag],
        "RepoDigests": [],
        "Os": "linux",
        "Architecture": "amd64",
        "Size": state.get("image_size", 4096),
        "Config": {"Labels": labels},
    }
    save()
    sys.stdout.write("built\n")
elif command[:2] == ["container", "ls"]:
    sys.stdout.write("occupied\n" if state.get("occupied") else "")
elif command[:2] == ["image", "rm"]:
    state.setdefault("images", {}).pop(command[-1], None)
    save()
    sys.stdout.write("removed\n")
else:
    sys.stderr.write("unexpected command: " + repr(command))
    raise SystemExit(64)
"""


class _BuildSandbox:
    def __init__(self, root: Path, endpoint: Path, listener: socket.socket) -> None:
        self.root = root
        self.endpoint = endpoint
        self.listener = listener
        self.docker = root / "docker"
        self.buildx = root / "docker-buildx"
        self.config = root / "empty-config"
        self.state = root / "state.json"
        self.log = root / "commands.ndjson"


@contextmanager
def _build_sandbox(
    *,
    base_present: bool = True,
    driver: str = "docker",
) -> Generator[_BuildSandbox]:
    root = Path(tempfile.mkdtemp(prefix="perflens-docker-build-test-"))
    root.chmod(0o700)
    endpoint = root / "docker.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    endpoint.chmod(0o600)
    sandbox = _BuildSandbox(root, endpoint, listener)
    sandbox.state.write_text(
        json.dumps(
            {
                "base_present": base_present,
                "driver": driver,
                "generation": 1,
                "images": {},
                "occupied": False,
                "wrong_label": False,
                "missing_provenance": False,
                "image_size": 4096,
            }
        ),
        encoding="utf-8",
    )
    source = (
        _FAKE_DOCKER.replace("STATE_PATH", repr(str(sandbox.state)))
        .replace("LOG_PATH", repr(str(sandbox.log)))
        .replace("BASE_DIGEST", repr(BASE_DIGEST))
    )
    sandbox.docker.write_text(source, encoding="utf-8")
    sandbox.docker.chmod(0o500)
    sandbox.buildx.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    sandbox.buildx.chmod(0o500)
    sandbox.config.mkdir(mode=0o500)
    try:
        yield sandbox
    finally:
        listener.close()
        sandbox.config.chmod(0o700)
        shutil.rmtree(root)


def _trusted_uids() -> tuple[int, ...]:
    return tuple(dict.fromkeys((0, os.geteuid(), Path("/").stat().st_uid)))


def _policy_text(
    *,
    network_tier: str = "local_only",
    builder_policy_id: str = "",
) -> str:
    return (
        render_default_docker_project_policy()
        .replace(
            'default_workflow = "existing_container"',
            'default_workflow = "managed_temporary_container"',
        )
        .replace(
            "allow_managed_temporary_containers = false",
            "allow_managed_temporary_containers = true",
        )
        .replace('entrypoint = ""', 'entrypoint = "/workspace/app"')
        .replace('container_user = ""', 'container_user = "1000:1000"')
        .replace('benchmark_output = ""', 'benchmark_output = "result.json"')
        .replace("enabled = false", "enabled = true")
        .replace("context_paths = []", 'context_paths = ["Dockerfile", "src"]')
        .replace("mutable_paths = []", 'mutable_paths = ["src"]')
        .replace('dockerfile = ""', 'dockerfile = "Dockerfile"')
        .replace('base_image_digest = ""', f'base_image_digest = "{BASE_DIGEST}"')
        .replace('network_tier = "local_only"', f'network_tier = "{network_tier}"')
        .replace('builder_policy_id = ""', f'builder_policy_id = "{builder_policy_id}"')
    )


def _project(
    tmp_path: Path,
    *,
    dockerfile: str | None = None,
    network_tier: str = "local_only",
    builder_policy_id: str = "",
):
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    (project / "Dockerfile").write_text(
        dockerfile or f"FROM registry.example/base@{BASE_DIGEST}\nCOPY src/app /app\n",
        encoding="utf-8",
    )
    source = project / "src"
    source.mkdir()
    (source / "app").write_bytes(b"binary")
    policy_path = project / "container-workload.toml"
    policy_path.write_text(
        _policy_text(network_tier=network_tier, builder_policy_id=builder_policy_id),
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    policy = load_docker_project_policy(policy_path, allowed_roots=(project,))
    recipe = build_docker_build_recipe(
        policy,
        project_identity_sha256="a" * 64,
        created_at=NOW,
    )
    snapshot = capture_docker_build_context(
        policy,
        recipe,
        project_root=project,
        private_directory=private,
        created_at=NOW,
    )
    return project, private, policy, snapshot


def _runtime_capability() -> DockerRuntimeCapabilityArtifact:
    data = {
        "schema_version": "1.0",
        "perflens_version": "0.3.2",
        "capability_id": "docker-capability-" + "a" * 20,
        "checked_at": NOW.isoformat(),
        "status": "available",
        "endpoint_kind": "local_rootless",
        "daemon_mode": "rootless",
        "docker_cli": {
            "path": "/fixed/docker",
            "version": "29.7.2",
            "binary_sha256": "b" * 64,
        },
        "api_version": "1.55",
        "server_operating_system": "linux",
        "cgroup_version": "v2",
        "existing_container_discovery": True,
        "managed_container_execution": True,
        "content_sha256": "0" * 64,
    }
    provisional = DockerRuntimeCapabilityArtifact.model_validate(data)
    return DockerRuntimeCapabilityArtifact.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "content_sha256": contract_content_sha256(
                provisional,
                exclude={"content_sha256"},
            ),
        }
    )


def _adapter(
    sandbox: _BuildSandbox,
    *,
    administrator_policy: DockerAdministratorBuilderPolicy | None = None,
) -> TypedDockerBuildAdapter:
    return TypedDockerBuildAdapter(
        docker_path=sandbox.docker,
        buildx_path=sandbox.buildx,
        endpoint_path=sandbox.endpoint,
        endpoint_kind="local_rootless",
        config_directory=sandbox.config,
        administrator_policy=administrator_policy,
        buildx_plugin_directories=(sandbox.root,),
        trusted_tool_owner_uids=_trusted_uids(),
        trusted_policy_owner_uids=_trusted_uids(),
        invoking_uid=os.geteuid(),
    )


def _capability(
    adapter: TypedDockerBuildAdapter,
    policy: DockerProjectPolicy,
    *,
    base_present: bool = True,
):
    return project_docker_build_capability(
        runtime=_runtime_capability(),
        policy=policy,
        docker_tool=adapter.docker_tool_projection,
        buildx_tool=adapter.buildx_tool_projection,
        builder=adapter.builder_projection,
        available_network_tiers=adapter.available_network_tiers,
        base_image_present=base_present,
        collector_available=True,
        checked_at=NOW,
    )


def _commands(sandbox: _BuildSandbox) -> list[list[str]]:
    return [json.loads(line) for line in sandbox.log.read_text(encoding="utf-8").splitlines()]


def _builder_identity(*, driver: str = "docker", generation: int = 1) -> str:
    stable = {
        "Name": "default",
        "Driver": driver,
        "Nodes": [{"Name": "node0", "Endpoint": "unix:///fixed", "Generation": generation}],
    }
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _admin_policy(
    tmp_path: Path,
    *,
    tier: str,
    driver: str,
) -> DockerAdministratorBuilderPolicy:
    path = tmp_path / "builder-policy.toml"
    builder_image = "sha256:" + "f" * 64 if tier == "admin_builder_network" else ""
    path.write_text(
        f'''schema_version = "1.0"
policy_id = "test-builder"
network_tier = "{tier}"
builder_name = "default"
driver = "{driver}"
builder_identity_sha256 = "{_builder_identity(driver=driver)}"
builder_image_digest = "{builder_image}"
network_policy_sha256 = "{"1" * 64}"
source_policy_sha256 = "{"2" * 64}"
allowed_registry_prefixes = ["registry.example"]
base_image_reference = "registry.example/base@{BASE_DIGEST}"
''',
        encoding="utf-8",
    )
    path.chmod(0o400)
    return load_docker_administrator_builder_policy(path, trusted_owner_uids=_trusted_uids())


def test_local_only_build_is_content_bound_and_cleanup_removes_only_session_tag(
    tmp_path: Path,
) -> None:
    project, private, policy, snapshot = _project(tmp_path)
    del project
    with _build_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        result = adapter.build(
            capability=_capability(adapter, policy),
            policy=policy,
            snapshot=snapshot,
            private_directory=private,
            session_identity_sha256=SESSION_SHA256,
            build_kind="baseline",
            candidate_round=0,
            started_at=NOW,
        )
        assert result.artifact.status == "verified"
        assert result.artifact.final_image_digest.startswith("sha256:")
        assert result.artifact.treatment_manifest_sha256 == (
            snapshot.artifact.mutable_manifest_sha256
        )
        assert result.artifact.content_sha256 == contract_content_sha256(
            result.artifact,
            exclude={"content_sha256"},
        )
        build = next(
            command for command in _commands(sandbox) if command[:2] == ["buildx", "build"]
        )
        assert build[-1] == "-"
        assert build[build.index("--network") + 1] == "none"
        assert build[build.index("--pull=false")] == "--pull=false"
        forbidden = {"--secret", "--ssh", "--privileged", "--cache-from", "--cache-to"}
        assert forbidden.isdisjoint(build)
        assert adapter.cleanup_build(result, session_identity_sha256=SESSION_SHA256) == "removed"
        assert adapter.cleanup_build(result, session_identity_sha256=SESSION_SHA256) == "missing"


@pytest.mark.parametrize(
    "dockerfile",
    (
        "# syntax=docker/dockerfile:1\n" + f"FROM registry.example/base@{BASE_DIGEST}\n",
        "FROM registry.example/base:latest\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nADD https://example.invalid/a /a\n",
        f'FROM registry.example/base@{BASE_DIGEST}\nADD ["https://x/a", "/a"]\n',
        f"FROM registry.example/base@{BASE_DIGEST}\nRUN --mount=type=secret echo x\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nRUN --network=host echo x\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nRUN --device=/dev/kvm echo x\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nCOPY --from=other/image /a /a\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nONBUILD ADD https://x/a /a\n",
        f"FROM --network=host registry.example/base@{BASE_DIGEST}\n",
        f"FROM --platform=$TARGETPLATFORM registry.example/base@{BASE_DIGEST}\n",
        "FROM scratch\n",
        f"FROM registry.example/base@{BASE_DIGEST} AS bad/name\n",
        (
            f"FROM registry.example/base@{BASE_DIGEST} AS repeated\n"
            "FROM scratch AS repeated\n"
        ),
        f"FROM registry.example/base@{BASE_DIGEST}\nRUN --mount=type=bind,from=external echo x\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nONBUILD ONBUILD RUN echo x\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nADD [\"only-source\"]\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nADD {{\"source\":\"x\"}}\n",
        f"FROM \"registry.example/base@{BASE_DIGEST}\n",
        f"FROM registry.example/base@{BASE_DIGEST} \\\n",
        f"FROM registry.example/base@{BASE_DIGEST}\nMALFORMED\n",
    ),
)
def test_build_rejects_unpinned_or_exfiltrating_dockerfile(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    _, private, policy, snapshot = _project(tmp_path, dockerfile=dockerfile)
    with _build_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        with pytest.raises(PerfLensError) as captured:
            adapter.build(
                capability=_capability(adapter, policy),
                policy=policy,
                snapshot=snapshot,
                private_directory=private,
                session_identity_sha256=SESSION_SHA256,
                build_kind="baseline",
                candidate_round=0,
            )
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION
        assert not any(command[:2] == ["buildx", "build"] for command in _commands(sandbox))


def test_multistage_dockerfile_allows_only_captured_local_sources(tmp_path: Path) -> None:
    dockerfile = f"""
# an ordinary comment is inert
FROM --platform=linux/amd64 registry.example/base@{BASE_DIGEST} AS build
ADD ["src/app", "/work/app"]
RUN --mount=type=bind,from=build echo local
FROM scratch AS final
COPY --from=build /work/app /app
"""
    _, private, policy, snapshot = _project(tmp_path, dockerfile=dockerfile)
    with _build_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        result = adapter.build(
            capability=_capability(adapter, policy),
            policy=policy,
            snapshot=snapshot,
            private_directory=private,
            session_identity_sha256=SESSION_SHA256,
            build_kind="baseline",
            candidate_round=0,
        )
    assert result.artifact.status == "verified"


def test_pinned_pull_uses_only_administrator_reference_then_builds_offline(
    tmp_path: Path,
) -> None:
    administrator = _admin_policy(tmp_path, tier="pinned_pull", driver="docker")
    _, private, policy, snapshot = _project(
        tmp_path,
        network_tier="pinned_pull",
        builder_policy_id="test-builder",
    )
    with _build_sandbox(base_present=False) as sandbox:
        adapter = _adapter(sandbox, administrator_policy=administrator)
        result = adapter.build(
            capability=_capability(adapter, policy, base_present=False),
            policy=policy,
            snapshot=snapshot,
            private_directory=private,
            session_identity_sha256=SESSION_SHA256,
            build_kind="baseline",
            candidate_round=0,
        )
        commands = _commands(sandbox)
        pull = next(command for command in commands if command[:2] == ["image", "pull"])
        build = next(command for command in commands if command[:2] == ["buildx", "build"])
        assert pull[-1] == f"registry.example/base@{BASE_DIGEST}"
        assert build[build.index("--network") + 1] == "none"
        assert result.artifact.network_policy_sha256 == "1" * 64


def test_administrator_network_builder_is_pinned_and_uses_fixed_network(
    tmp_path: Path,
) -> None:
    administrator = _admin_policy(
        tmp_path,
        tier="admin_builder_network",
        driver="docker-container",
    )
    _, private, policy, snapshot = _project(
        tmp_path,
        network_tier="admin_builder_network",
        builder_policy_id="test-builder",
    )
    with _build_sandbox(base_present=False, driver="docker-container") as sandbox:
        adapter = _adapter(sandbox, administrator_policy=administrator)
        result = adapter.build(
            capability=_capability(adapter, policy, base_present=False),
            policy=policy,
            snapshot=snapshot,
            private_directory=private,
            session_identity_sha256=SESSION_SHA256,
            build_kind="candidate",
            candidate_round=1,
        )
        build = next(
            command for command in _commands(sandbox) if command[:2] == ["buildx", "build"]
        )
        assert build[build.index("--network") + 1] == "default"
        assert not any(command[:2] == ["image", "pull"] for command in _commands(sandbox))
        assert result.artifact.builder_identity_sha256 == _builder_identity(
            driver="docker-container"
        )


def test_builder_and_buildx_replacement_are_rejected_before_build(tmp_path: Path) -> None:
    _, private, policy, snapshot = _project(tmp_path)
    with _build_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        state = json.loads(sandbox.state.read_text(encoding="utf-8"))
        state["generation"] = 2
        sandbox.state.write_text(json.dumps(state), encoding="utf-8")
        with pytest.raises(PerfLensError):
            adapter.build(
                capability=_capability(adapter, policy),
                policy=policy,
                snapshot=snapshot,
                private_directory=private,
                session_identity_sha256=SESSION_SHA256,
                build_kind="baseline",
                candidate_round=0,
            )

    with _build_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        sandbox.buildx.chmod(0o700)
        sandbox.buildx.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        sandbox.buildx.chmod(0o500)
        with pytest.raises(PerfLensError):
            adapter.base_image_present(BASE_DIGEST)


def test_higher_priority_buildx_plugin_insertion_is_rejected() -> None:
    with _build_sandbox() as sandbox:
        higher_priority = sandbox.root / "higher-priority"
        higher_priority.mkdir(mode=0o700)
        adapter = TypedDockerBuildAdapter(
            docker_path=sandbox.docker,
            buildx_path=sandbox.buildx,
            endpoint_path=sandbox.endpoint,
            endpoint_kind="local_rootless",
            config_directory=sandbox.config,
            buildx_plugin_directories=(higher_priority, sandbox.root),
            trusted_tool_owner_uids=_trusted_uids(),
            invoking_uid=os.geteuid(),
        )
        replacement = higher_priority / "docker-buildx"
        replacement.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        replacement.chmod(0o500)
        with pytest.raises(PerfLensError) as captured:
            adapter.base_image_present(BASE_DIGEST)
        assert captured.value.code is ErrorCode.PATH_SAFETY_VIOLATION


def test_cleanup_retains_image_with_different_session_label(tmp_path: Path) -> None:
    _, private, policy, snapshot = _project(tmp_path)
    with _build_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        result = adapter.build(
            capability=_capability(adapter, policy),
            policy=policy,
            snapshot=snapshot,
            private_directory=private,
            session_identity_sha256=SESSION_SHA256,
            build_kind="baseline",
            candidate_round=0,
        )
        state = json.loads(sandbox.state.read_text(encoding="utf-8"))
        state["images"][result.temporary_tag]["Config"]["Labels"][
            "io.perflens.optimization-session-sha256"
        ] = "f" * 64
        sandbox.state.write_text(json.dumps(state), encoding="utf-8")
        assert adapter.cleanup_build(result, session_identity_sha256=SESSION_SHA256) == "retained"


@pytest.mark.parametrize("failure", ("missing_provenance", "wrong_label", "oversize"))
def test_build_rejects_unbound_metadata_labels_and_image_budget(
    tmp_path: Path,
    failure: str,
) -> None:
    _, private, policy, snapshot = _project(tmp_path)
    with _build_sandbox() as sandbox:
        state = json.loads(sandbox.state.read_text(encoding="utf-8"))
        if failure == "oversize":
            state["image_size"] = (10 << 30) + 1
        else:
            state[failure] = True
        sandbox.state.write_text(json.dumps(state), encoding="utf-8")
        adapter = _adapter(sandbox)
        with pytest.raises(PerfLensError):
            adapter.build(
                capability=_capability(adapter, policy),
                policy=policy,
                snapshot=snapshot,
                private_directory=private,
                session_identity_sha256=SESSION_SHA256,
                build_kind="baseline",
                candidate_round=0,
            )


def test_cleanup_retains_session_image_while_a_container_references_it(tmp_path: Path) -> None:
    _, private, policy, snapshot = _project(tmp_path)
    with _build_sandbox() as sandbox:
        adapter = _adapter(sandbox)
        result = adapter.build(
            capability=_capability(adapter, policy),
            policy=policy,
            snapshot=snapshot,
            private_directory=private,
            session_identity_sha256=SESSION_SHA256,
            build_kind="baseline",
            candidate_round=0,
        )
        state = json.loads(sandbox.state.read_text(encoding="utf-8"))
        state["occupied"] = True
        sandbox.state.write_text(json.dumps(state), encoding="utf-8")
        assert adapter.cleanup_build(result, session_identity_sha256=SESSION_SHA256) == "retained"


def test_builder_policy_rejects_unknown_fields_and_registry_escape(tmp_path: Path) -> None:
    policy = _admin_policy(tmp_path, tier="pinned_pull", driver="docker")
    assert policy.base_image_reference.endswith(BASE_DIGEST)
    path = policy.path
    original = path.read_text(encoding="utf-8")
    path.chmod(0o600)
    path.write_text(original + "unexpected = true\n", encoding="utf-8")
    path.chmod(0o400)
    with pytest.raises(PerfLensError):
        load_docker_administrator_builder_policy(path, trusted_owner_uids=_trusted_uids())
    path.chmod(0o600)
    path.write_text(
        original.replace(
            'base_image_reference = "registry.example/base@',
            'base_image_reference = "evil.example/base@',
        ),
        encoding="utf-8",
    )
    path.chmod(0o400)
    with pytest.raises(PerfLensError):
        load_docker_administrator_builder_policy(path, trusted_owner_uids=_trusted_uids())
