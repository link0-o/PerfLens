# pyright: reportPrivateUsage=false
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel
from tests.unit.test_docker_optimization_runtime import _authorize, make_optimization_runtime

from perflens.artifacts.filesystem import serialize_json
from perflens.contracts.artifacts import ArtifactReference
from perflens.domain.errors import PerfLensError
from perflens.mcp.storage import ArtifactStore, PathPolicy

_BASE_TYPES = (
    "docker-build-capability",
    "docker-build-recipe",
    "docker-build-context",
    "docker-optimization-preview",
    "docker-optimization-session",
    "docker-build",
)
_LINKED_TYPES = ("docker-optimization-iteration", "docker-optimization-disposition")


@pytest.fixture
def docker_models(tmp_path: Path) -> dict[str, tuple[BaseModel, str]]:
    runtime, _, _ = make_optimization_runtime(tmp_path)
    preview, session = _authorize(runtime)
    build = runtime.build(session.session_id, build_kind="baseline", candidate_round=0).build
    return {
        "docker-build-capability": (preview.capability, preview.capability.capability_id),
        "docker-build-recipe": (preview.recipe, preview.recipe.recipe_id),
        "docker-build-context": (preview.context, preview.context.context_id),
        "docker-optimization-preview": (preview.preview, preview.preview.preview_id),
        "docker-optimization-session": (session, session.session_artifact_id),
        "docker-build": (build, build.build_id),
    }


@pytest.mark.parametrize("artifact_type", _BASE_TYPES)
@pytest.mark.parametrize("corruption", (None, "digest", "id"))
def test_docker_paging_checks_identity_and_digest(
    tmp_path: Path,
    docker_models: dict[str, tuple[BaseModel, str]],
    artifact_type: str,
    corruption: str | None,
) -> None:
    model, artifact_id = docker_models[artifact_type]
    store = ArtifactStore(tmp_path / "artifacts", PathPolicy((tmp_path,)), allow_writes=True)
    if corruption == "digest":
        model = model.model_copy(update={"perflens_version": "99.0.0"})
    elif corruption == "id":
        artifact_id = "swapped-id"
    store.save(model, artifact_id, artifact_type)
    if corruption is not None:
        with pytest.raises(PerfLensError):
            store.read_page(artifact_id, artifact_type, offset=0, limit=65536)
    else:
        text, next_offset, size = store.read_page(artifact_id, artifact_type, offset=0, limit=65536)
        assert next_offset is None
        assert text.encode() == serialize_json(model)
        assert size == len(text.encode())


@pytest.mark.parametrize("artifact_type", (*_BASE_TYPES, *_LINKED_TYPES))
def test_docker_paging_rejects_wrong_schema(tmp_path: Path, artifact_type: str) -> None:
    store = ArtifactStore(tmp_path / "artifacts", PathPolicy((tmp_path,)), allow_writes=True)
    model = ArtifactReference(
        artifact_id="wrong", artifact_type="wrong", uri="perflens://wrong", summary={}
    )
    store.save(model, "known-id", artifact_type)
    with pytest.raises(PerfLensError, match="invalid"):
        store.read_page("known-id", artifact_type, offset=0, limit=65536)


@pytest.mark.parametrize("artifact_type", _BASE_TYPES)
def test_docker_paging_returns_only_the_validated_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    docker_models: dict[str, tuple[BaseModel, str]],
    artifact_type: str,
) -> None:
    model, artifact_id = docker_models[artifact_type]
    store = ArtifactStore(tmp_path / "artifacts", PathPolicy((tmp_path,)), allow_writes=True)
    path = store.save(model, artifact_id, artifact_type)
    original_read = store._read_file
    reads: list[Path] = []

    def replace_after_read(source: Path, *, maximum: int) -> bytes:
        data = original_read(source, maximum=maximum)
        reads.append(source)
        path.write_bytes(b'{"unverified_replacement":true}\n')
        return data

    monkeypatch.setattr(store, "_read_file", replace_after_read)
    text, _, _ = store.read_page(artifact_id, artifact_type, offset=0, limit=65536)
    assert text.encode() == serialize_json(model)
    assert reads == [path]
