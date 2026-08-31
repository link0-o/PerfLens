from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from perflens.domain.errors import PerfLensError
from perflens.runtime_locks import supervisor as supervisor_module
from perflens.runtime_locks.supervisor import (
    RuntimeSupervisorClient,
    RuntimeSupervisorJavaJfrPrintRequest,
    RuntimeSupervisorReceipt,
    RuntimeSupervisorRequest,
    discover_runtime_supervisor_policy,
    parse_runtime_supervisor_json_object,
    runtime_supervisor_directory_identity,
    runtime_supervisor_file_identity,
    runtime_supervisor_receipt_schema,
    runtime_supervisor_request_descriptors,
    runtime_supervisor_request_id,
    runtime_supervisor_request_schema,
    runtime_supervisor_writable_identity,
)

_FIXTURES = Path(__file__).parents[1] / "fixtures/runtime_supervisor"


class _JsonSchemaValidator(Protocol):
    def validate(self, instance: Any) -> None: ...


def _load_fixture(name: str) -> dict[str, Any]:
    value = cast(
        object,
        json.loads((_FIXTURES / name).read_text(encoding="utf-8")),
    )
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def test_python_models_accept_every_shared_valid_request_fixture() -> None:
    fixtures = tuple(
        path for path in sorted(_FIXTURES.glob("valid-*.json")) if "receipt" not in path.name
    )
    assert {path.name for path in fixtures} == {
        "valid-java-print-request.json",
        "valid-java-workload-request.json",
        "valid-native-request.json",
    }
    for path in fixtures:
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["expected_parent_pid"] = os.getpid()
        request = RuntimeSupervisorRequest.model_validate(payload)
        assert request.expected_parent_pid == os.getpid()
        assert len(runtime_supervisor_request_descriptors(request)) in {4, 5}


def test_python_models_reject_shared_invalid_request_and_receipt() -> None:
    request = _load_fixture("invalid-unknown-field.json")
    request["expected_parent_pid"] = os.getpid()
    with pytest.raises(ValueError):
        RuntimeSupervisorRequest.model_validate(request)

    with pytest.raises(ValueError):
        RuntimeSupervisorReceipt.model_validate(
            _load_fixture("invalid-supervisor-receipt-unknown-field.json")
        )

    for name in (
        "invalid-duplicate-field.json",
        "invalid-supervisor-receipt-duplicate-field.json",
    ):
        with pytest.raises(ValueError, match="duplicate JSON field"):
            parse_runtime_supervisor_json_object((_FIXTURES / name).read_bytes())


def test_checked_supervisor_schemas_match_models_and_shared_goldens() -> None:
    schema_root = Path(__file__).parents[2] / "schemas"
    request_schema = json.loads(
        (schema_root / "runtime-supervisor-request.schema.json").read_text(encoding="utf-8")
    )
    receipt_schema = json.loads(
        (schema_root / "runtime-supervisor-receipt.schema.json").read_text(encoding="utf-8")
    )
    assert request_schema == runtime_supervisor_request_schema()
    assert receipt_schema == runtime_supervisor_receipt_schema()
    Draft202012Validator.check_schema(request_schema)
    Draft202012Validator.check_schema(receipt_schema)
    request_validator = cast(_JsonSchemaValidator, Draft202012Validator(request_schema))
    receipt_validator = cast(_JsonSchemaValidator, Draft202012Validator(receipt_schema))
    for name in (
        "valid-native-request.json",
        "valid-java-workload-request.json",
        "valid-java-print-request.json",
    ):
        request_validator.validate(_load_fixture(name))
    receipt_validator.validate(_load_fixture("valid-supervisor-receipt.json"))
    with pytest.raises(JsonSchemaValidationError):
        request_validator.validate(_load_fixture("invalid-unknown-field.json"))
    with pytest.raises(JsonSchemaValidationError):
        receipt_validator.validate(_load_fixture("invalid-supervisor-receipt-unknown-field.json"))


def test_supervisor_request_schema_requires_wire_defaults_and_semantic_pairing() -> None:
    validator = cast(
        _JsonSchemaValidator,
        Draft202012Validator(runtime_supervisor_request_schema()),
    )
    payload = _load_fixture("valid-native-request.json")
    for required in ("schema_version", "protocol_version"):
        invalid = dict(payload)
        invalid.pop(required)
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid)

    native_value = cast(object, payload["request"])
    assert isinstance(native_value, dict)
    native = cast(dict[str, Any], native_value.copy())
    native.pop("adapter")
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**payload, "request": native})

    thresholded: dict[str, Any] = {
        **payload,
        "request": {
            **cast(dict[str, Any], native_value),
            "semantics": "thresholded",
            "threshold_ns": None,
        },
    }
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(thresholded)

    java_print = _load_fixture("invalid-java-print-arguments.json")
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(java_print)
    java_print["expected_parent_pid"] = os.getpid()
    with pytest.raises(ValueError, match="does not accept"):
        RuntimeSupervisorRequest.model_validate(java_print)


def test_python_model_accepts_shared_receipt_and_rejects_zero_start_ticks() -> None:
    payload = _load_fixture("valid-supervisor-receipt.json")
    receipt = RuntimeSupervisorReceipt.model_validate(payload)
    assert receipt.workload_start_ticks == 987654

    payload["workload_start_ticks"] = 0
    with pytest.raises(ValueError):
        RuntimeSupervisorReceipt.model_validate(payload)


@contextmanager
def _java_print_request(
    tmp_path: Path,
    client: RuntimeSupervisorClient,
    *,
    executable: Path = Path("/bin/true"),
) -> Generator[RuntimeSupervisorRequest]:
    recording = tmp_path / f"java-jfr-{runtime_supervisor_request_id()}.jfr"
    output = tmp_path / f"output-{runtime_supervisor_request_id()}.json"
    recording.write_bytes(b"FLR\x00bounded")
    output.write_bytes(b"")
    recording.chmod(0o600)
    output.chmod(0o600)
    executable_fd = directory_fd = recording_directory_fd = recording_fd = output_fd = -1
    try:
        executable_fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC)
        directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        recording_directory_fd = os.open(
            tmp_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )
        recording_fd = os.open(recording, os.O_RDONLY | os.O_CLOEXEC)
        output_fd = os.open(output, os.O_RDWR | os.O_CLOEXEC)
        yield RuntimeSupervisorRequest(
            request_id=runtime_supervisor_request_id(),
            expected_parent_pid=os.getpid(),
            expected_supervisor_sha256=client.policy.sha256,
            executable=runtime_supervisor_file_identity(executable_fd),
            working_directory=runtime_supervisor_directory_identity(directory_fd),
            arguments=(),
            timeout_milliseconds=1_000,
            request=RuntimeSupervisorJavaJfrPrintRequest(
                recording_directory=runtime_supervisor_directory_identity(recording_directory_fd),
                recording_name=recording.name,
                recording=runtime_supervisor_file_identity(recording_fd),
                output=runtime_supervisor_writable_identity(
                    output_fd,
                    maximum_size=1 << 20,
                ),
            ),
        )
    finally:
        for descriptor in (
            executable_fd,
            directory_fd,
            recording_directory_fd,
            recording_fd,
            output_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)


def test_client_executes_pinned_supervisor_in_a_new_session(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[bool] = []
    real_popen = subprocess.Popen

    def recording_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        observed.append(kwargs.get("start_new_session") is True)
        return real_popen(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(supervisor_module.subprocess, "Popen", recording_popen)
    with _java_print_request(tmp_path, runtime_supervisor_client) as request:
        receipt = runtime_supervisor_client.execute(request)

    assert observed == [True]
    assert receipt.request_id == request.request_id
    assert receipt.cleanup_complete is True
    assert receipt.workload_start_ticks > 0


def test_client_does_not_leak_unlisted_parent_descriptor(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler is unavailable")
    source = tmp_path / "fd-check.c"
    executable = tmp_path / "fd-check"
    source.write_text(
        "#include <fcntl.h>\nint main(void) { return fcntl(500, F_GETFD) < 0 ? 0 : 50; }\n",
        encoding="utf-8",
    )
    subprocess.run(  # noqa: S603 - fixed compiler argv for a private test helper
        (compiler, "-O2", "-o", str(executable), str(source)),
        check=True,
        capture_output=True,
    )
    executable.chmod(0o755)
    source_fd = os.open("/dev/null", os.O_RDONLY)
    os.dup2(source_fd, 500, inheritable=True)
    os.close(source_fd)
    try:
        with _java_print_request(
            tmp_path,
            runtime_supervisor_client,
            executable=executable,
        ) as request:
            receipt = runtime_supervisor_client.execute(request)
    finally:
        os.close(500)

    assert receipt.exit_code == 0


def test_client_rejects_supervisor_replacement_before_spawn(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
) -> None:
    copied = tmp_path / "supervisor"
    shutil.copyfile(runtime_supervisor_client.policy.path, copied)
    copied.chmod(0o755)
    discovery = discover_runtime_supervisor_policy(copied, expected_owner_uid=os.geteuid())
    assert discovery.policy is not None
    client = RuntimeSupervisorClient(discovery.policy)
    copied.unlink()
    shutil.copyfile("/bin/true", copied)
    copied.chmod(0o755)

    with (
        _java_print_request(tmp_path, client) as request,
        pytest.raises(PerfLensError, match="identity changed"),
    ):
        client.execute(request)


def test_discovery_rejects_supervisor_file_capabilities(
    tmp_path: Path,
    runtime_supervisor_client: RuntimeSupervisorClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied = tmp_path / "capable-supervisor"
    shutil.copyfile(runtime_supervisor_client.policy.path, copied)
    copied.chmod(0o755)

    def file_capability(*_args: object) -> bytes:
        return b""

    monkeypatch.setattr(supervisor_module.os, "getxattr", file_capability)
    discovery = discover_runtime_supervisor_policy(copied, expected_owner_uid=os.geteuid())

    assert discovery.availability == "unavailable"
    assert discovery.policy is None
    assert any("file capabilities" in item for item in discovery.limitations)


def test_client_reports_missing_receipt_without_signalling_child(tmp_path: Path) -> None:
    fake = tmp_path / "silent-supervisor"
    shutil.copyfile("/bin/true", fake)
    fake.chmod(0o755)
    discovery = discover_runtime_supervisor_policy(fake, expected_owner_uid=os.geteuid())
    assert discovery.policy is not None
    client = RuntimeSupervisorClient(discovery.policy)

    with (
        _java_print_request(tmp_path, client) as request,
        pytest.raises(PerfLensError, match="without a complete receipt"),
    ):
        client.execute(request)


def test_client_rejects_malformed_receipt(tmp_path: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler is unavailable")
    source = tmp_path / "bad-supervisor.c"
    fake = tmp_path / "bad-supervisor"
    source.write_text(
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <unistd.h>\n"
        "int main(int argc, char **argv) {\n"
        "  int fd = -1;\n"
        "  for (int i = 1; i + 1 < argc; ++i)\n"
        '    if (strcmp(argv[i], "--receipt-fd") == 0) fd = atoi(argv[i + 1]);\n'
        "  unsigned char frame[5] = {0, 0, 0, 1, '{'};\n"
        "  return fd >= 0 && write(fd, frame, 5) == 5 ? 0 : 2;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(  # noqa: S603 - fixed compiler argv for a private test helper
        (compiler, "-O2", "-o", str(fake), str(source)),
        check=True,
        capture_output=True,
    )
    fake.chmod(0o755)
    discovery = discover_runtime_supervisor_policy(fake, expected_owner_uid=os.geteuid())
    assert discovery.policy is not None
    client = RuntimeSupervisorClient(discovery.policy)

    with (
        _java_print_request(tmp_path, client) as request,
        pytest.raises(PerfLensError, match="malformed receipt"),
    ):
        client.execute(request)


@pytest.mark.parametrize(
    ("initial_payload", "mode", "flags"),
    (
        (b"already present", 0o600, os.O_RDWR),
        (b"", 0o644, os.O_RDWR),
        (b"", 0o600, os.O_WRONLY | os.O_APPEND),
    ),
)
def test_writable_identity_rejects_unsafe_descriptor_state(
    tmp_path: Path,
    initial_payload: bytes,
    mode: int,
    flags: int,
) -> None:
    path = tmp_path / f"unsafe-{runtime_supervisor_request_id()}"
    path.write_bytes(initial_payload)
    path.chmod(mode)
    descriptor = os.open(path, flags)
    try:
        with pytest.raises(PerfLensError, match="regular, empty, writable, non-append"):
            runtime_supervisor_writable_identity(descriptor, maximum_size=1 << 20)
    finally:
        os.close(descriptor)


def test_writable_identity_requires_regular_file(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir(mode=0o600)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert stat.S_ISDIR(os.fstat(descriptor).st_mode)
        with pytest.raises(PerfLensError, match="regular, empty, writable, non-append"):
            runtime_supervisor_writable_identity(descriptor, maximum_size=1 << 20)
    finally:
        os.close(descriptor)
