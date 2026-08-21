//! Strict protocol boundary for the optional `PerfLens` privileged Helper.

mod execution;

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use serde::{Deserialize, Serialize};

use crate::execution::{
    ExecutionError, ExecutionPlan, execute_production_plan_with_ready,
    prepare_production_environment,
};

pub const HELPER_SCHEMA_VERSION: &str = "1.3";
pub const MAX_HELPER_MESSAGE_BYTES: usize = 64 << 10;
pub const MAX_HELPER_PLAN_TTL_MILLISECONDS: u64 = 120_000;
pub const MAX_HELPER_DURATION_MILLISECONDS: u64 = 86_400_000;
pub const MAX_HELPER_OUTPUT_BYTES: u64 = 1 << 40;
pub const MAX_HELPER_FREQUENCY_HZ: u32 = 10_000;
pub const MAX_HELPER_EVENTS: usize = 64;
pub const MAX_HELPER_RESPONSE_BYTES: usize = 64 << 10;
pub const PRIVATE_HELPER_SOCKET: &str = "/run/perflens-helper/helper.sock";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperTarget {
    pub target_runtime: TargetRuntime,
    pub pid: u32,
    pub uid: u32,
    pub start_time_ticks: u64,
    pub container: Option<Box<ContainerTargetBinding>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRuntime {
    Host,
    Docker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerTargetKind {
    ExistingContainer,
    ManagedTemporaryContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerUidMapping {
    RootlessSameUid,
    RootfulSameUid,
    RootfulCrossUid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DockerAdapterRecipe {
    LocalDockerReadV1,
    LocalDockerManagedV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerNamespaceBinding {
    pub pid_namespace_inode: u64,
    pub user_namespace_inode: u64,
    pub mount_namespace_inode: u64,
    pub cgroup_namespace_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerCgroupBinding {
    pub version: String,
    pub inode: u64,
    pub identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerTargetBinding {
    pub target_id: String,
    pub target_kind: DockerTargetKind,
    pub target_content_sha256: String,
    pub container_identity_sha256: String,
    pub image_identity_sha256: String,
    pub identity_fingerprint: String,
    pub container_pid: u32,
    pub host_pid: u32,
    pub host_uid: u32,
    pub host_start_time_ticks: u64,
    pub executable_name: String,
    pub namespace: ContainerNamespaceBinding,
    pub cgroup: ContainerCgroupBinding,
    pub uid_mapping: DockerUidMapping,
    pub rootful_risk_authorized: bool,
    pub adapter_recipe_id: DockerAdapterRecipe,
    pub adapter_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMode {
    Record,
    Stat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallGraph {
    Dwarf,
    Fp,
    Lbr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedEventSource {
    Auto,
    HardwareRequired,
    SoftwareOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActualEventSource {
    Hardware,
    Software,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordEvent {
    Cycles,
    CpuClock,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperRequest {
    Health {
        schema_version: String,
        request_id: String,
    },
    CollectPid {
        schema_version: String,
        request_id: String,
        plan_id: String,
        caller_uid: u32,
        target: HelperTarget,
        mode: CollectionMode,
        duration_milliseconds: u64,
        frequency_hz: Option<u32>,
        call_graph: Option<CallGraph>,
        events: Vec<String>,
        requested_event_source: RequestedEventSource,
        fallback_allowed: bool,
        fallback_events: Vec<String>,
        record_event: Option<RecordEvent>,
        fallback_record_event: Option<RecordEvent>,
        max_output_bytes: u64,
        expires_at_unix_milliseconds: u64,
        report_ready: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HelperResult {
    Health {
        helper_version: &'static str,
        helper_pid: u32,
        helper_uid: u32,
        privilege_mode: &'static str,
        ready: bool,
    },
    CollectionReady {
        plan_id: String,
        target_pid: u32,
    },
    Collection {
        plan_id: String,
        mode: CollectionMode,
        target_pid: u32,
        artifact_name: String,
        output_bytes: u64,
        output_sha256: String,
        output_format: &'static str,
        actual_event_source: ActualEventSource,
        fallback_used: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        fallback_reason: Option<&'static str>,
        events: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        record_event: Option<RecordEvent>,
        started_at_unix_milliseconds: u64,
        finished_at_unix_milliseconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelperErrorBody {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: &'static str,
    pub recoverable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelperResponse {
    pub schema_version: &'static str,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<HelperResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<HelperErrorBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperServerPolicy {
    pub broker_uid: u32,
    pub allowed_uid: u32,
    pub artifact_gid: u32,
    pub perf_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolErrorKind {
    Frame,
    Json,
    Schema,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    kind: ProtocolErrorKind,
    message: &'static str,
}

impl ProtocolError {
    #[must_use]
    pub const fn kind(&self) -> ProtocolErrorKind {
        self.kind
    }

    const fn new(kind: ProtocolErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for ProtocolError {}

/// Serve the fixed private Helper socket until the process receives a termination signal.
///
/// # Errors
///
/// Returns an I/O error when the socket boundary is unsafe or cannot accept connections.
pub fn serve_private_socket(socket_path: &Path, policy: &HelperServerPolicy) -> io::Result<()> {
    prepare_production_environment(&policy.perf_path, policy.artifact_gid).map_err(|_error| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privileged Helper production environment is unsafe",
        )
    })?;
    let listener = bind_private_socket(socket_path)?;
    serve_listener(&listener, policy, None)
}

fn serve_listener(
    listener: &UnixListener,
    policy: &HelperServerPolicy,
    connection_limit: Option<usize>,
) -> io::Result<()> {
    let mut handled = 0_usize;
    for accepted in listener.incoming() {
        let mut connection = accepted?;
        if connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .and_then(|()| connection.set_write_timeout(Some(Duration::from_secs(5))))
            .is_err()
        {
            continue;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis()
            .try_into()
            .map_err(io::Error::other)?;
        let _connection_result = handle_connection(&mut connection, policy, now);
        handled += 1;
        if connection_limit.is_some_and(|limit| handled >= limit) {
            break;
        }
    }
    Ok(())
}

fn bind_private_socket(socket_path: &Path) -> io::Result<UnixListener> {
    if !socket_path.is_absolute() {
        return Err(unsafe_socket_error());
    }
    let parent = socket_path.parent().ok_or_else(unsafe_socket_error)?;
    let parent_metadata = parent.symlink_metadata()?;
    let effective_uid = geteuid().as_raw();
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != effective_uid
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(unsafe_socket_error());
    }
    match socket_path.symlink_metadata() {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.uid() != effective_uid {
                return Err(unsafe_socket_error());
            }
            std::fs::remove_file(socket_path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    let metadata = socket_path.symlink_metadata()?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != 0o660
    {
        return Err(unsafe_socket_error());
    }
    Ok(listener)
}

fn unsafe_socket_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private Helper socket boundary is unsafe",
    )
}

/// Authenticate and handle one already-accepted private Helper connection.
///
/// # Errors
///
/// Returns an I/O error when peer credential lookup, bounded reading, or response writing fails.
#[allow(clippy::too_many_lines)] // Keep authentication and streamed response order explicit.
pub fn handle_connection(
    connection: &mut UnixStream,
    policy: &HelperServerPolicy,
    now_unix_milliseconds: u64,
) -> io::Result<()> {
    let credentials = getsockopt(&*connection, PeerCredentials).map_err(io::Error::other)?;
    if credentials.uid() != policy.broker_uid {
        return write_response(
            connection,
            &rejected_response(
                "unknown",
                "PATH_SAFETY_VIOLATION",
                "authorization",
                "Privileged Helper rejected an unauthorized peer",
            ),
        );
    }

    let frame = read_bounded_frame(connection)?;
    match parse_request_frame(&frame, now_unix_milliseconds) {
        Ok(HelperRequest::Health { request_id, .. }) => write_response(
            connection,
            &HelperResponse {
                schema_version: HELPER_SCHEMA_VERSION,
                request_id,
                ok: true,
                result: Some(HelperResult::Health {
                    helper_version: env!("CARGO_PKG_VERSION"),
                    helper_pid: std::process::id(),
                    helper_uid: geteuid().as_raw(),
                    privilege_mode: "paranoid3_helper",
                    ready: true,
                }),
                error: None,
            },
        ),
        Ok(HelperRequest::CollectPid {
            request_id,
            caller_uid,
            target,
            ..
        }) if caller_uid != policy.allowed_uid || target.uid != policy.allowed_uid => {
            write_response(
                connection,
                &rejected_response(
                    &request_id,
                    "PATH_SAFETY_VIOLATION",
                    "authorization",
                    "Privileged Helper policy rejected the caller or target UID",
                ),
            )
        }
        Ok(HelperRequest::CollectPid {
            request_id,
            plan_id,
            caller_uid,
            target,
            mode,
            duration_milliseconds,
            frequency_hz,
            call_graph,
            events,
            requested_event_source,
            fallback_allowed,
            fallback_events,
            record_event,
            fallback_record_event,
            max_output_bytes,
            report_ready,
            ..
        }) => {
            let target_pid = target.pid;
            let mut notify_ready = || {
                if !report_ready {
                    return Ok(());
                }
                write_response(
                    connection,
                    &HelperResponse {
                        schema_version: HELPER_SCHEMA_VERSION,
                        request_id: request_id.clone(),
                        ok: true,
                        result: Some(HelperResult::CollectionReady {
                            plan_id: plan_id.clone(),
                            target_pid,
                        }),
                        error: None,
                    },
                )
                .map_err(|_error| ExecutionError {
                    code: "INTERNAL_ERROR",
                    stage: "privileged_helper",
                    message: "Privileged Helper could not report collection readiness",
                })
            };
            let outcome = execute_production_plan_with_ready(
                &ExecutionPlan {
                    plan_id: plan_id.clone(),
                    caller_uid,
                    target,
                    mode,
                    duration_milliseconds,
                    frequency_hz,
                    call_graph,
                    events,
                    requested_event_source,
                    fallback_allowed,
                    fallback_events,
                    record_event,
                    fallback_record_event,
                    max_output_bytes,
                },
                policy.allowed_uid,
                policy.artifact_gid,
                &policy.perf_path,
                &mut notify_ready,
            );
            write_response(
                connection,
                &collection_response(request_id, plan_id, mode, target_pid, outcome),
            )
        }
        Err(error) => write_response(
            connection,
            &rejected_response(
                "unknown",
                "INVALID_INPUT",
                "privileged_helper_protocol",
                error.message,
            ),
        ),
    }
}

fn collection_response(
    request_id: String,
    plan_id: String,
    mode: CollectionMode,
    target_pid: u32,
    outcome: Result<execution::ExecutionResult, execution::ExecutionError>,
) -> HelperResponse {
    match outcome {
        Ok(result) => HelperResponse {
            schema_version: HELPER_SCHEMA_VERSION,
            request_id,
            ok: true,
            result: Some(HelperResult::Collection {
                plan_id,
                mode,
                target_pid,
                artifact_name: result.artifact_name,
                output_bytes: result.output_bytes,
                output_sha256: result.output_sha256,
                output_format: result.output_format,
                actual_event_source: result.actual_event_source,
                fallback_used: result.fallback_used,
                fallback_reason: result.fallback_reason,
                events: result.events,
                record_event: result.record_event,
                started_at_unix_milliseconds: result.started_at_unix_milliseconds,
                finished_at_unix_milliseconds: result.finished_at_unix_milliseconds,
            }),
            error: None,
        },
        Err(error) => rejected_response(&request_id, error.code, error.stage, error.message),
    }
}

fn read_bounded_frame(connection: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(4096);
    let mut byte = [0_u8; 1];
    while frame.len() <= MAX_HELPER_MESSAGE_BYTES {
        let count = connection.read(&mut byte)?;
        if count == 0 {
            break;
        }
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if frame.len() > MAX_HELPER_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private Helper frame exceeds its bound",
        ));
    }
    Ok(frame)
}

fn write_response(connection: &mut UnixStream, response: &HelperResponse) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(response).map_err(io::Error::other)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_HELPER_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private Helper response exceeds its bound",
        ));
    }
    connection.write_all(&encoded)
}

fn rejected_response(
    request_id: &str,
    code: &'static str,
    stage: &'static str,
    message: &'static str,
) -> HelperResponse {
    HelperResponse {
        schema_version: HELPER_SCHEMA_VERSION,
        request_id: request_id.to_owned(),
        ok: false,
        result: None,
        error: Some(HelperErrorBody {
            code,
            stage,
            message,
            recoverable: true,
        }),
    }
}

/// Parse and validate exactly one newline-delimited request frame.
///
/// # Errors
///
/// Returns a bounded classification when framing, JSON, structural, or TTL checks fail.
pub fn parse_request_frame(
    frame: &[u8],
    now_unix_milliseconds: u64,
) -> Result<HelperRequest, ProtocolError> {
    if frame.len() > MAX_HELPER_MESSAGE_BYTES {
        return Err(ProtocolError::new(
            ProtocolErrorKind::Frame,
            "privileged Helper request exceeds the protocol limit",
        ));
    }
    let Some(payload) = frame.strip_suffix(b"\n") else {
        return Err(ProtocolError::new(
            ProtocolErrorKind::Frame,
            "privileged Helper request requires a newline terminator",
        ));
    };
    if payload.contains(&b'\n') {
        return Err(ProtocolError::new(
            ProtocolErrorKind::Frame,
            "privileged Helper request contains multiple frames",
        ));
    }
    let request: HelperRequest = serde_json::from_slice(payload).map_err(|_error| {
        ProtocolError::new(
            ProtocolErrorKind::Json,
            "privileged Helper request is not strict valid JSON",
        )
    })?;
    validate_request(&request, now_unix_milliseconds)?;
    Ok(request)
}

fn validate_request(
    request: &HelperRequest,
    now_unix_milliseconds: u64,
) -> Result<(), ProtocolError> {
    match request {
        HelperRequest::Health {
            schema_version,
            request_id,
        } => {
            validate_common(schema_version, request_id)?;
        }
        HelperRequest::CollectPid {
            schema_version,
            request_id,
            plan_id,
            caller_uid,
            target,
            mode,
            duration_milliseconds,
            frequency_hz,
            call_graph,
            events,
            requested_event_source,
            fallback_allowed,
            fallback_events,
            record_event,
            fallback_record_event,
            max_output_bytes,
            expires_at_unix_milliseconds,
            report_ready: _,
        } => {
            validate_common(schema_version, request_id)?;
            if !valid_identifier(plan_id, "plan-", 20, 20)
                || target.pid == 0
                || target.pid > i32::MAX.cast_unsigned()
                || target.start_time_ticks == 0
                || *duration_milliseconds == 0
                || *duration_milliseconds > MAX_HELPER_DURATION_MILLISECONDS
                || *max_output_bytes == 0
                || *max_output_bytes > MAX_HELPER_OUTPUT_BYTES
            {
                return Err(schema_error());
            }
            validate_target(target, *caller_uid)?;
            validate_mode_fields(ModeFields {
                mode: *mode,
                frequency_hz: *frequency_hz,
                call_graph: *call_graph,
                events,
                requested_event_source: *requested_event_source,
                fallback_allowed: *fallback_allowed,
                fallback_events,
                record_event: *record_event,
                fallback_record_event: *fallback_record_event,
            })?;
            let remaining = expires_at_unix_milliseconds
                .checked_sub(now_unix_milliseconds)
                .ok_or_else(expired_error)?;
            if remaining == 0 || remaining > MAX_HELPER_PLAN_TTL_MILLISECONDS {
                return Err(expired_error());
            }
        }
    }
    Ok(())
}

fn validate_target(target: &HelperTarget, caller_uid: u32) -> Result<(), ProtocolError> {
    match (&target.target_runtime, &target.container) {
        (TargetRuntime::Host, None) if caller_uid == target.uid => Ok(()),
        (TargetRuntime::Docker, Some(container)) => {
            let recipe_matches = matches!(
                (container.target_kind, container.adapter_recipe_id),
                (
                    DockerTargetKind::ExistingContainer,
                    DockerAdapterRecipe::LocalDockerReadV1
                ) | (
                    DockerTargetKind::ManagedTemporaryContainer,
                    DockerAdapterRecipe::LocalDockerManagedV1
                )
            );
            let risk_matches = match container.uid_mapping {
                DockerUidMapping::RootfulCrossUid => {
                    container.rootful_risk_authorized && target.uid == 0 && caller_uid != target.uid
                }
                DockerUidMapping::RootlessSameUid | DockerUidMapping::RootfulSameUid => {
                    !container.rootful_risk_authorized && caller_uid == target.uid
                }
            };
            let hashes = [
                &container.target_content_sha256,
                &container.container_identity_sha256,
                &container.image_identity_sha256,
                &container.identity_fingerprint,
                &container.cgroup.identity_sha256,
                &container.adapter_sha256,
            ];
            if container.host_pid != target.pid
                || container.host_uid != target.uid
                || container.host_start_time_ticks != target.start_time_ticks
                || container.container_pid == 0
                || !valid_identifier(&container.target_id, "container-target-", 20, 20)
                || hashes.into_iter().any(|value| !valid_sha256(value))
                || container.cgroup.version != "v2"
                || container.cgroup.inode == 0
                || container.namespace.pid_namespace_inode == 0
                || container.namespace.user_namespace_inode == 0
                || container.namespace.mount_namespace_inode == 0
                || container.namespace.cgroup_namespace_inode == 0
                || container.executable_name.is_empty()
                || container.executable_name.len() > 255
                || container
                    .executable_name
                    .bytes()
                    .any(|byte| byte == b'/' || byte < 0x20 || byte == 0x7f)
                || !recipe_matches
                || !risk_matches
            {
                return Err(schema_error());
            }
            Ok(())
        }
        _ => Err(schema_error()),
    }
}

fn validate_common(schema_version: &str, request_id: &str) -> Result<(), ProtocolError> {
    if schema_version != HELPER_SCHEMA_VERSION || !valid_identifier(request_id, "request-", 16, 64)
    {
        return Err(schema_error());
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ModeFields<'a> {
    mode: CollectionMode,
    frequency_hz: Option<u32>,
    call_graph: Option<CallGraph>,
    events: &'a [String],
    requested_event_source: RequestedEventSource,
    fallback_allowed: bool,
    fallback_events: &'a [String],
    record_event: Option<RecordEvent>,
    fallback_record_event: Option<RecordEvent>,
}

fn validate_mode_fields(fields: ModeFields<'_>) -> Result<(), ProtocolError> {
    let ModeFields {
        mode,
        frequency_hz,
        call_graph,
        events,
        requested_event_source,
        fallback_allowed,
        fallback_events,
        record_event,
        fallback_record_event,
    } = fields;
    if events.len() > MAX_HELPER_EVENTS
        || fallback_events.len() > MAX_HELPER_EVENTS
        || events
            .iter()
            .chain(fallback_events)
            .any(|event| event.is_empty() || event.len() > 128 || event.contains('\0'))
        || events.iter().collect::<HashSet<_>>().len() != events.len()
        || fallback_events.iter().collect::<HashSet<_>>().len() != fallback_events.len()
        || (fallback_allowed && requested_event_source != RequestedEventSource::Auto)
    {
        return Err(schema_error());
    }
    match mode {
        CollectionMode::Stat
            if !events.is_empty()
                && frequency_hz.is_none()
                && call_graph.is_none()
                && record_event.is_none()
                && fallback_record_event.is_none()
                && ((!fallback_allowed && fallback_events.is_empty())
                    || (fallback_allowed
                        && fallback_events
                            == [
                                "task-clock",
                                "context-switches",
                                "cpu-migrations",
                                "page-faults",
                            ])) => {}
        CollectionMode::Record
            if events.is_empty()
                && fallback_events.is_empty()
                && frequency_hz
                    .is_some_and(|value| (1..=MAX_HELPER_FREQUENCY_HZ).contains(&value))
                && call_graph.is_some()
                && record_event.is_some()
                && ((!fallback_allowed && fallback_record_event.is_none())
                    || (fallback_allowed
                        && fallback_record_event == Some(RecordEvent::CpuClock))) => {}
        CollectionMode::Record | CollectionMode::Stat => return Err(schema_error()),
    }
    let hardware_events = [
        "cycles",
        "instructions",
        "cache-references",
        "cache-misses",
        "branches",
        "branch-misses",
    ];
    let invalid_source = match (requested_event_source, mode) {
        (RequestedEventSource::SoftwareOnly, CollectionMode::Stat) => {
            events
                != [
                    "task-clock",
                    "context-switches",
                    "cpu-migrations",
                    "page-faults",
                ]
        }
        (RequestedEventSource::SoftwareOnly, CollectionMode::Record) => {
            record_event != Some(RecordEvent::CpuClock)
        }
        (_, CollectionMode::Stat) => events
            .iter()
            .any(|event| !hardware_events.contains(&event.as_str())),
        (_, CollectionMode::Record) => record_event != Some(RecordEvent::Cycles),
    };
    if invalid_source {
        return Err(schema_error());
    }
    Ok(())
}

fn valid_identifier(value: &str, prefix: &str, minimum: usize, maximum: usize) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    (minimum..=maximum).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn schema_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorKind::Schema,
        "privileged Helper request violates the typed protocol",
    )
}

const fn expired_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorKind::Expired,
        "privileged Helper plan is expired or exceeds the TTL ceiling",
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use nix::unistd::geteuid;

    use super::{
        HELPER_SCHEMA_VERSION, HelperRequest, HelperResponse, HelperResult, HelperServerPolicy,
        MAX_HELPER_MESSAGE_BYTES, ProtocolErrorKind, bind_private_socket, handle_connection,
        parse_request_frame, serve_listener,
    };

    const NOW_MILLISECONDS: u64 = 4_102_444_700_000;
    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn server_policy(allowed_uid: u32) -> HelperServerPolicy {
        HelperServerPolicy {
            broker_uid: geteuid().as_raw(),
            allowed_uid,
            artifact_gid: nix::unistd::getegid().as_raw(),
            perf_path: "/usr/bin/perf".into(),
        }
    }

    #[test]
    fn accepts_shared_valid_golden_frames() {
        let fixtures = [
            include_bytes!("../../../tests/fixtures/privileged_helper/valid/health.jsonl")
                .as_slice(),
            include_bytes!("../../../tests/fixtures/privileged_helper/valid/stat.jsonl").as_slice(),
            include_bytes!("../../../tests/fixtures/privileged_helper/valid/record.jsonl")
                .as_slice(),
            include_bytes!("../../../tests/fixtures/privileged_helper/valid/docker-stat.jsonl")
                .as_slice(),
        ];
        let parsed = fixtures
            .iter()
            .map(|frame| parse_request_frame(frame, NOW_MILLISECONDS))
            .collect::<Result<Vec<_>, _>>()
            .expect("valid shared fixtures must parse");
        assert!(matches!(parsed[0], HelperRequest::Health { .. }));
        assert!(matches!(parsed[1], HelperRequest::CollectPid { .. }));
        assert!(matches!(parsed[2], HelperRequest::CollectPid { .. }));
        assert!(matches!(parsed[3], HelperRequest::CollectPid { .. }));
    }

    #[test]
    fn collection_ready_response_matches_shared_golden_frame() {
        let expected: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/privileged_helper/responses/collection-ready.jsonl"
        ))
        .expect("parse shared ready response");
        let actual = serde_json::to_value(HelperResponse {
            schema_version: HELPER_SCHEMA_VERSION,
            request_id: "request-fedcba9876543210".to_owned(),
            ok: true,
            result: Some(HelperResult::CollectionReady {
                plan_id: "plan-fedcba9876543210abcd".to_owned(),
                target_pid: 4321,
            }),
            error: None,
        })
        .expect("serialize ready response");
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_shared_invalid_golden_frames() {
        let fixtures = [
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/arbitrary-command.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/arbitrary-fallback-event.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/arbitrary-output-path.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/duplicate-request-id.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/docker-target-mismatch.jsonl"
            )
            .as_slice(),
            include_bytes!("../../../tests/fixtures/privileged_helper/invalid/expired.jsonl")
                .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/record-with-events.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/report-ready-non-boolean.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/stat-with-frequency.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/system-wide-target.jsonl"
            )
            .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/unknown-operation.jsonl"
            )
            .as_slice(),
        ];
        for frame in fixtures {
            assert!(parse_request_frame(frame, NOW_MILLISECONDS).is_err());
        }
    }

    #[test]
    fn rejects_missing_or_multiple_frame_terminators() {
        let frame = br#"{"schema_version":"1.3","operation":"health","request_id":"request-0123456789abcdef"}"#;
        let error = parse_request_frame(frame, NOW_MILLISECONDS).expect_err("newline is required");
        assert_eq!(error.kind(), ProtocolErrorKind::Frame);

        let multiple = b"{}\n{}\n";
        let error =
            parse_request_frame(multiple, NOW_MILLISECONDS).expect_err("one frame is required");
        assert_eq!(error.kind(), ProtocolErrorKind::Frame);
    }

    #[test]
    fn authenticated_health_is_bounded_and_versioned() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let server_thread = thread::spawn(move || {
            handle_connection(
                &mut server,
                &server_policy(geteuid().as_raw()),
                NOW_MILLISECONDS,
            )
        });
        client
            .write_all(include_bytes!(
                "../../../tests/fixtures/privileged_helper/valid/health.jsonl"
            ))
            .expect("write request");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read response");
        server_thread
            .join()
            .expect("server join")
            .expect("server response");
        assert!(response.ends_with('\n'));
        assert!(response.contains("\"schema_version\":\"1.3\""));
        assert!(response.contains("\"privilege_mode\":\"paranoid3_helper\""));
        assert!(!response.contains("profile"));
    }

    #[test]
    fn authenticated_health_works_over_a_real_private_unix_socket() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-helper-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create private directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("set private directory mode");
        let socket_path = directory.join("helper.sock");
        let listener = bind_private_socket(&socket_path).expect("bind private socket");
        let server_thread = thread::spawn(move || {
            let (mut connection, _address) = listener.accept().expect("accept connection");
            handle_connection(
                &mut connection,
                &server_policy(geteuid().as_raw()),
                NOW_MILLISECONDS,
            )
        });
        let mut client = UnixStream::connect(&socket_path).expect("connect private socket");
        client
            .write_all(include_bytes!(
                "../../../tests/fixtures/privileged_helper/valid/health.jsonl"
            ))
            .expect("write health");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read health");
        server_thread
            .join()
            .expect("server join")
            .expect("server response");
        drop(client);
        std::fs::remove_file(&socket_path).expect("remove socket");
        std::fs::remove_dir(&directory).expect("remove directory");
        assert!(response.contains("\"ok\":true"));
    }

    #[test]
    fn authenticated_collection_denies_disallowed_uid_over_unix_socket() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let server_thread = thread::spawn(move || {
            handle_connection(&mut server, &server_policy(999), NOW_MILLISECONDS)
        });
        client
            .write_all(include_bytes!(
                "../../../tests/fixtures/privileged_helper/valid/stat.jsonl"
            ))
            .expect("write typed request");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read denial");
        server_thread
            .join()
            .expect("server join")
            .expect("server response");
        assert!(response.contains("\"ok\":false"));
        assert!(response.contains("PATH_SAFETY_VIOLATION"));
        assert!(response.contains("policy rejected the caller or target UID"));
    }

    #[test]
    fn malformed_worker_connection_does_not_terminate_the_helper_listener() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-helper-worker-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create private directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("set private directory mode");
        let socket_path = directory.join("helper.sock");
        let listener = bind_private_socket(&socket_path).expect("bind private socket");
        let server_thread = thread::spawn(move || {
            serve_listener(&listener, &server_policy(geteuid().as_raw()), Some(2))
        });

        let mut malformed = UnixStream::connect(&socket_path).expect("connect malformed client");
        malformed
            .write_all(&vec![b'x'; MAX_HELPER_MESSAGE_BYTES + 1])
            .expect("write oversized frame");
        malformed
            .shutdown(Shutdown::Write)
            .expect("finish malformed frame");
        drop(malformed);

        let mut healthy = UnixStream::connect(&socket_path).expect("connect healthy client");
        healthy
            .write_all(include_bytes!(
                "../../../tests/fixtures/privileged_helper/valid/health.jsonl"
            ))
            .expect("write health request");
        let mut response = String::new();
        healthy.read_to_string(&mut response).expect("read health");
        server_thread
            .join()
            .expect("server join")
            .expect("listener survives malformed worker");
        std::fs::remove_file(&socket_path).expect("remove socket");
        std::fs::remove_dir(&directory).expect("remove directory");
        assert!(response.contains("\"ok\":true"));
    }
}
