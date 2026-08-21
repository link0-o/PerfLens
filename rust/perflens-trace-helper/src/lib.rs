//! Fail-closed private boundary for the independent target-filtered Trace Helper.
//!
//! The v1 protocol is intentionally separate from the existing `stat`/`record` Helper.  This
//! initial implementation authenticates the Broker and validates every typed request, but reports
//! the kernel target-filter backend as unavailable.  Collection cannot become reachable until a
//! reviewed backend replaces that explicit gate and passes real-host privacy acceptance.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

mod backend;
mod execution;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TRACE_HELPER_SCHEMA_VERSION: &str = "1.1";
pub const MAX_TRACE_HELPER_MESSAGE_BYTES: usize = 64 << 10;
pub const MAX_TRACE_HELPER_PLAN_TTL_MILLISECONDS: u64 = 120_000;
pub const MAX_TRACE_HELPER_DURATION_MILLISECONDS: u64 = 10_000;
pub const MAX_TRACE_HELPER_OUTPUT_BYTES: u64 = 64 << 20;
pub const PRIVATE_TRACE_HELPER_SOCKET: &str = "/run/perflens-trace-helper/helper.sock";
const CAPTURE_BACKEND: &str = "target_filtered_kernel_v1";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceHelperTarget {
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
pub enum TraceMode {
    Sched,
    OffCpu,
    Lock,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum TraceHelperRequest {
    Health {
        schema_version: String,
        request_id: String,
    },
    CollectPid {
        schema_version: String,
        request_id: String,
        plan_id: String,
        caller_uid: u32,
        target: TraceHelperTarget,
        mode: TraceMode,
        duration_milliseconds: u64,
        max_output_bytes: u64,
        expires_at_unix_milliseconds: u64,
        expected_policy_sha256: String,
        expected_capture_backend: String,
        report_ready: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceHelperResult {
    Health {
        helper_version: &'static str,
        helper_pid: u32,
        helper_uid: u32,
        ready: bool,
        capture_backend: &'static str,
        capture_backend_status: &'static str,
        supported_modes: Vec<TraceMode>,
        policy_sha256: String,
        max_duration_milliseconds: u64,
        max_output_bytes: u64,
        max_concurrent_collections: u8,
        target_filter_before_userspace: bool,
    },
    CollectionReady {
        plan_id: String,
        target_pid: u32,
    },
    Collection {
        plan_id: String,
        mode: TraceMode,
        target_pid: u32,
        target_start_time_ticks: u64,
        artifact_name: String,
        output_bytes: u64,
        output_sha256: String,
        output_format: &'static str,
        capture_backend: &'static str,
        policy_sha256: String,
        observed_target_tids: Vec<u32>,
        event_count: u64,
        lost_event_count: u64,
        truncated: bool,
        started_at_monotonic_nanoseconds: u64,
        finished_at_monotonic_nanoseconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceHelperErrorBody {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: &'static str,
    pub recoverable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceHelperResponse {
    pub schema_version: &'static str,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TraceHelperResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<TraceHelperErrorBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceHelperServerPolicy {
    pub broker_uid: u32,
    pub allowed_uid: u32,
    pub artifact_gid: u32,
    pub allowed_modes: Vec<TraceMode>,
    pub policy_sha256: String,
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
    const fn new(kind: ProtocolErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    #[must_use]
    pub const fn kind(&self) -> ProtocolErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for ProtocolError {}

/// Serve the private Unix socket.  The caller/systemd must create its private parent directory.
///
/// # Errors
///
/// Returns an I/O error when the socket identity, peer, frame, or response cannot be handled.
pub fn serve_private_socket(
    socket_path: &Path,
    policy: &TraceHelperServerPolicy,
) -> io::Result<()> {
    let listener = bind_private_socket(socket_path)?;
    let policy = Arc::new(policy.clone());
    let worker_active = Arc::new(AtomicBool::new(false));
    for incoming in listener.incoming() {
        let mut connection = incoming?;
        let policy = Arc::clone(&policy);
        let worker_active = Arc::clone(&worker_active);
        thread::spawn(move || {
            let _result = handle_connection_with_worker(
                &mut connection,
                &policy,
                now_unix_milliseconds(),
                &worker_active,
            );
        });
    }
    Ok(())
}

fn bind_private_socket(socket_path: &Path) -> io::Result<UnixListener> {
    if !socket_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Trace Helper socket path must be absolute",
        ));
    }
    let parent = socket_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "socket parent is missing")
    })?;
    let parent_metadata = fs::metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != geteuid().as_raw()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Trace Helper socket parent is unsafe",
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        if !metadata.file_type().is_socket()
            || metadata.uid() != geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "existing Trace Helper socket is unsafe",
            ));
        }
        fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

#[cfg(test)]
fn handle_connection(
    connection: &mut UnixStream,
    policy: &TraceHelperServerPolicy,
    now_milliseconds: u64,
) -> io::Result<()> {
    handle_connection_with_worker(
        connection,
        policy,
        now_milliseconds,
        &AtomicBool::new(false),
    )
}

#[allow(clippy::too_many_lines)]
fn handle_connection_with_worker(
    connection: &mut UnixStream,
    policy: &TraceHelperServerPolicy,
    now_milliseconds: u64,
    worker_active: &AtomicBool,
) -> io::Result<()> {
    let credentials = getsockopt(connection, PeerCredentials).map_err(io::Error::other)?;
    if credentials.uid() != policy.broker_uid {
        return write_response(
            connection,
            &rejected_response(
                "unknown",
                "PATH_SAFETY_VIOLATION",
                "trace_helper_peer",
                "Trace Helper accepts only its configured Broker UID",
            ),
        );
    }
    let frame = read_bounded_frame(connection)?;
    match parse_request_frame(&frame, now_milliseconds) {
        Ok(TraceHelperRequest::Health {
            schema_version: _,
            request_id,
        }) => write_response(connection, &health_response(request_id, policy)),
        Ok(TraceHelperRequest::CollectPid {
            schema_version: _,
            request_id,
            plan_id,
            caller_uid,
            target,
            mode,
            duration_milliseconds,
            max_output_bytes,
            expires_at_unix_milliseconds: _,
            expected_policy_sha256,
            expected_capture_backend,
            report_ready,
        }) => {
            if caller_uid != policy.allowed_uid
                || target.uid != policy.allowed_uid
                || !policy.allowed_modes.contains(&mode)
                || expected_policy_sha256 != policy.policy_sha256
                || expected_capture_backend != CAPTURE_BACKEND
                || assert_pid_identity(&target).is_err()
            {
                return write_response(
                    connection,
                    &rejected_response(
                        &request_id,
                        "PATH_SAFETY_VIOLATION",
                        "trace_helper_policy",
                        "Trace Helper immutable policy rejected the typed PID plan",
                    ),
                );
            }
            let available_modes = execution::backend_modes();
            if !available_modes.contains(&mode) {
                return write_response(
                    connection,
                    &rejected_response(
                        &request_id,
                        "UNSUPPORTED_FORMAT",
                        "trace_backend",
                        "Target-filtered kernel Trace backend is unavailable",
                    ),
                );
            }
            if worker_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return write_response(
                    connection,
                    &rejected_response(
                        &request_id,
                        "RESOURCE_LIMIT_EXCEEDED",
                        "trace_helper_worker",
                        "Trace Helper already has one active collection",
                    ),
                );
            }
            let _worker_guard = WorkerGuard(worker_active);
            let plan = execution::TraceExecutionPlan {
                plan_id: plan_id.clone(),
                target: target.clone(),
                mode,
                duration_milliseconds,
                max_output_bytes,
            };
            let mut notify_ready = || {
                if report_ready {
                    write_response(
                        connection,
                        &TraceHelperResponse {
                            schema_version: TRACE_HELPER_SCHEMA_VERSION,
                            request_id: request_id.clone(),
                            ok: true,
                            result: Some(TraceHelperResult::CollectionReady {
                                plan_id: plan_id.clone(),
                                target_pid: target.pid,
                            }),
                            error: None,
                        },
                    )?;
                }
                Ok(())
            };
            match execution::execute_plan(&plan, policy.artifact_gid, &mut notify_ready) {
                Ok(result) => write_response(
                    connection,
                    &TraceHelperResponse {
                        schema_version: TRACE_HELPER_SCHEMA_VERSION,
                        request_id,
                        ok: true,
                        result: Some(TraceHelperResult::Collection {
                            plan_id,
                            mode,
                            target_pid: target.pid,
                            target_start_time_ticks: target.start_time_ticks,
                            artifact_name: result.artifact_name,
                            output_bytes: result.output_bytes,
                            output_sha256: result.output_sha256,
                            output_format: "target_filtered_trace_ndjson",
                            capture_backend: CAPTURE_BACKEND,
                            policy_sha256: policy.policy_sha256.clone(),
                            observed_target_tids: result.observed_target_tids,
                            event_count: result.event_count,
                            lost_event_count: result.lost_event_count,
                            truncated: result.truncated,
                            started_at_monotonic_nanoseconds: result
                                .started_at_monotonic_nanoseconds,
                            finished_at_monotonic_nanoseconds: result
                                .finished_at_monotonic_nanoseconds,
                        }),
                        error: None,
                    },
                ),
                Err(error) => {
                    let (code, stage, message) = match error.kind() {
                        io::ErrorKind::PermissionDenied => (
                            "PATH_SAFETY_VIOLATION",
                            "trace_helper_policy",
                            "Trace Helper immutable policy or spool rejected the collection",
                        ),
                        io::ErrorKind::StorageFull => (
                            "RESOURCE_LIMIT_EXCEEDED",
                            "trace_helper_spool",
                            "Trace Helper spool quota rejected the collection",
                        ),
                        _ => (
                            "EXTERNAL_TOOL_FAILED",
                            "trace_backend",
                            "Target-filtered kernel Trace collection failed safely",
                        ),
                    };
                    write_response(
                        connection,
                        &rejected_response(&request_id, code, stage, message),
                    )
                }
            }
        }
        Err(error) => write_response(
            connection,
            &rejected_response(
                "unknown",
                "INVALID_INPUT",
                "trace_helper_protocol",
                error.message(),
            ),
        ),
    }
}

fn health_response(request_id: String, policy: &TraceHelperServerPolicy) -> TraceHelperResponse {
    let supported_modes = execution::backend_modes()
        .into_iter()
        .filter(|mode| policy.allowed_modes.contains(mode))
        .collect::<Vec<_>>();
    let available = !supported_modes.is_empty();
    TraceHelperResponse {
        schema_version: TRACE_HELPER_SCHEMA_VERSION,
        request_id,
        ok: true,
        result: Some(TraceHelperResult::Health {
            helper_version: env!("CARGO_PKG_VERSION"),
            helper_pid: std::process::id(),
            helper_uid: geteuid().as_raw(),
            ready: true,
            capture_backend: CAPTURE_BACKEND,
            capture_backend_status: if available {
                "available"
            } else {
                "unavailable"
            },
            supported_modes,
            policy_sha256: policy.policy_sha256.clone(),
            max_duration_milliseconds: MAX_TRACE_HELPER_DURATION_MILLISECONDS,
            max_output_bytes: MAX_TRACE_HELPER_OUTPUT_BYTES,
            max_concurrent_collections: 1,
            target_filter_before_userspace: available,
        }),
        error: None,
    }
}

struct WorkerGuard<'worker>(&'worker AtomicBool);

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn rejected_response(
    request_id: &str,
    code: &'static str,
    stage: &'static str,
    message: &'static str,
) -> TraceHelperResponse {
    TraceHelperResponse {
        schema_version: TRACE_HELPER_SCHEMA_VERSION,
        request_id: request_id.to_owned(),
        ok: false,
        result: None,
        error: Some(TraceHelperErrorBody {
            code,
            stage,
            message,
            recoverable: true,
        }),
    }
}

pub(crate) fn assert_pid_identity(target: &TraceHelperTarget) -> io::Result<()> {
    assert_pid_identity_at(target, Path::new("/proc"), Path::new("/sys/fs/cgroup"))
}

fn assert_pid_identity_at(
    target: &TraceHelperTarget,
    proc_root: &Path,
    cgroup_root: &Path,
) -> io::Result<()> {
    if target.pid == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Trace Helper cannot trace itself",
        ));
    }
    let process_root = proc_root.join(target.pid.to_string());
    let metadata = fs::metadata(&process_root)?;
    let status_text = fs::read_to_string(process_root.join("status"))?;
    let target_tgid = status_text
        .lines()
        .find_map(|line| {
            line.strip_prefix("Tgid:")
                .and_then(|value| value.trim().parse::<u32>().ok())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target status is malformed"))?;
    let stat_text = fs::read_to_string(process_root.join("stat"))?;
    let closing = stat_text
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target stat is malformed"))?;
    let start_time_ticks = stat_text
        .get(closing + 2..)
        .and_then(|tail| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target stat is malformed"))?;
    if metadata.uid() != target.uid
        || start_time_ticks != target.start_time_ticks
        || target_tgid != target.pid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target identity changed or is not a process leader",
        ));
    }
    match (&target.target_runtime, &target.container) {
        (TargetRuntime::Host, None) => {}
        (TargetRuntime::Docker, Some(container)) => {
            assert_docker_identity(&process_root, cgroup_root, target, container)?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target runtime and container binding differ",
            ));
        }
    }
    Ok(())
}

fn assert_docker_identity(
    proc_root: &Path,
    cgroup_root: &Path,
    target: &TraceHelperTarget,
    container: &ContainerTargetBinding,
) -> io::Result<()> {
    let denied = |message| io::Error::new(io::ErrorKind::PermissionDenied, message);
    let status = fs::read_to_string(proc_root.join("status"))?;
    let uid_values = parse_u32_status_field(&status, "Uid:")?;
    let namespace_pids = parse_u32_status_field(&status, "NSpid:")?;
    if uid_values.len() != 4
        || uid_values.iter().any(|uid| *uid != target.uid)
        || namespace_pids.len() < 2
        || namespace_pids.first() != Some(&target.pid)
        || namespace_pids.last() != Some(&container.container_pid)
    {
        return Err(denied("Docker target UID or NSpid identity changed"));
    }
    for (name, expected_inode) in [
        ("pid", container.namespace.pid_namespace_inode),
        ("user", container.namespace.user_namespace_inode),
        ("mnt", container.namespace.mount_namespace_inode),
        ("cgroup", container.namespace.cgroup_namespace_inode),
    ] {
        if namespace_inode(proc_root, name)? != expected_inode {
            return Err(denied("Docker target namespace identity changed"));
        }
    }
    let executable_name = fs::read_to_string(proc_root.join("comm"))?;
    if executable_name
        .strip_suffix('\n')
        .unwrap_or(&executable_name)
        != container.executable_name
    {
        return Err(denied("Docker target executable identity changed"));
    }
    let cgroup_identity = assert_docker_cgroup(proc_root, cgroup_root, container)?;
    let fingerprint = docker_identity_fingerprint(target, container, &cgroup_identity);
    if fingerprint != container.identity_fingerprint
        || (container.target_kind == DockerTargetKind::ManagedTemporaryContainer
            && container.container_pid != 1)
    {
        return Err(denied("Docker target identity fingerprint changed"));
    }
    Ok(())
}

fn assert_docker_cgroup(
    proc_root: &Path,
    cgroup_root: &Path,
    container: &ContainerTargetBinding,
) -> io::Result<String> {
    let denied = |message| io::Error::new(io::ErrorKind::PermissionDenied, message);
    let cgroup_text = fs::read_to_string(proc_root.join("cgroup"))?;
    let cgroup_path = parse_cgroup_v2_path(&cgroup_text)?;
    let cgroup_directory = cgroup_root.join(cgroup_path.trim_start_matches('/'));
    let resolved = cgroup_directory.canonicalize()?;
    let cgroup_metadata = cgroup_directory.metadata()?;
    if resolved != cgroup_directory
        || !cgroup_metadata.is_dir()
        || cgroup_metadata.ino() != container.cgroup.inode
    {
        return Err(denied("Docker target cgroup inode changed"));
    }
    let cgroup_inode = container.cgroup.inode.to_string();
    let identity = sha256_nul(&[
        "cgroup-v2",
        &container.container_identity_sha256,
        cgroup_path,
        &cgroup_inode,
    ]);
    if identity != container.cgroup.identity_sha256 {
        return Err(denied("Docker target cgroup identity digest changed"));
    }
    Ok(identity)
}

fn docker_identity_fingerprint(
    target: &TraceHelperTarget,
    container: &ContainerTargetBinding,
    cgroup_identity: &str,
) -> String {
    let fields = [
        target.pid.to_string(),
        target.uid.to_string(),
        target.start_time_ticks.to_string(),
        container.container_pid.to_string(),
        container.namespace.pid_namespace_inode.to_string(),
        container.namespace.user_namespace_inode.to_string(),
        container.namespace.mount_namespace_inode.to_string(),
        container.namespace.cgroup_namespace_inode.to_string(),
        container.cgroup.inode.to_string(),
    ];
    sha256_nul(&[
        &container.container_identity_sha256,
        &container.image_identity_sha256,
        &fields[0],
        &fields[1],
        &fields[2],
        &fields[3],
        &fields[4],
        &fields[5],
        &fields[6],
        &fields[7],
        &fields[8],
        cgroup_identity,
    ])
}

fn parse_u32_status_field(text: &str, prefix: &str) -> io::Result<Vec<u32>> {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "target status field is missing")
        })?
        .split_whitespace()
        .map(|value| {
            value.parse::<u32>().map_err(|_error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "target status field is malformed",
                )
            })
        })
        .collect()
}

fn namespace_inode(proc_root: &Path, namespace: &str) -> io::Result<u64> {
    let value = fs::read_link(proc_root.join("ns").join(namespace))?;
    let text = value
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "namespace is malformed"))?;
    let prefix = format!("{namespace}:[");
    text.strip_prefix(&prefix)
        .and_then(|tail| tail.strip_suffix(']'))
        .and_then(|inode| inode.parse::<u64>().ok())
        .filter(|inode| *inode > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "namespace is malformed"))
}

fn parse_cgroup_v2_path(text: &str) -> io::Result<&str> {
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let value = lines
        .next()
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "cgroup v2 identity is missing")
        })?;
    if lines.next().is_some()
        || !value.starts_with('/')
        || value.contains('\0')
        || value.len() > 4096
        || value.contains("//")
        || (value != "/" && value.ends_with('/'))
        || Path::new(value).components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cgroup v2 path is unsafe",
        ));
    }
    Ok(value)
}

fn sha256_nul(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            digest.update([0]);
        }
        digest.update(part.as_bytes());
    }
    hex_sha256(digest.finalize().as_slice())
}

fn hex_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Parse and validate one newline-delimited request.
///
/// # Errors
///
/// Returns a bounded protocol classification for malformed, expired, or over-limit frames.
pub fn parse_request_frame(
    frame: &[u8],
    now_unix_milliseconds: u64,
) -> Result<TraceHelperRequest, ProtocolError> {
    if frame.len() > MAX_TRACE_HELPER_MESSAGE_BYTES {
        return Err(ProtocolError::new(
            ProtocolErrorKind::Frame,
            "Trace Helper request exceeds the protocol limit",
        ));
    }
    let Some(payload) = frame.strip_suffix(b"\n") else {
        return Err(ProtocolError::new(
            ProtocolErrorKind::Frame,
            "Trace Helper request requires a newline terminator",
        ));
    };
    if payload.contains(&b'\n') {
        return Err(ProtocolError::new(
            ProtocolErrorKind::Frame,
            "Trace Helper request contains multiple frames",
        ));
    }
    let request: TraceHelperRequest = serde_json::from_slice(payload).map_err(|_error| {
        ProtocolError::new(
            ProtocolErrorKind::Json,
            "Trace Helper request is not strict valid JSON",
        )
    })?;
    validate_request(&request, now_unix_milliseconds)?;
    Ok(request)
}

fn validate_request(
    request: &TraceHelperRequest,
    now_unix_milliseconds: u64,
) -> Result<(), ProtocolError> {
    match request {
        TraceHelperRequest::Health {
            schema_version,
            request_id,
        } => validate_common(schema_version, request_id),
        TraceHelperRequest::CollectPid {
            schema_version,
            request_id,
            plan_id,
            caller_uid,
            target,
            mode: _,
            duration_milliseconds,
            max_output_bytes,
            expires_at_unix_milliseconds,
            expected_policy_sha256,
            expected_capture_backend,
            report_ready: _,
        } => {
            validate_common(schema_version, request_id)?;
            if !valid_identifier(plan_id, "trace-plan-", 20)
                || target.pid == 0
                || target.pid > i32::MAX.cast_unsigned()
                || target.start_time_ticks == 0
                || *duration_milliseconds == 0
                || *duration_milliseconds > MAX_TRACE_HELPER_DURATION_MILLISECONDS
                || *max_output_bytes == 0
                || *max_output_bytes > MAX_TRACE_HELPER_OUTPUT_BYTES
                || !valid_sha256(expected_policy_sha256)
                || expected_capture_backend != CAPTURE_BACKEND
            {
                return Err(schema_error());
            }
            validate_target(target, *caller_uid)?;
            let remaining = expires_at_unix_milliseconds
                .checked_sub(now_unix_milliseconds)
                .ok_or_else(expired_error)?;
            if remaining == 0 || remaining > MAX_TRACE_HELPER_PLAN_TTL_MILLISECONDS {
                return Err(expired_error());
            }
            Ok(())
        }
    }
}

fn validate_target(target: &TraceHelperTarget, caller_uid: u32) -> Result<(), ProtocolError> {
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
                || !valid_exact_identifier(&container.target_id, "container-target-", 20)
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
    if schema_version != TRACE_HELPER_SCHEMA_VERSION
        || !valid_identifier(request_id, "request-", 16)
    {
        return Err(schema_error());
    }
    Ok(())
}

fn valid_identifier(value: &str, prefix: &str, minimum_hex: usize) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() >= minimum_hex && valid_lower_hex(suffix))
}

fn valid_exact_identifier(value: &str, prefix: &str, exact_hex: usize) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == exact_hex && valid_lower_hex(suffix))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && valid_lower_hex(value)
}

fn valid_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn schema_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorKind::Schema,
        "Trace Helper request violates the fixed typed policy",
    )
}

const fn expired_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorKind::Expired,
        "Trace Helper plan is expired or exceeds TTL ceiling",
    )
}

fn read_bounded_frame(connection: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(4096);
    let mut byte = [0_u8; 1];
    while frame.len() <= MAX_TRACE_HELPER_MESSAGE_BYTES {
        let count = connection.read(&mut byte)?;
        if count == 0 {
            break;
        }
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if frame.len() > MAX_TRACE_HELPER_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trace Helper frame exceeds its bound",
        ));
    }
    Ok(frame)
}

fn write_response(connection: &mut UnixStream, response: &TraceHelperResponse) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(response).map_err(io::Error::other)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_TRACE_HELPER_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trace Helper response exceeds its bound",
        ));
    }
    connection.write_all(&encoded)
}

fn now_unix_milliseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    use nix::unistd::{getegid, geteuid, gettid};

    use super::{
        ContainerCgroupBinding, ContainerNamespaceBinding, ContainerTargetBinding,
        DockerAdapterRecipe, DockerTargetKind, DockerUidMapping, ProtocolErrorKind, TargetRuntime,
        TraceHelperRequest, TraceHelperServerPolicy, TraceHelperTarget, TraceMode,
        assert_pid_identity, assert_pid_identity_at, docker_identity_fingerprint,
        handle_connection, parse_request_frame, sha256_nul,
    };

    const NOW_MILLISECONDS: u64 = 4_102_444_700_000;
    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct DockerIdentityFixture {
        root: PathBuf,
        proc_root: PathBuf,
        cgroup_root: PathBuf,
        process_root: PathBuf,
        target: TraceHelperTarget,
    }

    impl Drop for DockerIdentityFixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn docker_identity_fixture() -> DockerIdentityFixture {
        let root = std::env::temp_dir().join(format!(
            "perflens-trace-docker-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let process_root = proc_root.join("5252");
        let namespace_root = process_root.join("ns");
        let cgroup_directory = cgroup_root.join("docker/session");
        fs::create_dir_all(&namespace_root).expect("create fake proc namespace root");
        fs::create_dir_all(&cgroup_directory).expect("create fake cgroup");
        let uid = geteuid().as_raw();
        fs::write(
            process_root.join("stat"),
            format!("5252 (worker) S {} 87654\n", vec!["0"; 18].join(" ")),
        )
        .expect("write fake stat");
        fs::write(
            process_root.join("status"),
            format!("Tgid:\t5252\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nNSpid:\t5252\t1\n"),
        )
        .expect("write fake status");
        fs::write(process_root.join("comm"), "worker\n").expect("write fake comm");
        fs::write(process_root.join("cgroup"), "0::/docker/session\n")
            .expect("write fake cgroup membership");
        for (name, inode) in [("pid", 201), ("user", 202), ("mnt", 203), ("cgroup", 204)] {
            symlink(format!("{name}:[{inode}]"), namespace_root.join(name))
                .expect("write fake namespace link");
        }
        let cgroup_inode = cgroup_directory
            .metadata()
            .expect("fake cgroup metadata")
            .ino();
        let container_identity = "a".repeat(64);
        let cgroup_identity = sha256_nul(&[
            "cgroup-v2",
            &container_identity,
            "/docker/session",
            &cgroup_inode.to_string(),
        ]);
        let mut container = ContainerTargetBinding {
            target_id: "container-target-0123456789abcdefabcd".to_owned(),
            target_kind: DockerTargetKind::ManagedTemporaryContainer,
            target_content_sha256: "b".repeat(64),
            container_identity_sha256: container_identity,
            image_identity_sha256: "c".repeat(64),
            identity_fingerprint: String::new(),
            container_pid: 1,
            host_pid: 5252,
            host_uid: uid,
            host_start_time_ticks: 87_654,
            executable_name: "worker".to_owned(),
            namespace: ContainerNamespaceBinding {
                pid_namespace_inode: 201,
                user_namespace_inode: 202,
                mount_namespace_inode: 203,
                cgroup_namespace_inode: 204,
            },
            cgroup: ContainerCgroupBinding {
                version: "v2".to_owned(),
                inode: cgroup_inode,
                identity_sha256: cgroup_identity.clone(),
            },
            uid_mapping: DockerUidMapping::RootlessSameUid,
            rootful_risk_authorized: false,
            adapter_recipe_id: DockerAdapterRecipe::LocalDockerManagedV1,
            adapter_sha256: "d".repeat(64),
        };
        let mut target = TraceHelperTarget {
            target_runtime: TargetRuntime::Docker,
            pid: 5252,
            uid,
            start_time_ticks: 87_654,
            container: None,
        };
        container.identity_fingerprint =
            docker_identity_fingerprint(&target, &container, &cgroup_identity);
        target.container = Some(Box::new(container));
        DockerIdentityFixture {
            root,
            proc_root,
            cgroup_root,
            process_root,
            target,
        }
    }

    #[test]
    fn docker_identity_is_revalidated_from_proc_and_cgroup_state() {
        let fixture = docker_identity_fixture();
        assert_pid_identity_at(&fixture.target, &fixture.proc_root, &fixture.cgroup_root)
            .expect("matching Docker identity");
    }

    #[test]
    fn docker_identity_rejects_pid_reuse_namespace_and_cgroup_changes() {
        let fixture = docker_identity_fixture();
        fs::write(
            fixture.process_root.join("stat"),
            format!("5252 (worker) S {} 87655\n", vec!["0"; 18].join(" ")),
        )
        .expect("replace start time");
        assert!(
            assert_pid_identity_at(&fixture.target, &fixture.proc_root, &fixture.cgroup_root)
                .is_err()
        );
        fs::write(
            fixture.process_root.join("stat"),
            format!("5252 (worker) S {} 87654\n", vec!["0"; 18].join(" ")),
        )
        .expect("restore start time");
        fs::remove_file(fixture.process_root.join("ns/pid")).expect("remove namespace link");
        symlink("pid:[999]", fixture.process_root.join("ns/pid")).expect("replace namespace link");
        assert!(
            assert_pid_identity_at(&fixture.target, &fixture.proc_root, &fixture.cgroup_root)
                .is_err()
        );
    }

    #[test]
    fn docker_identity_rejects_executable_and_unsafe_cgroup_changes() {
        let fixture = docker_identity_fixture();
        fs::write(fixture.process_root.join("comm"), "replacement\n")
            .expect("replace executable name");
        assert!(
            assert_pid_identity_at(&fixture.target, &fixture.proc_root, &fixture.cgroup_root)
                .is_err()
        );
        fs::write(fixture.process_root.join("comm"), "worker\n").expect("restore executable name");
        fs::write(fixture.process_root.join("cgroup"), "0::/docker//session\n")
            .expect("write unsafe cgroup path");
        assert!(
            assert_pid_identity_at(&fixture.target, &fixture.proc_root, &fixture.cgroup_root)
                .is_err()
        );
    }

    fn fixture(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/trace_helper")
            .join(relative)
    }

    #[test]
    fn parses_shared_valid_frames() {
        let health = fs::read(fixture("valid/health.jsonl")).expect("health fixture");
        let sched = fs::read(fixture("valid/sched.jsonl")).expect("sched fixture");
        let docker = fs::read(fixture("valid/docker-sched.jsonl")).expect("Docker fixture");
        assert!(matches!(
            parse_request_frame(&health, NOW_MILLISECONDS).expect("health"),
            TraceHelperRequest::Health { .. }
        ));
        assert!(matches!(
            parse_request_frame(&sched, NOW_MILLISECONDS).expect("sched"),
            TraceHelperRequest::CollectPid { .. }
        ));
        assert!(matches!(
            parse_request_frame(&docker, NOW_MILLISECONDS).expect("Docker sched"),
            TraceHelperRequest::CollectPid { .. }
        ));
    }

    #[test]
    fn rejects_every_shared_invalid_frame() {
        for entry in fs::read_dir(fixture("invalid")).expect("invalid fixtures") {
            let path = entry.expect("entry").path();
            let payload = fs::read(&path).expect("fixture payload");
            assert!(
                parse_request_frame(&payload, NOW_MILLISECONDS).is_err(),
                "accepted {}",
                path.display()
            );
        }
    }

    #[test]
    fn rejects_expired_plan_and_multiple_frames() {
        let sched = fs::read(fixture("valid/sched.jsonl")).expect("sched fixture");
        let expired =
            parse_request_frame(&sched, 4_102_444_760_000).expect_err("expired plan must fail");
        assert_eq!(expired.kind(), ProtocolErrorKind::Expired);
        let mut multiple = fs::read(fixture("valid/health.jsonl")).expect("health fixture");
        multiple.extend_from_slice(b"{}\n");
        assert!(parse_request_frame(&multiple, NOW_MILLISECONDS).is_err());
    }

    #[test]
    fn authenticated_health_explicitly_reports_backend_unavailable() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .write_all(&fs::read(fixture("valid/health.jsonl")).expect("health fixture"))
            .expect("write health");
        handle_connection(&mut server, &policy(geteuid().as_raw()), NOW_MILLISECONDS)
            .expect("health response");
        let response = read_response(&mut client);
        assert_eq!(response["ok"], true);
        assert_eq!(response["result"]["capture_backend_status"], "unavailable");
        assert_eq!(response["result"]["supported_modes"], serde_json::json!([]));
        assert_eq!(response["result"]["target_filter_before_userspace"], false);
    }

    #[test]
    fn valid_typed_pid_request_fails_closed_before_backend_exists() {
        let mut child = Command::new("/usr/bin/sleep")
            .arg("2")
            .spawn()
            .expect("spawn fixed test target");
        let pid = child.id();
        let proc_root = Path::new("/proc").join(pid.to_string());
        let uid = fs::metadata(&proc_root).expect("target metadata").uid();
        let stat = fs::read_to_string(proc_root.join("stat")).expect("target stat");
        let closing = stat.rfind(')').expect("stat comm terminator");
        let start_ticks = stat[closing + 2..]
            .split_whitespace()
            .nth(19)
            .expect("start ticks")
            .parse::<u64>()
            .expect("numeric ticks");
        let request = format!(
            "{{\"schema_version\":\"1.1\",\"operation\":\"collect_pid\",\"request_id\":\"request-0123456789abcdef\",\"plan_id\":\"trace-plan-0123456789abcdefabcd\",\"caller_uid\":{uid},\"target\":{{\"target_runtime\":\"host\",\"pid\":{pid},\"uid\":{uid},\"start_time_ticks\":{start_ticks}}},\"mode\":\"sched\",\"duration_milliseconds\":1000,\"max_output_bytes\":1048576,\"expires_at_unix_milliseconds\":4102444760000,\"expected_policy_sha256\":\"{}\",\"expected_capture_backend\":\"target_filtered_kernel_v1\",\"report_ready\":false}}\n",
            "a".repeat(64)
        );
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .write_all(request.as_bytes())
            .expect("write typed request");
        handle_connection(&mut server, &policy(uid), NOW_MILLISECONDS).expect("bounded rejection");
        let response = read_response(&mut client);
        child.kill().expect("stop target");
        child.wait().expect("reap target");
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "UNSUPPORTED_FORMAT");
        assert_eq!(response["error"]["stage"], "trace_backend");
    }

    #[test]
    fn unauthorized_peer_is_rejected_before_frame_parsing() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client.write_all(b"not-json\n").expect("write request");
        let mut rejected_policy = policy(geteuid().as_raw());
        rejected_policy.broker_uid = geteuid().as_raw().saturating_add(1);
        handle_connection(&mut server, &rejected_policy, NOW_MILLISECONDS)
            .expect("bounded peer rejection");
        let response = read_response(&mut client);
        assert_eq!(response["error"]["code"], "PATH_SAFETY_VIOLATION");
        assert_eq!(response["request_id"], "unknown");
    }

    #[test]
    fn target_identity_requires_a_process_leader() {
        let (tid_sender, tid_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            tid_sender
                .send(gettid().as_raw().cast_unsigned())
                .expect("send worker TID");
            release_receiver.recv().expect("release worker");
        });
        let tid = tid_receiver.recv().expect("receive worker TID");
        let proc_root = Path::new("/proc").join(tid.to_string());
        let uid = fs::metadata(&proc_root).expect("worker metadata").uid();
        let stat = fs::read_to_string(proc_root.join("stat")).expect("worker stat");
        let closing = stat.rfind(')').expect("stat comm terminator");
        let start_time_ticks = stat[closing + 2..]
            .split_whitespace()
            .nth(19)
            .expect("start ticks")
            .parse::<u64>()
            .expect("numeric ticks");
        let error = assert_pid_identity(&TraceHelperTarget {
            target_runtime: TargetRuntime::Host,
            pid: tid,
            uid,
            start_time_ticks,
            container: None,
        })
        .expect_err("thread TID must not be accepted as target TGID");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        release_sender.send(()).expect("release worker");
        worker.join().expect("join worker");
    }

    fn policy(allowed_uid: u32) -> TraceHelperServerPolicy {
        TraceHelperServerPolicy {
            broker_uid: geteuid().as_raw(),
            allowed_uid,
            artifact_gid: getegid().as_raw(),
            allowed_modes: vec![TraceMode::Sched, TraceMode::OffCpu, TraceMode::Lock],
            policy_sha256: "a".repeat(64),
        }
    }

    fn read_response(stream: &mut UnixStream) -> serde_json::Value {
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).expect("read response");
            response.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        serde_json::from_slice(&response).expect("response JSON")
    }
}
