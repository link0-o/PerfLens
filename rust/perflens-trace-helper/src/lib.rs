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

pub const TRACE_HELPER_SCHEMA_VERSION: &str = "1.0";
pub const MAX_TRACE_HELPER_MESSAGE_BYTES: usize = 64 << 10;
pub const MAX_TRACE_HELPER_PLAN_TTL_MILLISECONDS: u64 = 120_000;
pub const MAX_TRACE_HELPER_DURATION_MILLISECONDS: u64 = 10_000;
pub const MAX_TRACE_HELPER_OUTPUT_BYTES: u64 = 64 << 20;
pub const PRIVATE_TRACE_HELPER_SOCKET: &str = "/run/perflens-trace-helper/helper.sock";
const CAPTURE_BACKEND: &str = "target_filtered_kernel_v1";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceHelperTarget {
    pub pid: u32,
    pub uid: u32,
    pub start_time_ticks: u64,
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
    if target.pid == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Trace Helper cannot trace itself",
        ));
    }
    let proc_root = Path::new("/proc").join(target.pid.to_string());
    let metadata = fs::metadata(&proc_root)?;
    let status_text = fs::read_to_string(proc_root.join("status"))?;
    let target_tgid = status_text
        .lines()
        .find_map(|line| {
            line.strip_prefix("Tgid:")
                .and_then(|value| value.trim().parse::<u32>().ok())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target status is malformed"))?;
    let stat_text = fs::read_to_string(proc_root.join("stat"))?;
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
    Ok(())
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
                || *caller_uid != target.uid
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
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::mpsc;

    use nix::unistd::{getegid, geteuid, gettid};

    use super::{
        ProtocolErrorKind, TraceHelperRequest, TraceHelperServerPolicy, TraceHelperTarget,
        TraceMode, assert_pid_identity, handle_connection, parse_request_frame,
    };

    const NOW_MILLISECONDS: u64 = 4_102_444_700_000;

    fn fixture(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/trace_helper")
            .join(relative)
    }

    #[test]
    fn parses_shared_valid_frames() {
        let health = fs::read(fixture("valid/health.jsonl")).expect("health fixture");
        let sched = fs::read(fixture("valid/sched.jsonl")).expect("sched fixture");
        assert!(matches!(
            parse_request_frame(&health, NOW_MILLISECONDS).expect("health"),
            TraceHelperRequest::Health { .. }
        ));
        assert!(matches!(
            parse_request_frame(&sched, NOW_MILLISECONDS).expect("sched"),
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
            "{{\"schema_version\":\"1.0\",\"operation\":\"collect_pid\",\"request_id\":\"request-0123456789abcdef\",\"plan_id\":\"trace-plan-0123456789abcdefabcd\",\"caller_uid\":{uid},\"target\":{{\"pid\":{pid},\"uid\":{uid},\"start_time_ticks\":{start_ticks}}},\"mode\":\"sched\",\"duration_milliseconds\":1000,\"max_output_bytes\":1048576,\"expires_at_unix_milliseconds\":4102444760000,\"expected_policy_sha256\":\"{}\",\"expected_capture_backend\":\"target_filtered_kernel_v1\",\"report_ready\":false}}\n",
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
            pid: tid,
            uid,
            start_time_ticks,
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
