//! Strict protocol boundary for the optional `PerfLens` privileged Helper.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::geteuid;
use serde::{Deserialize, Serialize};

pub const HELPER_SCHEMA_VERSION: &str = "1.0";
pub const MAX_HELPER_MESSAGE_BYTES: usize = 64 << 10;
pub const MAX_HELPER_PLAN_TTL_MILLISECONDS: u64 = 3_600_000;
pub const MAX_HELPER_DURATION_MILLISECONDS: u64 = 86_400_000;
pub const MAX_HELPER_OUTPUT_BYTES: u64 = 1 << 40;
pub const MAX_HELPER_FREQUENCY_HZ: u32 = 10_000;
pub const MAX_HELPER_EVENTS: usize = 64;
pub const MAX_HELPER_RESPONSE_BYTES: usize = 64 << 10;
pub const PRIVATE_HELPER_SOCKET: &str = "/run/perflens-helper/helper.sock";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperTarget {
    pub pid: u32,
    pub uid: u32,
    pub start_time_ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMode {
    Record,
    Stat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallGraph {
    Dwarf,
    Fp,
    Lbr,
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
        target: HelperTarget,
        mode: CollectionMode,
        duration_milliseconds: u64,
        frequency_hz: Option<u32>,
        call_graph: Option<CallGraph>,
        events: Vec<String>,
        max_output_bytes: u64,
        expires_at_unix_milliseconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelperHealthResult {
    pub helper_version: &'static str,
    pub helper_pid: u32,
    pub helper_uid: u32,
    pub privilege_mode: &'static str,
    pub ready: bool,
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
    pub result: Option<HelperHealthResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<HelperErrorBody>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperServerPolicy {
    pub broker_uid: u32,
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
pub fn serve_private_socket(socket_path: &Path, policy: HelperServerPolicy) -> io::Result<()> {
    let listener = bind_private_socket(socket_path)?;
    for accepted in listener.incoming() {
        let mut connection = accepted?;
        connection.set_read_timeout(Some(Duration::from_secs(5)))?;
        connection.set_write_timeout(Some(Duration::from_secs(5)))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis()
            .try_into()
            .map_err(io::Error::other)?;
        handle_connection(&mut connection, policy, now)?;
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
pub fn handle_connection(
    connection: &mut UnixStream,
    policy: HelperServerPolicy,
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
    let response = match parse_request_frame(&frame, now_unix_milliseconds) {
        Ok(HelperRequest::Health { request_id, .. }) => HelperResponse {
            schema_version: HELPER_SCHEMA_VERSION,
            request_id,
            ok: true,
            result: Some(HelperHealthResult {
                helper_version: env!("CARGO_PKG_VERSION"),
                helper_pid: std::process::id(),
                helper_uid: geteuid().as_raw(),
                privilege_mode: "paranoid3_helper",
                ready: true,
            }),
            error: None,
        },
        Ok(HelperRequest::CollectPid { request_id, .. }) => rejected_response(
            &request_id,
            "INTERNAL_ERROR",
            "privileged_helper",
            "Privileged collection is not enabled in this build milestone",
        ),
        Err(error) => rejected_response(
            "unknown",
            "INVALID_INPUT",
            "privileged_helper_protocol",
            error.message,
        ),
    };
    write_response(connection, &response)
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
            target,
            mode,
            duration_milliseconds,
            frequency_hz,
            call_graph,
            events,
            max_output_bytes,
            expires_at_unix_milliseconds,
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
            validate_mode_fields(*mode, *frequency_hz, *call_graph, events)?;
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

fn validate_common(schema_version: &str, request_id: &str) -> Result<(), ProtocolError> {
    if schema_version != HELPER_SCHEMA_VERSION || !valid_identifier(request_id, "request-", 16, 64)
    {
        return Err(schema_error());
    }
    Ok(())
}

fn validate_mode_fields(
    mode: CollectionMode,
    frequency_hz: Option<u32>,
    call_graph: Option<CallGraph>,
    events: &[String],
) -> Result<(), ProtocolError> {
    if events.len() > MAX_HELPER_EVENTS
        || events
            .iter()
            .any(|event| event.is_empty() || event.len() > 128 || event.contains('\0'))
        || events.iter().collect::<HashSet<_>>().len() != events.len()
    {
        return Err(schema_error());
    }
    match mode {
        CollectionMode::Stat
            if !events.is_empty() && frequency_hz.is_none() && call_graph.is_none() => {}
        CollectionMode::Record
            if events.is_empty()
                && frequency_hz
                    .is_some_and(|value| (1..=MAX_HELPER_FREQUENCY_HZ).contains(&value))
                && call_graph.is_some() => {}
        CollectionMode::Record | CollectionMode::Stat => return Err(schema_error()),
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
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use nix::unistd::geteuid;

    use super::{
        HelperRequest, HelperServerPolicy, ProtocolErrorKind, bind_private_socket,
        handle_connection, parse_request_frame,
    };

    const NOW_MILLISECONDS: u64 = 4_102_444_700_000;
    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn accepts_shared_valid_golden_frames() {
        let fixtures = [
            include_bytes!("../../../tests/fixtures/privileged_helper/valid/health.jsonl")
                .as_slice(),
            include_bytes!("../../../tests/fixtures/privileged_helper/valid/stat.jsonl").as_slice(),
            include_bytes!("../../../tests/fixtures/privileged_helper/valid/record.jsonl")
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
    }

    #[test]
    fn rejects_shared_invalid_golden_frames() {
        let fixtures = [
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/arbitrary-command.jsonl"
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
            include_bytes!("../../../tests/fixtures/privileged_helper/invalid/expired.jsonl")
                .as_slice(),
            include_bytes!(
                "../../../tests/fixtures/privileged_helper/invalid/record-with-events.jsonl"
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
        let frame = br#"{"schema_version":"1.0","operation":"health","request_id":"request-0123456789abcdef"}"#;
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
                HelperServerPolicy {
                    broker_uid: geteuid().as_raw(),
                },
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
        assert!(response.contains("\"schema_version\":\"1.0\""));
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
                HelperServerPolicy {
                    broker_uid: geteuid().as_raw(),
                },
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
}
