//! Fixed, unprivileged process supervision for Runtime Lock adapters.
//!
//! The public protocol contains file-descriptor identities instead of paths.
//! Callers must open and authenticate every executable/input/output before
//! starting the supervisor. The supervisor independently revalidates those
//! identities, launches without a shell, and owns teardown even if its MCP
//! parent disappears.

mod process;
mod sys;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const PROTOCOL_VERSION: &str = "1.0";
pub const SUPERVISOR_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_FRAME_BYTES: usize = 65_536;
pub const MAX_ARGUMENTS: usize = 256;
pub const MAX_ARGUMENT_BYTES: usize = 65_536;
pub const MAX_TIMEOUT_MILLISECONDS: u64 = 30_000;
pub const REQUEST_HANDSHAKE_TIMEOUT_MILLISECONDS: u64 = 5_000;
pub const TERM_GRACE_MILLISECONDS: u64 = 100;
pub const KILL_GRACE_MILLISECONDS: u64 = 1_000;
const MAX_EXECUTABLE_BYTES: u64 = 512 << 20;
const MAX_NATIVE_PROBE_BYTES: u64 = 64 << 20;
const MAX_JAVA_JAR_BYTES: u64 = 512 << 20;
const MAX_JFR_PROFILE_BYTES: u64 = 1 << 20;
const MAX_JFR_RECORDING_BYTES: u64 = 64 << 20;
const MAX_CPYTHON_BOOTSTRAP_BYTES: u64 = 1 << 20;
const MAX_CPYTHON_SCRIPT_BYTES: u64 = 64 << 20;
const MAX_GO_PROFILE_BYTES: u64 = 64 << 20;
const MAX_SUPERVISOR_BYTES: u64 = 64 << 20;
static SUPERVISOR_ACTIVE: AtomicBool = AtomicBool::new(false);

struct SupervisorExecutionGuard;

impl SupervisorExecutionGuard {
    fn acquire() -> Result<Self, SupervisorError> {
        SUPERVISOR_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                SupervisorError::new(
                    "concurrent_supervision",
                    "one runtime supervisor process accepts only one active request",
                )
            })?;
        Ok(Self)
    }
}

impl Drop for SupervisorExecutionGuard {
    fn drop(&mut self) {
        SUPERVISOR_ACTIVE.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub descriptor: RawFd,
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub mode: u32,
    pub links: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WritableFileIdentity {
    pub descriptor: RawFd,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub mode: u32,
    pub links: u64,
    pub maximum_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub descriptor: RawFd,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "adapter", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdapterRequest {
    NativePthread {
        probe: FileIdentity,
        output: WritableFileIdentity,
        semantics: NativeSemantics,
        threshold_ns: Option<u64>,
        max_events: u32,
    },
    JavaJfrWorkload {
        jar: FileIdentity,
        profile: FileIdentity,
        recording: WritableFileIdentity,
    },
    JavaJfrPrint {
        recording_directory: DirectoryIdentity,
        recording_name: String,
        recording: FileIdentity,
        output: WritableFileIdentity,
    },
    CpythonThreading {
        runtime_home: DirectoryIdentity,
        bootstrap: FileIdentity,
        script: FileIdentity,
        script_label: String,
        output: WritableFileIdentity,
        semantics: NativeSemantics,
        threshold_ns: Option<u64>,
        max_events: u32,
    },
    GoPprofWorkload {
        mutex_profile: WritableFileIdentity,
        block_profile: WritableFileIdentity,
    },
    GoPprofRaw {
        profile: FileIdentity,
        output: WritableFileIdentity,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSemantics {
    Exact,
    Thresholded,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorRequest {
    pub schema_version: String,
    pub protocol_version: String,
    pub request_id: String,
    pub expected_parent_pid: u32,
    pub expected_supervisor_sha256: String,
    pub executable: FileIdentity,
    pub working_directory: DirectoryIdentity,
    pub arguments: Vec<String>,
    pub timeout_milliseconds: u64,
    pub request: AdapterRequest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Exited,
    Timeout,
    ParentLost,
    SupervisorSignal,
    SetupFailed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorReceipt {
    pub schema_version: String,
    pub protocol_version: String,
    pub request_id: String,
    pub supervisor_version: String,
    pub supervisor_sha256: String,
    pub workload_pid: u32,
    pub workload_start_ticks: u64,
    pub elapsed_monotonic_ns: u64,
    pub accounted_active_seconds: u64,
    pub exit_code: Option<i32>,
    pub terminating_signal: Option<i32>,
    pub termination_reason: TerminationReason,
    pub term_sent: bool,
    pub kill_sent: bool,
    pub observed_group_descendants: u32,
    pub residual_group_descendants: u32,
    pub cleanup_complete: bool,
}

#[derive(Debug)]
pub struct SupervisorError {
    pub code: &'static str,
    pub message: String,
}

impl SupervisorError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SupervisorError {}

#[derive(Clone, Copy, Debug)]
pub struct ControlDescriptors {
    pub request: RawFd,
    pub receipt: RawFd,
    pub liveness: RawFd,
}

/// Run one already-authorized request to completion and verified teardown.
///
/// # Errors
///
/// Returns an error when the protocol, any descriptor identity, the parent
/// liveness boundary, child setup, or process-group cleanup cannot be proven.
pub fn run_supervisor(control: &ControlDescriptors) -> Result<SupervisorReceipt, SupervisorError> {
    let _execution_guard = SupervisorExecutionGuard::acquire()?;
    validate_control_descriptors(control)?;
    for descriptor in [control.request, control.receipt, control.liveness] {
        set_cloexec(descriptor)?;
    }
    let signal_boundary = process::SupervisorSignalBoundary::new()?;
    sys::set_nonblocking(control.request)?;
    sys::set_nonblocking(control.liveness)?;
    let request_result = read_frame(
        control.request,
        control.liveness,
        signal_boundary.as_raw_fd(),
    );
    close_fd(control.request);
    let request_bytes = request_result?;
    let request: SupervisorRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| SupervisorError::new("invalid_request", error.to_string()))?;
    let validated = validate_request(request, control)?;
    let receipt = process::supervise(&validated, control.liveness, &signal_boundary)?;
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| SupervisorError::new("receipt_encoding_failed", error.to_string()))?;
    write_frame(control.receipt, &receipt_bytes)?;
    Ok(receipt)
}

pub(crate) struct ValidatedRequest {
    pub request: SupervisorRequest,
    pub supervisor_sha256: String,
    pub executable_arguments: Vec<CString>,
    pub environment: Vec<CString>,
    pub retained_child_fds: Vec<RawFd>,
    pub evidence_output: EvidenceOutput,
}

pub(crate) enum EvidenceOutput {
    BoundedStream {
        destination_fd: RawFd,
        maximum_size: u64,
        native_environment_fd: bool,
        redirect_stdout: bool,
    },
    MonitoredFile {
        descriptor: RawFd,
        maximum_size: u64,
    },
    MonitoredFiles {
        first_descriptor: RawFd,
        first_maximum_size: u64,
        second_descriptor: RawFd,
        second_maximum_size: u64,
    },
}

#[allow(clippy::too_many_lines)]
fn validate_request(
    request: SupervisorRequest,
    control: &ControlDescriptors,
) -> Result<ValidatedRequest, SupervisorError> {
    if request.schema_version != "1.0" || request.protocol_version != PROTOCOL_VERSION {
        return Err(SupervisorError::new(
            "protocol_mismatch",
            "request schema or protocol version is unsupported",
        ));
    }
    if !is_lower_hex(&request.request_id, 20)
        || !is_lower_hex(&request.expected_supervisor_sha256, 64)
    {
        return Err(SupervisorError::new(
            "invalid_request",
            "request or supervisor identity is malformed",
        ));
    }
    let actual_parent = sys::parent_pid();
    if request.expected_parent_pid == 0 || request.expected_parent_pid != actual_parent {
        return Err(SupervisorError::new(
            "parent_identity_changed",
            "supervisor parent changed before request validation",
        ));
    }
    if request.timeout_milliseconds == 0 || request.timeout_milliseconds > MAX_TIMEOUT_MILLISECONDS
    {
        return Err(SupervisorError::new(
            "resource_limit_exceeded",
            "timeout exceeds the fixed supervisor bound",
        ));
    }
    validate_arguments(&request.arguments)?;
    validate_adapter_arguments(&request.request, &request.arguments)?;
    let supervisor_sha256 = hash_self()?;
    if supervisor_sha256 != request.expected_supervisor_sha256 {
        return Err(SupervisorError::new(
            "supervisor_identity_changed",
            "running supervisor differs from the package-bound digest",
        ));
    }
    validate_regular_file(&request.executable, true, MAX_EXECUTABLE_BYTES)?;
    validate_directory(&request.working_directory)?;

    let mut descriptors = BTreeSet::from([
        control.receipt,
        control.liveness,
        request.executable.descriptor,
        request.working_directory.descriptor,
    ]);
    let mut retained = vec![request.executable.descriptor];
    let mut environment = vec![c_string("LANG=C")?, c_string("LC_ALL=C")?];
    let mut executable_arguments = Vec::new();
    let evidence_output = match &request.request {
        AdapterRequest::NativePthread {
            probe,
            output,
            semantics,
            threshold_ns,
            max_events,
        } => {
            validate_regular_file(probe, false, MAX_NATIVE_PROBE_BYTES)?;
            validate_writable_file(output)?;
            insert_unique(&mut descriptors, probe.descriptor)?;
            insert_unique(&mut descriptors, output.descriptor)?;
            if *max_events == 0 || *max_events > 20_000 {
                return Err(SupervisorError::new(
                    "resource_limit_exceeded",
                    "Native event budget exceeds 20,000",
                ));
            }
            match (semantics, threshold_ns) {
                (NativeSemantics::Exact, None) => {
                    if request.timeout_milliseconds > 3_000 {
                        return Err(SupervisorError::new(
                            "resource_limit_exceeded",
                            "exact Native supervision exceeds three seconds",
                        ));
                    }
                }
                (NativeSemantics::Thresholded, Some(value))
                    if (1..=1_000_000_000).contains(value) => {}
                _ => {
                    return Err(SupervisorError::new(
                        "invalid_request",
                        "Native measurement threshold is inconsistent with its semantics",
                    ));
                }
            }
            retained.push(probe.descriptor);
            environment.extend([
                c_string(&format!("LD_PRELOAD=/proc/self/fd/{}", probe.descriptor))?,
                c_string(&format!("PERFLENS_RUNTIME_LOCK_MAX_EVENTS={max_events}"))?,
                c_string(&format!(
                    "PERFLENS_RUNTIME_LOCK_MODE={}",
                    match semantics {
                        NativeSemantics::Exact => "exact",
                        NativeSemantics::Thresholded => "thresholded",
                    }
                ))?,
            ]);
            if let Some(value) = threshold_ns {
                environment.push(c_string(&format!(
                    "PERFLENS_RUNTIME_LOCK_THRESHOLD_NS={value}"
                ))?);
            }
            executable_arguments.push(c_string("perflens-native-workload")?);
            executable_arguments.extend(strings_to_c(&request.arguments)?);
            EvidenceOutput::BoundedStream {
                destination_fd: output.descriptor,
                maximum_size: output.maximum_size,
                native_environment_fd: true,
                redirect_stdout: false,
            }
        }
        AdapterRequest::JavaJfrWorkload {
            jar,
            profile,
            recording,
        } => {
            validate_regular_file(jar, false, MAX_JAVA_JAR_BYTES)?;
            validate_regular_file(profile, false, MAX_JFR_PROFILE_BYTES)?;
            validate_writable_file(recording)?;
            for descriptor in [jar.descriptor, profile.descriptor, recording.descriptor] {
                insert_unique(&mut descriptors, descriptor)?;
            }
            retained.extend([jar.descriptor, profile.descriptor, recording.descriptor]);
            environment.push(c_string("PATH=/usr/bin:/bin")?);
            executable_arguments.extend(strings_to_c(&[
                "java".to_owned(),
                "-XX:+DisableAttachMechanism".to_owned(),
                "-XX:FlightRecorderOptions=stackdepth=127".to_owned(),
                format!(
                    "-XX:StartFlightRecording=settings=/proc/self/fd/{},filename=/proc/self/fd/{},dumponexit=true,maxsize={}",
                    profile.descriptor, recording.descriptor, recording.maximum_size
                ),
                "-jar".to_owned(),
                format!("/proc/self/fd/{}", jar.descriptor),
            ])?);
            executable_arguments.extend(strings_to_c(&request.arguments)?);
            EvidenceOutput::MonitoredFile {
                descriptor: recording.descriptor,
                maximum_size: recording.maximum_size,
            }
        }
        AdapterRequest::JavaJfrPrint {
            recording_directory,
            recording_name,
            recording,
            output,
        } => {
            validate_directory(recording_directory)?;
            validate_java_recording_name(recording_name)?;
            validate_regular_file(recording, false, MAX_JFR_RECORDING_BYTES)?;
            validate_named_recording(recording_directory, recording_name, recording)?;
            validate_writable_file(output)?;
            insert_unique(&mut descriptors, recording_directory.descriptor)?;
            insert_unique(&mut descriptors, recording.descriptor)?;
            insert_unique(&mut descriptors, output.descriptor)?;
            retained.extend([recording_directory.descriptor, recording.descriptor]);
            environment.push(c_string("PATH=/usr/bin:/bin")?);
            executable_arguments.extend(strings_to_c(&[
                "jfr".to_owned(),
                "print".to_owned(),
                "--json".to_owned(),
                "--events".to_owned(),
                "jdk.JavaMonitorEnter,jdk.JavaMonitorWait,jdk.ThreadPark,jdk.DataLoss".to_owned(),
                "--stack-depth".to_owned(),
                "127".to_owned(),
                format!(
                    "/proc/self/fd/{}/{}",
                    recording_directory.descriptor, recording_name
                ),
            ])?);
            EvidenceOutput::BoundedStream {
                destination_fd: output.descriptor,
                maximum_size: output.maximum_size,
                native_environment_fd: false,
                redirect_stdout: true,
            }
        }
        AdapterRequest::CpythonThreading {
            runtime_home,
            bootstrap,
            script,
            script_label,
            output,
            semantics,
            threshold_ns,
            max_events,
        } => {
            validate_directory(runtime_home)?;
            validate_regular_file(bootstrap, false, MAX_CPYTHON_BOOTSTRAP_BYTES)?;
            validate_regular_file(script, false, MAX_CPYTHON_SCRIPT_BYTES)?;
            validate_writable_file(output)?;
            for descriptor in [
                runtime_home.descriptor,
                bootstrap.descriptor,
                script.descriptor,
                output.descriptor,
            ] {
                insert_unique(&mut descriptors, descriptor)?;
            }
            validate_cpython_controls(
                *semantics,
                *threshold_ns,
                *max_events,
                request.timeout_milliseconds,
            )?;
            validate_cpython_script_label(script_label)?;
            retained.extend([
                runtime_home.descriptor,
                bootstrap.descriptor,
                script.descriptor,
            ]);
            environment.push(c_string(&format!(
                "PYTHONHOME=/proc/self/fd/{}",
                runtime_home.descriptor
            ))?);
            executable_arguments.extend(strings_to_c(&[
                "python".to_owned(),
                "-P".to_owned(),
                "-B".to_owned(),
                "-s".to_owned(),
                format!("/proc/self/fd/{}", bootstrap.descriptor),
                script.descriptor.to_string(),
                script_label.clone(),
                match semantics {
                    NativeSemantics::Exact => "exact".to_owned(),
                    NativeSemantics::Thresholded => "thresholded".to_owned(),
                },
                threshold_ns.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                max_events.to_string(),
            ])?);
            executable_arguments.extend(strings_to_c(&request.arguments)?);
            EvidenceOutput::BoundedStream {
                destination_fd: output.descriptor,
                maximum_size: output.maximum_size,
                native_environment_fd: true,
                redirect_stdout: false,
            }
        }
        AdapterRequest::GoPprofWorkload {
            mutex_profile,
            block_profile,
        } => {
            validate_writable_file(mutex_profile)?;
            validate_writable_file(block_profile)?;
            insert_unique(&mut descriptors, mutex_profile.descriptor)?;
            insert_unique(&mut descriptors, block_profile.descriptor)?;
            retained.extend([mutex_profile.descriptor, block_profile.descriptor]);
            environment.extend([
                c_string(&format!(
                    "PERFLENS_GO_MUTEX_PROFILE=/proc/self/fd/{}",
                    mutex_profile.descriptor
                ))?,
                c_string(&format!(
                    "PERFLENS_GO_BLOCK_PROFILE=/proc/self/fd/{}",
                    block_profile.descriptor
                ))?,
            ]);
            executable_arguments.push(c_string("perflens-go-workload")?);
            executable_arguments.extend(strings_to_c(&request.arguments)?);
            EvidenceOutput::MonitoredFiles {
                first_descriptor: mutex_profile.descriptor,
                first_maximum_size: mutex_profile.maximum_size,
                second_descriptor: block_profile.descriptor,
                second_maximum_size: block_profile.maximum_size,
            }
        }
        AdapterRequest::GoPprofRaw { profile, output } => {
            validate_regular_file(profile, false, MAX_GO_PROFILE_BYTES)?;
            validate_writable_file(output)?;
            insert_unique(&mut descriptors, profile.descriptor)?;
            insert_unique(&mut descriptors, output.descriptor)?;
            retained.push(profile.descriptor);
            executable_arguments.extend(strings_to_c(&[
                "pprof".to_owned(),
                "-raw".to_owned(),
                format!("/proc/self/fd/{}", profile.descriptor),
            ])?);
            EvidenceOutput::BoundedStream {
                destination_fd: output.descriptor,
                maximum_size: output.maximum_size,
                native_environment_fd: false,
                redirect_stdout: true,
            }
        }
    };
    retained.sort_unstable();
    retained.dedup();
    Ok(ValidatedRequest {
        request,
        supervisor_sha256,
        executable_arguments,
        environment,
        retained_child_fds: retained,
        evidence_output,
    })
}

fn validate_cpython_controls(
    semantics: NativeSemantics,
    threshold_ns: Option<u64>,
    max_events: u32,
    timeout_milliseconds: u64,
) -> Result<(), SupervisorError> {
    if max_events == 0 || max_events > 20_000 {
        return Err(SupervisorError::new(
            "resource_limit_exceeded",
            "CPython event budget exceeds 20,000",
        ));
    }
    match (semantics, threshold_ns) {
        (NativeSemantics::Exact, None) if timeout_milliseconds <= 3_000 => Ok(()),
        (NativeSemantics::Thresholded, Some(10_000)) => Ok(()),
        _ => Err(SupervisorError::new(
            "invalid_request",
            "CPython threshold or exact duration is inconsistent",
        )),
    }
}

fn validate_cpython_script_label(label: &str) -> Result<(), SupervisorError> {
    if label.is_empty()
        || label.len() > 4096
        || label.starts_with('/')
        || label.contains('\\')
        || label
            .chars()
            .any(|character| character.is_control() || character == '\u{7f}')
        || label
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(SupervisorError::new(
            "invalid_request",
            "CPython script label must be one safe project-relative path",
        ));
    }
    Ok(())
}

fn insert_unique(set: &mut BTreeSet<RawFd>, descriptor: RawFd) -> Result<(), SupervisorError> {
    if descriptor < 3 || !set.insert(descriptor) {
        return Err(SupervisorError::new(
            "invalid_request",
            "file descriptors must be distinct positive non-stdio values",
        ));
    }
    Ok(())
}

fn validate_control_descriptors(control: &ControlDescriptors) -> Result<(), SupervisorError> {
    let values = [control.request, control.receipt, control.liveness];
    if values.iter().any(|descriptor| *descriptor < 3)
        || values.into_iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(SupervisorError::new(
            "invalid_control",
            "control descriptors must be distinct non-stdio values",
        ));
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), SupervisorError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(SupervisorError::new(
            "resource_limit_exceeded",
            "argument count exceeds the fixed bound",
        ));
    }
    let total = arguments.iter().try_fold(0_usize, |size, argument| {
        if argument.as_bytes().contains(&0) {
            return None;
        }
        size.checked_add(argument.len())
    });
    if total.is_none_or(|size| size > MAX_ARGUMENT_BYTES) {
        return Err(SupervisorError::new(
            "resource_limit_exceeded",
            "argument bytes exceed the fixed bound",
        ));
    }
    Ok(())
}

fn validate_adapter_arguments(
    adapter: &AdapterRequest,
    arguments: &[String],
) -> Result<(), SupervisorError> {
    if matches!(
        adapter,
        AdapterRequest::JavaJfrPrint { .. } | AdapterRequest::GoPprofRaw { .. }
    ) && !arguments.is_empty()
    {
        return Err(SupervisorError::new(
            "invalid_request",
            "runtime profile conversion does not accept workload arguments",
        ));
    }
    Ok(())
}

fn validate_regular_file(
    identity: &FileIdentity,
    executable: bool,
    maximum_size: u64,
) -> Result<(), SupervisorError> {
    if identity.descriptor < 3 || !is_lower_hex(&identity.sha256, 64) {
        return Err(SupervisorError::new(
            "invalid_identity",
            "file identity is malformed",
        ));
    }
    let metadata = metadata_for_fd(identity.descriptor)?;
    let mode = metadata.mode() & 0o7777;
    let allowed = if executable {
        matches!(mode, 0o500 | 0o550 | 0o555 | 0o700 | 0o750 | 0o755)
    } else {
        matches!(mode, 0o400 | 0o440 | 0o444 | 0o600 | 0o640 | 0o644)
    };
    if !metadata.file_type().is_file()
        || metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || metadata.uid() != identity.owner_uid
        || mode != identity.mode
        || metadata.nlink() != identity.links
        || metadata.size() != identity.size
        || identity.size == 0
        || identity.size > maximum_size
        || !allowed
        || mode & 0o6000 != 0
    {
        return Err(SupervisorError::new(
            "identity_changed",
            "file descriptor differs from its authorized identity",
        ));
    }
    if hash_fd_exact(identity.descriptor, identity.size)? != identity.sha256 {
        return Err(SupervisorError::new(
            "identity_changed",
            "file content differs from its authorized digest",
        ));
    }
    if executable && sys::has_file_capabilities(identity.descriptor)? {
        return Err(SupervisorError::new(
            "privilege_boundary_violation",
            "executable file capabilities are forbidden",
        ));
    }
    Ok(())
}

fn validate_writable_file(identity: &WritableFileIdentity) -> Result<(), SupervisorError> {
    if identity.descriptor < 3 || identity.maximum_size == 0 || identity.maximum_size > 64 << 20 {
        return Err(SupervisorError::new(
            "invalid_identity",
            "writable evidence identity is malformed",
        ));
    }
    let metadata = metadata_for_fd(identity.descriptor)?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || metadata.uid() != identity.owner_uid
        || mode != identity.mode
        || metadata.nlink() != identity.links
        || identity.links != 1
        || metadata.size() != 0
        || mode != 0o600
    {
        return Err(SupervisorError::new(
            "identity_changed",
            "writable evidence differs from its authorized identity",
        ));
    }
    let flags = sys::file_status_flags(identity.descriptor)?;
    if flags & libc::O_ACCMODE == libc::O_RDONLY || flags & libc::O_APPEND != 0 {
        return Err(SupervisorError::new(
            "identity_changed",
            "writable evidence descriptor access flags are unsafe",
        ));
    }
    Ok(())
}

fn validate_directory(identity: &DirectoryIdentity) -> Result<(), SupervisorError> {
    if identity.descriptor < 3 {
        return Err(SupervisorError::new(
            "invalid_identity",
            "working directory descriptor is invalid",
        ));
    }
    let metadata = metadata_for_fd(identity.descriptor)?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_dir()
        || metadata.dev() != identity.device
        || metadata.ino() != identity.inode
        || metadata.uid() != identity.owner_uid
        || mode != identity.mode
        || mode & 0o022 != 0
    {
        return Err(SupervisorError::new(
            "identity_changed",
            "working directory differs from its authorized identity",
        ));
    }
    Ok(())
}

fn validate_java_recording_name(name: &str) -> Result<(), SupervisorError> {
    let token = name
        .strip_prefix("java-jfr-")
        .and_then(|value| value.strip_suffix(".jfr"));
    if token.is_none_or(|value| !is_lower_hex(value, 20)) {
        return Err(SupervisorError::new(
            "invalid_request",
            "Java recording name is outside the fixed private naming contract",
        ));
    }
    Ok(())
}

fn validate_named_recording(
    directory: &DirectoryIdentity,
    name: &str,
    recording: &FileIdentity,
) -> Result<(), SupervisorError> {
    let path = format!("/proc/self/fd/{}/{}", directory.descriptor, name);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.dev() != recording.device
        || metadata.ino() != recording.inode
        || metadata.uid() != recording.owner_uid
        || metadata.mode() & 0o7777 != recording.mode
        || metadata.nlink() != recording.links
        || metadata.size() != recording.size
    {
        return Err(SupervisorError::new(
            "identity_changed",
            "Java recording name differs from its authorized descriptor",
        ));
    }
    Ok(())
}

fn metadata_for_fd(descriptor: RawFd) -> Result<std::fs::Metadata, SupervisorError> {
    std::fs::metadata(format!("/proc/self/fd/{descriptor}"))
        .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))
}

fn hash_fd_exact(descriptor: RawFd, expected_size: u64) -> Result<String, SupervisorError> {
    let duplicate = duplicate_cloexec(descriptor)?;
    // SAFETY: `duplicate_cloexec` returned a new owned descriptor and this is
    // the sole conversion of that descriptor into `File`.
    let mut file = sys::owned_file(duplicate);
    let original = file
        .stream_position()
        .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))?;
    file.rewind()
        .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20].into_boxed_slice();
    let mut remaining = expected_size;
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            SupervisorError::new("identity_unavailable", "file size cannot be represented")
        })?;
        let count = file
            .read(&mut buffer[..requested])
            .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))?;
        if count == 0 {
            return Err(SupervisorError::new(
                "identity_changed",
                "file became shorter while its digest was computed",
            ));
        }
        digest.update(&buffer[..count]);
        remaining = remaining.saturating_sub(count as u64);
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))?
        != 0
    {
        return Err(SupervisorError::new(
            "identity_changed",
            "file became longer while its digest was computed",
        ));
    }
    file.seek(io::SeekFrom::Start(original))
        .map_err(|error| SupervisorError::new("identity_unavailable", error.to_string()))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_self() -> Result<String, SupervisorError> {
    let file = File::open("/proc/self/exe").map_err(|error| {
        SupervisorError::new("supervisor_identity_unavailable", error.to_string())
    })?;
    let size = file
        .metadata()
        .map_err(|error| {
            SupervisorError::new("supervisor_identity_unavailable", error.to_string())
        })?
        .len();
    if size == 0 || size > MAX_SUPERVISOR_BYTES {
        return Err(SupervisorError::new(
            "supervisor_identity_unavailable",
            "supervisor size exceeds the fixed identity bound",
        ));
    }
    if sys::has_file_capabilities(file.as_raw_fd())? {
        return Err(SupervisorError::new(
            "privilege_boundary_violation",
            "runtime supervisor file capabilities are forbidden",
        ));
    }
    hash_fd_exact(file.as_raw_fd(), size)
}

fn duplicate_cloexec(descriptor: RawFd) -> Result<RawFd, SupervisorError> {
    sys::duplicate_cloexec(descriptor)
}

fn set_cloexec(descriptor: RawFd) -> Result<(), SupervisorError> {
    sys::set_cloexec(descriptor)
}

fn read_frame(
    descriptor: RawFd,
    liveness_fd: RawFd,
    signal_fd: RawFd,
) -> Result<Vec<u8>, SupervisorError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(
            REQUEST_HANDSHAKE_TIMEOUT_MILLISECONDS,
        ))
        .ok_or_else(|| SupervisorError::new("request_timeout", "request deadline overflowed"))?;
    let mut prefix = [0_u8; 4];
    read_frame_part(descriptor, liveness_fd, signal_fd, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(SupervisorError::new(
            "malformed_frame",
            "frame length exceeds the fixed bound",
        ));
    }
    let mut payload = vec![0_u8; length];
    read_frame_part(descriptor, liveness_fd, signal_fd, &mut payload, deadline)?;
    let mut trailing = [0_u8; 1];
    loop {
        check_request_boundary(liveness_fd, signal_fd, deadline)?;
        match sys::read_nonblocking(descriptor, &mut trailing) {
            Ok(0) => return Ok(payload),
            Ok(_) => {
                return Err(SupervisorError::new(
                    "malformed_frame",
                    "request contains trailing bytes",
                ));
            }
            Err(error) if is_would_block(&error) => {
                poll_request_boundary(descriptor, liveness_fd, signal_fd)?;
            }
            Err(error) => {
                return Err(SupervisorError::new("malformed_frame", error.to_string()));
            }
        }
    }
}

fn read_frame_part(
    descriptor: RawFd,
    liveness_fd: RawFd,
    signal_fd: RawFd,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), SupervisorError> {
    let mut offset = 0_usize;
    while offset < output.len() {
        check_request_boundary(liveness_fd, signal_fd, deadline)?;
        let count = match sys::read_nonblocking(descriptor, &mut output[offset..]) {
            Ok(count) => count,
            Err(error) if is_would_block(&error) => {
                poll_request_boundary(descriptor, liveness_fd, signal_fd)?;
                continue;
            }
            Err(error) => {
                return Err(SupervisorError::new("malformed_frame", error.to_string()));
            }
        };
        if count == 0 {
            return Err(SupervisorError::new(
                "malformed_frame",
                "request frame ended before its declared length",
            ));
        }
        offset += count;
    }
    Ok(())
}

fn check_request_boundary(
    liveness_fd: RawFd,
    signal_fd: RawFd,
    deadline: Instant,
) -> Result<(), SupervisorError> {
    if process::supervisor_signal_pending(signal_fd)? {
        return Err(SupervisorError::new(
            "supervisor_interrupted",
            "supervisor received a termination signal before workload launch",
        ));
    }
    let mut byte = [0_u8; 1];
    match sys::read_nonblocking(liveness_fd, &mut byte) {
        Ok(_) => {
            return Err(SupervisorError::new(
                "parent_lost",
                "supervisor parent disappeared during request framing",
            ));
        }
        Err(error) if is_would_block(&error) => {}
        Err(error) => {
            return Err(SupervisorError::new(
                "liveness_pipe_failed",
                error.to_string(),
            ));
        }
    }
    if Instant::now() >= deadline {
        return Err(SupervisorError::new(
            "request_timeout",
            "request frame was not completed within five seconds",
        ));
    }
    Ok(())
}

fn poll_request_boundary(
    request_fd: RawFd,
    liveness_fd: RawFd,
    signal_fd: RawFd,
) -> Result<(), SupervisorError> {
    sys::poll_readable(&[request_fd, liveness_fd, signal_fd], 10)
        .map_err(|error| SupervisorError::new("request_poll_failed", error.to_string()))
}

fn is_would_block(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK)
}

fn write_frame(descriptor: RawFd, payload: &[u8]) -> Result<(), SupervisorError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(SupervisorError::new(
            "receipt_encoding_failed",
            "receipt frame exceeds the fixed bound",
        ));
    }
    let duplicate = duplicate_cloexec(descriptor)?;
    // SAFETY: the duplicated descriptor is uniquely owned by this `File`.
    let mut file = sys::owned_file(duplicate);
    let length = u32::try_from(payload.len()).map_err(|_| {
        SupervisorError::new(
            "receipt_encoding_failed",
            "receipt length cannot be represented",
        )
    })?;
    file.write_all(&length.to_be_bytes())
        .and_then(|()| file.write_all(payload))
        .map_err(|error| SupervisorError::new("receipt_write_failed", error.to_string()))
}

fn strings_to_c(values: &[String]) -> Result<Vec<CString>, SupervisorError> {
    values.iter().map(|value| c_string(value)).collect()
}

fn c_string(value: &str) -> Result<CString, SupervisorError> {
    CString::new(value).map_err(|_| SupervisorError::new("invalid_request", "value contains NUL"))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn close_fd(descriptor: RawFd) {
    sys::close_fd(descriptor);
}

#[must_use]
pub const fn accounted_active_seconds(elapsed_monotonic_ns: u64) -> u64 {
    elapsed_monotonic_ns.saturating_add(999_999_999) / 1_000_000_000
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::{
        AdapterRequest, ControlDescriptors, DirectoryIdentity, FileIdentity, NativeSemantics,
        SupervisorError, SupervisorReceipt, SupervisorRequest, TerminationReason,
        WritableFileIdentity, accounted_active_seconds, run_supervisor, validate_adapter_arguments,
        validate_cpython_controls, validate_cpython_script_label,
    };
    use sha2::{Digest, Sha256};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    static SUPERVISOR_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn active_seconds_are_derived_only_from_monotonic_elapsed() {
        assert_eq!(accounted_active_seconds(0), 0);
        assert_eq!(accounted_active_seconds(1), 1);
        assert_eq!(accounted_active_seconds(1_000_000_000), 1);
        assert_eq!(accounted_active_seconds(1_000_000_001), 2);
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let error = serde_json::from_str::<SupervisorRequest>(
            r#"{"schema_version":"1.0","unexpected":true}"#,
        )
        .expect_err("unknown field must fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn shared_protocol_goldens_are_strict() {
        for valid in [
            include_str!("../../../tests/fixtures/runtime_supervisor/valid-native-request.json"),
            include_str!("../../../tests/fixtures/runtime_supervisor/valid-cpython-request.json"),
            include_str!(
                "../../../tests/fixtures/runtime_supervisor/valid-go-workload-request.json"
            ),
            include_str!("../../../tests/fixtures/runtime_supervisor/valid-go-raw-request.json"),
            include_str!(
                "../../../tests/fixtures/runtime_supervisor/valid-java-workload-request.json"
            ),
            include_str!(
                "../../../tests/fixtures/runtime_supervisor/valid-java-print-request.json"
            ),
        ] {
            serde_json::from_str::<SupervisorRequest>(valid).expect("valid shared request");
        }
        let invalid =
            include_str!("../../../tests/fixtures/runtime_supervisor/invalid-unknown-field.json");
        let error = serde_json::from_str::<SupervisorRequest>(invalid)
            .expect_err("shared unknown-field request must fail");
        assert!(error.to_string().contains("unknown field"));
        let duplicate =
            include_str!("../../../tests/fixtures/runtime_supervisor/invalid-duplicate-field.json");
        let error = serde_json::from_str::<SupervisorRequest>(duplicate)
            .expect_err("shared duplicate-field request must fail");
        assert!(error.to_string().contains("duplicate field"));

        let valid_receipt = include_str!(
            "../../../tests/fixtures/runtime_supervisor/valid-supervisor-receipt.json"
        );
        serde_json::from_str::<SupervisorReceipt>(valid_receipt).expect("valid shared receipt");
        let invalid_receipt = include_str!(
            "../../../tests/fixtures/runtime_supervisor/invalid-supervisor-receipt-unknown-field.json"
        );
        let error = serde_json::from_str::<SupervisorReceipt>(invalid_receipt)
            .expect_err("shared unknown-field receipt must fail");
        assert!(error.to_string().contains("unknown field"));
        let duplicate_receipt = include_str!(
            "../../../tests/fixtures/runtime_supervisor/invalid-supervisor-receipt-duplicate-field.json"
        );
        let error = serde_json::from_str::<SupervisorReceipt>(duplicate_receipt)
            .expect_err("shared duplicate-field receipt must fail");
        assert!(error.to_string().contains("duplicate field"));
    }

    #[test]
    fn java_print_rejects_semantically_ignored_arguments() {
        let valid: SupervisorRequest = serde_json::from_str(include_str!(
            "../../../tests/fixtures/runtime_supervisor/valid-java-print-request.json"
        ))
        .expect("valid Java print request");
        validate_adapter_arguments(&valid.request, &valid.arguments)
            .expect("argument-free Java print");
        let invalid: SupervisorRequest = serde_json::from_str(include_str!(
            "../../../tests/fixtures/runtime_supervisor/invalid-java-print-arguments.json"
        ))
        .expect("structurally valid Java print request");
        let error = validate_adapter_arguments(&invalid.request, &invalid.arguments)
            .expect_err("Java print arguments must be rejected");
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn go_raw_rejects_semantically_ignored_arguments() {
        let valid: SupervisorRequest = serde_json::from_str(include_str!(
            "../../../tests/fixtures/runtime_supervisor/valid-go-raw-request.json"
        ))
        .expect("valid Go raw request");
        validate_adapter_arguments(&valid.request, &valid.arguments)
            .expect("argument-free Go raw conversion");
        let mut invalid = valid;
        invalid.arguments.push("unexpected".to_owned());
        let error = validate_adapter_arguments(&invalid.request, &invalid.arguments)
            .expect_err("Go raw arguments must be rejected");
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn cpython_controls_enforce_exact_threshold_duration_and_event_bounds() {
        validate_cpython_controls(NativeSemantics::Exact, None, 20_000, 3_000)
            .expect("bounded exact controls");
        validate_cpython_controls(NativeSemantics::Thresholded, Some(10_000), 20_000, 30_000)
            .expect("fixed thresholded controls");

        for (semantics, threshold, events, timeout) in [
            (NativeSemantics::Exact, Some(10_000), 20_000, 3_000),
            (NativeSemantics::Exact, None, 20_000, 3_001),
            (NativeSemantics::Thresholded, Some(9_999), 20_000, 30_000),
            (NativeSemantics::Thresholded, Some(10_000), 0, 30_000),
            (NativeSemantics::Thresholded, Some(10_000), 20_001, 30_000),
        ] {
            validate_cpython_controls(semantics, threshold, events, timeout)
                .expect_err("unsafe CPython controls must fail");
        }
    }

    #[test]
    fn cpython_script_label_rejects_host_paths_and_traversal() {
        validate_cpython_script_label("workloads/locks.py").expect("safe project-relative label");
        for label in [
            "",
            "/etc/passwd",
            "../escape.py",
            "workloads/../escape.py",
            "workloads//locks.py",
            "workloads\\locks.py",
            "workloads/locks.py\nsecret",
        ] {
            validate_cpython_script_label(label).expect_err("unsafe source label must fail");
        }
    }

    #[test]
    fn malformed_frame_is_rejected_before_any_workload() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        let (request_read, request_write) = pipe();
        let (receipt_read, receipt_write) = pipe();
        let (liveness_read, liveness_write) = pipe();
        // SAFETY: the write descriptor is uniquely transferred to this File.
        let mut request = unsafe { File::from_raw_fd(request_write) };
        request
            .write_all(
                &(u32::try_from(super::MAX_FRAME_BYTES).expect("frame bound fits u32") + 1)
                    .to_be_bytes(),
            )
            .expect("write oversized prefix");
        drop(request);
        let error = run_supervisor(&ControlDescriptors {
            request: request_read,
            receipt: receipt_write,
            liveness: liveness_read,
        })
        .expect_err("oversized frame must fail");
        assert_eq!(error.code, "malformed_frame");
        for descriptor in [receipt_read, receipt_write, liveness_read, liveness_write] {
            super::sys::close_fd(descriptor);
        }
    }

    #[test]
    fn normal_exit_uses_monotonic_receipt_and_isolates_wall_clock() {
        let receipt = run_native_case(&["-c", "exit 7"], 2_000, None);
        assert_eq!(receipt.termination_reason, TerminationReason::Exited);
        assert_eq!(receipt.exit_code, Some(7));
        assert!(receipt.cleanup_complete);
        assert!(receipt.term_sent && receipt.kill_sent);
        assert_eq!(
            receipt.accounted_active_seconds,
            accounted_active_seconds(receipt.elapsed_monotonic_ns)
        );
        let encoded = serde_json::to_value(receipt).expect("serialize receipt");
        assert!(encoded.get("started_at").is_none());
        assert!(encoded.get("finished_at").is_none());
    }

    #[test]
    fn independent_timeout_kills_term_ignoring_workload() {
        let receipt = run_native_case(&["-c", "trap '' TERM; while :; do sleep 1; done"], 80, None);
        assert_eq!(receipt.termination_reason, TerminationReason::Timeout);
        assert_eq!(receipt.terminating_signal, Some(libc::SIGKILL));
        assert!(receipt.cleanup_complete);
        assert!(receipt.elapsed_monotonic_ns >= 80_000_000);
    }

    #[test]
    fn parent_liveness_eof_cleans_workload_without_waiting_for_timeout() {
        let receipt = run_native_case(
            &["-c", "trap '' TERM; while :; do sleep 1; done"],
            5_000,
            Some(Duration::from_secs(3)),
        );
        assert_eq!(receipt.termination_reason, TerminationReason::ParentLost);
        assert!(receipt.cleanup_complete);
        assert!(receipt.elapsed_monotonic_ns < 2_000_000_000);
    }

    #[test]
    fn leader_exit_still_removes_grandchild_and_unrelated_process_survives() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        let mut unrelated = std::process::Command::new("/usr/bin/sleep")
            .arg("5")
            .spawn()
            .expect("start unrelated process");
        let (receipt, _) = execute_native_case_with_maximum(
            &["-c", "(trap '' TERM; while :; do sleep 1; done) & exit 0"],
            2_000,
            None,
            64 << 20,
        )
        .expect("supervised workload");
        assert_eq!(receipt.termination_reason, TerminationReason::Exited);
        assert!(receipt.observed_group_descendants >= 1);
        assert_eq!(receipt.residual_group_descendants, 0);
        assert!(receipt.cleanup_complete);
        assert!(unrelated.try_wait().expect("check unrelated").is_none());
        unrelated.kill().expect("stop unrelated");
        unrelated.wait().expect("reap unrelated");
    }

    #[test]
    fn final_post_reap_sweep_removes_forking_session_escapees() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        let before = super::process::direct_child_identities(std::process::id(), false)
            .expect("baseline children");
        let (receipt, _) = execute_native_case_with_maximum(
            &[
                "-c",
                "trap '' TERM; while :; do /usr/bin/setsid /usr/bin/sleep 1 & /usr/bin/sleep 0.01; done",
            ],
            80,
            None,
            4_096,
        )
        .expect("forking workload receipt");
        assert_eq!(receipt.termination_reason, TerminationReason::Timeout);
        assert_eq!(receipt.residual_group_descendants, 0);
        assert!(receipt.cleanup_complete);
        let after = super::process::direct_child_identities(std::process::id(), false)
            .expect("children after final sweep");
        assert_eq!(after, before);
    }

    #[test]
    fn child_file_writes_cannot_exceed_the_authorized_evidence_limit() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        let before = super::process::direct_child_identities(std::process::id(), false)
            .expect("baseline children");
        let (result, output) = execute_native_case_raw(
            &[
                "-c",
                "/usr/bin/python3 -c 'import os; os.write(int(os.environ[\"PERFLENS_RUNTIME_LOCK_FD\"]), b\"x\" * 8192)'",
            ],
            2_000,
            None,
            4_096,
        );
        let error = result.expect_err("oversized evidence must fail closed");
        assert_eq!(error.code, "resource_limit_exceeded");
        assert_eq!(output.len(), 4_096);
        let after = super::process::direct_child_identities(std::process::id(), false)
            .expect("children after evidence-bound cleanup");
        assert_eq!(after, before);
    }

    #[test]
    fn evidence_limit_does_not_restrict_unrelated_workload_files() {
        let (receipt, output) = run_native_case_with_maximum(
            &[
                "-c",
                "/usr/bin/dd if=/dev/zero of=unrelated.bin bs=8192 count=1 2>/dev/null; /usr/bin/python3 -c 'import os; os.write(int(os.environ[\"PERFLENS_RUNTIME_LOCK_FD\"]), str(os.path.getsize(\"unrelated.bin\")).encode())'",
            ],
            2_000,
            None,
            4_096,
        );
        assert_eq!(receipt.termination_reason, TerminationReason::Exited);
        assert_eq!(
            std::str::from_utf8(&output)
                .expect("ASCII byte count")
                .trim(),
            "8192"
        );
        assert!(receipt.cleanup_complete);
    }

    #[test]
    fn session_escape_descendant_is_discovered_and_killed() {
        let (receipt, output) = run_native_case_with_maximum(
            &[
                "-c",
                "/usr/bin/setsid /usr/bin/python3 -c 'import os,time; os.write(int(os.environ[\"PERFLENS_RUNTIME_LOCK_FD\"]), str(os.getpid()).encode()); time.sleep(20)' & /usr/bin/sleep 0.1; exit 0",
            ],
            2_000,
            None,
            4_096,
        );
        let escaped_pid: u32 = std::str::from_utf8(&output)
            .expect("UTF-8 escaped PID")
            .trim()
            .parse()
            .expect("escaped PID");
        assert!(receipt.observed_group_descendants >= 1);
        assert_eq!(receipt.residual_group_descendants, 0);
        assert!(receipt.cleanup_complete);
        assert!(super::process::read_process_identity(escaped_pid).is_none());
    }

    #[test]
    fn pidfd_failure_runs_emergency_cleanup_and_reaps_leader() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        let before = super::process::direct_child_identities(std::process::id(), false)
            .expect("baseline children");
        super::process::inject_pidfd_open_failure();
        let error =
            execute_native_case_with_maximum(&["-c", "exec /usr/bin/sleep 20"], 2_000, None, 4_096)
                .expect_err("injected pidfd failure");
        assert_eq!(error.code, "pidfd_unavailable");
        let after = super::process::direct_child_identities(std::process::id(), false)
            .expect("children after cleanup");
        assert_eq!(after, before);
    }

    #[test]
    fn process_scan_failure_runs_emergency_cleanup_and_reaps_leader() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        let before = super::process::direct_child_identities(std::process::id(), false)
            .expect("baseline children");
        super::process::inject_process_scan_failure();
        let error = execute_native_case_with_maximum(&["-c", "exit 0"], 2_000, None, 4_096)
            .expect_err("injected process scan failure");
        assert_eq!(error.code, "procfs_unavailable");
        let after = super::process::direct_child_identities(std::process::id(), false)
            .expect("children after cleanup");
        assert_eq!(after, before);
    }

    #[test]
    fn close_range_failure_is_reported_as_child_setup_failure() {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        super::process::inject_close_range_failure();
        let (receipt, _) = execute_native_case_with_maximum(&["-c", "exit 0"], 2_000, None, 4_096)
            .expect("setup failure receipt");
        super::process::clear_close_range_failure();
        assert_eq!(receipt.termination_reason, TerminationReason::SetupFailed);
        assert_eq!(receipt.exit_code, Some(126));
        assert!(receipt.cleanup_complete);
    }

    #[test]
    fn partial_request_frames_honor_parent_liveness() {
        let cases: &[&[u8]] = &[&[0, 0], &[0, 0, 0, 10, b'{'], &[0, 0, 0, 2, b'{', b'}']];
        for payload in cases {
            let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
            let (request_read, request_write) = pipe();
            let (receipt_read, receipt_write) = pipe();
            let (liveness_read, liveness_write) = pipe();
            // SAFETY: the write descriptor is uniquely transferred to this File.
            let mut request = unsafe { File::from_raw_fd(request_write) };
            request.write_all(payload).expect("write partial request");
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                super::sys::close_fd(liveness_write);
            });
            let started = std::time::Instant::now();
            let error = run_supervisor(&ControlDescriptors {
                request: request_read,
                receipt: receipt_write,
                liveness: liveness_read,
            })
            .expect_err("partial request must stop on parent loss");
            assert_eq!(error.code, "parent_lost");
            assert!(started.elapsed() < Duration::from_secs(1));
            drop(request);
            for descriptor in [receipt_read, receipt_write, liveness_read] {
                super::sys::close_fd(descriptor);
            }
        }
    }

    fn run_native_case(
        arguments: &[&str],
        timeout_milliseconds: u64,
        close_liveness_after: Option<Duration>,
    ) -> SupervisorReceipt {
        run_native_case_with_maximum(
            arguments,
            timeout_milliseconds,
            close_liveness_after,
            64 << 20,
        )
        .0
    }

    fn run_native_case_with_maximum(
        arguments: &[&str],
        timeout_milliseconds: u64,
        close_liveness_after: Option<Duration>,
        maximum_output_bytes: u64,
    ) -> (SupervisorReceipt, Vec<u8>) {
        let _guard = SUPERVISOR_TEST_LOCK.lock().expect("test supervisor lock");
        execute_native_case_with_maximum(
            arguments,
            timeout_milliseconds,
            close_liveness_after,
            maximum_output_bytes,
        )
        .expect("supervised workload")
    }

    fn execute_native_case_with_maximum(
        arguments: &[&str],
        timeout_milliseconds: u64,
        close_liveness_after: Option<Duration>,
        maximum_output_bytes: u64,
    ) -> Result<(SupervisorReceipt, Vec<u8>), SupervisorError> {
        let (result, output) = execute_native_case_raw(
            arguments,
            timeout_milliseconds,
            close_liveness_after,
            maximum_output_bytes,
        );
        result.map(|receipt| (receipt, output))
    }

    fn execute_native_case_raw(
        arguments: &[&str],
        timeout_milliseconds: u64,
        close_liveness_after: Option<Duration>,
        maximum_output_bytes: u64,
    ) -> (Result<SupervisorReceipt, SupervisorError>, Vec<u8>) {
        let directory = private_test_directory();
        let probe_path = directory.join("probe.so");
        fs::write(&probe_path, b"not-a-real-preload-library").expect("write dummy probe");
        fs::set_permissions(&probe_path, fs::Permissions::from_mode(0o644))
            .expect("set probe mode");
        let output_path = directory.join("events.ndjson");
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output_path)
            .expect("create output");
        let executable = File::open("/usr/bin/dash").expect("open dash");
        let probe = File::open(&probe_path).expect("open probe");
        let working_directory = File::open(&directory).expect("open working directory");
        let (request_read, request_write) = pipe();
        let (receipt_read, receipt_write) = pipe();
        let (liveness_read, liveness_write) = pipe();
        let request = SupervisorRequest {
            schema_version: "1.0".to_owned(),
            protocol_version: super::PROTOCOL_VERSION.to_owned(),
            request_id: "0123456789abcdefabcd".to_owned(),
            expected_parent_pid: super::sys::parent_pid(),
            expected_supervisor_sha256: hash_path(Path::new("/proc/self/exe")),
            executable: file_identity(&executable),
            working_directory: directory_identity(&working_directory),
            arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
            timeout_milliseconds,
            request: AdapterRequest::NativePthread {
                probe: file_identity(&probe),
                output: writable_identity(&output, maximum_output_bytes),
                semantics: NativeSemantics::Thresholded,
                threshold_ns: Some(1_000),
                max_events: 20_000,
            },
        };
        write_json_frame(request_write, &request);
        if let Some(child_start_timeout) = close_liveness_after {
            let existing_children =
                super::process::direct_child_identities(std::process::id(), false)
                    .expect("snapshot children before liveness test");
            thread::spawn(move || {
                let deadline = std::time::Instant::now() + child_start_timeout;
                loop {
                    let child_started =
                        super::process::direct_child_identities(std::process::id(), false)
                            .is_ok_and(|children| children != existing_children);
                    if child_started || std::time::Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                super::sys::close_fd(liveness_write);
            });
        }
        let receipt_result = run_supervisor(&ControlDescriptors {
            request: request_read,
            receipt: receipt_write,
            liveness: liveness_read,
        });
        if close_liveness_after.is_none() {
            super::sys::close_fd(liveness_write);
        }
        let decoded = receipt_result.as_ref().ok().map(|receipt| {
            let decoded: SupervisorReceipt = read_json_frame(receipt_read);
            assert_eq!(decoded.request_id, receipt.request_id);
            decoded
        });
        for descriptor in [receipt_read, receipt_write, liveness_read] {
            super::sys::close_fd(descriptor);
        }
        let output_payload = fs::read(&output_path).expect("read output");
        drop((output, executable, probe, working_directory));
        fs::remove_dir_all(directory).expect("remove test directory");
        let result = receipt_result.inspect(|receipt| {
            assert_eq!(
                decoded.as_ref().expect("successful receipt").request_id,
                receipt.request_id
            );
        });
        (result, output_payload)
    }

    fn private_test_directory() -> PathBuf {
        for _ in 0..128 {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "perflens-runtime-supervisor-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("set private mode");
                    return path;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create test directory: {error}"),
            }
        }
        panic!("test directory collision bound exhausted")
    }

    fn pipe() -> (RawFd, RawFd) {
        let mut descriptors = [-1_i32; 2];
        // SAFETY: `pipe2` writes two descriptors into the valid array.
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        descriptors.into()
    }

    fn file_identity(file: &File) -> FileIdentity {
        let metadata = file.metadata().expect("file metadata");
        FileIdentity {
            descriptor: file.as_raw_fd(),
            sha256: hash_file(file),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            links: metadata.nlink(),
            size: metadata.size(),
        }
    }

    fn writable_identity(file: &File, maximum_size: u64) -> WritableFileIdentity {
        let metadata = file.metadata().expect("writable metadata");
        WritableFileIdentity {
            descriptor: file.as_raw_fd(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            links: metadata.nlink(),
            maximum_size,
        }
    }

    fn directory_identity(file: &File) -> DirectoryIdentity {
        let metadata = file.metadata().expect("directory metadata");
        DirectoryIdentity {
            descriptor: file.as_raw_fd(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
        }
    }

    fn hash_file(file: &File) -> String {
        hash_path(Path::new(&format!("/proc/self/fd/{}", file.as_raw_fd())))
    }

    fn hash_path(path: &Path) -> String {
        let mut file = File::open(path).expect("open hash input");
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 8192];
        while let count = file.read(&mut buffer).expect("read hash input")
            && count != 0
        {
            digest.update(&buffer[..count]);
        }
        format!("{:x}", digest.finalize())
    }

    fn write_json_frame<T: serde::Serialize>(descriptor: RawFd, value: &T) {
        // SAFETY: the write descriptor is uniquely transferred to this File.
        let mut output = unsafe { File::from_raw_fd(descriptor) };
        let payload = serde_json::to_vec(value).expect("encode frame");
        let length = u32::try_from(payload.len()).expect("bounded test frame");
        output
            .write_all(&length.to_be_bytes())
            .expect("write prefix");
        output.write_all(&payload).expect("write payload");
    }

    fn read_json_frame<T: serde::de::DeserializeOwned>(descriptor: RawFd) -> T {
        let duplicate = super::sys::duplicate_cloexec(descriptor).expect("duplicate receipt");
        let mut input = super::sys::owned_file(duplicate);
        let mut prefix = [0_u8; 4];
        input.read_exact(&mut prefix).expect("read receipt prefix");
        let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
        input
            .read_exact(&mut payload)
            .expect("read receipt payload");
        serde_json::from_slice(&payload).expect("decode receipt")
    }
}
