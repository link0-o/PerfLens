//! Linux process-boundary implementation.
//!
//! This is the only module allowed to use unsafe FFI. Every unsafe block wraps
//! one Linux/POSIX syscall with integer descriptors/PIDs or pointers backed by
//! pre-fork `CString` storage. No Rust allocation, lock, or unwinding occurs in
//! the post-fork child before `execveat`/`_exit`.

#![allow(unsafe_code)]

use crate::{
    EvidenceOutput, KILL_GRACE_MILLISECONDS, SUPERVISOR_VERSION, SupervisorError,
    SupervisorReceipt, TERM_GRACE_MILLISECONDS, TerminationReason, ValidatedRequest,
    accounted_active_seconds, sys,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Seek, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

const CHILD_SETUP_FAILED: u8 = 1;
const POLL_SLICE_MILLISECONDS: i32 = 10;

#[cfg(test)]
static FORCE_PIDFD_OPEN_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static FORCE_PROCESS_SCAN_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static FORCE_CLOSE_RANGE_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub fn inject_pidfd_open_failure() {
    FORCE_PIDFD_OPEN_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub fn inject_process_scan_failure() {
    FORCE_PROCESS_SCAN_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub fn inject_close_range_failure() {
    FORCE_CLOSE_RANGE_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub fn clear_close_range_failure() {
    FORCE_CLOSE_RANGE_FAILURE.store(false, std::sync::atomic::Ordering::SeqCst);
}

pub struct SupervisorSignalBoundary {
    descriptor: OwnedFd,
    previous_mask: libc::sigset_t,
}

impl SupervisorSignalBoundary {
    pub(crate) fn new() -> Result<Self, SupervisorError> {
        let mut blocked = MaybeUninit::<libc::sigset_t>::uninit();
        let mut previous = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: both sigset pointers refer to writable local storage and all
        // signal numbers are fixed constants.
        if unsafe { libc::sigemptyset(blocked.as_mut_ptr()) } != 0 {
            return Err(last_error(
                "signal_boundary_failed",
                "cannot initialize signal set",
            ));
        }
        // SAFETY: `blocked` was initialized immediately above.
        let mut blocked = unsafe { blocked.assume_init() };
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            // SAFETY: `blocked` is a valid sigset and each signal is valid.
            if unsafe { libc::sigaddset(&raw mut blocked, signal) } != 0 {
                return Err(last_error(
                    "signal_boundary_failed",
                    "cannot populate signal set",
                ));
            }
        }
        // SAFETY: both sigsets are initialized and valid for this call.
        if unsafe {
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const blocked, previous.as_mut_ptr())
        } != 0
        {
            return Err(SupervisorError::new(
                "signal_boundary_failed",
                "supervisor signals could not be blocked",
            ));
        }
        // SAFETY: pthread_sigmask initialized the previous mask on success.
        let previous_mask = unsafe { previous.assume_init() };
        // SAFETY: signalfd reads the initialized fixed signal set and returns
        // a new descriptor owned by this boundary.
        let descriptor = unsafe {
            libc::signalfd(
                -1,
                &raw const blocked,
                libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
            )
        };
        if descriptor < 0 {
            // SAFETY: restore the previously captured mask before returning.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const previous_mask, ptr::null_mut());
            }
            return Err(last_error(
                "signal_boundary_failed",
                "supervisor signalfd could not be created",
            ));
        }
        // SAFETY: signalfd returned a fresh descriptor with sole ownership.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        Ok(Self {
            descriptor,
            previous_mask,
        })
    }

    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }
}

impl Drop for SupervisorSignalBoundary {
    fn drop(&mut self) {
        // SAFETY: the previous mask was initialized by pthread_sigmask and is
        // restored on the same thread that owns the Supervisor boundary.
        unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const self.previous_mask,
                ptr::null_mut(),
            );
        }
    }
}

pub fn supervise(
    validated: &ValidatedRequest,
    liveness_fd: RawFd,
    signal_boundary: &SupervisorSignalBoundary,
) -> Result<SupervisorReceipt, SupervisorError> {
    validate_process_privilege_state(sys::process_privilege_state()?)?;
    set_child_subreaper()?;
    set_nonblocking(liveness_fd)?;
    ensure_parent_alive(validated.request.expected_parent_pid, liveness_fd)?;

    let supervisor_pid = process_id();
    let excluded_children = direct_child_identities(supervisor_pid, false)?;
    let started_ns = monotonic_ns()?;
    let mut child = spawn(validated)?;
    let completion = complete_spawned_child(
        &mut child,
        validated,
        liveness_fd,
        signal_boundary.as_raw_fd(),
        supervisor_pid,
        &excluded_children,
        started_ns,
    );
    let completion = match completion {
        Ok(value) => value,
        Err(primary) => {
            if matches!(
                primary.code,
                "leader_already_reaped" | "post_reap_cleanup_failed"
            ) {
                let cleanup = finalize_adopted_descendants(supervisor_pid, &excluded_children);
                let evidence_cleanup = enforce_final_evidence_bound(validated);
                return match (cleanup, evidence_cleanup) {
                    (Ok((_, 0)), Ok(())) => Err(primary),
                    (Ok((_, 0)), Err(evidence)) => Err(SupervisorError::new(
                        "post_reap_cleanup_failed",
                        format!("{primary}; final evidence cleanup also failed: {evidence}"),
                    )),
                    (Ok((_, residual)), _) => Err(SupervisorError::new(
                        "post_reap_cleanup_failed",
                        format!(
                            "{primary}; {residual} adopted descendants remained after safe cleanup"
                        ),
                    )),
                    (Err(cleanup), _) => Err(SupervisorError::new(
                        "post_reap_cleanup_failed",
                        format!(
                            "{primary}; safe adopted-descendant cleanup also failed: {cleanup}"
                        ),
                    )),
                };
            }
            let cleanup = emergency_cleanup(supervisor_pid, child.pid, &excluded_children);
            let evidence_cleanup = enforce_final_evidence_bound(validated);
            return match cleanup {
                Ok(()) if evidence_cleanup.is_ok() => Err(primary),
                Err(cleanup) => Err(SupervisorError::new(
                    "supervision_cleanup_failed",
                    format!("{primary}; cleanup also failed: {cleanup}"),
                )),
                Ok(()) => Err(SupervisorError::new(
                    "supervision_cleanup_failed",
                    format!(
                        "{primary}; evidence cleanup also failed: {}",
                        evidence_cleanup.expect_err("checked evidence cleanup error")
                    ),
                )),
            };
        }
    };
    Ok(SupervisorReceipt {
        schema_version: "1.0".to_owned(),
        protocol_version: crate::PROTOCOL_VERSION.to_owned(),
        request_id: validated.request.request_id.clone(),
        supervisor_version: SUPERVISOR_VERSION.to_owned(),
        supervisor_sha256: validated.supervisor_sha256.clone(),
        workload_pid: child.pid,
        workload_start_ticks: completion.start_ticks,
        elapsed_monotonic_ns: completion.elapsed_ns,
        accounted_active_seconds: accounted_active_seconds(completion.elapsed_ns),
        exit_code: completion.status.exit_code,
        terminating_signal: completion.status.signal,
        termination_reason: completion.termination_reason,
        term_sent: completion.teardown.term_sent,
        kill_sent: completion.teardown.kill_sent,
        observed_group_descendants: completion.observed_descendants,
        residual_group_descendants: completion.teardown.residual,
        cleanup_complete: completion.teardown.residual == 0,
    })
}

fn validate_process_privilege_state(
    state: sys::ProcessPrivilegeState,
) -> Result<(), SupervisorError> {
    let identity_is_ordinary = state.effective_uid != 0
        && state.effective_gid != 0
        && state.real_uid == state.effective_uid
        && state.saved_uid == state.effective_uid
        && state.real_gid == state.effective_gid
        && state.saved_gid == state.effective_gid;
    let capabilities_are_empty = state.effective_capabilities == 0
        && state.permitted_capabilities == 0
        && state.inheritable_capabilities == 0
        && state.ambient_capabilities == 0;
    if !identity_is_ordinary || !capabilities_are_empty {
        return Err(SupervisorError::new(
            "privilege_boundary_violation",
            "runtime supervisor requires one non-root UID/GID identity and empty capability sets",
        ));
    }
    Ok(())
}

struct CompletedChild {
    start_ticks: u64,
    elapsed_ns: u64,
    termination_reason: TerminationReason,
    observed_descendants: u32,
    teardown: Teardown,
    status: LeaderStatus,
}

enum EvidenceBoundary {
    BoundedStream {
        source: OwnedFd,
        destination: File,
        maximum_size: u64,
        written: u64,
        closed: bool,
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

impl EvidenceBoundary {
    fn new(
        child: &mut SpawnedChild,
        validated: &ValidatedRequest,
    ) -> Result<Self, SupervisorError> {
        match validated.evidence_output {
            EvidenceOutput::BoundedStream {
                destination_fd,
                maximum_size,
                ..
            } => {
                let source = child.evidence_read.take().ok_or_else(|| {
                    SupervisorError::new(
                        "evidence_boundary_failed",
                        "bounded evidence pipe is unavailable",
                    )
                })?;
                let duplicate = crate::sys::duplicate_cloexec(destination_fd)?;
                let mut destination = crate::sys::owned_file(duplicate);
                destination.rewind().map_err(|error| {
                    SupervisorError::new("evidence_boundary_failed", error.to_string())
                })?;
                Ok(Self::BoundedStream {
                    source,
                    destination,
                    maximum_size,
                    written: 0,
                    closed: false,
                })
            }
            EvidenceOutput::MonitoredFile {
                descriptor,
                maximum_size,
            } => Ok(Self::MonitoredFile {
                descriptor,
                maximum_size,
            }),
            EvidenceOutput::MonitoredFiles {
                first_descriptor,
                first_maximum_size,
                second_descriptor,
                second_maximum_size,
            } => Ok(Self::MonitoredFiles {
                first_descriptor,
                first_maximum_size,
                second_descriptor,
                second_maximum_size,
            }),
        }
    }

    fn poll_descriptor(&self) -> RawFd {
        match self {
            Self::BoundedStream { source, .. } => source.as_raw_fd(),
            Self::MonitoredFile { .. } | Self::MonitoredFiles { .. } => -1,
        }
    }

    fn check(&mut self) -> Result<(), SupervisorError> {
        match self {
            Self::BoundedStream {
                source,
                destination,
                maximum_size,
                written,
                closed,
            } => {
                let mut buffer = [0_u8; 8192];
                loop {
                    match crate::sys::read_nonblocking(source.as_raw_fd(), &mut buffer) {
                        Ok(0) => {
                            *closed = true;
                            return Ok(());
                        }
                        Ok(count) => {
                            let remaining = maximum_size.saturating_sub(*written);
                            let accepted =
                                count.min(usize::try_from(remaining).unwrap_or(usize::MAX));
                            if accepted != 0 {
                                destination
                                    .write_all(&buffer[..accepted])
                                    .map_err(|error| {
                                        SupervisorError::new(
                                            "evidence_write_failed",
                                            error.to_string(),
                                        )
                                    })?;
                                *written = written
                                    .saturating_add(u64::try_from(accepted).unwrap_or(u64::MAX));
                            }
                            if accepted != count {
                                return Err(SupervisorError::new(
                                    "resource_limit_exceeded",
                                    "runtime evidence exceeded its authorized file bound",
                                ));
                            }
                        }
                        Err(error) if is_would_block(&error) => return Ok(()),
                        Err(error) => {
                            return Err(SupervisorError::new(
                                "evidence_read_failed",
                                error.to_string(),
                            ));
                        }
                    }
                }
            }
            Self::MonitoredFile {
                descriptor,
                maximum_size,
            } => enforce_monitored_file_bound(*descriptor, *maximum_size),
            Self::MonitoredFiles {
                first_descriptor,
                first_maximum_size,
                second_descriptor,
                second_maximum_size,
            } => enforce_two_monitored_file_bounds(
                *first_descriptor,
                *first_maximum_size,
                *second_descriptor,
                *second_maximum_size,
            ),
        }
    }

    fn finish(&mut self) -> Result<(), SupervisorError> {
        self.check()?;
        if matches!(self, Self::BoundedStream { closed: false, .. }) {
            return Err(SupervisorError::new(
                "evidence_boundary_failed",
                "runtime evidence writer remained open after descendant teardown",
            ));
        }
        Ok(())
    }
}

fn enforce_monitored_file_bound(
    descriptor: RawFd,
    maximum_size: u64,
) -> Result<(), SupervisorError> {
    let size = fs::metadata(format!("/proc/self/fd/{descriptor}"))
        .map_err(|error| SupervisorError::new("evidence_boundary_failed", error.to_string()))?
        .len();
    if size <= maximum_size {
        return Ok(());
    }
    crate::sys::truncate_file(descriptor, maximum_size).map_err(|error| {
        SupervisorError::new(
            "evidence_boundary_failed",
            format!("oversized runtime evidence could not be bounded: {error}"),
        )
    })?;
    Err(SupervisorError::new(
        "resource_limit_exceeded",
        "runtime evidence exceeded its authorized file bound",
    ))
}

fn enforce_two_monitored_file_bounds(
    first_descriptor: RawFd,
    first_maximum_size: u64,
    second_descriptor: RawFd,
    second_maximum_size: u64,
) -> Result<(), SupervisorError> {
    let first = enforce_monitored_file_bound(first_descriptor, first_maximum_size);
    let second = enforce_monitored_file_bound(second_descriptor, second_maximum_size);
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(SupervisorError::new(
            "resource_limit_exceeded",
            format!("both Go profile bounds were exceeded: {first}; {second}"),
        )),
    }
}

fn enforce_final_evidence_bound(validated: &ValidatedRequest) -> Result<(), SupervisorError> {
    match validated.evidence_output {
        EvidenceOutput::BoundedStream { .. } => Ok(()),
        EvidenceOutput::MonitoredFile {
            descriptor,
            maximum_size,
        } => enforce_monitored_file_bound(descriptor, maximum_size),
        EvidenceOutput::MonitoredFiles {
            first_descriptor,
            first_maximum_size,
            second_descriptor,
            second_maximum_size,
        } => enforce_two_monitored_file_bounds(
            first_descriptor,
            first_maximum_size,
            second_descriptor,
            second_maximum_size,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn complete_spawned_child(
    child: &mut SpawnedChild,
    validated: &ValidatedRequest,
    liveness_fd: RawFd,
    signal_fd: RawFd,
    supervisor_pid: u32,
    excluded_children: &BTreeSet<ProcessKey>,
    started_ns: u64,
) -> Result<CompletedChild, SupervisorError> {
    let mut evidence = EvidenceBoundary::new(child, validated)?;
    let pidfd = pidfd_open(child.pid)?;
    let start_ticks = read_process_identity(child.pid)
        .map(|identity| identity.key.start_ticks)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            SupervisorError::new(
                "procfs_unavailable",
                "workload start identity is unavailable",
            )
        })?;
    let setup = wait_for_exec(
        child.setup_read.as_raw_fd(),
        liveness_fd,
        signal_fd,
        pidfd.as_raw_fd(),
        &mut evidence,
        validated.request.expected_parent_pid,
        started_ns,
        validated.request.timeout_milliseconds,
    )?;
    let termination_reason = match setup {
        SetupOutcome::ParentLost => TerminationReason::ParentLost,
        SetupOutcome::SupervisorSignal => TerminationReason::SupervisorSignal,
        SetupOutcome::TimedOut => TerminationReason::Timeout,
        SetupOutcome::Failed => TerminationReason::SetupFailed,
        SetupOutcome::ExecSucceeded => wait_for_termination(
            liveness_fd,
            signal_fd,
            pidfd.as_raw_fd(),
            &mut evidence,
            validated.request.expected_parent_pid,
            started_ns,
            validated.request.timeout_milliseconds,
        )?,
    };
    let observed_descendants =
        supervised_processes(supervisor_pid, child.pid, excluded_children, true, true)?
            .into_iter()
            .filter(|identity| identity.key.pid != child.pid)
            .count()
            .try_into()
            .unwrap_or(u32::MAX);
    let mut teardown = teardown_tree(supervisor_pid, child.pid, excluded_children)?;
    // After this reap the numeric leader PID/PGID is no longer pinned. Any
    // error below must use the `post_reap_cleanup_failed` class so the outer
    // epilogue never sends a raw signal to a potentially reused identity.
    let status = reap_leader(child.pid)?;
    let (final_kill_sent, residual) =
        finalize_adopted_descendants(supervisor_pid, excluded_children).map_err(|error| {
            SupervisorError::new(
                "post_reap_cleanup_failed",
                format!("final adopted-descendant cleanup could not be proven: {error}"),
            )
        })?;
    teardown.kill_sent |= final_kill_sent;
    teardown.residual = residual;
    evidence.finish().map_err(|error| {
        SupervisorError::new(
            "post_reap_cleanup_failed",
            format!("final evidence stream closure could not be proven: {error}"),
        )
    })?;
    enforce_final_evidence_bound(validated).map_err(|error| {
        SupervisorError::new(
            "post_reap_cleanup_failed",
            format!("final evidence size boundary could not be proven: {error}"),
        )
    })?;
    let elapsed_ns = monotonic_ns()
        .map_err(|error| {
            SupervisorError::new(
                "post_reap_cleanup_failed",
                format!("final monotonic accounting could not be proven: {error}"),
            )
        })?
        .saturating_sub(started_ns);
    Ok(CompletedChild {
        start_ticks,
        elapsed_ns,
        termination_reason,
        observed_descendants,
        teardown,
        status,
    })
}

struct SpawnedChild {
    pid: u32,
    setup_read: OwnedFd,
    evidence_read: Option<OwnedFd>,
}

fn spawn(validated: &ValidatedRequest) -> Result<SpawnedChild, SupervisorError> {
    let (setup_read, setup_write) = pipe_cloexec()?;
    let null_fd = open_dev_null()?;
    let (evidence_read, evidence_write) = match validated.evidence_output {
        EvidenceOutput::BoundedStream { .. } => {
            let (read, write) = pipe_cloexec()?;
            set_nonblocking(read.as_raw_fd())?;
            (Some(read), Some(write))
        }
        EvidenceOutput::MonitoredFile { .. } | EvidenceOutput::MonitoredFiles { .. } => {
            (None, None)
        }
    };
    let supervisor_pid = process_id();
    let argv: Vec<*const libc::c_char> = validated
        .executable_arguments
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();
    let mut environment = validated.environment.clone();
    if let (
        EvidenceOutput::BoundedStream {
            native_environment_fd: true,
            ..
        },
        Some(write),
    ) = (&validated.evidence_output, evidence_write.as_ref())
    {
        environment.push(crate::c_string(&format!(
            "PERFLENS_RUNTIME_LOCK_FD={}",
            write.as_raw_fd()
        ))?);
    }
    let envp: Vec<*const libc::c_char> = environment
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();
    let mut retained = validated.retained_child_fds.clone();
    retained.push(setup_write.as_raw_fd());
    retained.push(null_fd.as_raw_fd());
    if let Some(write) = &evidence_write {
        retained.push(write.as_raw_fd());
    }
    retained.sort_unstable();
    retained.dedup();

    // SAFETY: the process is single-thread agnostic because the child invokes
    // only the async-signal-safe syscall sequence in `child_exec`, never Rust
    // allocation, locking, or unwinding. The parent follows the normal branch.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(last_error(
            "fork_failed",
            "workload child could not be forked",
        ));
    }
    if pid == 0 {
        close_descriptor(setup_read.as_raw_fd());
        // SAFETY: all pointed-to C strings and pointer arrays were fully built
        // before `fork` and remain live in the child until `execveat`/`_exit`.
        unsafe {
            child_exec(
                validated,
                supervisor_pid,
                setup_write.as_raw_fd(),
                null_fd.as_raw_fd(),
                evidence_write.as_ref().map(AsRawFd::as_raw_fd),
                &retained,
                argv.as_ptr(),
                envp.as_ptr(),
            );
        }
    }
    drop(setup_write);
    drop(null_fd);
    drop(evidence_write);
    Ok(SpawnedChild {
        pid: pid.cast_unsigned(),
        setup_read,
        evidence_read,
    })
}

#[allow(clippy::too_many_arguments)] // fixed post-fork syscall boundary; grouping would hide FD ownership
unsafe fn child_exec(
    validated: &ValidatedRequest,
    expected_parent: u32,
    setup_fd: RawFd,
    null_fd: RawFd,
    evidence_write_fd: Option<RawFd>,
    retained: &[RawFd],
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    // SAFETY: `prctl`, `getppid`, `setsid`, `fchdir`, `dup2`, `fcntl`,
    // `close_range`, `sigprocmask`, `execveat`, `write`, and `_exit` are invoked with integer
    // values or the pre-fork pointer arrays described by the caller.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::getppid() }.cast_unsigned() != expected_parent
        || unsafe { libc::setsid() } < 0
        || unsafe { libc::fchdir(validated.request.working_directory.descriptor) } != 0
        || unsafe { libc::dup2(null_fd, libc::STDIN_FILENO) } < 0
        || unsafe { libc::dup2(null_fd, libc::STDERR_FILENO) } < 0
        || unsafe { unblock_supervisor_signals() } != 0
    {
        unsafe { child_fail(setup_fd) };
    }
    let stdout_source = if matches!(
        validated.evidence_output,
        EvidenceOutput::BoundedStream {
            redirect_stdout: true,
            ..
        }
    ) {
        evidence_write_fd.unwrap_or(null_fd)
    } else {
        null_fd
    };
    if unsafe { libc::dup2(stdout_source, libc::STDOUT_FILENO) } < 0 {
        unsafe { child_fail(setup_fd) };
    }
    if let Some(descriptor) = evidence_write_fd
        && matches!(
            validated.evidence_output,
            EvidenceOutput::BoundedStream {
                native_environment_fd: true,
                ..
            }
        )
    {
        // The Native probe receives this private relay descriptor through its
        // fixed environment variable. Unlike the setup pipe, it must survive
        // exec so the probe can write into the supervisor-owned bounded relay.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
        {
            unsafe { child_fail(setup_fd) };
        }
    }
    for descriptor in &validated.retained_child_fds {
        // SAFETY: descriptor values were validated and remain open in this child.
        let flags = unsafe { libc::fcntl(*descriptor, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(*descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
        {
            unsafe { child_fail(setup_fd) };
        }
    }
    if !unsafe { close_all_except(retained) } {
        unsafe { child_fail(setup_fd) };
    }
    let empty = c"";
    // SAFETY: executable FD is already-open and identity-verified; argv/envp
    // are NULL-terminated arrays backed by live `CString`s. `AT_EMPTY_PATH`
    // performs descriptor-bound execution without resolving a pathname.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            validated.request.executable.descriptor,
            empty.as_ptr(),
            argv,
            envp,
            libc::AT_EMPTY_PATH,
        );
        child_fail(setup_fd);
    }
}

unsafe fn unblock_supervisor_signals() -> i32 {
    let mut signals = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: the sigset pointer refers to writable local storage.
    if unsafe { libc::sigemptyset(signals.as_mut_ptr()) } != 0 {
        return -1;
    }
    // SAFETY: sigemptyset initialized the set immediately above.
    let mut signals = unsafe { signals.assume_init() };
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: `signals` is initialized and each signal is valid.
        if unsafe { libc::sigaddset(&raw mut signals, signal) } != 0 {
            return -1;
        }
    }
    // SAFETY: the fixed initialized set is read only for the duration of the call.
    unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &raw const signals, ptr::null_mut()) }
}

unsafe fn child_fail(setup_fd: RawFd) -> ! {
    let value = [CHILD_SETUP_FAILED];
    // SAFETY: the one-byte buffer is live and the descriptor is the private
    // CLOEXEC child-setup pipe. Errors are intentionally ignored before exit.
    unsafe {
        libc::write(setup_fd, value.as_ptr().cast(), value.len());
        libc::_exit(126);
    }
}

unsafe fn close_all_except(retained: &[RawFd]) -> bool {
    #[cfg(test)]
    if FORCE_CLOSE_RANGE_FAILURE.load(std::sync::atomic::Ordering::SeqCst) {
        return false;
    }
    let mut first = 3_u32;
    // `retained` was sorted and deduplicated before `fork`; no allocation or
    // sorting occurs in the post-fork child.
    for descriptor in retained.iter().copied().filter(|value| *value >= 3) {
        let descriptor = descriptor.cast_unsigned();
        if first < descriptor {
            // SAFETY: `close_range` takes only descriptor bounds.
            if unsafe { libc::syscall(libc::SYS_close_range, first, descriptor - 1, 0_u32) } < 0 {
                return false;
            }
        }
        first = descriptor.saturating_add(1);
    }
    // SAFETY: close every remaining non-retained descriptor. Linux clamps the
    // upper bound to the descriptor table limit.
    unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0_u32) >= 0 }
}

#[derive(Clone, Copy)]
enum SetupOutcome {
    ExecSucceeded,
    ParentLost,
    SupervisorSignal,
    TimedOut,
    Failed,
}

#[allow(clippy::too_many_arguments)] // each independently verified control boundary is explicit
fn wait_for_exec(
    setup_fd: RawFd,
    liveness_fd: RawFd,
    signal_fd: RawFd,
    pidfd: RawFd,
    evidence: &mut EvidenceBoundary,
    expected_parent: u32,
    started_ns: u64,
    timeout_ms: u64,
) -> Result<SetupOutcome, SupervisorError> {
    set_nonblocking(setup_fd)?;
    loop {
        evidence.check()?;
        if supervisor_signal_pending(signal_fd)? {
            return Ok(SetupOutcome::SupervisorSignal);
        }
        if parent_lost(expected_parent, liveness_fd)? {
            return Ok(SetupOutcome::ParentLost);
        }
        let mut value = [0_u8; 1];
        // SAFETY: buffer is valid and the descriptor is nonblocking.
        let count = unsafe { libc::read(setup_fd, value.as_mut_ptr().cast(), value.len()) };
        if count == 0 {
            return Ok(SetupOutcome::ExecSucceeded);
        }
        if count > 0 {
            return Ok(SetupOutcome::Failed);
        }
        let error = io::Error::last_os_error();
        if !is_would_block(&error) {
            return Err(SupervisorError::new("setup_pipe_failed", error.to_string()));
        }
        if pidfd_ready(pidfd, 0)? {
            return Ok(SetupOutcome::Failed);
        }
        if deadline_reached(started_ns, timeout_ms)? {
            return Ok(SetupOutcome::TimedOut);
        }
        poll_sleep(
            setup_fd,
            liveness_fd,
            signal_fd,
            pidfd,
            evidence.poll_descriptor(),
        )?;
    }
}

fn wait_for_termination(
    liveness_fd: RawFd,
    signal_fd: RawFd,
    pidfd: RawFd,
    evidence: &mut EvidenceBoundary,
    expected_parent: u32,
    started_ns: u64,
    timeout_ms: u64,
) -> Result<TerminationReason, SupervisorError> {
    loop {
        evidence.check()?;
        if supervisor_signal_pending(signal_fd)? {
            return Ok(TerminationReason::SupervisorSignal);
        }
        if parent_lost(expected_parent, liveness_fd)? {
            return Ok(TerminationReason::ParentLost);
        }
        if pidfd_ready(pidfd, 0)? {
            return Ok(TerminationReason::Exited);
        }
        if deadline_reached(started_ns, timeout_ms)? {
            return Ok(TerminationReason::Timeout);
        }
        poll_sleep(
            -1,
            liveness_fd,
            signal_fd,
            pidfd,
            evidence.poll_descriptor(),
        )?;
    }
}

pub fn supervisor_signal_pending(signal_fd: RawFd) -> Result<bool, SupervisorError> {
    let mut information = MaybeUninit::<libc::signalfd_siginfo>::uninit();
    // SAFETY: the signalfd writes at most one fully sized siginfo value into
    // valid local storage and is configured nonblocking.
    let count = unsafe {
        libc::read(
            signal_fd,
            information.as_mut_ptr().cast(),
            std::mem::size_of::<libc::signalfd_siginfo>(),
        )
    };
    if count == std::mem::size_of::<libc::signalfd_siginfo>().cast_signed() {
        return Ok(true);
    }
    if count < 0 && is_would_block(&io::Error::last_os_error()) {
        return Ok(false);
    }
    Err(SupervisorError::new(
        "signal_boundary_failed",
        "supervisor signalfd returned a malformed record",
    ))
}

fn parent_lost(expected_parent: u32, liveness_fd: RawFd) -> Result<bool, SupervisorError> {
    if parent_pid() != expected_parent {
        return Ok(true);
    }
    let mut byte = [0_u8; 1];
    // SAFETY: buffer is valid and descriptor was made nonblocking.
    let count = unsafe { libc::read(liveness_fd, byte.as_mut_ptr().cast(), 1) };
    if count >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if is_would_block(&error) {
        Ok(false)
    } else {
        Err(SupervisorError::new(
            "liveness_pipe_failed",
            error.to_string(),
        ))
    }
}

fn ensure_parent_alive(expected_parent: u32, liveness_fd: RawFd) -> Result<(), SupervisorError> {
    if parent_lost(expected_parent, liveness_fd)? {
        return Err(SupervisorError::new(
            "parent_identity_changed",
            "supervisor parent disappeared before workload fork",
        ));
    }
    Ok(())
}

struct Teardown {
    term_sent: bool,
    kill_sent: bool,
    residual: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_ticks: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessIdentity {
    pub key: ProcessKey,
    pub parent_pid: u32,
}

fn teardown_tree(
    supervisor_pid: u32,
    leader: u32,
    excluded_children: &BTreeSet<ProcessKey>,
) -> Result<Teardown, SupervisorError> {
    let term_sent = signal_supervised_tree(
        supervisor_pid,
        leader,
        excluded_children,
        libc::SIGTERM,
        true,
        true,
    )?;
    let term_deadline = monotonic_ns()?.saturating_add(TERM_GRACE_MILLISECONDS * 1_000_000);
    while monotonic_ns()? < term_deadline {
        reap_adopted_children(supervisor_pid, Some(leader));
        sleep_milliseconds(5)?;
    }
    let kill_deadline = monotonic_ns()?.saturating_add(KILL_GRACE_MILLISECONDS * 1_000_000);
    let mut kill_sent = false;
    loop {
        kill_sent |= signal_supervised_tree(
            supervisor_pid,
            leader,
            excluded_children,
            libc::SIGKILL,
            true,
            true,
        )?;
        reap_adopted_children(supervisor_pid, Some(leader));
        let residual = supervised_processes(supervisor_pid, leader, excluded_children, true, true)?
            .into_iter()
            .filter(|identity| identity.key.pid != leader)
            .count()
            .try_into()
            .unwrap_or(u32::MAX);
        if residual == 0 {
            return Ok(Teardown {
                term_sent,
                kill_sent,
                residual: 0,
            });
        }
        if monotonic_ns()? >= kill_deadline {
            return Ok(Teardown {
                term_sent,
                kill_sent,
                residual,
            });
        }
        sleep_milliseconds(5)?;
    }
}

fn finalize_adopted_descendants(
    supervisor_pid: u32,
    excluded_children: &BTreeSet<ProcessKey>,
) -> Result<(bool, u32), SupervisorError> {
    let deadline = monotonic_ns()?.saturating_add(KILL_GRACE_MILLISECONDS * 1_000_000);
    let mut kill_sent = false;
    let mut consecutive_empty_scans = 0_u8;
    loop {
        kill_sent |= signal_adopted_tree(supervisor_pid, excluded_children, libc::SIGKILL)?;
        reap_adopted_children(supervisor_pid, None);
        let residual = adopted_processes(supervisor_pid, excluded_children, false)?
            .len()
            .try_into()
            .unwrap_or(u32::MAX);
        if residual == 0 {
            consecutive_empty_scans = consecutive_empty_scans.saturating_add(1);
            if consecutive_empty_scans >= 2 {
                return Ok((kill_sent, 0));
            }
        } else {
            consecutive_empty_scans = 0;
        }
        if monotonic_ns()? >= deadline {
            return Ok((kill_sent, residual));
        }
        sleep_milliseconds(5)?;
    }
}

fn signal_adopted_tree(
    supervisor_pid: u32,
    excluded_children: &BTreeSet<ProcessKey>,
    signal: i32,
) -> Result<bool, SupervisorError> {
    signal_identities(
        adopted_processes(supervisor_pid, excluded_children, false)?,
        signal,
    )
}

fn signal_supervised_tree(
    supervisor_pid: u32,
    leader: u32,
    excluded_children: &BTreeSet<ProcessKey>,
    signal: i32,
    include_leader: bool,
    allow_fault_injection: bool,
) -> Result<bool, SupervisorError> {
    let identities = supervised_processes(
        supervisor_pid,
        leader,
        excluded_children,
        include_leader,
        allow_fault_injection,
    )?;
    signal_identities(identities, signal)
}

fn signal_identities(
    identities: Vec<ProcessIdentity>,
    signal: i32,
) -> Result<bool, SupervisorError> {
    let mut delivered = false;
    for identity in identities.into_iter().rev() {
        let Some(current) = read_process_identity(identity.key.pid) else {
            continue;
        };
        if current.key != identity.key {
            continue;
        }
        let pidfd = pidfd_open_without_fault(identity.key.pid)?;
        let Some(after_open) = read_process_identity(identity.key.pid) else {
            continue;
        };
        if after_open.key != identity.key {
            continue;
        }
        delivered |= pidfd_send_signal(pidfd.as_raw_fd(), signal)?;
    }
    Ok(delivered)
}

fn process_snapshot(allow_fault_injection: bool) -> Result<Vec<ProcessIdentity>, SupervisorError> {
    #[cfg(not(test))]
    let _ = allow_fault_injection;
    #[cfg(test)]
    if allow_fault_injection
        && FORCE_PROCESS_SCAN_FAILURE.swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        return Err(SupervisorError::new(
            "procfs_unavailable",
            "injected process scan failure",
        ));
    }
    let entries = fs::read_dir("/proc").map_err(|error| {
        SupervisorError::new("procfs_unavailable", format!("cannot scan procfs: {error}"))
    })?;
    let mut identities = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(identity) = read_process_identity(pid) {
            identities.push(identity);
        }
    }
    Ok(identities)
}

pub fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
    let raw = fs::read(format!("/proc/{pid}/stat")).ok()?;
    let close = raw.iter().rposition(|byte| *byte == b')')?;
    let suffix = std::str::from_utf8(raw.get(close + 2..)?).ok()?;
    let fields: Vec<&str> = suffix.split_ascii_whitespace().collect();
    Some(ProcessIdentity {
        key: ProcessKey {
            pid,
            start_ticks: fields.get(19)?.parse().ok()?,
        },
        parent_pid: fields.get(1)?.parse().ok()?,
    })
}

pub fn direct_child_identities(
    supervisor_pid: u32,
    allow_fault_injection: bool,
) -> Result<BTreeSet<ProcessKey>, SupervisorError> {
    Ok(process_snapshot(allow_fault_injection)?
        .into_iter()
        .filter(|identity| identity.parent_pid == supervisor_pid)
        .map(|identity| identity.key)
        .collect())
}

fn supervised_processes(
    supervisor_pid: u32,
    leader: u32,
    excluded_children: &BTreeSet<ProcessKey>,
    include_leader: bool,
    allow_fault_injection: bool,
) -> Result<Vec<ProcessIdentity>, SupervisorError> {
    let snapshot = process_snapshot(allow_fault_injection)?;
    Ok(supervised_processes_from_snapshot(
        &snapshot,
        supervisor_pid,
        include_leader.then_some(leader),
        excluded_children,
    ))
}

fn adopted_processes(
    supervisor_pid: u32,
    excluded_children: &BTreeSet<ProcessKey>,
    allow_fault_injection: bool,
) -> Result<Vec<ProcessIdentity>, SupervisorError> {
    let snapshot = process_snapshot(allow_fault_injection)?;
    Ok(supervised_processes_from_snapshot(
        &snapshot,
        supervisor_pid,
        None,
        excluded_children,
    ))
}

fn supervised_processes_from_snapshot(
    snapshot: &[ProcessIdentity],
    supervisor_pid: u32,
    leader: Option<u32>,
    excluded_children: &BTreeSet<ProcessKey>,
) -> Vec<ProcessIdentity> {
    let by_pid: BTreeMap<u32, ProcessIdentity> = snapshot
        .iter()
        .copied()
        .map(|identity| (identity.key.pid, identity))
        .collect();
    let mut accepted = BTreeSet::new();
    for identity in snapshot {
        if (leader == Some(identity.key.pid))
            || (identity.parent_pid == supervisor_pid && !excluded_children.contains(&identity.key))
        {
            accepted.insert(identity.key.pid);
        }
    }
    loop {
        let before = accepted.len();
        for identity in snapshot {
            if accepted.contains(&identity.parent_pid) {
                accepted.insert(identity.key.pid);
            }
        }
        if accepted.len() == before {
            break;
        }
    }
    accepted
        .into_iter()
        .filter_map(|pid| by_pid.get(&pid).copied())
        .collect()
}

fn reap_adopted_children(supervisor_pid: u32, leader_to_skip: Option<u32>) {
    let Ok(children) = direct_child_identities(supervisor_pid, false) else {
        return;
    };
    for child in children {
        if leader_to_skip == Some(child.pid) {
            continue;
        }
        let mut status = 0_i32;
        // SAFETY: waitpid writes to a valid local status integer and WNOHANG never blocks.
        unsafe {
            libc::waitpid(child.pid.cast_signed(), &raw mut status, libc::WNOHANG);
        }
    }
}

fn emergency_cleanup(
    supervisor_pid: u32,
    leader: u32,
    excluded_children: &BTreeSet<ProcessKey>,
) -> Result<(), SupervisorError> {
    // First pin the known process group even if the procfs tree scan failed.
    // SAFETY: negative PID targets the unreaped leader's process group only.
    unsafe {
        libc::kill(-leader.cast_signed(), libc::SIGKILL);
        libc::kill(leader.cast_signed(), libc::SIGKILL);
    }
    let tree_result = (|| {
        let deadline = monotonic_ns()?.saturating_add(KILL_GRACE_MILLISECONDS * 1_000_000);
        loop {
            let _ = signal_supervised_tree(
                supervisor_pid,
                leader,
                excluded_children,
                libc::SIGKILL,
                true,
                false,
            )?;
            reap_adopted_children(supervisor_pid, Some(leader));
            let residual =
                supervised_processes(supervisor_pid, leader, excluded_children, true, false)?
                    .into_iter()
                    .filter(|identity| identity.key.pid != leader)
                    .count();
            if residual == 0 || monotonic_ns()? >= deadline {
                return if residual == 0 {
                    Ok(())
                } else {
                    Err(SupervisorError::new(
                        "group_teardown_failed",
                        "supervised descendants remained after emergency teardown",
                    ))
                };
            }
            sleep_milliseconds(5)?;
        }
    })();
    let reap_result = reap_leader_tolerating_absent(leader);
    tree_result.and(reap_result)
}

struct LeaderStatus {
    exit_code: Option<i32>,
    signal: Option<i32>,
}

fn reap_leader(leader: u32) -> Result<LeaderStatus, SupervisorError> {
    let mut status = 0_i32;
    loop {
        // SAFETY: `waitpid` writes to the valid local status and targets our known child.
        let result = unsafe { libc::waitpid(leader.cast_signed(), &raw mut status, 0) };
        if result == leader.cast_signed() {
            break;
        }
        if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            return Err(SupervisorError::new(
                "leader_already_reaped",
                "workload leader was reaped outside the supervisor lifecycle",
            ));
        }
        return Err(last_error(
            "reap_failed",
            "workload leader could not be reaped",
        ));
    }
    if libc::WIFEXITED(status) {
        Ok(LeaderStatus {
            exit_code: Some(libc::WEXITSTATUS(status)),
            signal: None,
        })
    } else if libc::WIFSIGNALED(status) {
        Ok(LeaderStatus {
            exit_code: None,
            signal: Some(libc::WTERMSIG(status)),
        })
    } else {
        Ok(LeaderStatus {
            exit_code: None,
            signal: None,
        })
    }
}

fn reap_leader_tolerating_absent(leader: u32) -> Result<(), SupervisorError> {
    let mut status = 0_i32;
    loop {
        // SAFETY: waitpid writes to the valid local status and targets the
        // exact leader that this supervisor forked.
        let result = unsafe { libc::waitpid(leader.cast_signed(), &raw mut status, 0) };
        if result == leader.cast_signed() {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if result < 0 && error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if result < 0 && error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(());
        }
        return Err(SupervisorError::new("reap_failed", error.to_string()));
    }
}

fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd), SupervisorError> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: `pipe2` writes exactly two descriptors into the valid array.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(last_error(
            "pipe_failed",
            "child setup pipe could not be created",
        ));
    }
    // SAFETY: pipe2 returned two fresh descriptors, each with sole ownership.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn open_dev_null() -> Result<OwnedFd, SupervisorError> {
    let path = c"/dev/null";
    // SAFETY: path is a fixed NUL-terminated literal.
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if descriptor < 0 {
        Err(last_error(
            "stdio_isolation_failed",
            "/dev/null could not be opened",
        ))
    } else {
        // SAFETY: open returned a fresh descriptor with sole ownership.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn set_child_subreaper() -> Result<(), SupervisorError> {
    // SAFETY: `prctl` receives the fixed subreaper flag and integer value.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        Err(last_error(
            "subreaper_unavailable",
            "runtime supervisor could not become a child subreaper",
        ))
    } else {
        Ok(())
    }
}

fn pidfd_open(pid: u32) -> Result<OwnedFd, SupervisorError> {
    #[cfg(test)]
    if FORCE_PIDFD_OPEN_FAILURE.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(SupervisorError::new(
            "pidfd_unavailable",
            "injected pidfd_open failure",
        ));
    }
    pidfd_open_without_fault(pid)
}

fn pidfd_open_without_fault(pid: u32) -> Result<OwnedFd, SupervisorError> {
    // SAFETY: `pidfd_open` receives only PID and flags integers.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) as RawFd };
    if descriptor < 0 {
        Err(last_error(
            "pidfd_unavailable",
            "workload pidfd could not be opened",
        ))
    } else {
        // SAFETY: pidfd_open returned a fresh descriptor with sole ownership.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn pidfd_send_signal(pidfd: RawFd, signal: i32) -> Result<bool, SupervisorError> {
    // SAFETY: pidfd_send_signal receives a verified pidfd, an integer signal,
    // no siginfo payload, and fixed zero flags.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if result == 0 {
        Ok(true)
    } else if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(last_error(
            "group_teardown_failed",
            "supervised process could not be signaled through pidfd",
        ))
    }
}

fn pidfd_ready(pidfd: RawFd, timeout_ms: i32) -> Result<bool, SupervisorError> {
    let mut item = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the single-element pollfd array is valid for the call duration.
    let result = unsafe { libc::poll(&raw mut item, 1, timeout_ms) };
    if result < 0 {
        Err(last_error("poll_failed", "workload pidfd poll failed"))
    } else {
        Ok(result > 0 && item.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
    }
}

fn poll_sleep(
    setup_fd: RawFd,
    liveness_fd: RawFd,
    signal_fd: RawFd,
    pidfd: RawFd,
    evidence_fd: RawFd,
) -> Result<(), SupervisorError> {
    let mut items = [
        libc::pollfd {
            fd: liveness_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: setup_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: evidence_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: all five pollfd entries are valid for the call duration; a
    // negative setup fd is explicitly ignored by poll(2).
    let result = unsafe {
        libc::poll(
            items.as_mut_ptr(),
            items.len() as libc::nfds_t,
            POLL_SLICE_MILLISECONDS,
        )
    };
    if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
        Err(last_error("poll_failed", "runtime supervision poll failed"))
    } else {
        Ok(())
    }
}

fn set_nonblocking(descriptor: RawFd) -> Result<(), SupervisorError> {
    // SAFETY: descriptor-only `fcntl` calls do not dereference pointers.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        Err(last_error(
            "descriptor_unavailable",
            "control descriptor could not be made nonblocking",
        ))
    } else {
        Ok(())
    }
}

fn deadline_reached(started_ns: u64, timeout_ms: u64) -> Result<bool, SupervisorError> {
    Ok(monotonic_ns()?.saturating_sub(started_ns) >= timeout_ms.saturating_mul(1_000_000))
}

fn monotonic_ns() -> Result<u64, SupervisorError> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes to the valid local `timespec`.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(last_error(
            "monotonic_clock_failed",
            "CLOCK_MONOTONIC is unavailable",
        ));
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| {
        SupervisorError::new("monotonic_clock_failed", "monotonic seconds are invalid")
    })?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| {
        SupervisorError::new("monotonic_clock_failed", "monotonic nanos are invalid")
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanos))
        .ok_or_else(|| SupervisorError::new("monotonic_clock_failed", "monotonic clock overflowed"))
}

fn sleep_milliseconds(milliseconds: u64) -> Result<(), SupervisorError> {
    let request = libc::timespec {
        tv_sec: (milliseconds / 1_000) as libc::time_t,
        tv_nsec: ((milliseconds % 1_000) * 1_000_000).cast_signed(),
    };
    let mut remaining = request;
    loop {
        // SAFETY: request/remaining point to valid local `timespec` values.
        let result = unsafe { libc::nanosleep(&raw const remaining, &raw mut remaining) };
        if result == 0 {
            return Ok(());
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(last_error("monotonic_clock_failed", "nanosleep failed"));
        }
    }
}

fn process_id() -> u32 {
    std::process::id()
}

fn parent_pid() -> u32 {
    // SAFETY: `getppid` has no arguments or memory-safety preconditions.
    unsafe { libc::getppid().cast_unsigned() }
}

fn close_descriptor(descriptor: RawFd) {
    if descriptor >= 0 {
        // SAFETY: closing a best-effort integer descriptor has no memory-safety precondition.
        unsafe {
            libc::close(descriptor);
        }
    }
}

fn last_error(code: &'static str, message: &'static str) -> SupervisorError {
    SupervisorError::new(code, format!("{message}: {}", io::Error::last_os_error()))
}

fn is_would_block(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK)
}

#[cfg(test)]
mod tests {
    use super::{
        direct_child_identities, enforce_two_monitored_file_bounds, read_process_identity,
        validate_process_privilege_state,
    };
    use crate::sys::ProcessPrivilegeState;
    use std::fs::{self, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn proc_stat_parser_reads_current_process() {
        let pid = std::process::id();
        let identity = read_process_identity(pid).expect("current process identity");
        assert_eq!(identity.key.pid, pid);
        assert!(identity.key.start_ticks > 0);
        direct_child_identities(pid, false).expect("scan procfs");
    }

    #[test]
    fn privilege_boundary_rejects_mismatched_ids_and_every_capability_set() {
        let ordinary = ProcessPrivilegeState {
            real_uid: 1000,
            effective_uid: 1000,
            saved_uid: 1000,
            real_gid: 1000,
            effective_gid: 1000,
            saved_gid: 1000,
            effective_capabilities: 0,
            permitted_capabilities: 0,
            inheritable_capabilities: 0,
            ambient_capabilities: 0,
        };
        validate_process_privilege_state(ordinary).expect("ordinary unprivileged identity");

        let mut invalid = Vec::new();
        invalid.push(ProcessPrivilegeState {
            effective_uid: 0,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            real_uid: 1001,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            saved_uid: 1001,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            real_gid: 1001,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            effective_gid: 0,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            saved_gid: 1001,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            effective_capabilities: 1,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            permitted_capabilities: 1,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            inheritable_capabilities: 1,
            ..ordinary
        });
        invalid.push(ProcessPrivilegeState {
            ambient_capabilities: 1,
            ..ordinary
        });
        for state in invalid {
            let error = validate_process_privilege_state(state)
                .expect_err("privileged or inconsistent identity must be rejected");
            assert_eq!(error.code, "privilege_boundary_violation");
        }
    }

    #[test]
    fn both_go_profile_files_are_bounded_even_when_the_first_fails() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let first_path = std::env::temp_dir().join(format!("perflens-go-first-{suffix}"));
        let second_path = std::env::temp_dir().join(format!("perflens-go-second-{suffix}"));
        let first = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&first_path)
            .expect("first profile");
        let second = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&second_path)
            .expect("second profile");
        first.set_len(8).expect("oversize first");
        second.set_len(9).expect("oversize second");
        let error = enforce_two_monitored_file_bounds(first.as_raw_fd(), 4, second.as_raw_fd(), 5)
            .expect_err("both files exceed their bounds");
        assert_eq!(error.code, "resource_limit_exceeded");
        assert_eq!(first.metadata().expect("first metadata").len(), 4);
        assert_eq!(second.metadata().expect("second metadata").len(), 5);
        drop(first);
        drop(second);
        fs::remove_file(first_path).expect("remove first");
        fs::remove_file(second_path).expect("remove second");
    }
}
