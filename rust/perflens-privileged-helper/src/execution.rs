//! Fixed-path, policy-bounded `perf` execution for the privileged Helper.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::sys::statvfs::statvfs;
use nix::unistd::{Pid, getegid, geteuid};
use sha2::{Digest, Sha256};

use crate::{
    ActualEventSource, CallGraph, CollectionMode, HelperTarget, RecordEvent, RequestedEventSource,
};

const SPOOL_ROOT: &str = "/var/lib/perflens-helper";
const MAX_DURATION_MILLISECONDS: u64 = 30_000;
const MAX_FREQUENCY_HZ: u32 = 99;
const MAX_OUTPUT_BYTES: u64 = 256 << 20;
const MAX_SPOOL_BYTES: u64 = 5 << 30;
const MAX_SPOOL_ARTIFACTS: usize = 500;
const MIN_FREE_BYTES: u64 = 2 << 30;
const MAX_TRACKED_PLANS: usize = 4096;
const REPLAY_RETENTION: Duration = Duration::from_mins(2);
const HARDWARE_PROBE_MINIMUM_PLAN_MILLISECONDS: u64 = 300;
const HARDWARE_PROBE_MAX_MILLISECONDS: u64 = 250;
const HARDWARE_PROBE_OUTPUT_BYTES: u64 = 1 << 20;
const POST_PROBE_FALLBACK_MINIMUM_MILLISECONDS: u64 = 50;
const PERF_CONTROL_ACK_MAX_BYTES: usize = 16;
const SOFTWARE_STAT_EVENTS: &[&str] = &[
    "task-clock",
    "context-switches",
    "cpu-migrations",
    "page-faults",
];
const ALLOWED_STAT_EVENTS: &[&str] = &[
    "cycles",
    "instructions",
    "cache-references",
    "cache-misses",
    "branches",
    "branch-misses",
    "task-clock",
    "context-switches",
    "cpu-migrations",
    "page-faults",
];

#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    pub plan_id: String,
    pub caller_uid: u32,
    pub target: HelperTarget,
    pub mode: CollectionMode,
    pub duration_milliseconds: u64,
    pub frequency_hz: Option<u32>,
    pub call_graph: Option<CallGraph>,
    pub events: Vec<String>,
    pub requested_event_source: RequestedEventSource,
    pub fallback_allowed: bool,
    pub fallback_events: Vec<String>,
    pub record_event: Option<RecordEvent>,
    pub fallback_record_event: Option<RecordEvent>,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub artifact_name: String,
    pub output_bytes: u64,
    pub output_sha256: String,
    pub output_format: &'static str,
    pub actual_event_source: ActualEventSource,
    pub fallback_used: bool,
    pub fallback_reason: Option<&'static str>,
    pub events: Vec<String>,
    pub record_event: Option<RecordEvent>,
    pub started_at_unix_milliseconds: u64,
    pub finished_at_unix_milliseconds: u64,
}

#[derive(Debug)]
pub struct ExecutionError {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: &'static str,
}

pub fn execute_production_plan_with_ready<R>(
    plan: &ExecutionPlan,
    allowed_uid: u32,
    artifact_gid: u32,
    configured_perf_path: &Path,
    ready_notifier: &mut R,
) -> Result<ExecutionResult, ExecutionError>
where
    R: FnMut() -> Result<(), ExecutionError>,
{
    validate_plan(plan, allowed_uid)?;
    assert_pid_identity(&plan.target)?;
    let perf_path = trusted_root_executable(configured_perf_path)?;
    let spool_root = trusted_spool(Path::new(SPOOL_ROOT))?;
    recover_stale_temporary_files(&spool_root, artifact_gid)?;
    let active_markers = prune_replay_markers(&spool_root, Some(&plan.plan_id))?;
    if active_markers >= MAX_TRACKED_PLANS {
        return Err(resource_error(
            "Privileged Helper replay state reached its bounded capacity",
        ));
    }
    authorize_spool_capacity(&spool_root, plan.max_output_bytes, artifact_gid)?;
    consume_plan(&spool_root, &plan.plan_id)?;
    execute_perf_with_ready(
        plan,
        &perf_path,
        &spool_root,
        artifact_gid,
        &assert_pid_identity,
        ready_notifier,
    )
}

pub fn prepare_production_environment(
    configured_perf_path: &Path,
    artifact_gid: u32,
) -> Result<(), ExecutionError> {
    trusted_root_executable(configured_perf_path)?;
    let spool_root = trusted_spool(Path::new(SPOOL_ROOT))?;
    recover_stale_temporary_files(&spool_root, artifact_gid)?;
    prune_replay_markers(&spool_root, None)?;
    validate_spool_entries(&spool_root, artifact_gid).map(|_usage| ())
}

fn validate_plan(plan: &ExecutionPlan, allowed_uid: u32) -> Result<(), ExecutionError> {
    let allowed_events = ALLOWED_STAT_EVENTS.iter().copied().collect::<HashSet<_>>();
    let hardware_events = ALLOWED_STAT_EVENTS[..6]
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    if plan.caller_uid != allowed_uid
        || plan.target.uid != allowed_uid
        || plan.duration_milliseconds == 0
        || plan.duration_milliseconds > MAX_DURATION_MILLISECONDS
        || plan.max_output_bytes == 0
        || plan.max_output_bytes > MAX_OUTPUT_BYTES
        || (plan.mode == CollectionMode::Record
            && plan
                .frequency_hz
                .is_none_or(|frequency| frequency > MAX_FREQUENCY_HZ))
        || (plan.mode == CollectionMode::Stat
            && plan
                .events
                .iter()
                .any(|event| !allowed_events.contains(event.as_str())))
        || plan
            .fallback_events
            .iter()
            .any(|event| !allowed_events.contains(event.as_str()))
        || (plan.fallback_allowed && plan.requested_event_source != RequestedEventSource::Auto)
        || (plan.fallback_allowed
            && match plan.mode {
                CollectionMode::Stat => {
                    plan.fallback_events
                        != [
                            "task-clock",
                            "context-switches",
                            "cpu-migrations",
                            "page-faults",
                        ]
                        || plan.record_event.is_some()
                        || plan.fallback_record_event.is_some()
                }
                CollectionMode::Record => {
                    !plan.fallback_events.is_empty()
                        || plan.record_event != Some(RecordEvent::Cycles)
                        || plan.fallback_record_event != Some(RecordEvent::CpuClock)
                }
            })
        || (!plan.fallback_allowed
            && (!plan.fallback_events.is_empty() || plan.fallback_record_event.is_some()))
        || (plan.requested_event_source == RequestedEventSource::SoftwareOnly
            && match plan.mode {
                CollectionMode::Stat => {
                    plan.events
                        != [
                            "task-clock",
                            "context-switches",
                            "cpu-migrations",
                            "page-faults",
                        ]
                        || plan.record_event.is_some()
                }
                CollectionMode::Record => plan.record_event != Some(RecordEvent::CpuClock),
            })
        || (plan.requested_event_source == RequestedEventSource::HardwareRequired
            && plan.mode == CollectionMode::Record
            && plan.record_event != Some(RecordEvent::Cycles))
        || (plan.requested_event_source != RequestedEventSource::SoftwareOnly
            && plan.mode == CollectionMode::Stat
            && plan
                .events
                .iter()
                .any(|event| !hardware_events.contains(event.as_str())))
    {
        return Err(denied(
            "Privileged Helper immutable policy rejected the collection plan",
        ));
    }
    Ok(())
}

fn assert_pid_identity(target: &HelperTarget) -> Result<(), ExecutionError> {
    if target.pid == std::process::id() {
        return Err(denied("Privileged Helper cannot profile its own process"));
    }
    let proc_root = PathBuf::from(format!("/proc/{}", target.pid));
    let metadata = proc_root
        .metadata()
        .map_err(|_error| denied("Target PID identity cannot be inspected"))?;
    let stat_text = fs::read_to_string(proc_root.join("stat"))
        .map_err(|_error| denied("Target PID identity cannot be inspected"))?;
    let closing = stat_text
        .rfind(')')
        .ok_or_else(|| denied("Target PID stat record is malformed"))?;
    let start_time_ticks = stat_text
        .get(closing + 2..)
        .and_then(|tail| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| denied("Target PID stat record is malformed"))?;
    if metadata.uid() != target.uid || start_time_ticks != target.start_time_ticks {
        return Err(denied("Target PID owner or start time changed"));
    }
    Ok(())
}

fn trusted_root_executable(path: &Path) -> Result<PathBuf, ExecutionError> {
    if !path.is_absolute() || path.file_name().is_none_or(|name| name != "perf") {
        return Err(denied("Configured perf executable path is not canonical"));
    }
    let resolved = path
        .canonicalize()
        .map_err(|_error| denied("Fixed executable cannot be resolved"))?;
    let metadata = resolved
        .metadata()
        .map_err(|_error| denied("Fixed executable cannot be inspected"))?;
    if resolved != path
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || !trusted_root_directory_chain(resolved.parent())
    {
        return Err(denied(
            "Fixed executable identity or permissions are unsafe",
        ));
    }
    Ok(resolved)
}

fn trusted_root_directory_chain(parent: Option<&Path>) -> bool {
    parent.is_some_and(|directory| {
        directory.ancestors().all(|ancestor| {
            ancestor.metadata().is_ok_and(|metadata| {
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
            })
        })
    })
}

fn trusted_spool(path: &Path) -> Result<PathBuf, ExecutionError> {
    let resolved = path
        .canonicalize()
        .map_err(|_error| denied("Fixed spool cannot be resolved"))?;
    let metadata = resolved
        .metadata()
        .map_err(|_error| denied("Fixed spool cannot be inspected"))?;
    if resolved != path
        || !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(denied("Fixed spool identity or permissions are unsafe"));
    }
    Ok(resolved)
}

fn recover_stale_temporary_files(spool: &Path, artifact_gid: u32) -> Result<(), ExecutionError> {
    let mut removed_any = false;
    for entry in fs::read_dir(spool).map_err(|_error| spool_error())? {
        let entry = entry.map_err(|_error| spool_error())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(spool_error)?;
        let Some(plan_suffix) = name
            .strip_prefix(".perflens-helper-plan-")
            .or_else(|| name.strip_prefix(".perflens-helper-probe-plan-"))
            .and_then(|value| value.strip_suffix(".tmp"))
        else {
            continue;
        };
        if !valid_plan_suffix(plan_suffix) {
            return Err(spool_error());
        }
        let temporary = entry.path();
        let metadata = temporary
            .symlink_metadata()
            .map_err(|_error| spool_error())?;
        let safe_incomplete = metadata.is_file()
            && metadata.uid() == geteuid().as_raw()
            && metadata.nlink() == 1
            && ((metadata.mode() & 0o777 == 0o600 && metadata.gid() == getegid().as_raw())
                || (metadata.mode() & 0o777 == 0o640 && metadata.gid() == artifact_gid));
        let published_outputs = [".stat.csv", ".perf.data"]
            .iter()
            .map(|suffix| spool.join(format!("plan-{plan_suffix}{suffix}")))
            .filter(|output| {
                output.symlink_metadata().is_ok_and(|output_metadata| {
                    output_metadata.is_file()
                        && output_metadata.uid() == metadata.uid()
                        && output_metadata.gid() == metadata.gid()
                        && output_metadata.mode() & 0o777 == 0o640
                        && output_metadata.nlink() == 2
                        && output_metadata.dev() == metadata.dev()
                        && output_metadata.ino() == metadata.ino()
                })
            })
            .collect::<Vec<_>>();
        let safe_published = metadata.is_file()
            && metadata.uid() == geteuid().as_raw()
            && metadata.gid() == artifact_gid
            && metadata.mode() & 0o777 == 0o640
            && metadata.nlink() == 2
            && published_outputs.len() == 1;
        if !safe_incomplete && !safe_published {
            return Err(spool_error());
        }
        if safe_published {
            File::open(&published_outputs[0])
                .and_then(|file| file.sync_all())
                .map_err(|_error| spool_error())?;
        }
        fs::remove_file(&temporary).map_err(|_error| spool_error())?;
        removed_any = true;
    }
    if removed_any {
        File::open(spool)
            .and_then(|directory| directory.sync_all())
            .map_err(|_error| spool_error())?;
    }
    Ok(())
}

fn authorize_spool_capacity(
    spool: &Path,
    requested: u64,
    artifact_gid: u32,
) -> Result<(), ExecutionError> {
    let (count, bytes) = validate_spool_entries(spool, artifact_gid)?;
    let filesystem = statvfs(spool).map_err(|_error| spool_error())?;
    let free_bytes = filesystem
        .blocks_available()
        .saturating_mul(filesystem.fragment_size());
    if count >= MAX_SPOOL_ARTIFACTS
        || bytes.saturating_add(requested) > MAX_SPOOL_BYTES
        || free_bytes.saturating_sub(requested) < MIN_FREE_BYTES
    {
        return Err(resource_error(
            "Privileged Helper spool capacity policy rejected the plan",
        ));
    }
    Ok(())
}

fn validate_spool_entries(spool: &Path, artifact_gid: u32) -> Result<(usize, u64), ExecutionError> {
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    for entry in fs::read_dir(spool).map_err(|_error| spool_error())? {
        let entry = entry.map_err(|_error| spool_error())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(spool_error)?;
        let metadata = entry
            .path()
            .symlink_metadata()
            .map_err(|_error| spool_error())?;
        if valid_replay_marker_name(name) {
            if !safe_replay_marker_metadata(&metadata) {
                return Err(spool_error());
            }
            continue;
        }
        if !valid_artifact_name(name)
            || !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.gid() != artifact_gid
            || metadata.mode() & 0o777 != 0o640
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_OUTPUT_BYTES
        {
            return Err(spool_error());
        }
        count += 1;
        bytes = bytes.checked_add(metadata.len()).ok_or_else(spool_error)?;
    }
    Ok((count, bytes))
}

fn prune_replay_markers(
    spool: &Path,
    preserve_plan_id: Option<&str>,
) -> Result<usize, ExecutionError> {
    let preserve_name = preserve_plan_id.map(|plan_id| format!(".perflens-consumed-{plan_id}"));
    let cutoff = SystemTime::now()
        .checked_sub(REPLAY_RETENTION)
        .ok_or_else(spool_error)?;
    let mut active = 0_usize;
    let mut removed_any = false;
    for entry in fs::read_dir(spool).map_err(|_error| spool_error())? {
        let entry = entry.map_err(|_error| spool_error())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(spool_error)?;
        if !valid_replay_marker_name(name) {
            continue;
        }
        let metadata = entry
            .path()
            .symlink_metadata()
            .map_err(|_error| spool_error())?;
        if !safe_replay_marker_metadata(&metadata) {
            return Err(spool_error());
        }
        if preserve_name.as_deref() == Some(name) {
            return Err(denied("Privileged Helper plan was already consumed"));
        }
        if metadata.modified().map_err(|_error| spool_error())? <= cutoff {
            fs::remove_file(entry.path()).map_err(|_error| spool_error())?;
            removed_any = true;
        } else {
            active = active.checked_add(1).ok_or_else(spool_error)?;
            if active > MAX_TRACKED_PLANS {
                return Err(resource_error(
                    "Privileged Helper replay state exceeded its bounded capacity",
                ));
            }
        }
    }
    if removed_any {
        File::open(spool)
            .and_then(|directory| directory.sync_all())
            .map_err(|_error| spool_error())?;
    }
    Ok(active)
}

fn valid_plan_suffix(value: &str) -> bool {
    value.len() == 20
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_replay_marker_name(name: &str) -> bool {
    name.strip_prefix(".perflens-consumed-plan-")
        .is_some_and(valid_plan_suffix)
}

fn valid_artifact_name(name: &str) -> bool {
    [".stat.csv", ".perf.data"].iter().any(|suffix| {
        name.strip_prefix("plan-")
            .and_then(|value| value.strip_suffix(suffix))
            .is_some_and(valid_plan_suffix)
    })
}

fn safe_replay_marker_metadata(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == geteuid().as_raw()
        && metadata.gid() == getegid().as_raw()
        && metadata.mode() & 0o777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() == 0
}

fn consume_plan(spool: &Path, plan_id: &str) -> Result<(), ExecutionError> {
    let marker = spool.join(format!(".perflens-consumed-{plan_id}"));
    let marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)
        .map_err(|_error| denied("Privileged Helper plan was already consumed"))?;
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
        .map_err(|_error| spool_error())?;
    marker_file.sync_all().map_err(|_error| spool_error())?;
    File::open(spool)
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| spool_error())
}

#[cfg(test)]
fn execute_perf<V>(
    plan: &ExecutionPlan,
    perf_path: &Path,
    spool: &Path,
    artifact_gid: u32,
    target_validator: &V,
) -> Result<ExecutionResult, ExecutionError>
where
    V: Fn(&HelperTarget) -> Result<(), ExecutionError>,
{
    execute_perf_with_ready(
        plan,
        perf_path,
        spool,
        artifact_gid,
        target_validator,
        &mut || Ok(()),
    )
}

fn execute_perf_with_ready<V, R>(
    plan: &ExecutionPlan,
    perf_path: &Path,
    spool: &Path,
    artifact_gid: u32,
    target_validator: &V,
    ready_notifier: &mut R,
) -> Result<ExecutionResult, ExecutionError>
where
    V: Fn(&HelperTarget) -> Result<(), ExecutionError>,
    R: FnMut() -> Result<(), ExecutionError>,
{
    let mut ready_sent = false;
    let mut notify_once = || {
        if ready_sent {
            return Ok(());
        }
        ready_notifier()?;
        ready_sent = true;
        Ok(())
    };
    let (selected_plan, fallback_reason) = select_event_source(
        plan,
        perf_path,
        spool,
        artifact_gid,
        target_validator,
        &mut notify_once,
    )?;
    let suffix = if selected_plan.mode == CollectionMode::Stat {
        ".stat.csv"
    } else {
        ".perf.data"
    };
    let artifact_name = format!("{}{suffix}", plan.plan_id);
    let output = spool.join(&artifact_name);
    match output.symlink_metadata() {
        Ok(_metadata) => return Err(denied("Privileged Helper output already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_error) => return Err(spool_error()),
    }
    let temporary = spool.join(format!(".perflens-helper-{}.tmp", plan.plan_id));
    reserve_temporary_output(&temporary)?;
    let hardware_started = Instant::now();
    let mut outcome = execute_perf_inner_with_ready(
        &selected_plan,
        perf_path,
        PerfOutput {
            temporary: &temporary,
            output: &output,
            artifact_name: artifact_name.clone(),
            artifact_gid,
            publish: true,
        },
        target_validator,
        &mut notify_once,
    );
    if let Err(error) = &outcome {
        let elapsed_milliseconds =
            u64::try_from(hardware_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let remaining_milliseconds = selected_plan
            .duration_milliseconds
            .saturating_sub(elapsed_milliseconds);
        if plan.requested_event_source == RequestedEventSource::Auto
            && plan.fallback_allowed
            && fallback_reason.is_none()
            && error.code == "EXTERNAL_TOOL_FAILED"
            && remaining_milliseconds >= POST_PROBE_FALLBACK_MINIMUM_MILLISECONDS
        {
            fs::remove_file(&temporary).map_err(|_error| spool_error())?;
            reserve_temporary_output(&temporary)?;
            let software = software_plan(plan, remaining_milliseconds);
            outcome = execute_perf_inner_with_ready(
                &software,
                perf_path,
                PerfOutput {
                    temporary: &temporary,
                    output: &output,
                    artifact_name,
                    artifact_gid,
                    publish: true,
                },
                target_validator,
                &mut notify_once,
            );
            if let Ok(result) = &mut outcome {
                result.fallback_used = true;
                result.fallback_reason = Some("hardware_execution_failed_after_probe");
            }
        }
    }
    if outcome.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    outcome.map(|mut result| {
        if !result.fallback_used {
            result.fallback_used = fallback_reason.is_some();
            result.fallback_reason = fallback_reason;
        }
        result
    })
}

fn reserve_temporary_output(path: &Path) -> Result<(), ExecutionError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(|_file| ())
        .map_err(|_error| spool_error())
}

fn select_event_source<V, R>(
    plan: &ExecutionPlan,
    perf_path: &Path,
    spool: &Path,
    artifact_gid: u32,
    target_validator: &V,
    ready_notifier: &mut R,
) -> Result<(ExecutionPlan, Option<&'static str>), ExecutionError>
where
    V: Fn(&HelperTarget) -> Result<(), ExecutionError>,
    R: FnMut() -> Result<(), ExecutionError>,
{
    match plan.requested_event_source {
        RequestedEventSource::SoftwareOnly => {
            Ok((software_plan(plan, plan.duration_milliseconds), None))
        }
        RequestedEventSource::HardwareRequired => {
            Ok((hardware_plan(plan, plan.duration_milliseconds), None))
        }
        RequestedEventSource::Auto if !plan.fallback_allowed => {
            Ok((hardware_plan(plan, plan.duration_milliseconds), None))
        }
        RequestedEventSource::Auto
            if plan.duration_milliseconds < HARDWARE_PROBE_MINIMUM_PLAN_MILLISECONDS =>
        {
            Ok((
                software_plan(plan, plan.duration_milliseconds),
                Some("hardware_probe_skipped_for_short_collection"),
            ))
        }
        RequestedEventSource::Auto => {
            let probe_milliseconds =
                HARDWARE_PROBE_MAX_MILLISECONDS.min(plan.duration_milliseconds.saturating_div(4));
            let fallback_reason = probe_hardware_pmu(
                plan,
                probe_milliseconds,
                perf_path,
                spool,
                artifact_gid,
                target_validator,
                ready_notifier,
            )?;
            let final_milliseconds = plan
                .duration_milliseconds
                .checked_sub(probe_milliseconds)
                .ok_or_else(|| denied("Hardware probe exceeded the collection duration"))?;
            if fallback_reason.is_none() {
                Ok((hardware_plan(plan, final_milliseconds), None))
            } else {
                Ok((software_plan(plan, final_milliseconds), fallback_reason))
            }
        }
    }
}

fn hardware_plan(plan: &ExecutionPlan, duration_milliseconds: u64) -> ExecutionPlan {
    let mut selected = plan.clone();
    selected.duration_milliseconds = duration_milliseconds;
    selected.requested_event_source = RequestedEventSource::HardwareRequired;
    selected.fallback_allowed = false;
    selected.fallback_events.clear();
    selected.fallback_record_event = None;
    selected
}

fn software_plan(plan: &ExecutionPlan, duration_milliseconds: u64) -> ExecutionPlan {
    let mut selected = plan.clone();
    selected.duration_milliseconds = duration_milliseconds;
    selected.requested_event_source = RequestedEventSource::SoftwareOnly;
    selected.fallback_allowed = false;
    selected.fallback_events.clear();
    selected.fallback_record_event = None;
    match selected.mode {
        CollectionMode::Stat => {
            selected.events = SOFTWARE_STAT_EVENTS
                .iter()
                .map(|event| (*event).to_owned())
                .collect();
            selected.record_event = None;
        }
        CollectionMode::Record => selected.record_event = Some(RecordEvent::CpuClock),
    }
    selected
}

fn probe_hardware_pmu<V, R>(
    plan: &ExecutionPlan,
    duration_milliseconds: u64,
    perf_path: &Path,
    spool: &Path,
    artifact_gid: u32,
    target_validator: &V,
    ready_notifier: &mut R,
) -> Result<Option<&'static str>, ExecutionError>
where
    V: Fn(&HelperTarget) -> Result<(), ExecutionError>,
    R: FnMut() -> Result<(), ExecutionError>,
{
    let temporary = spool.join(format!(".perflens-helper-probe-{}.tmp", plan.plan_id));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_error| spool_error())?;
    let mut probe = plan.clone();
    probe.mode = CollectionMode::Stat;
    probe.duration_milliseconds = duration_milliseconds;
    probe.frequency_hz = None;
    probe.call_graph = None;
    probe.events = vec!["cycles".to_owned(), "instructions".to_owned()];
    probe.requested_event_source = RequestedEventSource::HardwareRequired;
    probe.fallback_allowed = false;
    probe.fallback_events.clear();
    probe.record_event = None;
    probe.fallback_record_event = None;
    probe.max_output_bytes = probe.max_output_bytes.min(HARDWARE_PROBE_OUTPUT_BYTES);
    let outcome = execute_perf_inner_with_ready(
        &probe,
        perf_path,
        PerfOutput {
            temporary: &temporary,
            output: &temporary,
            artifact_name: String::new(),
            artifact_gid,
            publish: false,
        },
        target_validator,
        ready_notifier,
    );
    let result = match outcome {
        Ok(_result) => hardware_probe_has_usable_counts(&temporary).map(|usable| {
            if usable {
                None
            } else {
                Some("hardware_probe_produced_no_usable_counts")
            }
        }),
        Err(error) if error.code == "EXTERNAL_TOOL_FAILED" => Ok(Some("hardware_probe_failed")),
        Err(error) => Err(error),
    };
    fs::remove_file(&temporary).map_err(|_error| spool_error())?;
    result
}

fn hardware_probe_has_usable_counts(path: &Path) -> Result<bool, ExecutionError> {
    let text = fs::read_to_string(path).map_err(|_error| spool_error())?;
    Ok(text.lines().any(|line| {
        let mut fields = line.split(';');
        let Some(raw_value) = fields.next() else {
            return false;
        };
        let _unit = fields.next();
        let Some(event) = fields.next() else {
            return false;
        };
        matches!(event.trim(), "cycles" | "instructions")
            && raw_value
                .trim()
                .parse::<f64>()
                .is_ok_and(|value| value > 0.0)
    }))
}

struct PerfOutput<'a> {
    temporary: &'a Path,
    output: &'a Path,
    artifact_name: String,
    artifact_gid: u32,
    publish: bool,
}

#[allow(clippy::too_many_lines)] // Linear lifecycle keeps spawn, watchdog, and publication ordered.
fn execute_perf_inner_with_ready<V, R>(
    plan: &ExecutionPlan,
    perf_path: &Path,
    output_settings: PerfOutput<'_>,
    target_validator: &V,
    ready_notifier: &mut R,
) -> Result<ExecutionResult, ExecutionError>
where
    V: Fn(&HelperTarget) -> Result<(), ExecutionError>,
    R: FnMut() -> Result<(), ExecutionError>,
{
    let PerfOutput {
        temporary,
        output,
        artifact_name,
        artifact_gid,
        publish,
    } = output_settings;
    let (mut control_writer, control_reader) =
        UnixStream::pair().map_err(|_error| external_error())?;
    let (ack_writer, ack_reader) = UnixStream::pair().map_err(|_error| external_error())?;
    fcntl(&control_reader, FcntlArg::F_SETFD(FdFlag::empty()))
        .map_err(|_error| external_error())?;
    fcntl(&ack_writer, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|_error| external_error())?;
    control_writer
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_error| external_error())?;
    ack_reader
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_error| external_error())?;
    let control_argument = format!(
        "fd:{},{}",
        control_reader.as_raw_fd(),
        ack_writer.as_raw_fd()
    );
    let mut acknowledgements = BufReader::new(ack_reader);
    let mut command = Command::new(perf_path);
    match plan.mode {
        CollectionMode::Stat => {
            command.args([
                "stat",
                "--no-big-num",
                "-x",
                ";",
                "-o",
                temporary.to_str().ok_or_else(spool_error)?,
                "-e",
                &plan.events.join(","),
            ]);
        }
        CollectionMode::Record => {
            let frequency = plan
                .frequency_hz
                .ok_or_else(|| denied("Record frequency is missing"))?;
            let call_graph = match plan.call_graph {
                Some(CallGraph::Dwarf) => "dwarf",
                Some(CallGraph::Fp) => "fp",
                Some(CallGraph::Lbr) => "lbr",
                None => return Err(denied("Record call graph is missing")),
            };
            command.args([
                "record",
                "-e",
                match plan.record_event {
                    Some(RecordEvent::Cycles) => "cycles",
                    Some(RecordEvent::CpuClock) => "cpu-clock",
                    None => return Err(denied("Record event is missing")),
                },
                "--freq",
                &frequency.to_string(),
                "--call-graph",
                call_graph,
                "--sample-cpu",
                "-g",
                "-o",
                temporary.to_str().ok_or_else(spool_error)?,
            ]);
        }
    }
    command
        .args(["-D", "-1", "--control", &control_argument])
        .args(["-p", &plan.target.pid.to_string()])
        .current_dir("/")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().map_err(|_error| external_error())?;
    drop(control_reader);
    drop(ack_writer);
    // `-D -1` makes perf open its target events disabled. `ping` is a non-mutating control command
    // which perf processes only after completing that binding. Revalidating the original
    // owner/start-time identity after this barrier ensures a recycled numeric PID is rejected
    // before any event can be enabled; the kernel event descriptors then remain bound to the task
    // perf actually opened.
    if send_perf_control(&mut control_writer, &mut acknowledgements, "ping").is_err() {
        terminate_perf(&mut child, Signal::SIGKILL);
        return Err(external_error());
    }
    if let Err(error) = target_validator(&plan.target) {
        terminate_perf(&mut child, Signal::SIGKILL);
        return Err(error);
    }
    if send_perf_control(&mut control_writer, &mut acknowledgements, "enable").is_err() {
        terminate_perf(&mut child, Signal::SIGKILL);
        return Err(external_error());
    }
    if let Err(error) = ready_notifier() {
        terminate_perf(&mut child, Signal::SIGKILL);
        return Err(error);
    }
    let started_at_unix_milliseconds = match unix_milliseconds() {
        Ok(value) => value,
        Err(error) => {
            terminate_perf(&mut child, Signal::SIGKILL);
            return Err(error);
        }
    };
    let started = Instant::now();
    let duration = Duration::from_millis(plan.duration_milliseconds);
    let mut status = None;
    let mut sent_bounded_sigint = false;
    while started.elapsed() < duration {
        let completed = match child.try_wait() {
            Ok(value) => value,
            Err(_error) => {
                terminate_perf(&mut child, Signal::SIGKILL);
                return Err(external_error());
            }
        };
        if let Some(completed) = completed {
            status = Some(completed);
            break;
        }
        let size = temporary.metadata().map_or(0, |metadata| metadata.len());
        if size > plan.max_output_bytes {
            terminate_perf(&mut child, Signal::SIGKILL);
            return Err(ExecutionError {
                code: "RESOURCE_LIMIT_EXCEEDED",
                stage: "external_tool",
                message: "Privileged perf exceeded its output limit",
            });
        }
        thread::sleep(Duration::from_millis(20));
    }
    if status.is_none() {
        if send_perf_control(&mut control_writer, &mut acknowledgements, "disable").is_err() {
            terminate_perf(&mut child, Signal::SIGKILL);
            return Err(external_error());
        }
        sent_bounded_sigint =
            killpg(Pid::from_raw(child.id().cast_signed()), Signal::SIGINT).is_ok();
        let shutdown_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let completed = match child.try_wait() {
                Ok(value) => value,
                Err(_error) => {
                    terminate_perf(&mut child, Signal::SIGKILL);
                    return Err(external_error());
                }
            };
            if let Some(completed) = completed {
                status = Some(completed);
                break;
            }
            if Instant::now() >= shutdown_deadline {
                terminate_perf(&mut child, Signal::SIGKILL);
                return Err(ExecutionError {
                    code: "RESOURCE_LIMIT_EXCEEDED",
                    stage: "external_tool",
                    message: "Privileged perf did not stop within its shutdown limit",
                });
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    let status = status.ok_or_else(external_error)?;
    if !perf_status_succeeded(status, sent_bounded_sigint) {
        return Err(external_error());
    }
    let metadata = temporary.metadata().map_err(|_error| spool_error())?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > plan.max_output_bytes
    {
        return Err(spool_error());
    }
    let actual_event_source = if plan.requested_event_source == RequestedEventSource::SoftwareOnly {
        ActualEventSource::Software
    } else {
        ActualEventSource::Hardware
    };
    let result = ExecutionResult {
        artifact_name,
        output_bytes: metadata.len(),
        output_sha256: sha256_file(temporary)?,
        output_format: if plan.mode == CollectionMode::Stat {
            "perf_stat_delimited"
        } else {
            "perf_data"
        },
        actual_event_source,
        fallback_used: false,
        fallback_reason: None,
        events: if plan.mode == CollectionMode::Stat {
            plan.events.clone()
        } else {
            Vec::new()
        },
        record_event: if plan.mode == CollectionMode::Record {
            plan.record_event
        } else {
            None
        },
        started_at_unix_milliseconds,
        finished_at_unix_milliseconds: unix_milliseconds()?,
    };
    if !publish {
        return Ok(result);
    }
    fs::set_permissions(temporary, fs::Permissions::from_mode(0o640))
        .map_err(|_error| spool_error())?;
    std::os::unix::fs::chown(temporary, None, Some(artifact_gid))
        .map_err(|_error| spool_error())?;
    File::open(temporary)
        .and_then(|file| file.sync_all())
        .map_err(|_error| spool_error())?;
    fs::hard_link(temporary, output).map_err(|_error| spool_error())?;
    File::open(output.parent().unwrap_or_else(|| Path::new("/")))
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| spool_error())?;
    fs::remove_file(temporary).map_err(|_error| spool_error())?;
    File::open(output.parent().unwrap_or_else(|| Path::new("/")))
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| spool_error())?;
    Ok(result)
}

fn perf_status_succeeded(status: ExitStatus, sent_bounded_sigint: bool) -> bool {
    status.success() || (sent_bounded_sigint && status.signal() == Some(Signal::SIGINT as i32))
}

fn send_perf_control(
    control: &mut UnixStream,
    acknowledgements: &mut BufReader<UnixStream>,
    operation: &str,
) -> Result<(), ExecutionError> {
    control
        .write_all(format!("{operation}\n").as_bytes())
        .map_err(|_error| external_error())?;
    read_perf_control_ack(acknowledgements)
}

fn read_perf_control_ack(
    acknowledgements: &mut BufReader<UnixStream>,
) -> Result<(), ExecutionError> {
    let mut acknowledgement = Vec::with_capacity(PERF_CONTROL_ACK_MAX_BYTES);
    loop {
        let (consumed, terminated) = {
            let available = acknowledgements
                .fill_buf()
                .map_err(|_error| external_error())?;
            if available.is_empty() {
                return Err(external_error());
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |position| position + 1);
            if acknowledgement.len().saturating_add(consumed) > PERF_CONTROL_ACK_MAX_BYTES {
                return Err(external_error());
            }
            acknowledgement.extend_from_slice(&available[..consumed]);
            (consumed, available[consumed - 1] == b'\n')
        };
        acknowledgements.consume(consumed);
        if terminated {
            break;
        }
    }

    // Linux perf currently writes `sizeof("ack\n")`, including its C-string NUL. `read_line`
    // leaves that NUL buffered, so it prefixes the following ACK. Accept only those leading NULs
    // and the documented ACK itself; every other byte or oversized response still fails closed.
    let first_payload_byte = acknowledgement
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(acknowledgement.len());
    if acknowledgement[first_payload_byte..] != *b"ack\n" {
        return Err(external_error());
    }
    Ok(())
}

fn terminate_perf(child: &mut std::process::Child, signal: Signal) {
    let _ignored = killpg(Pid::from_raw(child.id().cast_signed()), signal);
    if signal == Signal::SIGKILL {
        let _ignored = child.kill();
    }
    let _ignored = child.wait();
}

fn sha256_file(path: &Path) -> Result<String, ExecutionError> {
    let mut file = File::open(path).map_err(|_error| spool_error())?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 << 10].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).map_err(|_error| spool_error())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn unix_milliseconds() -> Result<u64, ExecutionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| external_error())?
        .as_millis()
        .try_into()
        .map_err(|_error| external_error())
}

const fn denied(message: &'static str) -> ExecutionError {
    ExecutionError {
        code: "PATH_SAFETY_VIOLATION",
        stage: "authorization",
        message,
    }
}

const fn spool_error() -> ExecutionError {
    ExecutionError {
        code: "OUTPUT_WRITE_FAILED",
        stage: "privileged_helper",
        message: "Privileged Helper spool operation failed safely",
    }
}

const fn external_error() -> ExecutionError {
    ExecutionError {
        code: "EXTERNAL_TOOL_FAILED",
        stage: "external_tool",
        message: "Privileged perf returned a non-zero result",
    }
}

const fn resource_error(message: &'static str) -> ExecutionError {
    ExecutionError {
        code: "RESOURCE_LIMIT_EXCEEDED",
        stage: "privileged_helper",
        message,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    use nix::sys::signal::Signal;

    use super::{
        ExecutionPlan, MAX_DURATION_MILLISECONDS, REPLAY_RETENTION, SOFTWARE_STAT_EVENTS,
        authorize_spool_capacity, consume_plan, denied, execute_perf, execute_perf_with_ready,
        perf_status_succeeded, prune_replay_markers, read_perf_control_ack,
        recover_stale_temporary_files, trusted_root_executable, validate_plan,
        validate_spool_entries,
    };
    use crate::{
        ActualEventSource, CallGraph, CollectionMode, HelperTarget, RecordEvent,
        RequestedEventSource,
    };

    static TEST_ID: AtomicU64 = AtomicU64::new(0);
    static EXECUTION_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn record_plan() -> ExecutionPlan {
        ExecutionPlan {
            plan_id: "plan-0123456789abcdefabcd".to_owned(),
            caller_uid: 1000,
            target: HelperTarget {
                pid: 1234,
                uid: 1000,
                start_time_ticks: 123,
            },
            mode: CollectionMode::Record,
            duration_milliseconds: 1000,
            frequency_hz: Some(99),
            call_graph: Some(CallGraph::Dwarf),
            events: Vec::new(),
            requested_event_source: RequestedEventSource::HardwareRequired,
            fallback_allowed: false,
            fallback_events: Vec::new(),
            record_event: Some(RecordEvent::Cycles),
            fallback_record_event: None,
            max_output_bytes: 8 << 20,
        }
    }

    fn write_fake_perf(path: &std::path::Path) {
        std::fs::write(
            path,
            r#"#!/bin/sh
set -eu
mode=$1
out=''
control=''
sample_cpu=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) shift; out=$1 ;;
    --control) shift; control=$1 ;;
    --sample-cpu) sample_cpu=1 ;;
    --) exit 91 ;;
  esac
  shift
done
[ "$mode" != 'record' ] || [ "$sample_cpu" = 1 ]
descriptors=${control#fd:}
ctl_fd=${descriptors%,*}
ack_fd=${descriptors#*,}
finish() {
  printf '1000;count;cycles;1;100.00;;\n' > "$out"
  exit 0
}
trap finish INT TERM
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'ping' ]
eval "printf 'ack\n\0' >&${ack_fd}"
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'enable' ]
eval "printf 'ack\n\0' >&${ack_fd}"
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'disable' ]
trap '' INT TERM
eval "printf 'ack\n\0' >&${ack_fd}"
finish
"#,
        )
        .expect("write perf test double");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("make test double executable");
    }

    fn write_fallback_fake_perf(path: &std::path::Path) {
        std::fs::write(
            path,
            r#"#!/bin/sh
set -eu
mode=$1
out=''
control=''
events=''
sample_cpu=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) shift; out=$1 ;;
    -e) shift; events=$1 ;;
    --control) shift; control=$1 ;;
    --sample-cpu) sample_cpu=1 ;;
    --) exit 91 ;;
  esac
  shift
done
[ "$mode" != 'record' ] || [ "$sample_cpu" = 1 ]
descriptors=${control#fd:}
ctl_fd=${descriptors%,*}
ack_fd=${descriptors#*,}
finish() {
  if [ "$events" = 'cycles,instructions' ]; then
    printf '0;;cycles;1;100.00;;\n0;;instructions;1;100.00;;\n' > "$out"
  else
    printf '1000;;task-clock;1;100.00;;\n1;;context-switches;1;100.00;;\n0;;cpu-migrations;1;100.00;;\n2;;page-faults;1;100.00;;\n' > "$out"
  fi
  exit 0
}
trap finish INT TERM
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'ping' ]
eval "printf 'ack\n\0' >&${ack_fd}"
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'enable' ]
eval "printf 'ack\n\0' >&${ack_fd}"
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'disable' ]
trap '' INT TERM
eval "printf 'ack\n\0' >&${ack_fd}"
finish
"#,
        )
        .expect("write fallback perf test double");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("make fallback test double executable");
    }

    fn write_post_probe_failure_fake_perf(path: &std::path::Path) {
        std::fs::write(
            path,
            r#"#!/bin/sh
set -eu
mode=$1
out=''
control=''
events=''
sample_cpu=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) shift; out=$1 ;;
    -e) shift; events=$1 ;;
    --control) shift; control=$1 ;;
    --sample-cpu) sample_cpu=1 ;;
    --) exit 91 ;;
  esac
  shift
done
[ "$mode" != 'record' ] || [ "$sample_cpu" = 1 ]
if [ "$mode" = 'record' ] && [ "$events" = 'cycles' ]; then
  exit 1
fi
descriptors=${control#fd:}
ctl_fd=${descriptors%,*}
ack_fd=${descriptors#*,}
finish() {
  if [ "$mode" = 'stat' ]; then
    printf '1000;;cycles;1;100.00;;\n2000;;instructions;1;100.00;;\n' > "$out"
  else
    printf 'PERFILE2-software-record' > "$out"
  fi
  exit 0
}
trap finish INT TERM
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'ping' ]
eval "printf 'ack\n\0' >&${ack_fd}"
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'enable' ]
eval "printf 'ack\n\0' >&${ack_fd}"
eval "IFS= read -r operation <&${ctl_fd}"
[ "$operation" = 'disable' ]
trap '' INT TERM
eval "printf 'ack\n\0' >&${ack_fd}"
finish
"#,
        )
        .expect("write post-probe failure perf test double");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("make post-probe failure test double executable");
    }

    #[test]
    fn immutable_policy_accepts_bounded_owner_only_record() {
        assert!(validate_plan(&record_plan(), 1000).is_ok());
    }

    #[test]
    fn bounded_sigint_is_success_only_when_the_helper_sent_it() {
        let success = ExitStatus::from_raw(0);
        let interrupted = ExitStatus::from_raw(Signal::SIGINT as i32);
        let failed = ExitStatus::from_raw(2 << 8);

        assert!(perf_status_succeeded(success, false));
        assert!(perf_status_succeeded(interrupted, true));
        assert!(!perf_status_succeeded(interrupted, false));
        assert!(!perf_status_succeeded(failed, true));
    }

    #[test]
    fn perf_control_ack_accepts_the_linux_nul_framing_across_commands() {
        let (mut writer, reader) = UnixStream::pair().expect("create ACK socket pair");
        writer
            .write_all(b"ack\n\0ack\n\0")
            .expect("write Linux perf ACK frames");
        let mut acknowledgements = BufReader::new(reader);

        read_perf_control_ack(&mut acknowledgements).expect("accept first ACK");
        read_perf_control_ack(&mut acknowledgements).expect("accept NUL-prefixed next ACK");
    }

    #[test]
    fn immutable_policy_rejects_cross_uid_duration_frequency_and_events() {
        let mut plan = record_plan();
        plan.target.uid = 1001;
        assert!(validate_plan(&plan, 1000).is_err());
        plan.target.uid = 1000;
        plan.duration_milliseconds = MAX_DURATION_MILLISECONDS + 1;
        assert!(validate_plan(&plan, 1000).is_err());
        plan.duration_milliseconds = 1000;
        plan.frequency_hz = Some(100);
        assert!(validate_plan(&plan, 1000).is_err());
        plan.mode = CollectionMode::Stat;
        plan.frequency_hz = None;
        plan.call_graph = None;
        plan.events = vec!["raw-unsafe-event".to_owned()];
        assert!(validate_plan(&plan, 1000).is_err());
    }

    #[test]
    fn configured_perf_path_rejects_non_root_and_symlinked_executables() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-perf-path-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create tool directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure tool directory");
        let owned = directory.join("perf");
        std::fs::write(&owned, b"not root owned").expect("write untrusted tool");
        std::fs::set_permissions(&owned, std::fs::Permissions::from_mode(0o700))
            .expect("make untrusted tool executable");
        assert!(trusted_root_executable(&owned).is_err());
        std::fs::remove_file(&owned).expect("remove untrusted tool");
        std::os::unix::fs::symlink("/bin/sh", &owned).expect("link misleading perf path");
        assert!(trusted_root_executable(&owned).is_err());
        std::fs::remove_file(owned).expect("remove misleading tool link");
        std::fs::remove_dir(directory).expect("remove tool directory");
    }

    #[test]
    fn fixed_argv_execution_publishes_a_bounded_new_artifact() {
        let _execution_guard = EXECUTION_TEST_LOCK.lock().expect("lock execution test");
        let directory = std::env::temp_dir().join(format!(
            "perflens-execution-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let fake_perf = directory.join("perf-test-double");
        write_fake_perf(&fake_perf);
        let mut plan = record_plan();
        plan.mode = CollectionMode::Stat;
        plan.frequency_hz = None;
        plan.call_graph = None;
        plan.events = vec!["cycles".to_owned()];
        plan.duration_milliseconds = 40;
        let identity_validated = AtomicU64::new(0);
        let ready_notifications = AtomicU64::new(0);
        let mut report_ready = || {
            assert_eq!(identity_validated.load(Ordering::Relaxed), 1);
            ready_notifications.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };
        let result = execute_perf_with_ready(
            &plan,
            &fake_perf,
            &directory,
            nix::unistd::getegid().as_raw(),
            &|_target| {
                identity_validated.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            &mut report_ready,
        )
        .expect("execute fixed argv test double");
        assert_eq!(identity_validated.load(Ordering::Relaxed), 1);
        assert_eq!(ready_notifications.load(Ordering::Relaxed), 1);
        let artifact = directory.join(&result.artifact_name);
        assert_eq!(
            std::fs::read_to_string(&artifact).expect("read artifact"),
            "1000;count;cycles;1;100.00;;\n"
        );
        assert_eq!(
            artifact
                .metadata()
                .expect("artifact metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(result.output_sha256.len(), 64);
        std::fs::remove_file(artifact).expect("remove artifact");
        std::fs::remove_file(fake_perf).expect("remove test double");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn auto_collection_falls_back_to_fixed_software_events_within_the_duration() {
        let _execution_guard = EXECUTION_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let directory = std::env::temp_dir().join(format!(
            "perflens-fallback-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let fake_perf = directory.join("perf-test-double");
        write_fallback_fake_perf(&fake_perf);
        let mut plan = record_plan();
        plan.mode = CollectionMode::Stat;
        plan.duration_milliseconds = 400;
        plan.frequency_hz = None;
        plan.call_graph = None;
        plan.events = vec!["cycles".to_owned(), "instructions".to_owned()];
        plan.requested_event_source = RequestedEventSource::Auto;
        plan.fallback_allowed = true;
        plan.fallback_events = SOFTWARE_STAT_EVENTS
            .iter()
            .map(|event| (*event).to_owned())
            .collect();
        plan.record_event = None;
        plan.fallback_record_event = None;
        let identity_validated = AtomicU64::new(0);
        let ready_notifications = AtomicU64::new(0);
        let mut report_ready = || {
            assert_eq!(identity_validated.load(Ordering::Relaxed), 1);
            ready_notifications.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };
        let result = execute_perf_with_ready(
            &plan,
            &fake_perf,
            &directory,
            nix::unistd::getegid().as_raw(),
            &|_target| {
                identity_validated.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            &mut report_ready,
        )
        .expect("fall back to software events");

        assert_eq!(identity_validated.load(Ordering::Relaxed), 2);
        assert_eq!(ready_notifications.load(Ordering::Relaxed), 1);
        assert_eq!(result.actual_event_source, ActualEventSource::Software);
        assert!(result.fallback_used);
        assert_eq!(
            result.fallback_reason,
            Some("hardware_probe_produced_no_usable_counts")
        );
        assert_eq!(
            result.events,
            SOFTWARE_STAT_EVENTS
                .iter()
                .map(|event| (*event).to_owned())
                .collect::<Vec<_>>()
        );
        let artifact = directory.join(&result.artifact_name);
        assert!(
            std::fs::read_to_string(&artifact)
                .expect("read fallback evidence")
                .contains("task-clock")
        );
        assert!(
            !directory
                .join(format!(".perflens-helper-probe-{}.tmp", plan.plan_id))
                .exists()
        );
        std::fs::remove_file(artifact).expect("remove artifact");
        std::fs::remove_file(fake_perf).expect("remove test double");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn auto_record_retries_software_when_hardware_execution_fails_after_probe() {
        let _execution_guard = EXECUTION_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let directory = std::env::temp_dir().join(format!(
            "perflens-post-probe-fallback-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let fake_perf = directory.join("perf-test-double");
        write_post_probe_failure_fake_perf(&fake_perf);
        let mut plan = record_plan();
        plan.duration_milliseconds = 500;
        plan.requested_event_source = RequestedEventSource::Auto;
        plan.fallback_allowed = true;
        plan.fallback_record_event = Some(RecordEvent::CpuClock);
        let result = execute_perf(
            &plan,
            &fake_perf,
            &directory,
            nix::unistd::getegid().as_raw(),
            &|_target| Ok(()),
        )
        .expect("retry with the fixed software record event");

        assert_eq!(result.actual_event_source, ActualEventSource::Software);
        assert!(result.fallback_used);
        assert_eq!(
            result.fallback_reason,
            Some("hardware_execution_failed_after_probe")
        );
        assert_eq!(result.record_event, Some(RecordEvent::CpuClock));
        let artifact = directory.join(&result.artifact_name);
        assert_eq!(
            std::fs::read(&artifact).expect("read software record evidence"),
            b"PERFILE2-software-record"
        );
        assert!(
            !directory
                .join(format!(".perflens-helper-{}.tmp", plan.plan_id))
                .exists()
        );
        std::fs::remove_file(artifact).expect("remove artifact");
        std::fs::remove_file(fake_perf).expect("remove test double");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn pid_identity_change_after_perf_binding_is_denied_before_enable() {
        let _execution_guard = EXECUTION_TEST_LOCK.lock().expect("lock execution test");
        let directory = std::env::temp_dir().join(format!(
            "perflens-pid-reuse-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let fake_perf = directory.join("perf-test-double");
        write_fake_perf(&fake_perf);
        let mut plan = record_plan();
        plan.mode = CollectionMode::Stat;
        plan.frequency_hz = None;
        plan.call_graph = None;
        plan.events = vec!["cycles".to_owned()];
        let error = execute_perf(
            &plan,
            &fake_perf,
            &directory,
            nix::unistd::getegid().as_raw(),
            &|_target| Err(denied("Target PID owner or start time changed")),
        )
        .expect_err("reused PID must be rejected after perf opens disabled events");
        assert_eq!(error.code, "PATH_SAFETY_VIOLATION");
        assert!(
            !directory
                .join(format!("{}.stat.csv", plan.plan_id))
                .exists()
        );
        assert!(
            !directory
                .join(format!(".perflens-helper-{}.tmp", plan.plan_id))
                .exists()
        );
        std::fs::remove_file(fake_perf).expect("remove test double");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn auto_collection_does_not_hide_pid_identity_change_with_fallback() {
        let _execution_guard = EXECUTION_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let directory = std::env::temp_dir().join(format!(
            "perflens-auto-pid-reuse-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let fake_perf = directory.join("perf-test-double");
        write_fake_perf(&fake_perf);
        let mut plan = record_plan();
        plan.duration_milliseconds = 500;
        plan.requested_event_source = RequestedEventSource::Auto;
        plan.fallback_allowed = true;
        plan.fallback_record_event = Some(RecordEvent::CpuClock);
        let validations = AtomicU64::new(0);
        let error = execute_perf(
            &plan,
            &fake_perf,
            &directory,
            nix::unistd::getegid().as_raw(),
            &|_target| {
                if validations.fetch_add(1, Ordering::Relaxed) == 0 {
                    Ok(())
                } else {
                    Err(denied("Target PID owner or start time changed"))
                }
            },
        )
        .expect_err("PID identity failure must not trigger a software retry");

        assert_eq!(error.code, "PATH_SAFETY_VIOLATION");
        assert_eq!(validations.load(Ordering::Relaxed), 2);
        assert!(
            !directory
                .join(format!("{}.perf.data", plan.plan_id))
                .exists()
        );
        assert!(
            !directory
                .join(format!(".perflens-helper-{}.tmp", plan.plan_id))
                .exists()
        );
        std::fs::remove_file(fake_perf).expect("remove test double");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn stale_safe_worker_files_recover_but_unsafe_entries_fail_closed() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-worker-recovery-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let stale = directory.join(".perflens-helper-plan-0123456789abcdefabcd.tmp");
        std::fs::write(&stale, b"partial").expect("write stale temporary");
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o600))
            .expect("secure stale temporary");
        recover_stale_temporary_files(&directory, nix::unistd::getegid().as_raw())
            .expect("recover safe stale file");
        assert!(!stale.exists());

        let published = directory.join("plan-0123456789abcdefabce.stat.csv");
        let published_temporary = directory.join(".perflens-helper-plan-0123456789abcdefabce.tmp");
        std::fs::write(&published, b"durable evidence").expect("write published evidence");
        std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o640))
            .expect("secure published evidence");
        std::fs::hard_link(&published, &published_temporary)
            .expect("simulate crash after publication link");
        recover_stale_temporary_files(&directory, nix::unistd::getegid().as_raw())
            .expect("complete safe published recovery");
        assert!(!published_temporary.exists());
        assert_eq!(
            std::fs::read(&published).expect("read recovered evidence"),
            b"durable evidence"
        );

        std::fs::write(&stale, b"unsafe").expect("write unsafe temporary");
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o666))
            .expect("make unsafe temporary");
        assert!(
            recover_stale_temporary_files(&directory, nix::unistd::getegid().as_raw()).is_err()
        );
        std::fs::remove_file(stale).expect("remove unsafe temporary");
        std::fs::remove_file(published).expect("remove recovered evidence");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn consumed_plan_marker_is_exact_mode_and_replay_safe() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-replay-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        consume_plan(&directory, "plan-0123456789abcdefabcd").expect("consume once");
        let marker = directory.join(".perflens-consumed-plan-0123456789abcdefabcd");
        assert_eq!(
            marker
                .metadata()
                .expect("marker metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(consume_plan(&directory, "plan-0123456789abcdefabcd").is_err());
        std::fs::remove_file(marker).expect("remove marker");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn spool_capacity_rejects_symlinked_or_malformed_managed_entries() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-spool-entry-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let outside = std::env::temp_dir().join(format!(
            "perflens-outside-artifact-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&outside, b"outside").expect("write outside target");
        let disguised = directory.join("plan-0123456789abcdefabcd.stat.csv");
        std::os::unix::fs::symlink(&outside, &disguised).expect("create disguised symlink");
        assert!(authorize_spool_capacity(&directory, 0, nix::unistd::getegid().as_raw()).is_err());
        std::fs::remove_file(disguised).expect("remove disguised symlink");

        let malformed = directory.join("plan-0123456789abcdefabcd.perf.data");
        std::fs::write(&malformed, b"unsafe mode").expect("write malformed artifact");
        std::fs::set_permissions(&malformed, std::fs::Permissions::from_mode(0o666))
            .expect("make malformed artifact writable");
        assert!(authorize_spool_capacity(&directory, 0, nix::unistd::getegid().as_raw()).is_err());
        std::fs::remove_file(malformed).expect("remove malformed artifact");
        std::fs::remove_file(outside).expect("remove outside target");
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn startup_spool_validation_does_not_apply_new_collection_quota() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-full-spool-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        let artifact_gid = nix::unistd::getegid().as_raw();
        for index in 0..500_u64 {
            let artifact = directory.join(format!("plan-{index:020x}.stat.csv"));
            std::fs::write(&artifact, b"x").expect("write retained artifact");
            std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o640))
                .expect("secure retained artifact");
        }
        assert_eq!(
            validate_spool_entries(&directory, artifact_gid).expect("validate full spool"),
            (500, 500)
        );
        assert!(authorize_spool_capacity(&directory, 1, artifact_gid).is_err());
        for entry in std::fs::read_dir(&directory).expect("read full spool") {
            std::fs::remove_file(entry.expect("read retained artifact").path())
                .expect("remove retained artifact");
        }
        std::fs::remove_dir(directory).expect("remove spool");
    }

    #[test]
    fn replay_state_prunes_expired_markers_and_rejects_reuse() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-replay-prune-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        let plan_id = "plan-0123456789abcdefabcd";
        consume_plan(&directory, plan_id).expect("consume plan");
        assert!(prune_replay_markers(&directory, Some(plan_id)).is_err());

        let marker = directory.join(".perflens-consumed-plan-0123456789abcdefabcd");
        let stale = SystemTime::now()
            .checked_sub(REPLAY_RETENTION + Duration::from_secs(1))
            .expect("stale timestamp");
        let times = std::fs::FileTimes::new().set_modified(stale);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&marker)
            .expect("open marker")
            .set_times(times)
            .expect("make marker stale");
        assert_eq!(
            prune_replay_markers(&directory, None).expect("prune stale marker"),
            0
        );
        assert!(!marker.exists());
        std::fs::remove_dir(directory).expect("remove spool");
    }
}
