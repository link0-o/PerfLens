//! Fixed-spool execution and publication for target-filtered trace plans.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::{Gid, fchown, getegid, geteuid};
use sha2::{Digest, Sha256};

use crate::backend;
use crate::{TraceHelperTarget, TraceMode};

pub const TRACE_SPOOL_ROOT: &str = "/var/lib/perflens-trace-helper";
const MAX_SPOOL_ARTIFACTS: usize = 128;
const MAX_SPOOL_BYTES: u64 = 4 << 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceExecutionPlan {
    pub plan_id: String,
    pub target: TraceHelperTarget,
    pub mode: TraceMode,
    pub duration_milliseconds: u64,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceExecutionResult {
    pub artifact_name: String,
    pub output_bytes: u64,
    pub output_sha256: String,
    pub observed_target_tids: Vec<u32>,
    pub event_count: u64,
    pub lost_event_count: u64,
    pub truncated: bool,
    pub started_at_monotonic_nanoseconds: u64,
    pub finished_at_monotonic_nanoseconds: u64,
}

#[allow(clippy::too_many_lines)]
pub fn execute_plan<R>(
    plan: &TraceExecutionPlan,
    artifact_gid: u32,
    ready_notifier: &mut R,
) -> io::Result<TraceExecutionResult>
where
    R: FnMut() -> io::Result<()>,
{
    crate::assert_pid_identity(&plan.target)?;
    let spool = trusted_spool(Path::new(TRACE_SPOOL_ROOT), artifact_gid)?;
    validate_spool_capacity(&spool, plan.max_output_bytes, artifact_gid)?;
    consume_plan(&spool, &plan.plan_id)?;
    let artifact_name = format!("{}.trace.ndjson", plan.plan_id);
    let output = spool.join(&artifact_name);
    if output.symlink_metadata().is_ok() {
        return Err(denied("Trace Helper output already exists"));
    }
    let temporary = spool.join(format!(".perflens-trace-{}.tmp", plan.plan_id));
    let mut temporary_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let key = random_lock_identity_key()?;
    ready_notifier()?;
    let capture = match backend::capture(
        plan.mode,
        &plan.target,
        Duration::from_millis(plan.duration_milliseconds),
        plan.max_output_bytes,
        &key,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            let _ignored = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    if capture.events.is_empty() {
        fs::remove_file(&temporary)?;
        return Err(io::Error::other(
            "Target-filtered trace produced no usable events",
        ));
    }

    let mut hasher = Sha256::new();
    let mut written = 0_u64;
    let mut event_count = 0_u64;
    let mut retained_target_tids = BTreeSet::new();
    let mut output_truncated = capture.truncated;
    for event in &capture.events {
        let mut line = serde_json::to_vec(event).map_err(io::Error::other)?;
        line.push(b'\n');
        let line_bytes = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if written.saturating_add(line_bytes) > plan.max_output_bytes {
            output_truncated = true;
            break;
        }
        temporary_file.write_all(&line)?;
        hasher.update(&line);
        written += line_bytes;
        event_count += 1;
        retained_target_tids.insert(event.target_tid);
        if let Some(related_target_tid) = event.related_target_tid {
            retained_target_tids.insert(related_target_tid);
        }
    }
    if event_count == 0 || written == 0 {
        drop(temporary_file);
        fs::remove_file(&temporary)?;
        return Err(io::Error::other(
            "Target-filtered trace output limit retained no usable events",
        ));
    }
    temporary_file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640))?;
    fchown(
        temporary_file.as_fd(),
        None,
        Some(Gid::from_raw(artifact_gid)),
    )
    .map_err(io::Error::other)?;
    temporary_file.sync_all()?;
    let metadata = temporary_file.metadata()?;
    if metadata.uid() != geteuid().as_raw()
        || metadata.gid() != artifact_gid
        || metadata.mode() & 0o777 != 0o640
        || metadata.nlink() != 1
        || metadata.len() != written
    {
        drop(temporary_file);
        fs::remove_file(&temporary)?;
        return Err(denied("Trace Helper temporary output identity changed"));
    }
    drop(temporary_file);
    fs::hard_link(&temporary, &output)?;
    File::open(&output)?.sync_all()?;
    fs::remove_file(&temporary)?;
    File::open(&spool)?.sync_all()?;
    let published = output.symlink_metadata()?;
    if !published.is_file()
        || published.uid() != geteuid().as_raw()
        || published.gid() != artifact_gid
        || published.mode() & 0o777 != 0o640
        || published.nlink() != 1
        || published.len() != written
    {
        return Err(denied("Trace Helper published output identity changed"));
    }

    Ok(TraceExecutionResult {
        artifact_name,
        output_bytes: written,
        output_sha256: hex_digest(&hasher.finalize()),
        observed_target_tids: retained_target_tids.into_iter().collect(),
        event_count,
        lost_event_count: capture.lost_event_count,
        truncated: output_truncated,
        started_at_monotonic_nanoseconds: capture.started_at_monotonic_nanoseconds,
        finished_at_monotonic_nanoseconds: capture.finished_at_monotonic_nanoseconds,
    })
}

pub fn backend_modes() -> Vec<TraceMode> {
    let scheduler = backend::probe(TraceMode::Sched);
    let lock = backend::probe(TraceMode::Lock);
    let mut modes = Vec::new();
    if scheduler {
        modes.extend([TraceMode::Sched, TraceMode::OffCpu]);
    }
    if lock {
        modes.push(TraceMode::Lock);
    }
    modes
}

fn trusted_spool(path: &Path, artifact_gid: u32) -> io::Result<PathBuf> {
    let resolved = path.canonicalize()?;
    let metadata = resolved.metadata()?;
    if resolved != path
        || !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.gid() != artifact_gid
        || metadata.mode() & 0o777 != 0o750
    {
        return Err(denied("Trace Helper fixed spool identity is unsafe"));
    }
    Ok(resolved)
}

fn validate_spool_capacity(spool: &Path, requested: u64, artifact_gid: u32) -> io::Result<()> {
    let mut artifacts = 0_usize;
    let mut bytes = 0_u64;
    for entry in fs::read_dir(spool)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| denied("Trace Helper spool contains an invalid name"))?;
        let metadata = entry.path().symlink_metadata()?;
        if valid_marker_name(name) {
            if !metadata.is_file()
                || metadata.uid() != geteuid().as_raw()
                || metadata.gid() != getegid().as_raw()
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() != 0
            {
                return Err(denied("Trace Helper replay marker is unsafe"));
            }
            continue;
        }
        if name.starts_with(".perflens-trace-")
            && Path::new(name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
        {
            return Err(denied(
                "Trace Helper spool contains an unfinished temporary output",
            ));
        }
        if !valid_artifact_name(name)
            || !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.gid() != artifact_gid
            || metadata.mode() & 0o777 != 0o640
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > crate::MAX_TRACE_HELPER_OUTPUT_BYTES
        {
            return Err(denied("Trace Helper spool contains an unsafe entry"));
        }
        artifacts = artifacts.saturating_add(1);
        bytes = bytes.saturating_add(metadata.len());
    }
    if artifacts >= MAX_SPOOL_ARTIFACTS || bytes.saturating_add(requested) > MAX_SPOOL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "Trace Helper spool quota rejected the plan",
        ));
    }
    Ok(())
}

fn consume_plan(spool: &Path, plan_id: &str) -> io::Result<()> {
    let marker = spool.join(format!(".perflens-consumed-{plan_id}"));
    let marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(marker)
        .map_err(|_error| denied("Trace Helper plan was already consumed"))?;
    marker_file.sync_all()?;
    File::open(spool)?.sync_all()
}

fn random_lock_identity_key() -> io::Result<[u8; 32]> {
    let mut key = [0_u8; 32];
    let mut random = File::open("/dev/urandom")?;
    random.read_exact(&mut key)?;
    Ok(key)
}

fn valid_marker_name(name: &str) -> bool {
    name.strip_prefix(".perflens-consumed-trace-plan-")
        .is_some_and(valid_plan_suffix)
}

fn valid_artifact_name(name: &str) -> bool {
    name.strip_prefix("trace-plan-")
        .and_then(|value| value.strip_suffix(".trace.ndjson"))
        .is_some_and(valid_plan_suffix)
}

fn valid_plan_suffix(value: &str) -> bool {
    value.len() == 20
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::{valid_artifact_name, valid_marker_name};

    #[test]
    fn accepts_only_fixed_trace_spool_names() {
        assert!(valid_artifact_name(
            "trace-plan-0123456789abcdefabcd.trace.ndjson"
        ));
        assert!(valid_marker_name(
            ".perflens-consumed-trace-plan-0123456789abcdefabcd"
        ));
        assert!(!valid_artifact_name(
            "../../trace-plan-0123456789abcdefabcd.trace.ndjson"
        ));
        assert!(!valid_artifact_name(
            "trace-plan-0123456789abcdefabcd.perf.data"
        ));
    }
}
