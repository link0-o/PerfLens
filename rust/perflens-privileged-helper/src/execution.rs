//! Fixed-path, policy-bounded `perf` execution for the privileged Helper.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, killpg};
use nix::sys::statvfs::statvfs;
use nix::unistd::{Pid, geteuid};
use sha2::{Digest, Sha256};

use crate::{CallGraph, CollectionMode, HelperTarget};

const PERF_PATH: &str = "/usr/bin/perf";
const SLEEP_PATH: &str = "/usr/bin/sleep";
const SPOOL_ROOT: &str = "/var/lib/perflens-helper";
const MAX_DURATION_MILLISECONDS: u64 = 30_000;
const MAX_FREQUENCY_HZ: u32 = 99;
const MAX_OUTPUT_BYTES: u64 = 256 << 20;
const MAX_SPOOL_BYTES: u64 = 5 << 30;
const MAX_SPOOL_ARTIFACTS: usize = 500;
const MIN_FREE_BYTES: u64 = 2 << 30;
const ALLOWED_STAT_EVENTS: &[&str] = &[
    "cycles",
    "instructions",
    "cache-references",
    "cache-misses",
    "branches",
    "branch-misses",
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
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub artifact_name: String,
    pub output_bytes: u64,
    pub output_sha256: String,
    pub output_format: &'static str,
    pub started_at_unix_milliseconds: u64,
    pub finished_at_unix_milliseconds: u64,
}

#[derive(Debug)]
pub struct ExecutionError {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: &'static str,
}

pub fn execute_production_plan(
    plan: &ExecutionPlan,
    allowed_uid: u32,
    artifact_gid: u32,
) -> Result<ExecutionResult, ExecutionError> {
    validate_plan(plan, allowed_uid)?;
    assert_pid_identity(&plan.target)?;
    let perf_path = trusted_root_executable(Path::new(PERF_PATH))?;
    let sleep_path = trusted_root_executable(Path::new(SLEEP_PATH))?;
    let spool_root = trusted_spool(Path::new(SPOOL_ROOT))?;
    authorize_spool_capacity(&spool_root, plan.max_output_bytes)?;
    consume_plan(&spool_root, &plan.plan_id)?;
    execute_perf(plan, &perf_path, &sleep_path, &spool_root, artifact_gid)
}

fn validate_plan(plan: &ExecutionPlan, allowed_uid: u32) -> Result<(), ExecutionError> {
    let allowed_events = ALLOWED_STAT_EVENTS.iter().copied().collect::<HashSet<_>>();
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
    let resolved = path
        .canonicalize()
        .map_err(|_error| denied("Fixed executable cannot be resolved"))?;
    let metadata = resolved
        .metadata()
        .map_err(|_error| denied("Fixed executable cannot be inspected"))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(denied(
            "Fixed executable identity or permissions are unsafe",
        ));
    }
    Ok(resolved)
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

fn authorize_spool_capacity(spool: &Path, requested: u64) -> Result<(), ExecutionError> {
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    for entry in fs::read_dir(spool).map_err(|_error| spool_error())? {
        let entry = entry.map_err(|_error| spool_error())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(spool_error)?;
        let metadata = entry.metadata().map_err(|_error| spool_error())?;
        if name.starts_with(".perflens-consumed-plan-") {
            if !metadata.is_file() || metadata.len() != 0 || metadata.mode() & 0o777 != 0o600 {
                return Err(spool_error());
            }
            continue;
        }
        if !(name.starts_with("plan-")
            && (name.ends_with(".stat.csv") || name.ends_with(".perf.data")))
            || !metadata.is_file()
        {
            return Err(spool_error());
        }
        count += 1;
        bytes = bytes.checked_add(metadata.len()).ok_or_else(spool_error)?;
    }
    let filesystem = statvfs(spool).map_err(|_error| spool_error())?;
    let free_bytes = filesystem
        .blocks_available()
        .saturating_mul(filesystem.fragment_size());
    if count >= MAX_SPOOL_ARTIFACTS
        || bytes.saturating_add(requested) > MAX_SPOOL_BYTES
        || free_bytes.saturating_sub(requested) < MIN_FREE_BYTES
    {
        return Err(ExecutionError {
            code: "RESOURCE_LIMIT_EXCEEDED",
            stage: "privileged_helper",
            message: "Privileged Helper spool capacity policy rejected the plan",
        });
    }
    Ok(())
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

fn execute_perf(
    plan: &ExecutionPlan,
    perf_path: &Path,
    sleep_path: &Path,
    spool: &Path,
    artifact_gid: u32,
) -> Result<ExecutionResult, ExecutionError> {
    let suffix = if plan.mode == CollectionMode::Stat {
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
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_error| spool_error())?;
    let outcome = execute_perf_inner(
        plan,
        perf_path,
        sleep_path,
        &temporary,
        &output,
        artifact_name,
        artifact_gid,
    );
    if outcome.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    outcome
}

#[allow(clippy::too_many_lines)] // Linear lifecycle keeps spawn, watchdog, and publication ordered.
fn execute_perf_inner(
    plan: &ExecutionPlan,
    perf_path: &Path,
    sleep_path: &Path,
    temporary: &Path,
    output: &Path,
    artifact_name: String,
    artifact_gid: u32,
) -> Result<ExecutionResult, ExecutionError> {
    let duration = format!(
        "{}.{:03}",
        plan.duration_milliseconds / 1000,
        plan.duration_milliseconds % 1000
    );
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
                "--freq",
                &frequency.to_string(),
                "--call-graph",
                call_graph,
                "-g",
                "-o",
                temporary.to_str().ok_or_else(spool_error)?,
            ]);
        }
    }
    command
        .args(["-p", &plan.target.pid.to_string(), "--"])
        .arg(sleep_path)
        .arg(duration)
        .current_dir("/")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let started_at_unix_milliseconds = unix_milliseconds()?;
    let started = Instant::now();
    let mut child = command.spawn().map_err(|_error| external_error())?;
    let timeout = Duration::from_millis(plan.duration_milliseconds.saturating_add(10_000));
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_error| external_error())? {
            break status;
        }
        let size = temporary.metadata().map_or(0, |metadata| metadata.len());
        if started.elapsed() > timeout || size > plan.max_output_bytes {
            let _ignored = killpg(Pid::from_raw(child.id().cast_signed()), Signal::SIGKILL);
            let _ignored = child.wait();
            return Err(ExecutionError {
                code: "RESOURCE_LIMIT_EXCEEDED",
                stage: "external_tool",
                message: "Privileged perf exceeded its time or output limit",
            });
        }
        thread::sleep(Duration::from_millis(20));
    };
    if !status.success() {
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
    fs::set_permissions(temporary, fs::Permissions::from_mode(0o640))
        .map_err(|_error| spool_error())?;
    std::os::unix::fs::chown(temporary, None, Some(artifact_gid))
        .map_err(|_error| spool_error())?;
    let digest = sha256_file(temporary)?;
    fs::hard_link(temporary, output).map_err(|_error| spool_error())?;
    fs::remove_file(temporary).map_err(|_error| spool_error())?;
    File::open(output)
        .and_then(|file| file.sync_all())
        .and_then(|()| File::open(output.parent().unwrap_or_else(|| Path::new("/"))))
        .and_then(|directory| directory.sync_all())
        .map_err(|_error| spool_error())?;
    Ok(ExecutionResult {
        artifact_name,
        output_bytes: metadata.len(),
        output_sha256: digest,
        output_format: if plan.mode == CollectionMode::Stat {
            "perf_stat_delimited"
        } else {
            "perf_data"
        },
        started_at_unix_milliseconds,
        finished_at_unix_milliseconds: unix_milliseconds()?,
    })
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        ExecutionPlan, MAX_DURATION_MILLISECONDS, consume_plan, execute_perf, validate_plan,
    };
    use crate::{CallGraph, CollectionMode, HelperTarget};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

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
            max_output_bytes: 8 << 20,
        }
    }

    #[test]
    fn immutable_policy_accepts_bounded_owner_only_record() {
        assert!(validate_plan(&record_plan(), 1000).is_ok());
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
    fn fixed_argv_execution_publishes_a_bounded_new_artifact() {
        let directory = std::env::temp_dir().join(format!(
            "perflens-execution-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("create spool");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure spool");
        let fake_perf = directory.join("perf-test-double");
        std::fs::write(
            &fake_perf,
            "#!/bin/sh\nset -eu\nout=''\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = '-o' ]; then shift; out=$1; fi\n  shift\ndone\nprintf '1000;count;cycles;1;100.00;;\n' > \"$out\"\n",
        )
        .expect("write perf test double");
        std::fs::set_permissions(&fake_perf, std::fs::Permissions::from_mode(0o700))
            .expect("make test double executable");
        let mut plan = record_plan();
        plan.mode = CollectionMode::Stat;
        plan.frequency_hz = None;
        plan.call_graph = None;
        plan.events = vec!["cycles".to_owned()];
        let result = execute_perf(
            &plan,
            &fake_perf,
            std::path::Path::new("/usr/bin/sleep"),
            &directory,
            nix::unistd::getegid().as_raw(),
        )
        .expect("execute fixed argv test double");
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
}
