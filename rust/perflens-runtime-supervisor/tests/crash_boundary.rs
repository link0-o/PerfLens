#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn sigkill_of_mcp_equivalent_parent_triggers_verified_cleanup() {
    let directory = private_directory();
    let script = directory.join("parent.py");
    fs::write(&script, PYTHON_PARENT).expect("write parent harness");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o600)).expect("protect harness");

    let mut unrelated = Command::new("/usr/bin/sleep")
        .arg("10")
        .spawn()
        .expect("start unrelated process");
    let mut parent = Command::new("/usr/bin/python3")
        .arg(&script)
        .arg(env!("CARGO_BIN_EXE_perflens-runtime-supervisor"))
        .arg(&directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start MCP-equivalent parent");
    let stdout = parent.stdout.take().expect("parent stdout");
    let mut reader = BufReader::new(stdout);
    let mut supervisor_line = String::new();
    reader
        .read_line(&mut supervisor_line)
        .expect("read supervisor pid");
    let supervisor_pid: u32 = supervisor_line.trim().parse().expect("supervisor pid");
    let workload_file = directory.join("workload.pid");
    let workload_pid = wait_for_pid_file(&workload_file, Duration::from_secs(5));

    parent.kill().expect("SIGKILL MCP-equivalent parent");
    parent.wait().expect("reap parent");
    assert!(
        wait_until_gone(workload_pid, Duration::from_secs(5)),
        "workload survived parent crash"
    );
    assert!(
        wait_until_gone(supervisor_pid, Duration::from_secs(5)),
        "supervisor did not finish cleanup"
    );
    assert!(unrelated.try_wait().expect("check unrelated").is_none());
    unrelated.kill().expect("stop unrelated process");
    unrelated.wait().expect("reap unrelated process");

    fs::remove_file(workload_file).expect("remove workload marker");
    fs::remove_file(directory.join("events.ndjson")).expect("remove private output");
    fs::remove_file(directory.join("probe.so")).expect("remove probe");
    fs::remove_file(script).expect("remove harness");
    fs::remove_dir(directory).expect("remove test directory");
}

#[test]
fn sigterm_of_supervisor_runs_descendant_cleanup_before_exit() {
    let directory = private_directory();
    let script = directory.join("parent.py");
    fs::write(&script, PYTHON_PARENT).expect("write parent harness");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o600)).expect("protect harness");

    let mut parent = Command::new("/usr/bin/python3")
        .arg(&script)
        .arg(env!("CARGO_BIN_EXE_perflens-runtime-supervisor"))
        .arg(&directory)
        .arg("wait")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start MCP-equivalent parent");
    let stdout = parent.stdout.take().expect("parent stdout");
    let mut reader = BufReader::new(stdout);
    let mut supervisor_line = String::new();
    reader
        .read_line(&mut supervisor_line)
        .expect("read supervisor pid");
    let supervisor_pid: u32 = supervisor_line.trim().parse().expect("supervisor pid");
    let workload_pid = wait_for_pid_file(&directory.join("workload.pid"), Duration::from_secs(5));
    wait_for_group_descendant(workload_pid, Duration::from_secs(5));

    // SAFETY: SIGTERM targets the exact child PID printed by the parent harness.
    assert_eq!(
        unsafe { libc::kill(supervisor_pid.cast_signed(), libc::SIGTERM) },
        0
    );
    let status = parent
        .wait()
        .expect("wait for signal-aware supervisor parent");
    assert!(
        status.success(),
        "supervisor did not report verified cleanup"
    );
    assert!(
        wait_until_gone(workload_pid, Duration::from_secs(5)),
        "workload survived direct supervisor SIGTERM"
    );
    assert!(
        wait_until_gone(supervisor_pid, Duration::from_secs(5)),
        "supervisor survived after writing its cleanup receipt"
    );
    assert!(!process_group_exists(workload_pid));

    fs::remove_file(directory.join("workload.pid")).expect("remove workload marker");
    fs::remove_file(directory.join("events.ndjson")).expect("remove private output");
    fs::remove_file(directory.join("probe.so")).expect("remove probe");
    fs::remove_file(script).expect("remove harness");
    fs::remove_dir(directory).expect("remove test directory");
}

fn private_directory() -> PathBuf {
    for _attempt in 0..128 {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "perflens-runtime-supervisor-crash-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("protect test directory");
                return path;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create private directory: {error}"),
        }
    }
    panic!("private directory collision bound exhausted")
}

fn wait_for_pid_file(path: &Path, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(value) = fs::read_to_string(path)
            && let Ok(pid) = value.trim().parse()
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "workload marker was not created");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_until_gone(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while process_exists(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    !process_exists(pid)
}

fn wait_for_group_descendant(group: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !process_group_exists(group) {
        assert!(
            Instant::now() < deadline,
            "workload descendant was not observed"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn process_group_exists(group: u32) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return false;
        };
        if pid == group {
            return false;
        }
        let Ok(raw) = fs::read(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let Some(close) = raw.iter().rposition(|byte| *byte == b')') else {
            return false;
        };
        std::str::from_utf8(raw.get(close + 2..).unwrap_or_default())
            .ok()
            .and_then(|suffix| suffix.split_ascii_whitespace().nth(2))
            .and_then(|value| value.parse::<u32>().ok())
            == Some(group)
    })
}

fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 only queries the integer PID and does not dereference memory.
    let result = unsafe { libc::kill(pid.cast_signed(), 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

const PYTHON_PARENT: &str = r#"
import hashlib
import json
import os
import stat
import subprocess
import sys
import time

supervisor = os.path.realpath(sys.argv[1])
root = os.path.realpath(sys.argv[2])
probe_path = os.path.join(root, "probe.so")
output_path = os.path.join(root, "events.ndjson")
with open(probe_path, "wb") as stream:
    stream.write(b"not-a-real-preload-library")
os.chmod(probe_path, 0o644)
executable_fd = os.open("/usr/bin/dash", os.O_RDONLY | os.O_CLOEXEC)
probe_fd = os.open(probe_path, os.O_RDONLY | os.O_CLOEXEC)
output_fd = os.open(output_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
request_read, request_write = os.pipe2(os.O_CLOEXEC)
receipt_read, receipt_write = os.pipe2(os.O_CLOEXEC)
liveness_read, liveness_write = os.pipe2(os.O_CLOEXEC)

def digest_fd(descriptor):
    with open(f"/proc/self/fd/{descriptor}", "rb", buffering=0) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def file_identity(descriptor):
    metadata = os.fstat(descriptor)
    return {
        "descriptor": descriptor,
        "sha256": digest_fd(descriptor),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "owner_uid": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "links": metadata.st_nlink,
        "size": metadata.st_size,
    }

output_metadata = os.fstat(output_fd)
directory_metadata = os.fstat(directory_fd)
request = {
    "schema_version": "1.0",
    "protocol_version": "1.0",
    "request_id": "0123456789abcdefabcd",
    "expected_parent_pid": os.getpid(),
    "expected_supervisor_sha256": hashlib.sha256(open(supervisor, "rb").read()).hexdigest(),
    "executable": file_identity(executable_fd),
    "working_directory": {
        "descriptor": directory_fd,
        "device": directory_metadata.st_dev,
        "inode": directory_metadata.st_ino,
        "owner_uid": directory_metadata.st_uid,
        "mode": stat.S_IMODE(directory_metadata.st_mode),
    },
    "arguments": [
        "-c",
        "echo $$ > workload.pid; trap '' TERM; while :; do sleep 1; done",
    ],
    "timeout_milliseconds": 30000,
    "request": {
        "adapter": "native_pthread",
        "probe": file_identity(probe_fd),
        "output": {
            "descriptor": output_fd,
            "device": output_metadata.st_dev,
            "inode": output_metadata.st_ino,
            "owner_uid": output_metadata.st_uid,
            "mode": stat.S_IMODE(output_metadata.st_mode),
            "links": output_metadata.st_nlink,
            "maximum_size": 67108864,
        },
        "semantics": "thresholded",
        "threshold_ns": 1000,
        "max_events": 20000,
    },
}
passed = (
    request_read, receipt_write, liveness_read, executable_fd, probe_fd,
    output_fd, directory_fd,
)
child = subprocess.Popen(
    [
        supervisor,
        "--request-fd", str(request_read),
        "--receipt-fd", str(receipt_write),
        "--liveness-fd", str(liveness_read),
    ],
    close_fds=True,
    pass_fds=passed,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
os.close(request_read)
os.close(receipt_write)
os.close(liveness_read)
payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
os.write(request_write, len(payload).to_bytes(4, "big") + payload)
os.close(request_write)
print(child.pid, flush=True)
if len(sys.argv) > 3 and sys.argv[3] == "wait":
    raise SystemExit(child.wait())
while True:
    time.sleep(1)
"#;
