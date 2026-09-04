use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};

const CONTROL_PATH: &str = "/run/perflens-gate/control.sock";
const READY_PREFIX: &[u8] = b"PERFLENS_GATE_V3 READY\0";
const READY_FRAME_LEN: usize = READY_PREFIX.len() + (5 * std::mem::size_of::<u64>());
const EXEC_FRAME: &[u8] = b"PERFLENS_GATE_V3 EXEC\n";
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 65_536;
const CONTROL_TIMEOUT: Duration = Duration::from_mins(1);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_CONNECT_RETRY: Duration = Duration::from_millis(10);
const NATIVE_PROBE_PATH: &str = "/usr/lib/perflens/libperflens-pthread-probe.so";
const CPYTHON_BOOTSTRAP_ROOT: &str = "/usr/lib/perflens/python-runtime-lock";
const JAVA_JFR_CONFIG_PATH: &str = "/usr/lib/perflens/runtime-lock.jfc";
const NATIVE_OUTPUT_PATH: &str = "/perflens-scratch/runtime-lock-native.ndjson";
const CPYTHON_OUTPUT_PATH: &str = "/perflens-scratch/runtime-lock-cpython.ndjson";
const JAVA_JFR_OUTPUT_PATH: &str = "/perflens-scratch/runtime-lock.jfr";
const GO_MUTEX_OUTPUT_PATH: &str = "/perflens-scratch/runtime-lock-mutex.pprof";
const GO_BLOCK_OUTPUT_PATH: &str = "/perflens-scratch/runtime-lock-block.pprof";
const RUNTIME_LOCK_OUTPUT_MODE: u32 = 0o644;

#[derive(Debug, Eq, PartialEq)]
enum RuntimeLockLaunch {
    Native {
        semantics: String,
        threshold_ns: String,
        max_events: String,
    },
    Cpython {
        semantics: String,
        threshold_ns: String,
        max_events: String,
    },
    Java {
        profile: String,
    },
    Go {
        profiles: String,
    },
}

#[derive(Debug, Eq, PartialEq)]
struct GateCommand {
    control: PathBuf,
    runtime_lock: Option<RuntimeLockLaunch>,
    executable: OsString,
    arguments: Vec<OsString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceIdentity {
    pid: u64,
    user: u64,
    mount: u64,
    cgroup: u64,
    effective_uid: u64,
}

fn main() -> ExitCode {
    match parse_arguments(env::args_os()) {
        Ok(command) => run(&command),
        Err(message) => {
            eprintln!("perflens-container-gate: {message}");
            ExitCode::from(64)
        }
    }
}

fn parse_arguments<I>(arguments: I) -> Result<GateCommand, &'static str>
where
    I: IntoIterator<Item = OsString>,
{
    let mut values = arguments.into_iter();
    let _program = values.next().ok_or("missing program name")?;
    if values.next().as_deref() != Some(std::ffi::OsStr::new("--control")) {
        return Err("expected the fixed --control option");
    }
    let control = values.next().ok_or("missing control path")?;
    if control != std::ffi::OsStr::new(CONTROL_PATH) {
        return Err("control path differs from the packaged mount");
    }
    let next = values.next().ok_or("missing workload separator")?;
    let (runtime_lock, separator) = if next == std::ffi::OsStr::new("--runtime-lock") {
        let adapter = values.next().ok_or("missing Runtime Lock adapter")?;
        let launch = parse_runtime_lock(&adapter, &mut values)?;
        (
            Some(launch),
            values.next().ok_or("missing workload separator")?,
        )
    } else {
        (None, next)
    };
    if separator != std::ffi::OsStr::new("--") {
        return Err("missing workload separator");
    }
    let executable = values.next().ok_or("missing workload executable")?;
    validate_executable(Path::new(&executable))?;
    let arguments: Vec<OsString> = values.collect();
    if arguments.len() > MAX_ARGUMENTS {
        return Err("workload argument count exceeds the fixed limit");
    }
    let bytes = arguments.iter().try_fold(0usize, |total, value| {
        use std::os::unix::ffi::OsStrExt;
        total.checked_add(value.as_bytes().len())
    });
    if bytes.is_none_or(|value| value > MAX_ARGUMENT_BYTES) {
        return Err("workload arguments exceed the fixed byte limit");
    }
    Ok(GateCommand {
        control: PathBuf::from(control),
        runtime_lock,
        executable,
        arguments,
    })
}

fn parse_runtime_lock<I>(
    adapter: &std::ffi::OsStr,
    values: &mut I,
) -> Result<RuntimeLockLaunch, &'static str>
where
    I: Iterator<Item = OsString>,
{
    if adapter == std::ffi::OsStr::new("native_pthread")
        || adapter == std::ffi::OsStr::new("cpython_threading")
    {
        expect_option(values, "--runtime-lock-semantics")?;
        let semantics = ascii_value(values, "missing Runtime Lock semantics")?;
        expect_option(values, "--runtime-lock-threshold-ns")?;
        let threshold_ns = ascii_value(values, "missing Runtime Lock threshold")?;
        expect_option(values, "--runtime-lock-max-events")?;
        let max_events = ascii_value(values, "missing Runtime Lock event limit")?;
        validate_event_controls(&semantics, &threshold_ns, &max_events)?;
        return if adapter == std::ffi::OsStr::new("native_pthread") {
            Ok(RuntimeLockLaunch::Native {
                semantics,
                threshold_ns,
                max_events,
            })
        } else {
            Ok(RuntimeLockLaunch::Cpython {
                semantics,
                threshold_ns,
                max_events,
            })
        };
    }
    if adapter == std::ffi::OsStr::new("java_jfr") {
        expect_option(values, "--runtime-lock-profile")?;
        let profile = ascii_value(values, "missing Java JFR profile")?;
        if profile != "balanced" && profile != "deep" {
            return Err("Java JFR profile is unsupported");
        }
        return Ok(RuntimeLockLaunch::Java { profile });
    }
    if adapter == std::ffi::OsStr::new("go_pprof") {
        expect_option(values, "--runtime-lock-profiles")?;
        let profiles = ascii_value(values, "missing Go pprof profile scope")?;
        if !matches!(profiles.as_str(), "block" | "mutex" | "block,mutex") {
            return Err("Go pprof profile scope is unsupported");
        }
        return Ok(RuntimeLockLaunch::Go { profiles });
    }
    Err("Runtime Lock adapter is unsupported")
}

fn expect_option<I>(values: &mut I, expected: &'static str) -> Result<(), &'static str>
where
    I: Iterator<Item = OsString>,
{
    if values.next().as_deref() != Some(std::ffi::OsStr::new(expected)) {
        return Err("Runtime Lock option order is invalid");
    }
    Ok(())
}

fn ascii_value<I>(values: &mut I, missing: &'static str) -> Result<String, &'static str>
where
    I: Iterator<Item = OsString>,
{
    values
        .next()
        .ok_or(missing)?
        .into_string()
        .map_err(|_| "Runtime Lock option is not UTF-8")
}

fn validate_event_controls(
    semantics: &str,
    threshold_ns: &str,
    max_events: &str,
) -> Result<(), &'static str> {
    if !matches!(semantics, "exact" | "thresholded") {
        return Err("Runtime Lock semantics is unsupported");
    }
    if (semantics == "exact") != (threshold_ns == "none") {
        return Err("Runtime Lock threshold contradicts its semantics");
    }
    if semantics == "thresholded"
        && !threshold_ns
            .parse::<u64>()
            .is_ok_and(|value| (1..=1_000_000_000).contains(&value))
    {
        return Err("Runtime Lock threshold is outside its fixed bound");
    }
    if !max_events
        .parse::<u64>()
        .is_ok_and(|value| (1..=20_000).contains(&value))
    {
        return Err("Runtime Lock event limit is outside its fixed bound");
    }
    Ok(())
}

fn validate_executable(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("workload executable must be a bounded absolute path");
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("workload executable path is not normalized");
    }
    Ok(())
}

fn run(command: &GateCommand) -> ExitCode {
    if let Err(message) = await_execution_release(&command.control) {
        eprintln!("perflens-container-gate: {message}");
        return ExitCode::from(69);
    }
    let mut process = Command::new(&command.executable);
    process.args(&command.arguments);
    let output = match configure_runtime_lock(&mut process, command.runtime_lock.as_ref()) {
        Ok(output) => output,
        Err(message) => {
            eprintln!("perflens-container-gate: {message}");
            return ExitCode::from(70);
        }
    };
    let error = process.exec();
    drop(output);
    eprintln!("perflens-container-gate: workload exec failed: {error}");
    ExitCode::from(126)
}

fn configure_runtime_lock(
    process: &mut Command,
    launch: Option<&RuntimeLockLaunch>,
) -> Result<Option<File>, &'static str> {
    let Some(launch) = launch else {
        return Ok(None);
    };
    match launch {
        RuntimeLockLaunch::Native {
            semantics,
            threshold_ns,
            max_events,
        } => {
            let output = create_private_output(NATIVE_OUTPUT_PATH)?;
            process
                .env("LD_PRELOAD", NATIVE_PROBE_PATH)
                .env("PERFLENS_RUNTIME_LOCK_CONTAINER", "1")
                .env("PERFLENS_RUNTIME_LOCK_FD", output_fd_text(&output))
                .env("PERFLENS_RUNTIME_LOCK_MODE", semantics)
                .env(
                    "PERFLENS_RUNTIME_LOCK_THRESHOLD_NS",
                    if threshold_ns == "none" {
                        ""
                    } else {
                        threshold_ns
                    },
                )
                .env("PERFLENS_RUNTIME_LOCK_MAX_EVENTS", max_events);
            Ok(Some(output))
        }
        RuntimeLockLaunch::Cpython {
            semantics,
            threshold_ns,
            max_events,
        } => {
            let output = create_private_output(CPYTHON_OUTPUT_PATH)?;
            process
                .env("PYTHONPATH", CPYTHON_BOOTSTRAP_ROOT)
                .env("PERFLENS_RUNTIME_LOCK_CONTAINER", "1")
                .env("PERFLENS_RUNTIME_LOCK_FD", output_fd_text(&output))
                .env("PERFLENS_RUNTIME_LOCK_MODE", semantics)
                .env("PERFLENS_RUNTIME_LOCK_THRESHOLD_NS", threshold_ns)
                .env("PERFLENS_RUNTIME_LOCK_MAX_EVENTS", max_events);
            Ok(Some(output))
        }
        RuntimeLockLaunch::Java { profile } => {
            prepare_fixed_output(JAVA_JFR_OUTPUT_PATH)?;
            let options = format!(
                "-XX:StartFlightRecording=settings={JAVA_JFR_CONFIG_PATH},filename={JAVA_JFR_OUTPUT_PATH},dumponexit=true,name=PerfLens-{profile}"
            );
            process.env("JAVA_TOOL_OPTIONS", options);
            Ok(None)
        }
        RuntimeLockLaunch::Go { profiles } => {
            if profiles == "mutex" || profiles == "block,mutex" {
                prepare_fixed_output(GO_MUTEX_OUTPUT_PATH)?;
            }
            if profiles == "block" || profiles == "block,mutex" {
                prepare_fixed_output(GO_BLOCK_OUTPUT_PATH)?;
            }
            process
                .env("PERFLENS_RUNTIME_LOCK_GO_PROFILES", profiles)
                .env("PERFLENS_RUNTIME_LOCK_GO_MUTEX_PATH", GO_MUTEX_OUTPUT_PATH)
                .env("PERFLENS_RUNTIME_LOCK_GO_BLOCK_PATH", GO_BLOCK_OUTPUT_PATH);
            Ok(None)
        }
    }
}

fn create_private_output(path: &str) -> Result<File, &'static str> {
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(RUNTIME_LOCK_OUTPUT_MODE)
        .open(path)
        .map_err(|_| "Runtime Lock private output cannot be created")?;
    let metadata = output
        .metadata()
        .map_err(|_| "Runtime Lock private output identity is unavailable")?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.len() != 0 {
        return Err("Runtime Lock private output identity is unsafe");
    }
    output
        .set_permissions(std::fs::Permissions::from_mode(RUNTIME_LOCK_OUTPUT_MODE))
        .map_err(|_| "Runtime Lock private output mode cannot be fixed")?;
    fcntl(&output, FcntlArg::F_SETFD(FdFlag::empty()))
        .map_err(|_| "Runtime Lock output descriptor cannot survive exec")?;
    Ok(output)
}

fn prepare_fixed_output(path: &str) -> Result<(), &'static str> {
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(RUNTIME_LOCK_OUTPUT_MODE)
        .open(path)
        .map_err(|_| "Runtime Lock private output cannot be created")?;
    output
        .set_permissions(std::fs::Permissions::from_mode(RUNTIME_LOCK_OUTPUT_MODE))
        .map_err(|_| "Runtime Lock private output mode cannot be fixed")?;
    let metadata = output
        .metadata()
        .map_err(|_| "Runtime Lock private output identity is unavailable")?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.len() != 0 {
        return Err("Runtime Lock private output identity is unsafe");
    }
    Ok(())
}

fn output_fd_text(output: &File) -> String {
    use std::os::fd::AsRawFd;
    output.as_raw_fd().to_string()
}

fn await_execution_release(control_path: &Path) -> Result<(), &'static str> {
    let mut control = connect_control(control_path)?;
    let ready = ready_frame(namespace_identity()?);
    if control.set_read_timeout(Some(CONTROL_TIMEOUT)).is_err()
        || control.set_write_timeout(Some(CONTROL_TIMEOUT)).is_err()
        || control.write_all(&ready).is_err()
    {
        return Err("control handshake failed");
    }
    let mut response = [0_u8; EXEC_FRAME.len()];
    if control.read_exact(&mut response).is_err() || response != EXEC_FRAME {
        return Err("invalid execution release");
    }
    let mut trailing = [0_u8; 1];
    if !matches!(control.read(&mut trailing), Ok(0)) {
        return Err("execution release contains an extra frame");
    }
    Ok(())
}

fn namespace_identity() -> Result<NamespaceIdentity, &'static str> {
    Ok(NamespaceIdentity {
        pid: namespace_inode("pid")?,
        user: namespace_inode("user")?,
        mount: namespace_inode("mnt")?,
        cgroup: namespace_inode("cgroup")?,
        effective_uid: u64::from(nix::unistd::geteuid().as_raw()),
    })
}

fn namespace_inode(name: &str) -> Result<u64, &'static str> {
    let inode = std::fs::metadata(Path::new("/proc/self/ns").join(name))
        .map_err(|_| "self namespace identity is unavailable")?
        .ino();
    if inode == 0 {
        return Err("self namespace identity is invalid");
    }
    Ok(inode)
}

fn ready_frame(identity: NamespaceIdentity) -> [u8; READY_FRAME_LEN] {
    let mut frame = [0_u8; READY_FRAME_LEN];
    frame[..READY_PREFIX.len()].copy_from_slice(READY_PREFIX);
    let mut offset = READY_PREFIX.len();
    for value in [
        identity.pid,
        identity.user,
        identity.mount,
        identity.cgroup,
        identity.effective_uid,
    ] {
        let end = offset + std::mem::size_of::<u64>();
        frame[offset..end].copy_from_slice(&value.to_be_bytes());
        offset = end;
    }
    frame
}

fn connect_control(control_path: &Path) -> Result<UnixStream, &'static str> {
    let deadline = Instant::now() + CONTROL_CONNECT_TIMEOUT;
    loop {
        match UnixStream::connect(control_path) {
            Ok(control) => return Ok(control),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                thread::sleep(CONTROL_CONNECT_RETRY);
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err("control endpoint permission denied");
            }
            Err(_) => return Err("control endpoint unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CONTROL_PATH, EXEC_FRAME, GateCommand, NamespaceIdentity, READY_FRAME_LEN, READY_PREFIX,
        RUNTIME_LOCK_OUTPUT_MODE, await_execution_release, create_private_output,
        namespace_identity, parse_arguments, prepare_fixed_output, ready_frame,
    };
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use std::ffi::OsString;
    use std::fs;
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn parse(values: &[&str]) -> Result<GateCommand, &'static str> {
        parse_arguments(values.iter().map(OsString::from))
    }

    fn private_test_directory() -> PathBuf {
        let epoch_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must follow the Unix epoch")
            .as_nanos();
        for _attempt in 0..128 {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "perflens-container-gate-test-{}-{epoch_nanos}-{sequence}",
                process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => return directory,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create private gate test directory: {error}"),
            }
        }
        panic!("private gate test directory collision limit was exhausted")
    }

    #[test]
    fn accepts_only_fixed_control_then_absolute_workload() {
        assert_eq!(
            parse(&[
                "gate",
                "--control",
                CONTROL_PATH,
                "--",
                "/usr/bin/python3",
                "/workspace/bench.py",
                "--rounds",
                "3",
            ]),
            Ok(GateCommand {
                control: PathBuf::from(CONTROL_PATH),
                runtime_lock: None,
                executable: OsString::from("/usr/bin/python3"),
                arguments: vec![
                    OsString::from("/workspace/bench.py"),
                    OsString::from("--rounds"),
                    OsString::from("3"),
                ],
            })
        );
    }

    #[test]
    fn rejects_other_control_or_relative_workload() {
        assert!(parse(&["gate", "--control", "/tmp/x", "--", "/bin/true"]).is_err());
        assert!(parse(&["gate", "--control", CONTROL_PATH, "--", "sh"]).is_err());
        assert!(
            parse(&[
                "gate",
                "--control",
                CONTROL_PATH,
                "--",
                "/workspace/../bin/run",
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_separator_and_excess_arguments() {
        assert!(parse(&["gate", "--control", CONTROL_PATH, "/bin/true"]).is_err());
        let mut values = vec![
            "gate".to_owned(),
            "--control".to_owned(),
            CONTROL_PATH.to_owned(),
            "--".to_owned(),
            "/bin/true".to_owned(),
        ];
        values.extend((0..257).map(|_| "x".to_owned()));
        assert!(parse_arguments(values.into_iter().map(OsString::from)).is_err());
    }

    #[test]
    fn accepts_typed_native_and_cpython_runtime_lock_controls() {
        assert_eq!(
            parse(&[
                "gate",
                "--control",
                CONTROL_PATH,
                "--runtime-lock",
                "native_pthread",
                "--runtime-lock-semantics",
                "thresholded",
                "--runtime-lock-threshold-ns",
                "1000",
                "--runtime-lock-max-events",
                "20000",
                "--",
                "/workspace/workload",
            ])
            .expect("parse fixed Native launch")
            .runtime_lock,
            Some(super::RuntimeLockLaunch::Native {
                semantics: "thresholded".to_owned(),
                threshold_ns: "1000".to_owned(),
                max_events: "20000".to_owned(),
            })
        );
        assert_eq!(
            parse(&[
                "gate",
                "--control",
                CONTROL_PATH,
                "--runtime-lock",
                "cpython_threading",
                "--runtime-lock-semantics",
                "exact",
                "--runtime-lock-threshold-ns",
                "none",
                "--runtime-lock-max-events",
                "20",
                "--",
                "/workspace/workload.py",
            ])
            .expect("parse fixed CPython launch")
            .runtime_lock,
            Some(super::RuntimeLockLaunch::Cpython {
                semantics: "exact".to_owned(),
                threshold_ns: "none".to_owned(),
                max_events: "20".to_owned(),
            })
        );
    }

    #[test]
    fn accepts_typed_java_runtime_lock_controls() {
        for profile in ["balanced", "deep"] {
            assert_eq!(
                parse(&[
                    "gate",
                    "--control",
                    CONTROL_PATH,
                    "--runtime-lock",
                    "java_jfr",
                    "--runtime-lock-profile",
                    profile,
                    "--",
                    "/usr/bin/java",
                ])
                .expect("parse fixed Java launch")
                .runtime_lock,
                Some(super::RuntimeLockLaunch::Java {
                    profile: profile.to_owned(),
                })
            );
        }
    }

    #[test]
    fn accepts_typed_go_runtime_lock_controls() {
        for profiles in ["block", "mutex", "block,mutex"] {
            assert_eq!(
                parse(&[
                    "gate",
                    "--control",
                    CONTROL_PATH,
                    "--runtime-lock",
                    "go_pprof",
                    "--runtime-lock-profiles",
                    profiles,
                    "--",
                    "/workspace/workload",
                ])
                .expect("parse fixed Go launch")
                .runtime_lock,
                Some(super::RuntimeLockLaunch::Go {
                    profiles: profiles.to_owned(),
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_runtime_lock_control_combinations() {
        for invalid in [
            vec![
                "gate",
                "--control",
                CONTROL_PATH,
                "--runtime-lock",
                "native_pthread",
                "--runtime-lock-semantics",
                "exact",
                "--runtime-lock-threshold-ns",
                "1000",
                "--runtime-lock-max-events",
                "1",
                "--",
                "/bin/true",
            ],
            vec![
                "gate",
                "--control",
                CONTROL_PATH,
                "--runtime-lock",
                "unknown",
                "--",
                "/bin/true",
            ],
            vec![
                "gate",
                "--control",
                CONTROL_PATH,
                "--runtime-lock",
                "java_jfr",
                "--runtime-lock-profile",
                "default",
                "--",
                "/bin/true",
            ],
            vec![
                "gate",
                "--control",
                CONTROL_PATH,
                "--runtime-lock",
                "go_pprof",
                "--runtime-lock-profiles",
                "mutex,block",
                "--",
                "/bin/true",
            ],
        ] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn runtime_lock_outputs_are_exportable_inside_the_private_run_root() {
        let directory = private_test_directory();
        let inherited_path = directory.join("native.ndjson");
        let output = create_private_output(inherited_path.to_str().expect("UTF-8 test path"))
            .expect("create inherited Runtime Lock output");
        assert_eq!(
            output
                .metadata()
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777,
            RUNTIME_LOCK_OUTPUT_MODE
        );
        let flags = FdFlag::from_bits_truncate(
            fcntl(&output, FcntlArg::F_GETFD).expect("read inherited descriptor flags"),
        );
        assert!(!flags.contains(FdFlag::FD_CLOEXEC));
        assert!(create_private_output(inherited_path.to_str().expect("UTF-8 test path")).is_err());
        drop(output);

        let named_path = directory.join("runtime-lock.jfr");
        prepare_fixed_output(named_path.to_str().expect("UTF-8 test path"))
            .expect("create named Runtime Lock output");
        assert_eq!(
            named_path
                .metadata()
                .expect("named output metadata")
                .permissions()
                .mode()
                & 0o777,
            RUNTIME_LOCK_OUTPUT_MODE
        );
        assert!(prepare_fixed_output(named_path.to_str().expect("UTF-8 test path")).is_err());

        fs::remove_file(inherited_path).expect("remove inherited output");
        fs::remove_file(named_path).expect("remove named output");
        fs::remove_dir(directory).expect("remove output test directory");
    }

    #[test]
    fn waits_for_exact_ready_and_release_frames() {
        let expected_ready = ready_frame(namespace_identity().expect("read test namespaces"));
        let directory = private_test_directory();
        let socket = directory.join("control.sock");
        let listener = UnixListener::bind(&socket).expect("bind gate test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept gate test peer");
            let mut ready = [0_u8; READY_FRAME_LEN];
            stream
                .read_exact(&mut ready)
                .expect("read gate ready frame");
            assert_eq!(ready, expected_ready);
            stream
                .write_all(EXEC_FRAME)
                .expect("write execution release");
        });
        assert_eq!(await_execution_release(&socket), Ok(()));
        server.join().expect("join gate test server");
        fs::remove_file(&socket).expect("remove gate test socket");

        let listener = UnixListener::bind(&socket).expect("bind extra-frame test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept extra-frame peer");
            let mut ready = [0_u8; READY_FRAME_LEN];
            stream
                .read_exact(&mut ready)
                .expect("read second ready frame");
            stream
                .write_all(EXEC_FRAME)
                .expect("write execution release");
            stream.write_all(b"x").expect("write forbidden extra frame");
        });
        assert!(await_execution_release(&socket).is_err());
        server.join().expect("join extra-frame server");
        fs::remove_file(&socket).expect("remove extra-frame socket");
        fs::remove_dir(&directory).expect("remove gate test directory");
    }

    #[test]
    fn retries_a_fixed_control_socket_until_it_appears() {
        let expected_ready = ready_frame(namespace_identity().expect("read test namespaces"));
        let directory = private_test_directory();
        let socket = directory.join("control.sock");
        let delayed_socket = socket.clone();
        let server = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            let listener = UnixListener::bind(&delayed_socket).expect("bind delayed socket");
            let (mut stream, _) = listener.accept().expect("accept delayed gate peer");
            let mut ready = [0_u8; READY_FRAME_LEN];
            stream
                .read_exact(&mut ready)
                .expect("read delayed ready frame");
            assert_eq!(ready, expected_ready);
            stream
                .write_all(EXEC_FRAME)
                .expect("write delayed execution release");
        });
        assert_eq!(await_execution_release(&socket), Ok(()));
        server.join().expect("join delayed socket server");
        fs::remove_file(&socket).expect("remove delayed socket");
        fs::remove_dir(&directory).expect("remove delayed socket directory");
    }

    #[test]
    fn ready_frame_is_fixed_width_and_network_order() {
        let identity = NamespaceIdentity {
            pid: 101,
            user: 102,
            mount: 103,
            cgroup: 104,
            effective_uid: 1000,
        };
        let frame = ready_frame(identity);
        assert_eq!(&frame[..READY_PREFIX.len()], READY_PREFIX);
        assert_eq!(frame.len(), READY_FRAME_LEN);
        let values = frame[READY_PREFIX.len()..]
            .chunks_exact(8)
            .map(|value| u64::from_be_bytes(value.try_into().expect("eight-byte inode")))
            .collect::<Vec<_>>();
        assert_eq!(values, vec![101, 102, 103, 104, 1000]);
    }
}
