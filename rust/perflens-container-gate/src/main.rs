use std::env;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::{Duration, Instant};

const CONTROL_PATH: &str = "/run/perflens-gate/control.sock";
const READY_PREFIX: &[u8] = b"PERFLENS_GATE_V2 READY\0";
const READY_FRAME_LEN: usize = READY_PREFIX.len() + (4 * std::mem::size_of::<u64>());
const EXEC_FRAME: &[u8] = b"PERFLENS_GATE_V2 EXEC\n";
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 65_536;
const CONTROL_TIMEOUT: Duration = Duration::from_mins(1);
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_CONNECT_RETRY: Duration = Duration::from_millis(10);

#[derive(Debug, Eq, PartialEq)]
struct GateCommand {
    control: PathBuf,
    executable: OsString,
    arguments: Vec<OsString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceIdentity {
    pid: u64,
    user: u64,
    mount: u64,
    cgroup: u64,
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
    if values.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
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
        executable,
        arguments,
    })
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
    let error = Command::new(&command.executable)
        .args(&command.arguments)
        .exec();
    eprintln!("perflens-container-gate: workload exec failed: {error}");
    ExitCode::from(126)
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
    for inode in [identity.pid, identity.user, identity.mount, identity.cgroup] {
        let end = offset + std::mem::size_of::<u64>();
        frame[offset..end].copy_from_slice(&inode.to_be_bytes());
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
        await_execution_release, namespace_identity, parse_arguments, ready_frame,
    };
    use std::ffi::OsString;
    use std::fs;
    use std::io::{ErrorKind, Read, Write};
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
        };
        let frame = ready_frame(identity);
        assert_eq!(&frame[..READY_PREFIX.len()], READY_PREFIX);
        assert_eq!(frame.len(), READY_FRAME_LEN);
        let values = frame[READY_PREFIX.len()..]
            .chunks_exact(8)
            .map(|value| u64::from_be_bytes(value.try_into().expect("eight-byte inode")))
            .collect::<Vec<_>>();
        assert_eq!(values, vec![101, 102, 103, 104]);
    }
}
