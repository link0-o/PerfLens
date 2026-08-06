use std::env;
use std::path::Path;
use std::process::ExitCode;

use perflens_privileged_helper::{HelperServerPolicy, PRIVATE_HELPER_SOCKET, serve_private_socket};

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["--version"] {
        println!("perflens-privileged-helper {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let [flag, raw_uid] = arguments.as_slice() else {
        eprintln!("perflens-privileged-helper: expected --broker-uid <uid>");
        return ExitCode::from(64);
    };
    if flag != "--broker-uid" {
        eprintln!("perflens-privileged-helper: unsupported argument");
        return ExitCode::from(64);
    }
    let Ok(broker_uid) = raw_uid.parse::<u32>() else {
        eprintln!("perflens-privileged-helper: broker UID must be an unsigned integer");
        return ExitCode::from(64);
    };
    match serve_private_socket(
        Path::new(PRIVATE_HELPER_SOCKET),
        HelperServerPolicy { broker_uid },
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_error) => {
            eprintln!("perflens-privileged-helper: private service failed safely");
            ExitCode::from(70)
        }
    }
}
