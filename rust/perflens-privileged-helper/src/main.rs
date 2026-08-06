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
    let [
        broker_flag,
        raw_broker_uid,
        allowed_flag,
        raw_allowed_uid,
        group_flag,
        raw_artifact_gid,
    ] = arguments.as_slice()
    else {
        eprintln!(
            "perflens-privileged-helper: expected --broker-uid <uid> --allowed-uid <uid> --artifact-gid <gid>"
        );
        return ExitCode::from(64);
    };
    if broker_flag != "--broker-uid"
        || allowed_flag != "--allowed-uid"
        || group_flag != "--artifact-gid"
    {
        eprintln!("perflens-privileged-helper: unsupported argument");
        return ExitCode::from(64);
    }
    let Ok(broker_uid) = raw_broker_uid.parse::<u32>() else {
        eprintln!("perflens-privileged-helper: broker UID must be an unsigned integer");
        return ExitCode::from(64);
    };
    let Ok(allowed_uid) = raw_allowed_uid.parse::<u32>() else {
        eprintln!("perflens-privileged-helper: allowed UID must be an unsigned integer");
        return ExitCode::from(64);
    };
    let Ok(artifact_gid) = raw_artifact_gid.parse::<u32>() else {
        eprintln!("perflens-privileged-helper: artifact GID must be an unsigned integer");
        return ExitCode::from(64);
    };
    match serve_private_socket(
        Path::new(PRIVATE_HELPER_SOCKET),
        HelperServerPolicy {
            broker_uid,
            allowed_uid,
            artifact_gid,
        },
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_error) => {
            eprintln!("perflens-privileged-helper: private service failed safely");
            ExitCode::from(70)
        }
    }
}
